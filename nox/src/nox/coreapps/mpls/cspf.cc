/* Copyright 2008, 2009 (C) Nicira, Inc.
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "cspf.hh"

#include <boost/bind.hpp>
#include <inttypes.h>

#include "assert.hh"
#include "openflow/nicira-ext.h"
#include "vlog.hh"
#include "openflow-default.hh"
#include "mpls_config.hh"

#define TOTAL_BW 1000
namespace vigil {
namespace applications {

static Vlog_module lg("cspf");

std::size_t
Cspf::linkhash::operator()(const Link& link) const
{
    return (HASH_NAMESPACE::hash<datapathid>()(link.dst)
                ^ HASH_NAMESPACE::hash<uint16_t>()(link.inport)
                ^ HASH_NAMESPACE::hash<uint16_t>()(link.outport));
}

bool
Cspf::linkeq::operator()(const Link& a, const Link& b) const
{
    return (a.dst == b.dst && a.inport == b.inport && a.outport == b.outport);
}

std::size_t
Cspf::ridhash::operator()(const RouteId& rid) const
{
    HASH_NAMESPACE::hash<datapathid> dphash;
    return (dphash(rid.src) ^ dphash(rid.dst));
}

bool
Cspf::rideq::operator()(const RouteId& a, const RouteId& b) const
{
    return (a.src == b.src && a.dst == b.dst);
}

std::size_t
Cspf::routehash::operator()(const RoutePtr& rte) const
{
    return (ridhash()(rte->id)
            ^ HASH_NAMESPACE::hash<uint32_t>()(rte->path.size()));
}

bool
Cspf::routeq::operator()(const RoutePtr& a, const RoutePtr& b) const
{
    if (a->id.src != b->id.src || a->id.dst != b->id.dst
        || a->path.size() != b->path.size())
    {
        return false;
    }
    std::list<Link>::const_iterator aiter, biter;
    for (aiter = a->path.begin(), biter = b->path.begin();
         aiter != a->path.end(); ++aiter, ++biter)
    {
        if (aiter->dst != biter->dst || aiter->outport != biter->outport
            || aiter->inport != biter->inport)
        {
            return false;
        }
    }
    return true;
}

bool
Cspf::ruleptrcmp::operator()(const RoutePtr& a, const RoutePtr& b) const
{
    return (a->path.size() > b->path.size());
}

static
inline
uint32_t
get_max_action_len() {
    if (sizeof(ofp_action_output) >= sizeof(nx_action_snat)) {
        return sizeof(ofp_action_output)+sizeof(ofp_action_dl_addr);
    }
    return sizeof(nx_action_snat)+sizeof(ofp_action_dl_addr);
}

// Constructor - initializes openflow packet memory used to setup route

Cspf::Cspf(const container::Context* c,
                               const xercesc::DOMNode* d)
    : container::Component(c), topology(0), nat(0), len_flow_actions(0),
      num_actions(0), ofm(0)
{
    max_output_action_len = get_max_action_len();
    xidcounter = 0;
}

void
Cspf::getInstance(const container::Context* ctxt,
                            Cspf*& r)
{
    r = dynamic_cast<Cspf*>
        (ctxt->get_by_interface(container::Interface_description
                                (typeid(Cspf).name())));
}


void
Cspf::configure(const container::Configuration*)
{
    resolve(topology);
    resolve(nat);
    register_handler<Link_event>
        (boost::bind(&Cspf::handle_link_change, this, _1));
}

void
Cspf::install()
{}

bool
Cspf::ruletunnelcmp::operator()(const TunnelStat& a, const TunnelStat& b) const
{
    return (a.priority > b.priority);
}

bool
Cspf::tunnel_fit(datapathid dpid, struct Link link, uint16_t resbw, uint8_t priority,
TunnelMap& removeDB) {
    struct LinkStat linkStat =  tunnelDB[dpid][link];
    struct TunnelStat tunnelStat;
    uint32_t available = linkStat.availableBw;

    if (available >= resbw) return true;
    if(linkStat.totalBw < resbw) return false;

    std::make_heap(linkStat.tunnels.begin(), linkStat.tunnels.end(), ruletunnelcmp());
    std::sort_heap(linkStat.tunnels.begin(), linkStat.tunnels.end(), ruletunnelcmp());

    for(TunnelQueue::iterator iter = linkStat.tunnels.begin(); iter != linkStat.tunnels.end(); iter++) {
         tunnelStat = *iter;
         if (tunnelStat.priority <= priority) {
            //TODO: empty the removeDB entries (needed??)
            return false;
        } else {
            removeDB[dpid][link].tunnels.push_back(tunnelStat);
            available += tunnelStat.resbw;
            if(available >= resbw) return true;
        }
    }
    return false;
}

void
Cspf::populate_ejected(const RouteId& id, RoutePtr& route,
                std::vector<uint16_t>& ejected, TunnelMap& removeDB, bool cleanup)
{
    datapathid cur = id.src;
    for(std::list<Link>::iterator it = route->path.begin();
            it != route->path.end(); it++) {
        struct Link link = *it;
        //add tunnelid in removeDB[dpid][link].tunnels to the removed vector
        for(TunnelQueue::iterator iter = removeDB[cur][link].tunnels.begin();
            iter != removeDB[cur][link].tunnels.end(); iter++) {
            if(std::find(ejected.begin(), ejected.end(), iter->tid) == ejected.end()) {
                ejected.push_back(iter->tid);
            }
        }
        cur = link.dst;
    }
     // clean up ejected tid from tunnelDB
    if(cleanup) remove_tunnels(ejected);
}
bool
Cspf::get_route(const RouteId& id, RoutePtr& route, uint16_t tid,
                uint32_t resbw, uint8_t priority,
                std::vector<uint16_t>& ejected)
{
    TunnelMap removeDB;
    if(find_route(id, route, tid, resbw, priority, removeDB)) {
        populate_ejected(id, route, ejected, removeDB, true);
        set_route(route, tid, priority, resbw);
        return true;
    }
    return false;
}

bool
Cspf::find_route(const RouteId& id, RoutePtr& route, uint16_t tid,
                uint32_t resbw, uint8_t priority, TunnelMap& removeDB)
{
    hash_map<datapathid, int32_t> distance;
    hash_map<datapathid, Link> prev;
    hash_map<datapathid, bool> visited;

    std::priority_queue<std::pair<int32_t, datapathid> > queue;
    std::pair<int32_t, datapathid> node;
    struct Link temp_link;

    int weight = 1;

    topology->get_switches();

    for(Topology::SwitchSet::iterator iter=topology->swSet.begin(); iter !=topology->swSet.end(); iter++) {
        distance[*iter] = INT32_MAX;
        visited[*iter] = false;
    }

    distance[id.src] = 0;
    queue.push(std::pair<int32_t, datapathid>(-distance[id.src], id.src));

    while(!queue.empty()) {
        datapathid src,dst;
        bool changed;
        node = queue.top();
        queue.pop();
        src = node.second;

         if(!visited[src]) {
            visited[src] = true;
            const Topology::DatapathLinkMap& outlinks = topology->get_outlinks(node.second);
            for(Topology::DatapathLinkMap::const_iterator iter=outlinks.begin(); iter != outlinks.end(); iter++) {
                dst = iter->first;
                changed = false;
                if(!visited[dst]) {
                    for(Topology::LinkSet::const_iterator liter=iter->second.begin(); liter != iter->second.end(); liter++) {
                        temp_link.dst = dst; temp_link.outport = liter->src; temp_link.inport = liter->dst;

                        //if link is a tunnel, don't use it
                        if(temp_link.inport >= MPLS_TUNNEL_ID_START) continue;
                        if(distance[dst] > distance[src] + weight &&
                            tunnel_fit(src, temp_link, resbw, priority, removeDB)) {
                            distance[dst] = distance[src] + weight;
                            prev[dst].dst = src;
                            prev[dst].outport =  liter->src;
                            prev[dst].inport =  liter->dst;
                            changed = true;
                        }
                    }
                    if(changed) {
                        queue.push(std::pair<int32_t, datapathid>(-distance[dst], dst));
                    }
                }
            }
         }
    }

    datapathid cur = id.dst;
    if(distance[id.dst] == INT32_MAX) return false;
    route.reset(new Route());
    route->id = id;
    while(cur != id.src) {
        struct Link link = {cur, prev[cur].outport, prev[cur].inport};
        route->path.push_front(link);
        cur = prev[cur].dst;
    }
    return true;

}

void
Cspf::clear_route(uint16_t tid, RoutePtr& route)
{
    datapathid src = route->id.src;
    for(std::list<Link>::iterator iter = route->path.begin(); iter != route->path.end(); iter++) {
        struct Link link  = *iter;
        for(TunnelQueue::iterator it = tunnelDB[src][link].tunnels.begin();
                it != tunnelDB[src][link].tunnels.end(); it++) {
            if(it->tid == tid) {
                tunnelDB[src][link].tunnels.erase(it);
                break;
            }
        }
        src = link.dst;
    }
}

bool
Cspf::check_explicit_route(RoutePtr& route, uint32_t resbw, uint8_t priority,
                              std::vector<uint16_t>& eject)
{
    return false;
}

bool
Cspf::check_existing_route(RoutePtr& route, uint32_t currresbw, uint8_t priority,
                              uint16_t tid, uint32_t newresbw, bool& newroute,
                              std::vector<uint16_t>& eject)
{
    TunnelMap removeDB;
    bool fits = true;

    newroute = false;
    if(currresbw >= newresbw) return true;

    uint32_t neededbw = newresbw - currresbw;
    datapathid src = route->id.src;
    for(std::list<Link>::iterator iter = route->path.begin(); iter != route->path.end(); iter++) {
        struct Link link  = *iter;
        fits = tunnel_fit(src, link, neededbw, priority, removeDB);
        if(!fits) {
            removeDB.clear();
            break;
        }
        src = link.dst;
    }

    if(!fits) {
        //set bw to 0
        std::vector<uint16_t> temp_ejected;
        change_bw(route, tid, currresbw, 0, temp_ejected);
        if(!temp_ejected.empty()) {
            VLOG_ERR(lg, "attempted to set bw reservation to 0 and got ejections!");
            change_bw(route, tid, 0, currresbw, temp_ejected);
            return false;
        }
        if(find_route(route->id, route, tid, newresbw, priority, removeDB)) {
            newroute = true;
            fits = true;
            populate_ejected(route->id, route, eject, removeDB, false);
        }
       //set reservations back
       change_bw(route, tid, 0, currresbw, temp_ejected);
       if(!temp_ejected.empty()) {
            VLOG_ERR(lg, "attempted to reset the bw reservation and got ejections!");
            return false;
        }
    } else {
         populate_ejected(route->id, route, eject, removeDB, false);
    }

    return fits;
}

void
Cspf::set_route(RoutePtr& route, uint16_t tid, uint8_t priority, uint32_t resbw)
{
    datapathid src = route->id.src;
    for(std::list<Link>::iterator iter = route->path.begin(); iter != route->path.end(); iter++) {
        struct Link link  = *iter;
        struct TunnelStat tun = {tid, priority, resbw};
        tunnelDB[src][link].tunnels.push_back(tun);
        tunnelDB[src][link].availableBw -= resbw;
        src = link.dst;
    }
}

void
Cspf::change_bw(RoutePtr& route, uint16_t tid, uint32_t currresbw,
                            uint32_t newresbw, std::vector<uint16_t>& ejected)
{
    datapathid src = route->id.src;
    for(std::list<Link>::iterator iter = route->path.begin(); iter != route->path.end(); iter++) {
        struct Link link  = *iter;
        for(TunnelQueue::iterator it = tunnelDB[src][link].tunnels.begin();
                it != tunnelDB[src][link].tunnels.end(); it++) {
            if(it->tid == tid) {
                it->resbw = newresbw;
                tunnelDB[src][link].availableBw -= (newresbw-currresbw);
                break;
            }
        }
        src = link.dst;
    }
}

void
Cspf::remove_tid(uint16_t tid)
{
    for(TunnelMap::iterator it1 = tunnelDB.begin(); it1 != tunnelDB.end(); it1++) {
        LinkStatDB& linkDB = it1->second;
        for(LinkStatDB::iterator it2 = linkDB.begin(); it2 != linkDB.end(); it2++) {
            TunnelQueue& tunnels = it2->second.tunnels;
            for(TunnelQueue::iterator it3 = tunnels.begin(); it3 != tunnels.end();) {
                if(it3->tid == tid) {
                    VLOG_DBG(lg, "removed tid %"PRIx16" from link", tid);
                    it2->second.availableBw += it3->resbw;
                    it3 = tunnels.erase(it3);
                } else {
                    ++it3;
                }
            }
        }
    }
}

void
Cspf::remove_tunnels(std::vector<uint16_t>& ejected)
{
    for(std::vector<uint16_t>::iterator iter = ejected.begin(); iter != ejected.end(); iter++) {
        remove_tid(*iter);
    }
}

void
Cspf::set_existing_route(uint16_t tid, uint8_t priority, uint32_t currresbw,
                            uint32_t newresbw, RoutePtr& route, bool newroute,
                            RoutePtr& new_route, std::vector<uint16_t>& ejected)
{
    if(!newroute) {
        remove_tunnels(ejected);
        change_bw(route, tid, currresbw, newresbw, ejected);
    } else {
        remove_tunnels(ejected);
        clear_route(tid, route);
        set_route(new_route, tid, priority, newresbw);
    }
}

bool
Cspf::check_route(const Route& route, uint16_t inport,
                            uint16_t outport) const
{
    if (route.path.empty()) {
        if (inport == outport) {
            return false;
        }
    } else if (inport == route.path.front().outport) {
        return false;
    } else if (outport == route.path.back().inport) {
        return false;
    }
    return true;
}


// Updates shortests paths on link change based on algorithm in "A New Approach
// to Dynamic All Pairs Shortest Paths" - C. Demetrescu

Disposition
Cspf::handle_link_change(const Event& e)
{
    const Link_event& le = assert_cast<const Link_event&>(e);

    RouteQueue new_candidates;
    RoutePtr route(new Route());
    Link tmp = { le.dpdst, le.sport, le.dport };
    route->id.src = le.dpsrc;
    route->id.dst = le.dpdst;
    route->path.push_back(tmp);

    if (le.action == Link_event::REMOVE) {
        //TODO: mpls remove/reroute tunnels associated
        cleanup(route, true);
        fixup(new_candidates, true);
    } else if (le.action == Link_event::ADD) {
        //mpls
        if(le.dport < MPLS_TUNNEL_ID_START) {
            tunnelDB[le.dpsrc][tmp].totalBw = TOTAL_BW *.9;
            tunnelDB[le.dpsrc][tmp].availableBw =  tunnelDB[le.dpsrc][tmp].totalBw;
        }

        RoutePtr left_subpath(new Route());
        RoutePtr right_subpath(new Route());
        left_subpath->id.src = left_subpath->id.dst = le.dpsrc;
        right_subpath->id.src = right_subpath->id.dst = le.dpdst;
        add(local_routes, route);
        add(left_local, route, right_subpath);
        add(right_local, route, left_subpath);
        new_candidates.push(route);
        fixup(new_candidates, false);
    } else {
        VLOG_ERR(lg, "Unknown link event action %u", le.action);
    }

    return CONTINUE;
}


void
Cspf::cleanup(RoutePtr route, bool delete_route)
{
    bool is_short = remove(shortest, route);
    if (delete_route) {
        remove(local_routes, route);
    }

    RoutePtr subpath(new Route());
    *subpath = *route;
    set_subpath(subpath, true);
    if (delete_route) {
        remove(right_local, route, subpath);
    }
    if (is_short) {
        remove(right_shortest, route, subpath);
    }

    *subpath = *route;
    set_subpath(subpath, false);
    if (delete_route) {
        remove(left_local, route, subpath);
    }
    if (is_short) {
        remove(left_shortest, route, subpath);
    }

    RouteSet to_clean;
    subpath = route;
    while (true) {
        RouteList left, right;
        ExtensionMap::iterator rtes = left_local.find(subpath);
        if (rtes != left_local.end()) {
            left_shortest.erase(subpath);
            left.swap(rtes->second);
            left_local.erase(rtes);
        }
        rtes = right_local.find(subpath);
        if (rtes != right_local.end()) {
            right_shortest.erase(subpath);
            right.swap(rtes->second);
            right_local.erase(rtes);
        }

        clean_subpath(subpath, left, to_clean, true);
        clean_subpath(subpath, right, to_clean, false);

        if (to_clean.empty())
            break;
        subpath = *(to_clean.begin());
        to_clean.erase(to_clean.begin());
    }
}


void
Cspf::clean_subpath(RoutePtr& subpath, const RouteList& extensions,
                              RouteSet& to_clean, bool is_left_extension)
{
    datapathid tmpdp;
    Link tmplink;

    if (is_left_extension) {
        tmplink = subpath->path.back();
        subpath->path.pop_back();
        if (subpath->path.empty()) {
            subpath->id.dst = subpath->id.src;
        } else {
            subpath->id.dst = subpath->path.back().dst;
        }
    } else {
        tmplink = subpath->path.front();
        subpath->path.pop_front();
        tmpdp = subpath->id.src;
        subpath->id.src = tmplink.dst;
    }

    for (RouteList::const_iterator rte = extensions.begin();
         rte != extensions.end(); ++rte)
    {
        clean_route(*rte, subpath, is_left_extension);
        to_clean.insert(*rte);
    }

    if (is_left_extension) {
        subpath->path.push_back(tmplink);
        subpath->id.dst = tmplink.dst;
    } else {
        subpath->path.push_front(tmplink);
        subpath->id.src = tmpdp;
    }
}


void
Cspf::clean_route(const RoutePtr& route,
                            RoutePtr& subpath,
                            bool cleaned_left)
{
    datapathid tmpdp;

    if (remove(local_routes, route)) {
        bool is_short = remove(shortest, route);
        if (cleaned_left) {
            tmpdp = subpath->id.src;
            subpath->id.src = route->id.src;
            subpath->path.push_front(route->path.front());
            remove(right_local, route, subpath);
            if (is_short)
                remove(right_shortest, route, subpath);
            subpath->id.src = tmpdp;
            subpath->path.pop_front();
        } else {
            const Link& newlink = route->path.back();
            tmpdp = subpath->id.dst;
            subpath->id.dst = newlink.dst;
            subpath->path.push_back(newlink);
            remove(left_local, route, subpath);
            if (is_short)
                remove(left_shortest, route, subpath);
            subpath->id.dst = tmpdp;
            subpath->path.pop_back();
        }
    }
}


void
Cspf::fixup(RouteQueue& new_candidates, bool add_least)
{
    if (add_least) {
        for (RoutesMap::iterator rtes = local_routes.begin();
             rtes != local_routes.end(); ++rtes)
        {
            new_candidates.push(*(rtes->second.begin()));
        }
    }

    while (!new_candidates.empty()) {
        RoutePtr route = new_candidates.top();
        new_candidates.pop();
        RouteMap::iterator old = shortest.find(route->id);
        if (old != shortest.end()) {
            if (old->second->path.size() <= route->path.size()) {
                continue;
            }
            cleanup(old->second, false);
        } else if (route->id.src == route->id.dst) {
            continue;
        }

        RoutePtr left_subpath(new Route());
        RoutePtr right_subpath(new Route());
        *left_subpath = *right_subpath = *route;
        set_subpath(left_subpath, true);
        set_subpath(right_subpath, false);
        get_cached_path(left_subpath);
        get_cached_path(right_subpath);
        add(shortest, route);
        add(left_shortest, route, right_subpath);
        add(right_shortest, route, left_subpath);
        add_local_routes(route, left_subpath, right_subpath, new_candidates);
    }
}


void
Cspf::add_local_routes(const RoutePtr& route,
                                 const RoutePtr& left_subpath,
                                 const RoutePtr& right_subpath,
                                 RouteQueue& new_candidates)
{
    ExtensionMap::iterator rtes = left_shortest.find(left_subpath);
    if (rtes != left_shortest.end()) {
        for (RouteList::const_iterator rte = rtes->second.begin();
             rte != rtes->second.end(); ++rte)
        {
            RoutePtr new_local(new Route());
            *new_local = *route;
            new_local->id.src = (*rte)->id.src;
            new_local->path.push_front((*rte)->path.front());
            add(local_routes, new_local);
            add(left_local, new_local, route);
            add(right_local, new_local, *rte);
            new_candidates.push(new_local);
        }
    }
    rtes = right_shortest.find(right_subpath);
    if (rtes != right_shortest.end()) {
        for (RouteList::const_iterator rte = rtes->second.begin();
             rte != rtes->second.end(); ++rte)
        {
            RoutePtr new_local(new Route());
            *new_local = *route;
            new_local->id.dst = (*rte)->id.dst;
            new_local->path.push_back((*rte)->path.back());
            add(local_routes, new_local);
            add(left_local, new_local, *rte);
            add(right_local, new_local, route);
            new_candidates.push(new_local);
        }
    }
}


void
Cspf::set_subpath(RoutePtr& subpath, bool left)
{
    if (left) {
        subpath->path.pop_back();
        if (subpath->path.empty()) {
            subpath->id.dst = subpath->id.src;
            return;
        }
        subpath->id.dst = subpath->path.back().dst;
    } else {
        subpath->id.src = subpath->path.front().dst;
        subpath->path.pop_front();
    }
}


void
Cspf::get_cached_path(RoutePtr& route)
{
    RoutesMap::iterator rtes = local_routes.find(route->id);
    if (rtes == local_routes.end()) {
        // for (dp, dp) paths
        ExtensionMap::iterator check = left_local.find(route);
        if (check != left_local.end()) {
            route = check->first;
        }
        return;
    }

    for (RouteList::const_iterator rte = rtes->second.begin();
         rte != rtes->second.end(); ++rte)
    {
        if (routeq()(route, *rte)) {
            route = *rte;
            return;
        }
    }
}


bool
Cspf::remove(RouteMap& routes, const RoutePtr& route)
{
    RouteMap::iterator rtes = routes.find(route->id);
    if (rtes != routes.end()) {
        if (routeq()(route, rtes->second)) {
            routes.erase(rtes);
            return true;
        }
    }
    return false;
}


bool
Cspf::remove(RoutesMap& routes, const RoutePtr& route)
{
    RoutesMap::iterator rtes = routes.find(route->id);
    if (rtes != routes.end()) {
        for (RouteList::iterator rte = rtes->second.begin();
             rte != rtes->second.end(); ++rte)
        {
            if (routeq()(route, *rte)) {
                rtes->second.erase(rte);
                if (rtes->second.empty())
                    routes.erase(rtes);
                return true;
            }
        }
    }
    return false;
}


bool
Cspf::remove(ExtensionMap& routes, const RoutePtr& route,
                       const RoutePtr& subpath)
{
    ExtensionMap::iterator rtes = routes.find(subpath);
    if (rtes != routes.end()) {
        for (RouteList::iterator rte = rtes->second.begin();
             rte != rtes->second.end(); ++rte)
        {
            if (routeq()(route, *rte)) {
                rtes->second.erase(rte);
                if (rtes->second.empty()) {
                    routes.erase(rtes);
                }
                return true;
            }
        }
    }
    return false;
}


void
Cspf::add(RouteMap& routes, const RoutePtr& route)
{
    routes[route->id] = route;
}

void
Cspf::add(RoutesMap& routes, const RoutePtr& route)
{
    RoutesMap::iterator rtes = routes.find(route->id);
    if (rtes == routes.end()) {
        routes[route->id] = RouteList(1, route);
    } else {
        uint32_t len = route->path.size();
        for (RouteList::iterator rte = rtes->second.begin();
             rte != rtes->second.end(); ++rte)
        {
            if ((*rte)->path.size() > len) {
                rtes->second.insert(rte, route);
                return;
            }
        }
        rtes->second.push_back(route);
    }
}

void
Cspf::add(ExtensionMap& routes, const RoutePtr& route,
                    const RoutePtr& subpath)
{
    ExtensionMap::iterator rtes = routes.find(subpath);
    if (rtes == routes.end()) {
        routes[subpath] = RouteList(1, route);
    } else {
        rtes->second.push_back(route);
    }
}


// Methods handling a Flow_in_event, setting up the route to permit the flow
// all the way to its destination without having to go up to the controller for
// a permission check.

#define CHECK_OF_ERR(error, dp)                                         \
    if (error) {                                                        \
        if (error == EAGAIN) {                                          \
            VLOG_DBG(lg, "Add flow entry to dp:%"PRIx64" failed with EAGAIN.", \
                     dp.as_host());                                     \
        } else {                                                        \
            VLOG_ERR(lg, "Add flow entry to dp:%"PRIx64" failed with %d:%s.", \
                     dp.as_host(), error, strerror(error));             \
        }                                                               \
        os.str("");                                                     \
        return false;                                                   \
    }


}
}

REGISTER_COMPONENT(vigil::container::Simple_component_factory
                   <vigil::applications::Cspf>,
                   vigil::applications::Cspf);
