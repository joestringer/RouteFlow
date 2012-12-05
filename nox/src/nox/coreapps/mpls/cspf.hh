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
#ifndef CSPF_HH
#define CSPF_HH 1

#include <boost/shared_ptr.hpp>
#include <boost/shared_array.hpp>
#include <list>
#include <queue>
#include <sstream>
#include <vector>
#include <algorithm>

#include "component.hh"
#include "event.hh"
#include "flow.hh"
#include "hash_map.hh"
#include "hash_set.hh"
#include "discovery/link-event.hh"
#include "routing/nat_enforcer.hh"
#include "netinet++/datapathid.hh"
#include "netinet++/ethernetaddr.hh"
#include "openflow/openflow.h"
#include "topology/topology.hh"

/*
 * Cspf is a utility component that can be called to retrieve a
 * constrained shortest path route or to check for one given an explicit path.
 *
 * Uses Dijiksta's algorithm modified to accomodate link constraints
 *
 * All integer values are stored in host byte order and should be passed in as
 * such as well.
 *
 */

namespace vigil {
namespace applications {

class Cspf
    : public container::Component {

public:
    struct Link {
        datapathid dst;    // destination dp of link starting at current dp
        uint16_t outport;  // outport of current dp link connected to
        uint16_t inport;   // inport of destination dp link connected to
    };

    struct RouteId {
        datapathid src;    // Source dp of a route
        datapathid dst;    // Destination dp of a route
    };

    struct Route {
        RouteId id;            // Start/End datapath
        std::list<Link> path;  // links connecting datapaths
    };

    struct TunnelStat {
        uint16_t tid;
        uint8_t priority;
        uint32_t resbw;
    };

    struct ruletunnelcmp {
        bool operator()(const TunnelStat& a, const TunnelStat& b) const;
    };

    typedef std::vector<TunnelStat> TunnelQueue;
    struct LinkStat {
        uint32_t totalBw;
        uint32_t availableBw;
        TunnelQueue  tunnels;
    };

    typedef boost::shared_ptr<Route> RoutePtr;
    typedef std::list<Nonowning_buffer> ActionList;

    Cspf(const container::Context*,
                   const xercesc::DOMNode*);
    // for python
    Cspf();
    ~Cspf() { }

    static void getInstance(const container::Context*, Cspf*&);

    void configure(const container::Configuration*);
    void install();


    // Given a RouteId 'id', sets 'route' to the route between the two
    // datapaths.  Returns 'true' if a route between the two exists which
    // meets the bandwidth and priority constraints, else 'false'.
    // In most cases, the route should later be passed on to
    // check_route() with the inport and outport of the start and end dps to
    // verify that a packet will not get routed out the same port it came in
    // on, (which should only happen in very specific cases, e.g. wireless APs).
    // Should avoid calling this method unnecessarily when id.src == id.dst -
    // as module will allocate a new empty Route() to populate 'route'.  Caller
    // will ideally check for this case.
    // Normally routes retrieved through this method SHOULD NOT BE MODIFIED.
    // This function assumes  that route returned for tunnel_id 'tid'
    // is immediately installed in the switches by the caller.
    // If this route ends up ejecting lower priority tunnels, the tunnel ids
    // of the ejected tunnels are passed back to the caller in 'ejected'. It
    // assumes that that tunnel state for the ejected tunnels are cleared in
    // the switches by the caller.
    bool get_route(const RouteId& id, RoutePtr& route, uint16_t tid,
                   uint32_t resbw, uint8_t priority,
                   std::vector<uint16_t>& ejected);

    // Given a route and an access point inport and outport, verifies that a
    // flow will not get routed out the same port it came in on at the
    // endpoints.  Returns 'true' if this will not happen, else 'false'.
    bool check_route(const Route& route, uint16_t inport, uint16_t outport) const;


    // This function should is called when a tunnel is deleted.
    void clear_route(uint16_t tid, RoutePtr& route);

    // Given an explicit route in 'route', verifies that a route can be found
    // along the explicit path which meets the bandwidth and priority constraints.
    // Note that the caller may only specify the datapathids in 'route' and not the
    // ports. In that case, the function populates the outport and inport for each
    // link in the 'route'. If this route were to be installed, the caller MUST
    // then submit a call to get_route. If this route could potentially eject
    // some lower priority tunnels, then the tunnel_ids of those tunnels are reported
    // in 'eject'. This function does NOT assume that the 'route' is eventually
    // installed, nor does it assume the 'eject's are actually ejected.
    // Finally, like get_route, this function is applicable only to routes for
    // new tunnels, NOT existing ones. After checking, if the caller wishes to
    // enable this new tunnel route, they can use get_route
    bool check_explicit_route(RoutePtr& route, uint32_t resbw, uint8_t priority,
                              std::vector<uint16_t>& eject);

    // Given a tunnel-id for an existing tunnel together with it's existing route
    // (including port numbers), current reserved bandwdith and priority, this
    // function checks if a new_reserved bandwidth is possible along the same route.
    // If it is possible, the function returns true.
    // If it is possible, but requires ejecting other lower priority tunnels, the
    // function returns true and populates the would-be-ejected tunnel_ids in 'eject'.
    // If it is possible, but requires using a new route, the function returns true,
    // clears the 'route', populates the new 'route', and sets 'newroute' to true.
    // If additionally the new 'route', bumps off lower priority tunnels, their
    // tunnel_ids are returned in 'eject'
    // This is a check - the function does not assume that the bandwidth reservation
    // changes or new routes are installed or any tunnels are actually ejected.
    bool check_existing_route(RoutePtr& route, uint32_t currresbw, uint8_t priority,
                              uint16_t tid, uint32_t newresbw, bool& newroute,
                              std::vector<uint16_t>& eject);

    // In response to check_existing_route, the caller may decide to alter the existing
    // route. The caller informs Cspf of the changes using set_existing_route. 'route is
    // the existing route (when check_existing_route was called). if the route has since
    // changed, then newroute is true and the new route is in 'new_route'. If the caller
    // ejected routes to establish either the 'newresbw', or the 'new_route', it
    // informs Cspf of the ejected tunnels in 'ejected'
    void set_existing_route(uint16_t tid, uint8_t priority, uint32_t currresbw,
                            uint32_t newresbw, RoutePtr& route, bool newroute,
                            RoutePtr& new_route, std::vector<uint16_t>& ejected);



private:
    struct ridhash {
        std::size_t operator()(const RouteId& rid) const;
    };

    struct rideq {
        bool operator()(const RouteId& a, const RouteId& b) const;
    };

    struct routehash {
        std::size_t operator()(const RoutePtr& rte) const;
    };

    struct routeq {
        bool operator()(const RoutePtr& a, const RoutePtr& b) const;
    };

    struct ruleptrcmp {
        bool operator()(const RoutePtr& a, const RoutePtr& b) const;
    };

    typedef std::list<RoutePtr> RouteList;
    typedef hash_set<RoutePtr, routehash, routeq> RouteSet;
    typedef hash_map<RouteId, RoutePtr, ridhash, rideq> RouteMap;
    typedef hash_map<RouteId, RouteList, ridhash, rideq> RoutesMap;
    typedef hash_map<RoutePtr, RouteList, routehash, routeq> ExtensionMap;
    typedef std::priority_queue<RoutePtr, std::vector<RoutePtr>, ruleptrcmp> RouteQueue;

    // Data structures needed by All-Pairs Shortest Path Algorithm

    Topology *topology;
    NAT_enforcer *nat;
    RouteMap shortest;
    RoutesMap local_routes;
    ExtensionMap left_local;
    ExtensionMap left_shortest;
    ExtensionMap right_local;
    ExtensionMap right_shortest;

    std::vector<const std::vector<uint64_t>*> nat_flow;

    uint32_t xidcounter;
    uint16_t max_output_action_len;
    uint16_t len_flow_actions;
    uint32_t num_actions;
    boost::shared_array<uint8_t> raw_of;
    ofp_flow_mod *ofm;

    std::ostringstream os;

    Disposition handle_link_change(const Event&);

    // All-pairs shortest path fns

    void cleanup(RoutePtr, bool);
    void clean_subpath(RoutePtr&, const RouteList&, RouteSet&, bool);
    void clean_route(const RoutePtr&, RoutePtr&, bool);

    void fixup(RouteQueue&, bool);
    void add_local_routes(const RoutePtr&, const RoutePtr&,
                          const RoutePtr&, RouteQueue&);

    void set_subpath(RoutePtr&, bool);
    void get_cached_path(RoutePtr&);

    bool remove(RouteMap&, const RoutePtr&);
    bool remove(RoutesMap&, const RoutePtr&);
    bool remove(ExtensionMap&, const RoutePtr&, const RoutePtr&);
    void add(RouteMap&, const RoutePtr&);
    void add(RoutesMap&, const RoutePtr&);
    void add(ExtensionMap&, const RoutePtr&, const RoutePtr&);

    //cspf helper methods
    struct linkhash {
        std::size_t operator()(const Link& link) const;
    };

    struct linkeq {
        bool operator()(const Link& a, const Link& b) const;
    };

    typedef hash_map<Link, LinkStat, linkhash, linkeq> LinkStatDB;
    typedef hash_map<datapathid, LinkStatDB> TunnelMap;
    TunnelMap tunnelDB;

    void populate_ejected(const RouteId& id, RoutePtr& route,
                std::vector<uint16_t>& ejected, TunnelMap& removeDB, bool cleanup);

   bool find_route(const RouteId& id, RoutePtr& route, uint16_t tid,
                uint32_t resbw, uint8_t priority, TunnelMap& removeDB);

    bool move_tunnels(TunnelQueue& from, TunnelQueue& to);
    void remove_tid(uint16_t tid);
    void remove_tunnels(std::vector<uint16_t>& ejected);
    // check if tunnel can be added to tunnelDB and put the tunnels that need to be
    // removed in removeDB
    bool tunnel_fit(datapathid dpid, struct Link link, uint16_t resbw, uint8_t priority,
TunnelMap &removeDB);

    void set_route(RoutePtr& route, uint16_t tid, uint8_t priority, uint32_t resbw);

    void change_bw(RoutePtr& route, uint16_t tid, uint32_t currresbw,
                            uint32_t newresbw, std::vector<uint16_t>& ejected);

};

}
}

#endif
