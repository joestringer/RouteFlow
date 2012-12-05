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

#include "authenticator.hh"

#include "assert.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "directory/group_event.hh"
#include "directory/netinfo_mod_event.hh"
#include "directory/principal_event.hh"
#include "discovery/link-event.hh"
#include "netinet++/ethernet.hh"
#include "port-status.hh"
#include "vlog.hh"

#define LOC_FROM_DP_PORT(dp, pt) ((dp).as_host() + (((uint64_t)(pt)) << 48))

#define DP_MASK          0xffffffffffffULL

namespace vigil {
namespace applications {

static Vlog_module lg("authenticator");

void
Authenticator::post_event(Event *to_post) const
{
    if (to_post) {
        post(to_post);
    }
}

Disposition
Authenticator::handle_bootstrap(const Event& e)
{
    auto_auth = ctxt->get_kernel()->get("sepl_enforcer",
                                        INSTALLED) == NULL;
    new_switch(datapathid::from_host(0));
    new_location(datapathid::from_host(0), 0, 0, "");
    timeval exp = { expire_timer, 0 };
    post(boost::bind(&Authenticator::expire_entities, this), exp);

    return CONTINUE;
}

Disposition
Authenticator::handle_datapath_join(const Event& e)
{
    const Datapath_join_event& dj = assert_cast<const Datapath_join_event&>(e);
    uint64_t dpint = dj.datapath_id.as_host();

    new_switch(dj.datapath_id);
    for (std::vector<Port>::const_iterator iter = dj.ports.begin();
         iter != dj.ports.end(); ++iter)
    {
        new_location(dj.datapath_id, iter->port_no,
                     dpint + (((uint64_t) iter->port_no) << 48), iter->name);
    }
    return CONTINUE;
}

Disposition
Authenticator::handle_datapath_leave(const Event& e)
{
    const Datapath_leave_event& dl = assert_cast<const Datapath_leave_event&>(e);

    remove_switch(dl.datapath_id, false);

    return CONTINUE;
}

// XXX can modify port name?!
Disposition
Authenticator::handle_port_status(const Event& e)
{
    const Port_status_event& ps = assert_cast<const Port_status_event&>(e);
    uint64_t loc = LOC_FROM_DP_PORT(ps.datapath_id, ps.port.port_no);

    if (ps.reason == OFPPR_DELETE) {
        remove_location(ps.datapath_id, ps.port.port_no, loc, false);
    } else if (ps.reason == OFPPR_ADD) {
        new_location(ps.datapath_id, ps.port.port_no, loc, ps.port.name);
    }

    return CONTINUE;
}

Disposition
Authenticator::handle_link_change(const Event& e)
{
    const Link_event& le = assert_cast<const Link_event&>(e);

    if (le.action == Link_event::ADD) {
        remove_host(LOC_FROM_DP_PORT(le.dpdst, le.dport),
                    Host_event::INTERNAL_LOCATION, false);
    }
    return CONTINUE;
}

Disposition
Authenticator::handle_host_auth(const Event& e)
{
    const Host_auth_event& host_auth = assert_cast<const Host_auth_event&>(e);
    Host_auth_event& ha = const_cast<Host_auth_event&>(host_auth);

    EmptyCb cb = boost::bind(&Authenticator::post_event, this, ha.to_post);

    VLOG_DBG(lg, "Host auth event received.");
    if (ha.action == Host_auth_event::AUTHENTICATE) {
        ha.to_post = NULL;
        call_with_global_lock_bool_cb(boost::bind(&Authenticator::add_host,
                                                  this, ha, _1, true), cb);
    } else if (ha.action == Host_auth_event::DEAUTHENTICATE) {
        ha.to_post = NULL;
        call_with_global_lock(boost::bind(&Authenticator::remove_host,
                                          this, ha), cb);
    }
    return CONTINUE;
}

Disposition
Authenticator::handle_user_auth(const Event& e)
{
    const User_auth_event& user_auth = assert_cast<const User_auth_event&>(e);
    User_auth_event& ua = const_cast<User_auth_event&>(user_auth);

    EmptyCb cb = boost::bind(&Authenticator::post_event,
                             this, ua.to_post);

    VLOG_DBG(lg, "User auth event received.");
    if (ua.action == User_auth_event::AUTHENTICATE) {
        ua.to_post = NULL;
        call_with_global_lock_bool_cb(boost::bind(&Authenticator::add_user,
                                                  this, ua, _1, true), cb);
    } else if (ua.action == User_auth_event::DEAUTHENTICATE) {
        ua.to_post = NULL;
        call_with_global_lock(boost::bind(&Authenticator::remove_user, this,
                                          ua.username, ua.hostname, ua.reason), cb);
    }
    return CONTINUE;
}

Disposition
Authenticator::handle_principal_delete(const Event& e)
{
    const Principal_delete_event& pd = assert_cast<const Principal_delete_event&>(e);
    EmptyCb cb;
    VLOG_DBG(lg, "Principal event received.");
    switch (pd.type) {
    case directory::SWITCH_PRINCIPAL:
        call_with_global_lock_cb(boost::bind(&Authenticator::reauthenticate_switch,
                                             this, pd.id, _1), cb);
        break;
    case directory::LOCATION_PRINCIPAL:
        call_with_global_lock_cb(boost::bind(&Authenticator::reauthenticate_location,
                                             this, pd.id, _1), cb);
        break;
    case directory::HOST_PRINCIPAL:
        call_with_global_lock_cb(boost::bind(&Authenticator::delete_host,
                                             this, pd.id,
                                             Host_event::HOST_DELETE, _1), cb);
        break;
    case directory::USER_PRINCIPAL:
        call_with_global_lock_cb(boost::bind(&Authenticator::delete_user,
                                             this, pd.id,
                                             User_event::USER_DELETE, _1), cb);
        break;
    default:
        VLOG_ERR(lg, "Cannot delete prinicipal type %u.", pd.type);
    }

    return CONTINUE;
}

void
Authenticator::reauthenticate_switch(uint32_t name, const EmptyCb& cb)
{
    get_switch_by_name(name, true,
                       boost::bind(&Authenticator::reauthenticate_switch2,
                                   this, _1, cb));
}

void
Authenticator::reauthenticate_switch2(SwitchEntry *swentry, const EmptyCb& cb)
{
    if (swentry == NULL) {
        cb();
        return;
    }

    datapathid dp = swentry->dp;
    std::vector<std::pair<uint64_t, std::string> > locs;

    for (std::list<LocEntry*>::iterator liter = swentry->locations.begin();
         liter != swentry->locations.end(); ++liter)
    {
        locs.push_back(std::pair<uint64_t, std::string>((*liter)->entry->dpport,
                                                        namemanager->get_name((*liter)->portname)));
    }

    new_switch(dp);
    std::vector<std::pair<uint64_t, std::string> >::iterator liter = locs.begin();;
    for (; liter != locs.end(); ++liter) {
        new_location(dp, (uint16_t)(liter->first >> 48), liter->first,
                     liter->second);
    }
    cb();
}

void
Authenticator::reauthenticate_location(uint32_t name, const EmptyCb& cb)
{
    get_location_by_name(name, true,
                         boost::bind(&Authenticator::reauthenticate_location2,
                                     this, _1, _2, cb));
}

void
Authenticator::reauthenticate_location2(DPIDMap::iterator& siter,
                                        DPPORTMap::iterator& dppiter,
                                        const EmptyCb& cb)
{
    if (siter != switches_by_dp.end() && dppiter != locations_by_dpport.end()) {
        new_location(siter->second.dp, (uint16_t)(dppiter->first >> 48),
                     dppiter->first, namemanager->get_name(dppiter->second.portname));
    }
    cb();
}

Disposition
Authenticator::handle_group_delete(const Event& e)
{
    const Group_delete_event& gd = assert_cast<const Group_delete_event&>(e);

    VLOG_DBG(lg, "Group event received.");

    boost::function<void(SwitchEntry&)> sfn;
    boost::function<void(HostEntry&)> hfn;
    boost::function<void(UserEntry&)> ufn;
    boost::function<void(DLEntry&)> dfn;

    switch (gd.type) {
    case directory::SWITCH_PRINCIPAL_GROUP:
    case directory::LOCATION_PRINCIPAL_GROUP:
        sfn = boost::bind(&Authenticator::remove_group<SwitchEntry>,
                          this, _1, gd.id);
        map_entries(&switches_by_dp, sfn);
        break;
    case directory::HOST_PRINCIPAL_GROUP:
        hfn = boost::bind(&Authenticator::remove_group<HostEntry>,
                          this, _1, gd.id);
        map_entries(&hosts, hfn);
        break;
    case directory::USER_PRINCIPAL_GROUP:
        ufn = boost::bind(&Authenticator::remove_group<UserEntry>,
                          this, _1, gd.id);
        map_entries(&users, ufn);
        break;
    case directory::DLADDR_GROUP:
    case directory::NWADDR_GROUP:
        dfn = boost::bind(&Authenticator::remove_group<DLEntry>,
                          this, _1, gd.id);
        map_entries(&hosts_by_dladdr, dfn);
        break;
    default:
        VLOG_WARN(lg, "Authenticator doesn't cache group type %"PRIu32".", gd.type);
    }

    return CONTINUE;
}

Disposition
Authenticator::handle_group_change(const Event& e)
{
    const Group_change_event& gc = assert_cast<const Group_change_event&>(e);

    VLOG_DBG(lg, "Group change event received.");

    bool subgroup = gc.change_type == Group_change_event::ADD_SUBGROUP
        || gc.change_type == Group_change_event::DEL_SUBGROUP;

    boost::function<void(SwitchEntry&)> sfn;
    boost::function<void(HostEntry&)> hfn;
    boost::function<void(UserEntry&)> ufn;
    boost::function<void(DLEntry&)> dfn;

    switch (gc.group_type) {
    case directory::SWITCH_PRINCIPAL_GROUP:
        if (!subgroup) {
            get_switch_by_name(gc.change_id, false,
                               boost::bind(&Authenticator::modify_sw_loc_group,
                                           this, _1, NameManager::UNKNOWN_ID,
                                           directory::SWITCH_PRINCIPAL_GROUP));
            break;
        }
        //cascade through
    case directory::LOCATION_PRINCIPAL_GROUP:
        if (!subgroup) {
            get_location_by_name(gc.change_id, false,
                                 boost::bind(&Authenticator::modify_location_group,
                                             this, _1, _2));
        } else {
            sfn = boost::bind(&Authenticator::modify_sw_loc_group_ref,
                              this, _1, gc.change_id, gc.group_type);
            map_entries(&switches_by_dp, sfn);
        }
        break;
    case directory::HOST_PRINCIPAL_GROUP:
        if (subgroup) {
            hfn = boost::bind(&Authenticator::modify_host_group,
                              this, _1, gc.change_id);
            map_entries(&hosts, hfn);
        } else {
            hfn = boost::bind(&Authenticator::modify_host_group,
                              this, _1, NameManager::UNKNOWN_ID);
            map_entry(&hosts, gc.change_id, hfn);
        }
        break;
    case directory::USER_PRINCIPAL_GROUP:
        if (subgroup) {
            ufn = boost::bind(&Authenticator::modify_user_group,
                              this, _1, gc.change_id);
            map_entries(&users, ufn);
        } else {
            ufn = boost::bind(&Authenticator::modify_user_group,
                              this, _1, NameManager::UNKNOWN_ID);
            map_entry(&users, gc.change_id, ufn);
        }
        break;
    case directory::DLADDR_GROUP:
        if (!subgroup) {
            dfn = boost::bind(&Authenticator::modify_addr_group,
                              this, _1, 0, 0, gc.group_type, subgroup);
            map_entry(&hosts_by_dladdr,
                      ethernetaddr(gc.change_name).hb_long(), dfn);
            break;
        }
        // cascade into next
    case directory::NWADDR_GROUP:
        if (!subgroup) {
            cidr_ipaddr cidr(gc.change_name);
            dfn = boost::bind(&Authenticator::modify_addr_group, this,
                              _1, ntohl(cidr.addr.addr), ntohl(cidr.mask),
                              gc.group_type, subgroup);
        } else {
            dfn = boost::bind(&Authenticator::modify_addr_group, this,
                              _1, gc.change_id, 0, gc.group_type, subgroup);
        }
        map_entries(&hosts_by_dladdr, dfn);
        break;
    default:
        VLOG_WARN(lg, "Authenticator doesn't cache group type %"PRIu32".", gc.group_type);
    }

    return CONTINUE;
}

Disposition
Authenticator::handle_netinfo_mod(const Event& e)
{
    VLOG_DBG(lg, "Netinfo mod event received.");

    const NetInfo_mod_event& nm = assert_cast<const NetInfo_mod_event&>(e);
    EmptyCb cb;
    call_with_global_lock_cb(boost::bind(&Authenticator::netinfo_mod, this,
                                         nm.dladdr.hb_long(),
                                         nm.is_router || nm.is_gateway, _1), cb);
    return CONTINUE;
}

void
Authenticator::netinfo_mod(uint64_t dladdr, bool is_router, const EmptyCb& cb)
{
    DLMap::iterator dliter = hosts_by_dladdr.find(dladdr);
    if (dliter == hosts_by_dladdr.end()) {
        cb();
        return;
    }

    if (dliter->second.status.locked) {
        VLOG_DBG(lg, "Queueing netinfo_mod %"PRIx64".", dladdr);
        dliter->second.status.waiters.push_back(
            boost::bind(&Authenticator::netinfo_mod, this,
                        dladdr, is_router, cb));
        return;
    }

    if (dliter->second.is_router != is_router) {
        remove_host_location(&dliter->second, 0, false,
                             Host_event::DLADDR_ATTR_CHANGE, true);
        dliter->second.is_router = is_router;
    }
    cb();
}

Disposition
Authenticator::handle_packet_in(const Event& e)
{
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);

    Flow flow(htons(pi.in_port), *(pi.buf));
    if (flow.dl_type == ethernet::LLDP) {
        return CONTINUE;
    }

    timeval curtime = { 0, 0 };
    gettimeofday(&curtime, NULL);
    Flow_in_event *fi = new Flow_in_event(curtime, pi, flow);
    BoolCb empty;
    set_flow_in(fi, true, empty);
    return CONTINUE;
}

void
Authenticator::set_flow_in(Flow_in_event *fi, bool auto_src_auth,
                           const BoolCb& sfi_cb)
{
    if (fi->src_location.location == NULL || fi->dst_locations.empty()) {
        EmptyCb fail = boost::bind(&Authenticator::set_flow_in, this,
                                   fi, auto_src_auth, sfi_cb);
        NWEntry *nwentry;
        if (fi->src_location.location == NULL) {
            nwentry = get_nwentry(fi->flow.dl_src, ntohl(fi->flow.nw_src), fail);
            if (nwentry == NULL) {
                return;
            }
            fi->src_addr_groups = nwentry->address_groups;
            if (!set_src_host(nwentry, fi, auto_src_auth, sfi_cb)) {
                return;
            }
        }

        if (fi->dst_locations.empty()) {
            nwentry = get_nwentry(fi->flow.dl_dst, ntohl(fi->flow.nw_dst), fail);
            if (nwentry == NULL) {
                return;
            }
            fi->dst_addr_groups = nwentry->address_groups;
            if (!set_dst_host(nwentry, fi, sfi_cb)) {
                return;
            }
        }
    }

    if (sfi_cb.empty()) {
        post(fi);
    } else {
        sfi_cb(true);
    }
}

bool
Authenticator::set_src_host(NWEntry *nwentry, Flow_in_event *fi,
                            bool auto_src_auth, const BoolCb& sfi_cb)
{
    std::list<AuthedLocation>& authed_locs = nwentry->dlentry->locations;
    std::list<AuthedLocation>::iterator authed;

    uint16_t in_port = ntohs(fi->flow.in_port);
    uint64_t loc = LOC_FROM_DP_PORT(fi->datapath_id, in_port);
    if (get_location(fi->datapath_id, in_port, loc, authed_locs, authed)) {
        if (authed->location->dpport == loc) {
            make_primary(fi->received.tv_sec, nwentry->dlentry->dladdr,
                         authed_locs, authed);
        }
        if (nwentry->authed) {
            fi->src_host = nwentry->host;
            fi->src_host->last_active = fi->received.tv_sec;
            fi->src_location = *authed;
            return true;
        } else {
            if (nwentry->dlentry->is_router) {
                fi->route_source = authed->location;
                nwentry->dlentry->zero->host->last_active = fi->received.tv_sec;
                if (set_router_host(nwentry->nwaddr, fi, true)) {
                    return true;
                }
                loc = 0;
            } else if (auto_src_auth) {
                VLOG_DBG(lg, "Automatically adding %s on %s.",
                         ipaddr(nwentry->nwaddr).string().c_str(),
                         nwentry->dlentry->dladdr.string().c_str());
                Host_auth_event ha(datapathid::from_host(authed->location->dpport & DP_MASK),
                                   (uint16_t)(authed->location->dpport >> 48),
                                   nwentry->dlentry->dladdr, nwentry->nwaddr,
                                   nwentry->dlentry->zero->host->name,
                                   authed->idle_timeout,
                                   nwentry->dlentry->zero->host->hard_timeout,
                                   Host_event::NWADDR_AUTO_ADD);
                // XXX want to wait until after auth is complete or just set to
                // zero host?
                EmptyCb cb =
                    boost::bind(&Authenticator::set_flow_in, this, fi, false, sfi_cb);
                call_with_global_lock_bool_cb(
                    boost::bind(&Authenticator::add_host, this, ha, _1, true), cb);
                return false;
            }
        }
    }

    if (auto_auth && sfi_cb.empty()) {
        VLOG_DBG(lg, "Automatically authing %s %s.",
                 nwentry->dlentry->dladdr.string().c_str(),
                 ipaddr(nwentry->nwaddr).string().c_str());
        auth_flow_host(*fi, nwentry);
        delete fi;
    } else {
        set_host_by_id(NameManager::UNAUTHENTICATED_ID, fi, true, NULL, loc, sfi_cb);
    }
    return false;
}

bool
Authenticator::set_dst_host(NWEntry *nwentry, Flow_in_event *fi,
                            const BoolCb& sfi_cb)
{
    std::list<AuthedLocation>& authed_locs = nwentry->dlentry->locations;
    std::list<AuthedLocation>::iterator authed;
    fi->dst_authed = false;
    if (nwentry->host != NULL
        && (nwentry->authed || !nwentry->dlentry->is_router
            || nwentry->nwaddr == 0))
    {
        fi->dst_host = nwentry->host;
        fi->dst_authed = nwentry->authed;
        if (!authed_locs.empty()) {
            set_destinations(authed_locs, fi);
            return true;
        }
    } else if (nwentry->dlentry->is_router) {
        bool success = set_router_host(nwentry->nwaddr, fi, false);
        if (!authed_locs.empty()) {
            for (authed = authed_locs.begin();
                 authed != authed_locs.end(); ++authed)
            {
                fi->route_destinations.push_back(authed->location);
            }
            if (success) {
                return true;
            }
        }
    } else if (nwentry->dlentry->zero != NULL) {
        fi->dst_host = nwentry->dlentry->zero->host;
        fi->dst_authed = false;
        if (!authed_locs.empty()) {
            set_destinations(authed_locs, fi);
            return true;
        }
    }

    if (fi->dst_host != NULL) {
        set_location(fi, 0, false, sfi_cb);
    } else if (fi->src_host->name == NameManager::UNAUTHENTICATED_ID) {
        set_host_by_id(NameManager::UNAUTHENTICATED_ID, fi, false, NULL,
                       0, sfi_cb);
    } else {
        VLOG_DBG(lg, "Looking up destination name for flow.");
        nwentry->dlentry->status.locked = true;
        get_host(datapathid::from_host(0), 0, nwentry->dlentry->dladdr,
                 nwentry->nwaddr, nwentry->dlentry->is_router,
                 boost::bind(&Authenticator::set_host_by_name, this,
                             _1, fi, false, nwentry, 0, sfi_cb), 0);
    }
    return false;
}

void
Authenticator::set_location(Flow_in_event *fi, uint64_t loc, bool src,
                            const BoolCb& sfi_cb)
{
    DPPORTMap::iterator liter = locations_by_dpport.find(loc);
    if (liter == locations_by_dpport.end()) {
        VLOG_ERR(lg, "Location %"PRIx64" doesn't exist, dropping flow.", loc);
        if (sfi_cb.empty()) {
            delete fi;
        } else {
            sfi_cb(false);
        }
        return;
    }

    if (liter->second.status.locked) {
        VLOG_DBG(lg, "Queuing flow in for location %"PRIx64".", loc);
        liter->second.status.waiters.push_back(
            boost::bind(&Authenticator::set_location, this, fi, loc,
                        src, sfi_cb));
        return;
    } else if (src) {
        fi->src_location.location = liter->second.entry;
        fi->src_location.last_active = fi->src_location.idle_timeout = 0;
    } else {
        if (fi->dst_locations.empty()) {
            AuthedLocation tmp_loc = { liter->second.entry, 0, 0 };
            Flow_in_event::DestinationInfo dest_info = { tmp_loc,
                                                         true,
                                                         std::vector<uint32_t>(),
                                                         hash_set<uint32_t>() };
            fi->dst_locations.push_back(dest_info);
        } else {
            fi->route_destinations.push_back(liter->second.entry);
        }
    }
    set_flow_in(fi, false, sfi_cb);
}

void
Authenticator::set_host_by_name(const std::string& name, Flow_in_event *fi,
                                bool src, NWEntry *nwentry, uint64_t loc,
                                const BoolCb& sfi_cb)
{
    uint32_t id = namemanager->get_principal_id(name, directory::HOST_PRINCIPAL,
                                                false, true);
    if (id == NameManager::UNKNOWN_ID) {
        id = NameManager::UNAUTHENTICATED_ID;
    }
    set_host_by_id(id, fi, src, nwentry, loc, sfi_cb);
}

void
Authenticator::set_host_by_id(uint32_t name,
                              Flow_in_event *fi, bool src,
                              NWEntry *nwentry, uint64_t loc,
                              const BoolCb& sfi_cb)
{
    HostMap::iterator hiter = hosts.find(name);
    if (hiter == hosts.end()) {
        new_host(name, boost::bind(&Authenticator::set_host_by_id2, this,
                                   name, fi, src, nwentry, loc, sfi_cb, _1));
        return;
    }

    HostEntry *hentry = &hiter->second;
    if (hentry->status.locked) {
        VLOG_DBG(lg, "Queuing set host by name for host entry.");
        hentry->status.waiters.push_back(
            boost::bind(&Authenticator::set_host_by_id,
                        this, name, fi, src, nwentry, loc, sfi_cb));
        return;
    }

    if (src) {
        fi->src_host = hentry->entry;
    } else {
        fi->dst_host = hentry->entry;
        if (nwentry) {
            VLOG_DBG(lg, "Caching host %s.",
                     namemanager->get_name(name).c_str());
            nwentry->host = hentry->entry;
            hentry->cached_entries.push_back(nwentry);
            if (nwentry->nwaddr != 0) {
                hosts_by_nwaddr[nwentry->nwaddr].push_back(nwentry);
            }
        }
    }
    set_location(fi, loc, src, sfi_cb);
    if (nwentry) {
        unlock_status(&nwentry->dlentry->status);
    }
}

void
Authenticator::set_host_by_id2(uint32_t name, Flow_in_event *fi, bool src,
                               NWEntry *nwentry, uint64_t loc,
                               const BoolCb& sfi_cb, bool success)
{
    if (success) {
        set_host_by_id(name, fi, src, nwentry, loc, sfi_cb);
    } else if (name != NameManager::UNAUTHENTICATED_ID) {
        set_host_by_id(NameManager::UNAUTHENTICATED_ID, fi, src,
                       nwentry, loc, sfi_cb);
    } else {
        VLOG_ERR(lg, "Cannot create host objects at all?!.");
        if (sfi_cb.empty()) {
            delete fi;
        } else {
            sfi_cb(false);
        }
        if (nwentry != NULL) {
            unlock_status(&nwentry->dlentry->status);
        }
    }
}

void
Authenticator::make_primary(const time_t& curtime, const ethernetaddr& dladdr,
                            std::list<AuthedLocation>& authed_locs,
                            std::list<AuthedLocation>::iterator& authed)
{
    authed->last_active = curtime;
    std::list<AuthedLocation>::iterator begin = authed_locs.begin();
    if (authed != begin) {
        poison_location(
            datapathid::from_host(begin->location->dpport & DP_MASK),
            dladdr, 0, true);
        authed_locs.splice(begin, authed_locs, authed);
    }
}

bool
Authenticator::set_router_host(uint32_t nwaddr, Flow_in_event *fi, bool src)
{
    NWMap::iterator nwiter = hosts_by_nwaddr.find(nwaddr);
    if (nwiter != hosts_by_nwaddr.end()) {
        NWEntry *hnwentry = *(nwiter->second.begin());
        if (src) {
            if (!hnwentry->authed) {
                return false;
            }
            fi->src_host = hnwentry->host;
            fi->src_location = hnwentry->dlentry->locations.front();
        } else {
            fi->dst_host = hnwentry->host;
            fi->dst_authed = hnwentry->authed;
            if (!fi->dst_authed) {
                return false;
            }
            set_destinations(hnwentry->dlentry->locations, fi);
        }
        return true;
    }
    return false;
}

void
Authenticator::set_destinations(const std::list<AuthedLocation>& als,
                                Flow_in_event *fi)
{
    for (std::list<AuthedLocation>::const_iterator al = als.begin();
         al != als.end(); ++al)
    {
        Flow_in_event::DestinationInfo dest_info = { *al,
                                                     true,
                                                     std::vector<uint32_t>(),
                                                     hash_set<uint32_t>() };
        fi->dst_locations.push_back(dest_info);
    }
}

Authenticator::NWEntry*
Authenticator::get_nwentry(const ethernetaddr& dladdr, uint32_t nwaddr,
                           const EmptyCb& cb)
{
    DLMap::iterator dliter = hosts_by_dladdr.find(dladdr.hb_long());
    if (dliter == hosts_by_dladdr.end()) {
        new_dlentry(dladdr, cb);
        return NULL;
    }

    DLEntry *dlentry = &dliter->second;
    if (dlentry->status.locked) {
        dlentry->status.waiters.push_back(cb);
        return NULL;
    }

    if (dlentry->is_router && nwaddr != 0 && !is_internal_ip(htonl(nwaddr))) {
        nwaddr = 0;
    }

    DLNWMap::iterator nwiter = dlentry->nwentries.find(nwaddr);
    if (nwiter == dlentry->nwentries.end()) {
        new_nwentry(dlentry, nwaddr, cb);
        return NULL;
    }

    NWEntry *nwentry = &nwiter->second;
    if (nwentry->dlentry->status.locked) {
        nwentry->dlentry->status.waiters.push_back(cb);
        return NULL;
    }

    return nwentry;
}

}
}
