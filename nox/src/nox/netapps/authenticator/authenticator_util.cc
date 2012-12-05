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

#include "bootstrap-complete.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "directory/group_event.hh"
#include "directory/netinfo_mod_event.hh"
#include "directory/principal_event.hh"
#include "discovery/link-event.hh"
#include "port-status.hh"
#include "openflow-default.hh"

#define TIMER_INTERVAL         30
#define DEFAULT_IDLE_TIMEOUT   300     // 5 min idle timeout
#define DEFAULT_HARD_TIMEOUT   18000   // 5 hr hard timeout

#define DP_MASK          0xffffffffffffULL

namespace vigil {
namespace applications {

static Vlog_module lg("authenticator");

Authenticator::Authenticator(const container::Context* c,
                             const xercesc::DOMNode*)
    : Component(c), auto_auth(true), expire_timer(TIMER_INTERVAL),
      dirmanager(0), routing_mod(0), namemanager(0), bindings(0),
      user_log(0)
{
    host_info.netinfos.push_back(directory::NetInfo());
    switchkey.insert("dpid");
    lockey.insert("dpid");
    lockey.insert("port");
    dlkey.insert("dladdr");
    nwkey.insert("nwaddr");
    global_lock.locked = false;

    raw_of.reset(new uint8_t[sizeof *ofm]);
    ofm = (ofp_flow_mod*) raw_of.get();
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(sizeof *ofm);
    ofm->header.xid = 0;
    ofm->command = htons(OFPFC_DELETE);
    ofm->idle_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->out_port = htons(OFPP_NONE);
    ofm->buffer_id = htonl(UINT32_MAX);
    ofm->priority = htons(OFP_DEFAULT_PRIORITY);
    ofm->flags = htons(ofd_flow_mod_flags());
    ofm->cookie = 0;
}

void
Authenticator::getInstance(const container::Context* ctxt,
                           Authenticator*& h)
{
    h = dynamic_cast<Authenticator*>
        (ctxt->get_by_interface(container::Interface_description
                                (typeid(Authenticator).name())));
}

void
Authenticator::configure(const container::Configuration*)
{
    register_event(Host_auth_event::static_get_name());
    register_event(Host_bind_event::static_get_name());
    register_event(Host_join_event::static_get_name());
    register_event(User_auth_event::static_get_name());
    register_event(User_join_event::static_get_name());

    resolve(dirmanager);
    resolve(routing_mod);
    resolve(namemanager);
    resolve(bindings);
    resolve(user_log);

    register_handler<Bootstrap_complete_event>
        (boost::bind(&Authenticator::handle_bootstrap, this, _1));
    register_handler<Datapath_join_event>
        (boost::bind(&Authenticator::handle_datapath_join, this, _1));
    register_handler<Datapath_leave_event>
        (boost::bind(&Authenticator::handle_datapath_leave, this, _1));
    register_handler<Port_status_event>
        (boost::bind(&Authenticator::handle_port_status, this, _1));
    register_handler<Link_event>
        (boost::bind(&Authenticator::handle_link_change, this, _1));
    register_handler<Host_auth_event>
        (boost::bind(&Authenticator::handle_host_auth, this, _1));
    register_handler<User_auth_event>
        (boost::bind(&Authenticator::handle_user_auth, this, _1));
    register_handler<Principal_delete_event>
        (boost::bind(&Authenticator::handle_principal_delete, this, _1));
    register_handler<Group_delete_event>
        (boost::bind(&Authenticator::handle_group_delete, this, _1));
    register_handler<Group_change_event>
        (boost::bind(&Authenticator::handle_group_change, this, _1));
    register_handler<NetInfo_mod_event>
        (boost::bind(&Authenticator::handle_netinfo_mod, this, _1));
    register_handler<Packet_in_event>
        (boost::bind(&Authenticator::handle_packet_in, this, _1));
}

void
Authenticator::install()
{
    Flow_util *flow_util;
    resolve(flow_util);
    flow_util->fns.register_function("authenticate_host",
                                     boost::bind(&Authenticator::auth_flow_host,
                                                 this, _1, (NWEntry *)(NULL)));
}

void
Authenticator::decrement_entry(HostEntry& host)
{
    namemanager->decrement_id(host.entry->name);
    namemanager->decrement_ids(host.entry->groups);
}

void
Authenticator::decrement_entry(UserEntry& user)
{
    namemanager->decrement_id(user.entry->name);
    namemanager->decrement_ids(user.entry->groups);
}

void
Authenticator::decrement_entry(NWEntry& nwentry)
{
    namemanager->decrement_ids(*nwentry.address_groups);
}

void
Authenticator::decrement_entry(LocEntry& location)
{
    namemanager->decrement_id(location.entry->name);
    namemanager->decrement_id(location.portname, true);
    namemanager->decrement_ids(location.entry->groups);
}

void
Authenticator::decrement_entry(SwitchEntry& swentry)
{
    namemanager->decrement_id(swentry.name);
    namemanager->decrement_ids(swentry.groups);
}

void
Authenticator::unlock_status(UpdateStatus *status)
{
    status->locked = false;
    std::list<EmptyCb> cbs;
    cbs.swap(status->waiters);
    while (!cbs.empty()) {
        cbs.front()();
        cbs.pop_front();
    }
}

void
Authenticator::unlock_status(UpdateStatus *status, const EmptyCb& cb)
{
    status->locked = false;
    std::list<EmptyCb> cbs;
    cbs.swap(status->waiters);
    cb();
    while (!cbs.empty()) {
        cbs.front()();
        cbs.pop_front();
    }
}

void
Authenticator::unlock_global()
{
    if (global_lock.waiters.empty()) {
        global_lock.locked = false;
    } else {
        EmptyCb cb = global_lock.waiters.front();
        global_lock.waiters.pop_front();
        cb();
    }
}

void
Authenticator::call_and_unlock(const EmptyCb& cb, const EmptyCb& after)
{
    if (!cb.empty()) {
        cb();
    }
    if (!after.empty()) {
        after();
    }
    unlock_global();
}

void
Authenticator::call_and_unlock_bool(const EmptyCb& cb, bool ignore)
{
    if (!cb.empty()) {
        cb();
    }
    unlock_global();
}

void
Authenticator::call_with_global_lock(const EmptyCb& cb, const EmptyCb& after)
{
    if (global_lock.locked) {
        VLOG_DBG(lg, "Queuing fn for global lock.");
        global_lock.waiters.push_back(
            boost::bind(&Authenticator::call_and_unlock,
                        this, cb, after));
    } else {
        global_lock.locked = true;
        call_and_unlock(cb, after);
    }
}

void
Authenticator::call_with_global_lock_cb(const boost::function<void(const EmptyCb&)>& cb,
                                        const EmptyCb& after)
{
    EmptyCb empty;
    EmptyCb unlock = boost::bind(&Authenticator::call_and_unlock,
                                 this, after, empty);
    if (global_lock.locked) {
        VLOG_DBG(lg, "Queuing fn with cb for global lock.");
        global_lock.waiters.push_back(boost::bind(cb, unlock));
    } else {
        global_lock.locked = true;
        cb(unlock);
    }
}

void
Authenticator::call_with_global_lock_bool_cb(const boost::function<void(const BoolCb&)>& cb,
                                             const EmptyCb& after)
{
    BoolCb unlock = boost::bind(&Authenticator::call_and_unlock_bool,
                                this, after, _1);
    if (global_lock.locked) {
        VLOG_DBG(lg, "Queuing fn with bool cb for global lock.");
        global_lock.waiters.push_back(boost::bind(cb, unlock));
    } else {
        global_lock.locked = true;
        cb(unlock);
    }
}

uint32_t
Authenticator::get_authed_host(const ethernetaddr& dladdr, uint32_t nwaddr) const
{
    DLMap::const_iterator dlentry = hosts_by_dladdr.find(dladdr.hb_long());
    if (dlentry == hosts_by_dladdr.end()) {
        return NameManager::UNKNOWN_ID;
    }

    DLNWMap::const_iterator nwentry = dlentry->second.nwentries.find(nwaddr);
    if (nwentry == dlentry->second.nwentries.end()) {
        return NameManager::UNKNOWN_ID;
    }

    if (nwentry->second.authed) {
        return nwentry->second.host->name;
    }
    return NameManager::UNKNOWN_ID;
}

void
Authenticator::get_names(const datapathid& dp, uint16_t inport,
                         const ethernetaddr& dlsrc, uint32_t nwsrc,
                         const ethernetaddr& dldst, uint32_t nwdst,
                         PyObject *callable)
{
#ifdef TWISTED_ENABLED
    Flow_in_event *event = new Flow_in_event();
    event->flow.in_port = htons(inport);
    event->flow.dl_src = dlsrc;
    event->flow.nw_src = htonl(nwsrc);
    event->flow.dl_dst = dldst;
    event->flow.nw_dst = htonl(nwdst);
    event->datapath_id = dp;
    Py_INCREF(callable);
    set_flow_in(event, false,
                boost::bind(&Authenticator::get_names2, this,
                            _1, event, callable));
#else
    VLOG_ERR(lg, "Cannot return names for host if Python disabled.");
#endif
}

#ifdef TWISTED_ENABLED
void
Authenticator::get_names2(bool success, Flow_in_event *fi, PyObject *callable)
{
    PyObject *result = NULL;;
    if (success) {
        result = PyDict_New();
        if (result != NULL) {
            pyglue_setdict_string(result, "src_host_name", name_to_python(fi->src_host->name));
            pyglue_setdict_string(result, "src_host_groups", namelist_to_python(fi->src_host->groups));
            pyglue_setdict_string(result, "src_users", users_to_python(fi->src_host->users));
            pyglue_setdict_string(result, "src_location", name_to_python(fi->src_location.location->name));
            pyglue_setdict_string(result, "src_location_groups", namelist_to_python(fi->src_location.location->groups));
            pyglue_setdict_string(result, "src_address_groups", namelist_to_python(*fi->src_addr_groups));
            pyglue_setdict_string(result, "dst_host_name", name_to_python(fi->dst_host->name));
            pyglue_setdict_string(result, "dst_host_groups", namelist_to_python(fi->dst_host->groups));
            pyglue_setdict_string(result, "dst_users", users_to_python(fi->dst_host->users));
            PyObject *pydlocations = PyList_New(fi->dst_locations.size());
            if (pydlocations == NULL) {
                VLOG_ERR(lg, "Could not create location list for get_names.");
                Py_INCREF(Py_None);
                pydlocations = Py_None;
            } else {
                Flow_in_event::DestinationList::const_iterator dst = fi->dst_locations.begin();
                for (uint32_t i = 0; dst != fi->dst_locations.end(); ++i, ++dst) {
                    PyObject *pyloc = PyDict_New();
                    if (pyloc == NULL) {
                        VLOG_ERR(lg, "Could not create location for get_names");
                        Py_INCREF(Py_None);
                        pyloc = Py_None;
                    } else {
                        pyglue_setdict_string(pyloc, "name", name_to_python(dst->authed_location.location->name));
                        pyglue_setdict_string(pyloc, "groups", namelist_to_python(dst->authed_location.location->groups));
                    }
                    if (PyList_SetItem(pydlocations, i, pyloc) != 0) {
                        VLOG_ERR(lg, "Could not set location list in get_names.");
                    }
                }
            }
            pyglue_setdict_string(result, "dst_locations", pydlocations);
            pyglue_setdict_string(result, "dst_address_groups", namelist_to_python(*fi->dst_addr_groups));
        }
    } else {
        VLOG_ERR(lg, "Flow_in_event did not complete through chain.");
    }

    if (result == NULL) {
        Py_INCREF(Py_None);
        result = Py_None;
    }

    PyObject *ret = PyObject_CallFunctionObjArgs(callable, result, NULL);
    Py_DECREF(callable);
    Py_DECREF(result);
    Py_XDECREF(ret);
    delete fi;
}

inline
PyObject*
Authenticator::name_to_python(uint32_t id)
{
    return to_python(namemanager->get_name(id));
}

PyObject*
Authenticator::namelist_to_python(const std::vector<uint32_t>& ids)
{
    PyObject *pylist = PyList_New(ids.size());
    if (pylist == NULL) {
        VLOG_ERR(lg, "Could not create id list for get_names.");
        Py_RETURN_NONE;
    }

    std::vector<uint32_t>::const_iterator iter = ids.begin();
    for (uint32_t i = 0; iter != ids.end(); ++i, ++iter)
    {
        if (PyList_SetItem(pylist, i, to_python(namemanager->get_name((*iter)))) != 0) {
            VLOG_ERR(lg, "Could not set id list item in get_names.");
        }
    }
    return pylist;;
}

PyObject*
Authenticator::users_to_python(const std::list<AuthedUser>& users)
{
    PyObject *pyusers = PyList_New(users.size());
    if (pyusers == NULL) {
        VLOG_ERR(lg, "Could not create user list for get_names.");
        Py_RETURN_NONE;
    }

    std::list<AuthedUser>::const_iterator user = users.begin();
    for (uint32_t i = 0; user != users.end(); ++i, ++user) {
        PyObject *pyuser = PyDict_New();
        if (pyuser == NULL) {
            VLOG_ERR(lg, "Could not create user dict for get_names.");
            Py_INCREF(Py_None);
            pyuser = Py_None;
        } else {
            pyglue_setdict_string(pyuser, "name", name_to_python(user->user->name));
            pyglue_setdict_string(pyuser, "groups", namelist_to_python(user->user->groups));
        }
        if (PyList_SetItem(pyusers, i, pyuser) != 0) {
            VLOG_ERR(lg, "Could not set user list in get_names.");
        }
    }
    return pyusers;
}
#endif

bool
Authenticator::contains_group(std::vector<uint32_t> &groups,
                              uint32_t group,
                              std::vector<uint32_t>::iterator& pos)
{
    for (pos = groups.begin(); pos != groups.end(); ++pos) {
        if (*pos == group) {
            return true;
        } else if (*pos > group) {
            return false;
        }
    }
    return false;
}

bool
Authenticator::contains_group(std::list<uint32_t> &groups,
                              uint32_t group,
                              std::list<uint32_t>::iterator& pos)
{
    for (pos = groups.begin(); pos != groups.end(); ++pos) {
        if (*pos == group) {
            return true;
        } else if (*pos > group) {
            return false;
        }
    }
    return false;
}

void
Authenticator::translate_groups(const std::vector<std::string>& groups,
                                directory::Group_Type type,
                                std::list<uint32_t>& translated)
{
    translated.clear();
    for (std::vector<std::string>::const_iterator iter = groups.begin();
         iter != groups.end(); ++iter)
    {
        bool inserted = false;
        uint32_t group = namemanager->get_group_id(*iter, type, true, true);
        for (std::list<uint32_t>::iterator pos = translated.begin();
             pos !=  translated.end(); ++pos)
        {
            if (group < *pos) {
                translated.insert(pos, group);
                inserted = true;
                break;
            } else if (group == *pos) {
                namemanager->decrement_id(group);
                inserted = true;
                break;
            }
        }
        if (!inserted) {
            translated.push_back(group);
        }
    }
}

void
Authenticator::merge_groups(const std::list<uint32_t>& one,
                            const std::list<uint32_t>& two,
                            std::vector<uint32_t>& merged)
{
    merged.resize(one.size() + two.size());
    std::list<uint32_t>::const_iterator iter1 = one.begin();
    std::list<uint32_t>::const_iterator iter2 = two.begin();

    uint32_t i = 0;
    while (true) {
        if (iter1 == one.end()) {
            while (iter2 != two.end()) {
                merged[i++] = *(iter2++);
            }
            return;
        }

        if (iter2 == two.end()) {
            while (iter1 != one.end()) {
                merged[i++] = *(iter1++);
            }
            return;
        }

        if (*iter1 < *iter2) {
            merged[i++] = *(iter1++);
        } else {
            merged[i++] = *(iter2++);
        }
    }
}

void
Authenticator::auth_flow_host(const Flow_in_event& fi, NWEntry *nwentry)
{
    Packet_in_event *pi = new Packet_in_event(fi.datapath_id,
                                              ntohs(fi.flow.in_port),
                                              fi.buf, fi.total_len,
                                              fi.buffer_id, fi.reason);

    if (nwentry == NULL) {
        auth_flow_host2(pi, fi.flow.dl_src, ntohl(fi.flow.nw_src));
    } else {
        auth_flow_host3(pi, nwentry);
    }
}

void
Authenticator::auth_flow_host2(Packet_in_event *pi,
                               const ethernetaddr& dladdr, uint32_t nwaddr)
{
    NWEntry *nwentry = get_nwentry(dladdr, nwaddr,
                                   boost::bind(&Authenticator::auth_flow_host2,
                                               this, pi, dladdr, nwaddr));
    // split up so that auto_auth in event handler uses same code
    if (nwentry != NULL) {
        auth_flow_host3(pi, nwentry);
    }
}

inline
void
Authenticator::auth_flow_host3(Packet_in_event *pi, NWEntry *nwentry)
{
    // when have static binding mod events - should use cached name here.
    get_host(pi->datapath_id, pi->in_port, nwentry->dlentry->dladdr,
             nwentry->nwaddr, nwentry->dlentry->is_router,
             boost::bind(&Authenticator::auto_auth_host, this,
                         pi, nwentry, _1), 0);
}

void
Authenticator::auto_auth_host(Packet_in_event *pi, NWEntry *nwentry,
                              const std::string& name)
{
    uint32_t id = namemanager->get_principal_id(name, directory::HOST_PRINCIPAL,
                                                false, true);
    if (id == NameManager::UNKNOWN_ID) {
        id = NameManager::AUTHENTICATED_ID;
    }
    Host_auth_event *ha = new Host_auth_event(pi->datapath_id, pi->in_port,
                                              nwentry->dlentry->dladdr,
                                              nwentry->nwaddr, id,
                                              DEFAULT_IDLE_TIMEOUT,
                                              DEFAULT_HARD_TIMEOUT,
                                              Host_event::AUTO_AUTHENTICATION);
    ha->to_post = pi;
    post(ha);
}


void
Authenticator::get_host(const datapathid& dp, uint16_t port,
                        const ethernetaddr& dladdr, uint32_t nwaddr,
                        bool router_mac, const StringCb& cb,
                        uint32_t iteration)
{
    EmptyCb fail = boost::bind(&Authenticator::generate_host_name,
                               this, dladdr, nwaddr, router_mac, cb);
    if (router_mac && nwaddr != 0) {
        host_info.netinfos[0].nwaddr = nwaddr;
        if (!dirmanager->search_hosts(host_info, nwkey, "",
                                      boost::bind(&Authenticator::get_principal,
                                                  this, _1, cb, fail), fail))
        {
            fail();
        }
        return;
    }

    if (iteration == 0) {
        host_info.netinfos[0].dladdr = dladdr;
        EmptyCb none = boost::bind(&Authenticator::get_host,
                                   this, dp, port, dladdr, nwaddr,
                                   router_mac, cb, iteration+1);
        if (!dirmanager->search_hosts(host_info, dlkey, "",
                                      boost::bind(&Authenticator::get_principal,
                                                  this, _1, cb, none), fail))
        {
            fail();
        }
        return;
    } else if (iteration == 1) {
        if (nwaddr != 0) {
            host_info.netinfos[0].nwaddr = nwaddr;
            EmptyCb none = boost::bind(&Authenticator::get_host,
                                       this, dp, port, dladdr, nwaddr,
                                       router_mac, cb, iteration+1);
            if (!dirmanager->search_hosts(host_info, nwkey, "",
                                          boost::bind(&Authenticator::get_principal,
                                                      this, _1, cb, none), fail))
            {
                fail();
            }
            return;
        }
    }

    host_info.netinfos[0].dpid = dp;
    host_info.netinfos[0].port = port;
    if (!dirmanager->search_hosts(host_info, lockey, "",
                                  boost::bind(&Authenticator::get_principal,
                                              this, _1, cb, fail), fail))
    {
        fail();
    }
}

void
Authenticator::generate_host_name(const ethernetaddr& dladdr,
                                  uint32_t nwaddr, bool router_mac,
                                  const StringCb& cb)
{
    EmptyCb fail = boost::bind(&Authenticator::return_unknown, this, cb);

    if (!dirmanager->get_discovered_host_name(dladdr, nwaddr,
                                              !router_mac || nwaddr == 0,
                                              false, cb, fail))
    {
        fail();
    }
}

void
Authenticator::get_principal(const std::vector<std::string>& names,
                             const StringCb& success, const EmptyCb& failcb)
{
    if (names.empty()) {
        failcb();
    } else {
        success(names[0]);
    }
}

void
Authenticator::return_unknown(const StringCb& cb)
{
    cb(namemanager->get_unknown_name());
}

void
Authenticator::get_dladdr_groups(const ethernetaddr& dladdr,
                                 const boost::function<void(const std::list<uint32_t>&)>& cb)
{
    EmptyCb fail = boost::bind(cb, std::list<uint32_t>());
    if (!dirmanager->search_dladdr_groups(dladdr, "", true,
                                          boost::bind(&Authenticator::get_dladdr_groups2,
                                                      this, _1, cb),
                                          fail))
    {
        fail();
    }
}

void
Authenticator::get_dladdr_groups(const ethernetaddr& dladdr,
                                 const boost::function<void(const std::list<uint32_t>&, bool)>& cb)
{
    boost::function<void(const std::list<uint32_t>&)> success =
        boost::bind(cb, _1, true);
    if (!dirmanager->search_dladdr_groups(dladdr, "", true,
                                          boost::bind(&Authenticator::get_dladdr_groups2,
                                                      this, _1, success),
                                          boost::bind(cb, std::list<uint32_t>(), false)))
    {
        cb(std::list<uint32_t>(), true);
    }
}

void
Authenticator::get_dladdr_groups2(const std::vector<std::string>& groups,
                                  const boost::function<void(const std::list<uint32_t>&)> &cb)
{
    std::list<uint32_t> translated;
    translate_groups(groups, directory::DLADDR_GROUP, translated);
    cb(translated);
}

void
Authenticator::get_nwaddr_groups(NWEntry *nwentry,
                                 const std::list<uint32_t>& dlgroups,
                                 const BoolCb& cb)
{
    if (!dirmanager->search_nwaddr_groups(nwentry->nwaddr, "", true,
                                          boost::bind(&Authenticator::get_nwaddr_groups2, this,
                                                      _1, nwentry, dlgroups, cb),
                                          boost::bind(cb, false)))
    {
        get_nwaddr_groups2(std::vector<std::string>(), nwentry, dlgroups, cb);
    }
}


void
Authenticator::get_nwaddr_groups2(const std::vector<std::string>& groups,
                                  NWEntry *nwentry,
                                  const std::list<uint32_t>& dlgroups,
                                  const BoolCb& cb)
{
    std::list<uint32_t> translated;
    translate_groups(groups, directory::NWADDR_GROUP, translated);
    if (nwentry->address_groups != NULL) {
        namemanager->decrement_ids(*nwentry->address_groups);
    }
    nwentry->address_groups.reset(new std::vector<uint32_t>(dlgroups.size() + translated.size()));
    merge_groups(dlgroups, translated, *(nwentry->address_groups));
    cb(true);
}

void
Authenticator::get_switch_groups(SwitchEntry *swentry, const BoolCb& cb)
{
    if (!dirmanager->search_switch_groups(namemanager->get_name(swentry->name),
                                          "", true,
                                          boost::bind(&Authenticator::get_switch_groups2,
                                                      this, _1, swentry, cb),
                                          boost::bind(cb, false)))
    {
        get_switch_groups2(std::vector<std::string>(), swentry, cb);
    }
}

void
Authenticator::get_switch_groups2(const std::vector<std::string>& groups,
                                  SwitchEntry *swentry, const BoolCb& cb)
{
    namemanager->decrement_ids(swentry->groups);
    translate_groups(groups, directory::SWITCH_PRINCIPAL_GROUP, swentry->groups);
    cb(true);
}

void
Authenticator::get_location_groups(LocEntry *lentry,
                                   const std::list<uint32_t>& swgroups,
                                   const BoolCb& cb)
{
    if (!dirmanager->search_location_groups(namemanager->get_name(lentry->entry->name),
                                            "", true,
                                            boost::bind(&Authenticator::get_location_groups2,
                                                        this, _1, lentry, swgroups, cb),
                                            boost::bind(cb, false)))
    {
        get_location_groups2(std::vector<std::string>(), lentry, swgroups, cb);
    }
}

void
Authenticator::get_location_groups2(const std::vector<std::string>& groups,
                                    LocEntry *lentry,
                                    const std::list<uint32_t>& swgroups,
                                    const BoolCb& cb)
{
    std::list<uint32_t> translated;
    translate_groups(groups, directory::LOCATION_PRINCIPAL_GROUP, translated);
    namemanager->decrement_ids(lentry->entry->groups);
    namemanager->increment_ids(swgroups);
    lentry->entry->groups.resize(swgroups.size() + translated.size());
    merge_groups(swgroups, translated, lentry->entry->groups);
    cb(true);
}

void
Authenticator::get_host_groups(HostEntry *host, const BoolCb& cb)
{
    if (!dirmanager->search_host_groups(namemanager->get_name(host->entry->name),
                                        "", true,
                                        boost::bind(&Authenticator::get_host_groups2,
                                                    this, _1, host, cb),
                                        boost::bind(cb, false)))
    {
        get_host_groups2(std::vector<std::string>(), host, cb);
    }
}

void
Authenticator::get_host_groups2(const std::vector<std::string>& groups,
                                HostEntry *host, const BoolCb& cb)
{
    std::list<uint32_t> translated;
    translate_groups(groups, directory::HOST_PRINCIPAL_GROUP, translated);
    namemanager->decrement_ids(host->entry->groups);
    host->entry->groups.resize(translated.size());
    host->entry->groups.assign(translated.begin(), translated.end());
    cb(true);
}


void
Authenticator::get_user_groups(UserEntry *user, const BoolCb& cb)
{
    if (!dirmanager->search_user_groups(namemanager->get_name(user->entry->name),
                                        "", true,
                                        boost::bind(&Authenticator::get_user_groups2,
                                                    this, _1, user, cb),
                                        boost::bind(cb, false)))
    {
        get_user_groups2(std::vector<std::string>(), user, cb);
    }
}

void
Authenticator::get_user_groups2(const std::vector<std::string>& groups,
                                UserEntry *user, const BoolCb& cb)
{
    std::list<uint32_t> translated;
    translate_groups(groups, directory::USER_PRINCIPAL_GROUP, translated);
    namemanager->decrement_ids(user->entry->groups);
    user->entry->groups.resize(translated.size());
    user->entry->groups.assign(translated.begin(), translated.end());
    cb(true);
}

void
Authenticator::get_switch_by_name(uint32_t name, bool only_one,
                                  const boost::function<void(SwitchEntry*)>& cb)
{
    SwitchMap::iterator swentry = switches.find(name);
    if (swentry == switches.end()) {
        cb(NULL);
        return;
    }

    bool looped = false;
    for (std::list<SwitchEntry*>::iterator sw = swentry->second.begin();
         sw != swentry->second.end(); ++sw)
    {
        if (looped && only_one) {
            VLOG_WARN(lg, "Multiple switches with name unexpected for cb type.");
            break;
        }
        if ((*sw)->status.locked) {
            (*sw)->status.waiters.push_back(
                boost::bind(&Authenticator::get_switch, this,
                            (*sw)->dp.as_host(), cb));
        } else {
            cb(*sw);
        }
        looped = true;
    }
}

void
Authenticator::get_switch(uint64_t dp,
                          const boost::function<void(SwitchEntry*)>& cb)
{
    DPIDMap::iterator swentry = switches_by_dp.find(dp);
    if (swentry == switches_by_dp.end()) {
        cb(NULL);
        return;
    }

    if (swentry->second.status.locked) {
        swentry->second.status.waiters.push_back(
            boost::bind(&Authenticator::get_switch, this, dp, cb));
    } else {
        cb(&swentry->second);
    }
}

void
Authenticator::get_location_by_name(uint32_t name, bool only_one,
                                    const boost::function<void(DPIDMap::iterator&,
                                                               DPPORTMap::iterator&)>& cb)
{
    LocMap::iterator lentry = locations.find(name);
    if (lentry == locations.end()) {
        DPIDMap::iterator siter = switches_by_dp.end();
        DPPORTMap::iterator liter = locations_by_dpport.end();
        cb(siter, liter);
        return;
    }

    bool looped = false;
    for (std::list<LocEntry*>::iterator loc = lentry->second.begin();
         loc != lentry->second.end(); ++loc)
    {
        if (looped && only_one) {
            VLOG_WARN(lg, "Multiple locations with name unexpected for cb type.");
            break;
        }
        get_location(datapathid::from_host((*loc)->entry->dpport && DP_MASK),
                     (*loc)->entry->dpport, cb);
        looped = true;
    }
}

void
Authenticator::get_location(const datapathid& dp, uint64_t loc,
                            const boost::function<void(DPIDMap::iterator&,
                                                       DPPORTMap::iterator&)>& cb)
{
    DPIDMap::iterator siter = switches_by_dp.find(dp.as_host());
    DPPORTMap::iterator dpend = locations_by_dpport.end();
    if (siter == switches_by_dp.end()) {
        cb(siter, dpend);
        return;
    }
    SwitchEntry *sentry = &siter->second;
    if (sentry->status.locked) {
        VLOG_DBG(lg, "Queuing get location %"PRIx64":%"PRIu16" for switch entry.",
                 dp.as_host(), (uint16_t)(loc >> 48));
        sentry->status.waiters.push_back(
            boost::bind(&Authenticator::get_location,
                        this, dp, loc, cb));
        return;
    }

    DPPORTMap::iterator dppiter = locations_by_dpport.find(loc);
    if (dppiter == locations_by_dpport.end()
        || dppiter->second.status.locked)
    {
        cb(siter, dpend);
        return;
    }

    cb(siter, dppiter);
}

bool
Authenticator::get_location(const datapathid &dp, uint16_t port, uint64_t loc,
                            std::list<AuthedLocation> &als,
                            std::list<AuthedLocation>::iterator &al)
{
    for (al = als.begin(); al != als.end(); ++al) {
        if (al->location->dpport == loc) {
            return true;
        }
    }
    return get_on_path_location(dp, port, als, al);
}

bool
Authenticator::get_on_path_location(const datapathid& dp, uint16_t port,
                                    std::list<AuthedLocation>& als,
                                    std::list<AuthedLocation>::iterator &al)
{
    Routing_module::RoutePtr rte;
    Routing_module::RouteId rid;
    rid.dst = dp;
    for (al = als.begin(); al != als.end(); ++al) {
        rid.src = datapathid::from_host(al->location->dpport & DP_MASK);
        if (routing_mod->is_on_path_location(rid,
                                             (uint16_t)(al->location->dpport >> 48),
                                             port))
        {
            return true;
        }
    }
    return false;
}

// nwaddr should be network byte order
bool
Authenticator::is_internal_ip(uint32_t nwaddr) const
{
    for (std::vector<cidr_ipaddr>::const_iterator iter = internal_subnets.begin();
         iter != internal_subnets.end(); ++iter)
    {
        VLOG_DBG(lg, "checking internal against nw:%x mask:%x",
                 iter->addr.addr, iter->mask);
        if ((nwaddr & iter->mask) == iter->addr.addr) {
            return true;
        }
    }
    VLOG_DBG(lg, "done checking for internal nw:%x", nwaddr);
    return false;
}

void
Authenticator::add_internal_subnet(const cidr_ipaddr& cidr)
{
    internal_subnets.push_back(cidr);
}

bool
Authenticator::remove_internal_subnet(const cidr_ipaddr& cidr)
{
    for (std::vector<cidr_ipaddr>::iterator iter = internal_subnets.begin();
         iter != internal_subnets.end(); ++iter)
    {
        if (*iter == cidr) {
            internal_subnets.erase(iter);
            return true;
        }
    }
    return false;
}

void
Authenticator::clear_internal_subnets()
{
    internal_subnets.clear();
}

void
Authenticator::expire_entities()
{
    timeval curtime = { 0, 0 };
    gettimeofday(&curtime, NULL);

    expire_host_locations(curtime);
    expire_hosts(curtime);
    expire_users(curtime);

    curtime.tv_sec = expire_timer;
    curtime.tv_usec = 0;
    post(boost::bind(&Authenticator::expire_entities, this), curtime);
}

void
Authenticator::expire_host_locations(const timeval& curtime)
{
    for (DLMap::iterator dliter = hosts_by_dladdr.begin();
         dliter != hosts_by_dladdr.end();)
    {
        if (!dliter->second.status.locked) {
            for(std::list<AuthedLocation>::iterator liter = dliter->second.locations.begin();
                liter != dliter->second.locations.end();)
            {
                if (liter->last_active + liter->idle_timeout <= curtime.tv_sec) {
                    remove_host_location(&dliter->second, liter,
                                         Host_event::IDLE_TIMEOUT, true);
                } else {
                    ++liter;
                }
            }

            for (DLNWMap::iterator niter = dliter->second.nwentries.begin();
                 niter != dliter->second.nwentries.end();)
            {
                if (!niter->second.authed
                    && niter->second.exp_time <= curtime.tv_sec)
                {
                    VLOG_DBG(lg, "Expiring address entry %s %s.",
                             dliter->second.dladdr.string().c_str(),
                             ipaddr(niter->second.nwaddr).string().c_str());
                    remove_host(&niter->second, Host_event::HARD_TIMEOUT, true);
                    if (niter->first == 0) {
                        dliter->second.zero = NULL;
                    }
                    decrement_entry(niter->second);
                    niter = dliter->second.nwentries.erase(niter);
                } else {
                    ++niter;
                }
            }

            if (dliter->second.nwentries.empty()) {
                VLOG_DBG(lg, "Expiring address entry %s.",
                         dliter->second.dladdr.string().c_str());
                dliter = hosts_by_dladdr.erase(dliter);
            } else {
                ++dliter;
            }
        } else {
            ++dliter;
        }
    }
}

void
Authenticator::expire_users(const timeval& curtime)
{
    for (UserMap::iterator uiter = users.begin(); uiter != users.end();) {
        if (!uiter->second.status.locked) {
            if (uiter->second.hostentries.empty()
                && uiter->second.entry->name != NameManager::UNAUTHENTICATED_ID)
            {
                delete_user(uiter, User_event::HARD_TIMEOUT);
            } else {
                ++uiter;
            }
        } else {
            ++uiter;
        }
    }
}

void
Authenticator::expire_hosts(const timeval& curtime)
{
    for (HostMap::iterator hiter = hosts.begin(); hiter != hosts.end();) {
        if (!hiter->second.status.locked) {
            Host& host = *(hiter->second.entry);
            if (host.users.size() == 1
                && host.users.front().user->name == NameManager::UNAUTHENTICATED_ID)
            {
                if (host.hard_timeout != 0
                    && host.auth_time + host.hard_timeout <= curtime.tv_sec)
                {
                    delete_host(hiter, Host_event::HARD_TIMEOUT);
                } else {
                    ++hiter;
                }
            } else {
                for (std::list<AuthedUser>::iterator uiter = host.users.begin();
                     uiter != host.users.end();)
                {
                    AuthedUser& user = *uiter;
                    ++uiter;
                    if (user.hard_timeout != 0
                        && user.auth_time + user.hard_timeout <= curtime.tv_sec)
                    {
                        remove_user(&users[user.user->name], &hiter->second,
                                    User_event::HARD_TIMEOUT, true);
                    } else if (user.idle_timeout != 0
                               && host.last_active + user.idle_timeout <= curtime.tv_sec)
                    {
                        remove_user(&users[user.user->name], &hiter->second,
                                    User_event::IDLE_TIMEOUT, true);
                    }
                }
                ++hiter;
            }
        } else {
            ++hiter;
        }
    }
}

#define CHECK_POISON_ERR(error, dp)                                     \
    if (error) {                                                        \
        if (error == EAGAIN) {                                          \
            VLOG_DBG(lg, "Poison location on switch %"PRIx64" failed with EAGAIN.", \
                     dp.as_host());                                     \
        } else {                                                        \
            VLOG_ERR(lg, "Poison location on switch %"PRIx64" failed with %d:%s.", \
                     dp.as_host(), error, strerror(error));             \
        }                                                               \
        return;                                                         \
    }

void
Authenticator::poison_location(const datapathid& dp, const ethernetaddr& dladdr,
                               uint32_t nwaddr, bool wildcard_nw) const
{
    if (AUTHENTICATOR_POISON_DISABLED)
      return;

    ofp_match& match = ofm->match;

    memcpy(match.dl_dst, dladdr.octet, ethernetaddr::LEN);
    match.wildcards = htonl(OFPFW_ALL & (~OFPFW_DL_DST));
    if (!wildcard_nw) {
        match.nw_dst = htonl(nwaddr);
        match.wildcards &= htonl(~OFPFW_NW_DST_MASK);
    }

    VLOG_DBG(lg, "Poisoning %s %s on location %"PRIx64".",
             dladdr.string().c_str(),
             wildcard_nw ? "" : ipaddr(nwaddr).string().c_str(),
             dp.as_host());

    int err = send_openflow_command(dp, &ofm->header, false);
    CHECK_POISON_ERR(err, dp);

    memcpy(match.dl_src, dladdr.octet, ethernetaddr::LEN);
    match.wildcards = htonl(OFPFW_ALL & (~OFPFW_DL_SRC));
    if (!wildcard_nw) {
        match.nw_src = htonl(nwaddr);
        match.wildcards &= htonl(~OFPFW_NW_SRC_MASK);
    }

    err = send_openflow_command(dp, &ofm->header, false);
    CHECK_POISON_ERR(err, dp);
}

#define OUI_MASK 0x3fffff000000ULL
#define OUI      0x002320000000ULL

bool
Authenticator::is_internal_mac(uint64_t hb_dladdr) const
{
    return ((OUI_MASK & hb_dladdr) == OUI);
}

}
}

REGISTER_COMPONENT(vigil::container::Simple_component_factory<vigil::applications::Authenticator>,
                   vigil::applications::Authenticator);
