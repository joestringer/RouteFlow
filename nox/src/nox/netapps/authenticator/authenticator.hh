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
#ifndef AUTHENTICATOR_HH
#define AUTHENTICATOR_HH 1

#include <boost/bind.hpp>
#include <boost/function.hpp>

#include "component.hh"
#include "bindings_storage/bindings_storage.hh"
#include "directory/directorymanager.hh"
#include "flow_in.hh"
#include "hash_map.hh"
#include "host_event.hh"
#include "name_manager.hh"
#include "netinet++/cidr.hh"
#include "routing/routing.hh"
#include "user_event.hh"
#include "user_event_log/user_event_log.hh"

#define AUTHENTICATOR_POISON_DISABLED true

namespace vigil {
namespace applications {

class Authenticator
    : public container::Component {

public:
    Authenticator(const container::Context*, const xercesc::DOMNode*);
    Authenticator() : Component(0) { }

    static void getInstance(const container::Context*, Authenticator*&);

    void configure(const container::Configuration*);
    void install();

    void add_internal_subnet(const cidr_ipaddr&);
    bool remove_internal_subnet(const cidr_ipaddr&);
    void clear_internal_subnets();

    uint32_t get_authed_host(const ethernetaddr& dladdr, uint32_t nwaddr) const;
    void get_names(const datapathid& dp, uint16_t inport,
                   const ethernetaddr& dlsrc, uint32_t nwsrc,
                   const ethernetaddr& dldst, uint32_t nwdst,
                   PyObject *callable);

private:
    struct DLEntry;

    struct NWEntry {
        uint32_t nwaddr;
        bool authed;
        time_t exp_time;
        boost::shared_ptr<Host> host;
        boost::shared_ptr<std::vector<uint32_t> > address_groups;
        DLEntry *dlentry;
    };

    typedef hash_map<uint32_t, NWEntry> DLNWMap;

    typedef boost::function<void()> EmptyCb;
    typedef boost::function<void(bool)> BoolCb;
    typedef boost::function<void(const std::string&)> StringCb;

    struct UpdateStatus {
        bool locked;
        std::list<EmptyCb> waiters;
    };

    struct DLEntry {
        ethernetaddr dladdr;
        bool is_router;
        DLNWMap nwentries;
        NWEntry *zero;
        std::list<AuthedLocation> locations;
        UpdateStatus status;
    };

    typedef hash_map<uint64_t, DLEntry> DLMap;
    typedef hash_map<uint32_t, std::list<NWEntry*> > NWMap;

    struct LocEntry {
        boost::shared_ptr<Location> entry;
        std::list<DLEntry*> dlentries;
        uint32_t portname;
        UpdateStatus status;
    };

    struct SwitchEntry {
        datapathid dp;
        uint32_t name;
        std::list<uint32_t> groups;
        std::list<LocEntry*> locations;
        UpdateStatus status;
    };

    struct HostEntry {
        boost::shared_ptr<Host> entry;
        std::list<NWEntry*> nwentries;
        std::list<NWEntry*> cached_entries;
        UpdateStatus status;
    };

    struct UserEntry {
        boost::shared_ptr<User> entry;
        std::list<HostEntry*> hostentries;
        UpdateStatus status;
    };

    typedef hash_map<uint64_t, SwitchEntry>  DPIDMap;
    typedef hash_map<uint64_t, LocEntry>     DPPORTMap;

    typedef hash_map<uint32_t, std::list<SwitchEntry*> >  SwitchMap;
    typedef hash_map<uint32_t, std::list<LocEntry*> >     LocMap;
    typedef hash_map<uint32_t, HostEntry>     HostMap;
    typedef hash_map<uint32_t, UserEntry>     UserMap;

    UpdateStatus global_lock;

    SwitchMap switches;
    LocMap locations;
    HostMap hosts;
    UserMap users;

    DLMap hosts_by_dladdr;
    NWMap hosts_by_nwaddr;
    DPIDMap switches_by_dp;
    DPPORTMap locations_by_dpport;

    bool auto_auth;
    uint32_t expire_timer;

    boost::shared_array<uint8_t> raw_of;
    ofp_flow_mod *ofm;

    std::vector<cidr_ipaddr> internal_subnets;

    DirectoryManager *dirmanager;
    Routing_module *routing_mod;
    NameManager *namemanager;
    Bindings_Storage *bindings;
    User_Event_Log *user_log;
    char buf[1024];

    directory::SwitchInfo switch_info;
    directory::LocationInfo loc_info;
    directory::HostInfo host_info;
    DirectoryManager::KeySet switchkey, lockey, dlkey, nwkey;

    /* authenticator_event.cc */
    void post_event(Event *event) const;

    Disposition handle_bootstrap(const Event& e);
    Disposition handle_datapath_join(const Event& e);
    Disposition handle_datapath_leave(const Event& e);
    Disposition handle_port_status(const Event& e);
    Disposition handle_link_change(const Event& e);
    Disposition handle_host_auth(const Event& e);
    Disposition handle_user_auth(const Event& e);
    Disposition handle_delete_principal(const Event& e);
    Disposition handle_principal_delete(const Event& e);
    void reauthenticate_switch(uint32_t name, const EmptyCb& cb);
    void reauthenticate_switch2(SwitchEntry *swentry, const EmptyCb& cb);
    void reauthenticate_location(uint32_t name, const EmptyCb& cb);
    void reauthenticate_location2(DPIDMap::iterator& siter,
                                  DPPORTMap::iterator& dppiter,
                                  const EmptyCb& cb);
    Disposition handle_group_delete(const Event& e);
    Disposition handle_group_change(const Event& e);
    Disposition handle_netinfo_mod(const Event& e);
    void netinfo_mod(uint64_t dladdr, bool is_router, const EmptyCb& cb);
    Disposition handle_packet_in(const Event& e);
    void set_flow_in(Flow_in_event *fi, bool auto_src_auth,
                     const BoolCb& sfi_cb);
    void make_primary(const time_t& curtime, const ethernetaddr& dladdr,
                      std::list<AuthedLocation>&,
                      std::list<AuthedLocation>::iterator&);
    bool set_src_host(NWEntry *nwentry, Flow_in_event *fi, bool auto_src_auth,
                      const BoolCb& sfi_cb);
    bool set_dst_host(NWEntry *nwentry, Flow_in_event *fi,
                      const BoolCb& sfi_cb);
    void set_location(Flow_in_event *fi, uint64_t loc, bool src,
                      const BoolCb& sfi_cb);
    void set_host_by_name(const std::string& name,
                          Flow_in_event *fi, bool src, NWEntry *,
                          uint64_t loc, const BoolCb& sfi_cb);
    void set_host_by_id(uint32_t name, Flow_in_event *fi,
                        bool src, NWEntry *, uint64_t loc,
                        const BoolCb& sfi_cb);
    void set_host_by_id2(uint32_t name, Flow_in_event* fi, bool src,
                         NWEntry *nwentry, uint64_t loc, const BoolCb& sfi_cb,
                         bool success);
    bool set_router_host(uint32_t nwaddr, Flow_in_event *fi, bool);
    void set_destinations(const std::list<AuthedLocation>& locs, Flow_in_event *fi);
    NWEntry* get_nwentry(const ethernetaddr& dladdr, uint32_t nwaddr,
                         const EmptyCb& cb);

    /* authenticator_modify.cc */

    void add_host(Host_auth_event& ha, const BoolCb& cb, bool prev_success);
    void set_hname_and_add(const std::string& hname, Host_auth_event& ha,
                           const BoolCb& cb);
    void add_host2(Host_auth_event& ha, DPIDMap::iterator& siter,
                   DPPORTMap::iterator& dppiter, const BoolCb& cb);
    void remove_host_location(DLEntry*, std::list<AuthedLocation>::iterator&,
                              Host_event::Reason reason, bool poison);
    void remove_host_location(DLEntry *dlentry, uint64_t loc, bool mask,
                              Host_event::Reason reason, bool poison);
    void remove_host(NWEntry *nwentry, Host_event::Reason reason, bool poison);
    bool remove_host(NWEntry *nwentry, uint64_t loc, bool mask,
                     Host_event::Reason reason);
    void remove_host(HostEntry *hentry, uint64_t loc, bool mask,
                     Host_event::Reason reason);
    void delete_host(HostMap::iterator& host, Host_event::Reason reason);
    void delete_host(uint32_t hostname, Host_event::Reason reason,
                     const EmptyCb& cb);
    void remove_host(LocEntry *lentry, Host_event::Reason reason, bool poison);
    void remove_host(uint64_t loc, Host_event::Reason reason, bool poison);
    void remove_host(const datapathid& dp, Host_event::Reason reason,
                     bool poison);
    bool remove_host(const Host_auth_event& ha, NWEntry *nwentry);
    void remove_host(const Host_auth_event& ha);
    void add_user(const User_auth_event& ua, const BoolCb& cb, bool prev_success);
    void remove_unauth_user(HostEntry *);
    void remove_user(UserEntry*, HostEntry*, User_event::Reason, bool);
    void remove_user(uint32_t username, uint32_t hostname,
                     User_event::Reason reason);
    void delete_user(UserMap::iterator& user, User_event::Reason reason);
    void delete_user(uint32_t username, User_event::Reason reason,
                     const EmptyCb& cb);
    void new_dlentry(const ethernetaddr& dladdr, const EmptyCb& success);
    void new_dlentry2(bool is_router, DLEntry *entry, const EmptyCb& cb);
    void new_nwentry(DLEntry *dlentry, uint32_t nwaddr,
                     const EmptyCb& success);
    void new_nwentry2(NWEntry *entry, const EmptyCb& cb, bool ignore);
    void new_host(uint32_t hostname, const BoolCb& cb);
    void new_host2(HostEntry *host, const BoolCb& cb, bool success);
    void new_user(uint32_t user_name, const BoolCb& cb);
    void new_user2(UserEntry *uentry, const BoolCb& cb, bool success);
    LocEntry* new_location(const datapathid& dp, uint16_t port,
                           uint64_t loc, const std::string& port_name);
    void new_location2(LocEntry *location, const datapathid& dp, uint16_t port);
    void new_location_name(const std::vector<std::string>& names,
                           SwitchEntry *sentry, LocEntry *location,
                           const datapathid& dp, uint16_t port);
    void new_location3(const std::string& location_name, uint16_t port,
                       SwitchEntry *sentry, LocEntry *location);
    void new_location4(SwitchEntry *sentry, LocEntry *location, bool ignore);
    SwitchEntry* new_switch(const datapathid& dp);
    void new_switch_name(const std::vector<std::string>& names,
                         SwitchEntry *sentry);
    void new_switch2(const std::string& switch_name, SwitchEntry *sentry);
    void new_switch3(SwitchEntry *sentry, bool ignore);
    void remove_location(const datapathid& dp, uint16_t port, uint64_t loc, bool poison);
    void remove_location2(const datapathid& dp, uint16_t port,
                          uint64_t loc, bool poison, DPIDMap::iterator& siter,
                          DPPORTMap::iterator& dppiter);
    void remove_switch(const datapathid& dp, bool poison);
    void modify_location_group(DPIDMap::iterator& siter,
                               DPPORTMap::iterator& dppiter);
    void modify_location_groups2(SwitchEntry *swentry,
                                 LocEntry *lentry, bool success);
    void modify_addr_group(DLEntry& dlentry, uint32_t cname, uint32_t nwmask,
                           directory::Group_Type gtype, bool group_change);
    void modify_addr_group2(const std::list<uint32_t>& dlgroups,
                            DLEntry *dlentry, DLNWMap::iterator& nwentry,
                            uint32_t cname, uint32_t nwmask, bool group_change,
                            bool success);
    void modify_host_group(HostEntry& hentry, uint32_t cname);
    void modify_user_group(UserEntry& uentry, uint32_t cname);
    void unlock_bool_status(UpdateStatus *status, bool ignore);
    // temp
    void modify_sw_loc_group_ref(SwitchEntry &swentry,
                                 uint32_t cname,
                                 directory::Group_Type gtype);
    void modify_sw_loc_group(SwitchEntry *swentry,
                             uint32_t cname,
                             directory::Group_Type gtype);
    void modify_sw_loc_group2(SwitchEntry *swentry,
                              std::list<LocEntry*>::iterator& lentry,
                              uint32_t group, bool group_change,
                              LocEntry *unlock, bool success);

    /* authenticator_util.cc */
    void decrement_entry(HostEntry& entry);
    void decrement_entry(UserEntry& entry);
    void decrement_entry(DLEntry& entry) { };
    void decrement_entry(NWEntry& entry);
    void decrement_entry(LocEntry& entry);
    void decrement_entry(SwitchEntry& entry);
    void unlock_status(UpdateStatus *status);
    void unlock_status(UpdateStatus *status, const EmptyCb& cb);
    void unlock_global();
    void call_and_unlock(const EmptyCb&, const EmptyCb&);
    void call_and_unlock_bool(const EmptyCb&, bool);
    void call_with_global_lock(const EmptyCb&, const EmptyCb&);
    void call_with_global_lock_cb(const boost::function<void(const EmptyCb&)>&,
                                  const EmptyCb&);
    void call_with_global_lock_bool_cb(const boost::function<void(const BoolCb&)>&,
                                       const EmptyCb&);
#ifdef TWISTED_ENABLED
    void get_names2(bool success, Flow_in_event *fi, PyObject *callable);
    PyObject* name_to_python(uint32_t id);
    PyObject* namelist_to_python(const std::vector<uint32_t>& ids);
    PyObject* users_to_python(const std::list<AuthedUser>& users);
#endif
    bool contains_group(std::vector<uint32_t> &groups, uint32_t group,
                        std::vector<uint32_t>::iterator& pos);
    bool contains_group(std::list<uint32_t> &groups, uint32_t group,
                        std::list<uint32_t>::iterator& pos);
    void translate_groups(const std::vector<std::string>& groups,
                          directory::Group_Type type,
                          std::list<uint32_t>& translated);
    void merge_groups(const std::list<uint32_t>& one,
                      const std::list<uint32_t>& two,
                      std::vector<uint32_t>& merged);
    void auth_flow_host(const Flow_in_event& fi, NWEntry *nwentry);
    void auth_flow_host2(Packet_in_event *pi, const ethernetaddr& dladdr,
                         uint32_t nwaddr);
    void auth_flow_host3(Packet_in_event *pi, NWEntry *nwentry);
    void auto_auth_host(Packet_in_event *pi, NWEntry *nwentry,
                        const std::string& name);
    void get_host(const datapathid& dp, uint16_t port,
                  const ethernetaddr& dladdr, uint32_t nwaddr,
                  bool router_mac, const StringCb& cb, uint32_t iteration);
    void generate_host_name(const ethernetaddr& dladdr,
                            uint32_t nwaddr, bool router_mac,
                            const StringCb& cb);
    void get_principal(const std::vector<std::string>& names,
                       const StringCb& success, const EmptyCb& failcb);
    void return_unknown(const StringCb& cb);
    void get_dladdr_groups(const ethernetaddr& dladdr,
                           const boost::function<void(const std::list<uint32_t>&)> &cb);
    void get_dladdr_groups(const ethernetaddr& dladdr,
                           const boost::function<void(const std::list<uint32_t>&, bool)>& cb);
    void get_dladdr_groups2(const std::vector<std::string>& groups,
                            const boost::function<void(const std::list<uint32_t>&)> &cb);
    void get_nwaddr_groups(NWEntry *nwentry, const std::list<uint32_t>& dlgroups,
                           const BoolCb& cb);
    void get_nwaddr_groups2(const std::vector<std::string>& groups,
                            NWEntry *nwentry, const std::list<uint32_t>& dlgroups,
                            const BoolCb& cb);
    void get_switch_groups(SwitchEntry *swentry, const BoolCb& cb);
    void get_switch_groups2(const std::vector<std::string>& groups,
                            SwitchEntry *swentry, const BoolCb& cb);
    void get_location_groups(LocEntry *lentry,
                             const std::list<uint32_t>& swgroups,
                             const BoolCb& cb);
    void get_location_groups2(const std::vector<std::string>& groups,
                              LocEntry *lentry,
                              const std::list<uint32_t>& swgroups,
                              const BoolCb& cb);
    void get_host_groups(HostEntry *host, const BoolCb& cb);
    void get_host_groups2(const std::vector<std::string>& groups,
                          HostEntry *host, const BoolCb& cb);
    void get_user_groups(UserEntry *user, const BoolCb& cb);
    void get_user_groups2(const std::vector<std::string>& groups,
                          UserEntry *user, const BoolCb& cb);
    void get_switch_by_name(uint32_t name, bool only_one,
                            const boost::function<void(SwitchEntry*)>& cb);
    void get_switch(uint64_t dp, const boost::function<void(SwitchEntry*)>& cb);
    void get_location_by_name(uint32_t name, bool only_one,
                              const boost::function<void(DPIDMap::iterator&,
                                                         DPPORTMap::iterator&)>& cb);
    void get_location(const datapathid& dp, uint64_t loc,
                      const boost::function<void(DPIDMap::iterator&,
                                                 DPPORTMap::iterator&)>& cb);
    bool get_location(const datapathid &dp, uint16_t port, uint64_t loc,
                      std::list<AuthedLocation> &locs,
                      std::list<AuthedLocation>::iterator &ap);
    bool get_on_path_location(const datapathid& dp, uint16_t port,
                              std::list<AuthedLocation>& locs,
                              std::list<AuthedLocation>::iterator &ap);
    bool is_internal_ip(uint32_t nwaddr) const;
    void expire_entities();
    void expire_host_locations(const timeval& curtime);
    void expire_hosts(const timeval& curtime);
    void expire_users(const timeval& curtime);
    void poison_location(const datapathid& dp, const ethernetaddr& dladdr,
                         uint32_t nwaddr, bool wildcard_nw) const;
    bool is_internal_mac(uint64_t) const;

    template<typename K, typename V>
    void map_entries(hash_map<K, V> *map, const boost::function<void(V&)>& fn);
    template<typename K, typename V>
    void map_entry(hash_map<K, V> *map, K key, const boost::function<void(V&)>& fn);
    template<typename V>
    void remove_group(V& value, uint32_t group);
    template<typename K, typename V>
    void new_entry_fail(hash_map<K, V> *map, K key, const BoolCb& cb);
};

template<typename K, typename V>
void
Authenticator::map_entries(hash_map<K, V> *map,
                           const boost::function<void(V&)>& fn)
{
    EmptyCb cb;
    for (typename hash_map<K, V>::iterator entry = map->begin();
         entry != map->end(); ++entry)
    {
        if (entry->second.status.locked) {
            cb = boost::bind(&Authenticator::map_entry<K, V>, this, map,
                             entry->first, fn);
            entry->second.status.waiters.push_back(cb);
        } else {
            fn(entry->second);
        }
    }
}

template<typename K, typename V>
void
Authenticator::map_entry(hash_map<K, V> *map, K key,
                         const boost::function<void(V&)>& fn)
{
    typename hash_map<K, V>::iterator entry = map->find(key);
    if (entry != map->end()) {
        if (entry->second.status.locked) {
            entry->second.status.waiters.push_back(
                boost::bind(&Authenticator::map_entry<K, V>,
                            this, map, key, fn));
            return;
        }
        fn(entry->second);
    }
}

template<typename V>
void
Authenticator::remove_group(V& value, uint32_t group)
{
    std::vector<uint32_t>::iterator g;
    if (contains_group(value.entry->groups, group, g)) {
        namemanager->decrement_id(group);
        value.entry->groups.erase(g);
    }
}

template<>
inline
void
Authenticator::remove_group(SwitchEntry& value, uint32_t group)
{
    directory::Group_Type gtype = ((directory::Group_Type)0xffffffffU);
    namemanager->get_group_type(group, gtype);

    if (gtype == directory::SWITCH_PRINCIPAL_GROUP) {
        std::list<uint32_t>::iterator g;
        if (contains_group(value.groups, group, g)) {
            namemanager->decrement_id(group);
            value.groups.erase(g);
            for (std::list<LocEntry*>::iterator loc = value.locations.begin();
                 loc != value.locations.end(); ++loc)
            {
                remove_group(**loc, group);
            }
        }
    } else {
        for (std::list<LocEntry*>::iterator loc = value.locations.begin();
             loc != value.locations.end(); ++loc)
        {
            remove_group(**loc, group);
        }
    }
}

template<>
inline
void
Authenticator::remove_group(DLEntry& value, uint32_t group)
{
    for (DLNWMap::iterator niter = value.nwentries.begin();
         niter != value.nwentries.end(); ++niter)
    {
        std::vector<uint32_t>::iterator g;
        if (contains_group(*(niter->second.address_groups), group, g)) {
            namemanager->decrement_id(group);
            niter->second.address_groups->erase(g);
        }
    }
}

// -----------------------------------------------------------------------------
// Deletes failed entry, calling cb and unlocking its status.
// -----------------------------------------------------------------------------

template<typename K, typename V>
void
Authenticator::new_entry_fail(hash_map<K, V> *map, K key,
                              const BoolCb& cb)
{
    typename hash_map<K, V>::iterator value = map->find(key);
    if (value == map->end()) {
        cb(false);
        return;
    }

    UpdateStatus tmp;
    tmp.waiters.swap(value->second.status.waiters);

    decrement_entry(value->second);
    map->erase(value);
    unlock_status(&tmp, boost::bind(cb, false));
}

} // namespace applications
} // namespace vigil

#endif // AUTHENTICATOR_HH
