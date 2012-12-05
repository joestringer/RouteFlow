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

#define LOC_FROM_DP_PORT(dp, pt) ((dp).as_host() + (((uint64_t)(pt)) << 48))

#define NWADDR_TIMEOUT         300
#define HOST_TIMEOUT           300

#define DP_MASK          0xffffffffffffULL

namespace vigil {
namespace applications {

static Vlog_module lg("authenticator");
static const std::string app_name("authenticator");

// -----------------------------------------------------------------------------
// Authenticates host for the given address pair and location.  'prev_success'
// signals success for a previous call this add_host depends on.  Calls 'cb'
// with true on successful authentication, else with false.
// -----------------------------------------------------------------------------

void
Authenticator::add_host(Host_auth_event& ha, const BoolCb& cb, bool prev_success)
{
    if (!prev_success) {
        cb(false);
        return;
    }

    uint64_t loc = LOC_FROM_DP_PORT(ha.datapath_id, ha.port);
    get_location(ha.datapath_id, loc,
                 boost::bind(&Authenticator::add_host2, this,
                             ha, _1, _2, cb));
}

// -----------------------------------------------------------------------------
// Sets hostname to be authenticated and calls 'add_host'.
// -----------------------------------------------------------------------------

void
Authenticator::set_hname_and_add(const std::string& hname,
                                 Host_auth_event &ha, const BoolCb& cb)
{
    uint32_t id = namemanager->get_principal_id(hname,
                                                directory::HOST_PRINCIPAL,
                                                false, true);

    if (id == NameManager::UNKNOWN_ID) {
        id = NameManager::AUTHENTICATED_ID;
    }

    if (id != ha.hostname) {
        ha.reason = Host_event::NWADDR_AUTO_ADD;
        ha.hostname = id;
    }

    add_host(ha, cb, true);
}

// -----------------------------------------------------------------------------
// Performs authentication once location is available (unlocked).
// -----------------------------------------------------------------------------

void
Authenticator::add_host2(Host_auth_event& ha, DPIDMap::iterator& siter,
                         DPPORTMap::iterator& dppiter, const BoolCb& cb)
{
    if (siter == switches_by_dp.end()) {
        VLOG_ERR(lg, "Cannot add host %s, switch %"PRIx64" does not exist.",
                 namemanager->get_name(ha.hostname).c_str(),
                 ha.datapath_id.as_host());
        cb(false);
        return;
    } else if (dppiter == locations_by_dpport.end()) {
        VLOG_ERR(lg, "Cannot add host %s, location %"PRIx64":%"PRIu16" does not exist.",
                 namemanager->get_name(ha.hostname).c_str(),
                 siter->first, ha.port);
        cb(false);
        return;
    }

    LocEntry *lentry = &dppiter->second;

    HostMap::iterator hiter = hosts.find(ha.hostname);
    if (hiter == hosts.end()) {
        new_host(ha.hostname,
                 boost::bind(&Authenticator::add_host,
                             this, ha, cb, _1));
        return;
    }

    HostEntry *hentry = &hiter->second;
    if (hentry->status.locked) {
        VLOG_DBG(lg, "Queuing add host %s %"PRIx64":%"PRIu16" %s %s for host entry.",
                 namemanager->get_name(ha.hostname).c_str(), siter->first,
                 ha.port, ha.dladdr.string().c_str(),
                 ipaddr(ha.nwaddr).string().c_str());
        hentry->status.waiters.push_back(
            boost::bind(&Authenticator::add_host, this, ha, cb, true));
        return;
    }

    DLMap::iterator diter = hosts_by_dladdr.find(ha.dladdr.hb_long());
    if (diter == hosts_by_dladdr.end()) {
        new_dlentry(ha.dladdr,
                    boost::bind(&Authenticator::add_host,
                                this, ha, cb, true));
        return;
    }

    DLEntry *dlentry = &diter->second;
    if (dlentry->status.locked) {
        VLOG_DBG(lg, "Queuing add host %s %"PRIx64":%"PRIu16" %s %s for dladdr.",
                 namemanager->get_name(ha.hostname).c_str(),
                 ha.datapath_id.as_host(), ha.port, ha.dladdr.string().c_str(),
                 ipaddr(ha.nwaddr).string().c_str());
        dlentry->status.waiters.push_back(
            boost::bind(&Authenticator::add_host, this, ha, cb, true));
        return;
    }

    DLNWMap::iterator niter = dlentry->nwentries.find(ha.nwaddr);
    if (niter == dlentry->nwentries.end()) {
        new_nwentry(dlentry, ha.nwaddr,
                    boost::bind(&Authenticator::add_host, this,
                                ha, cb, true));
        return;
    }

    NWEntry *nwentry = &niter->second;
    if (nwentry->dlentry->status.locked) {
        VLOG_DBG(lg, "Queuing add host %s %"PRIx64":%"PRIu16" %s %s for nwaddr.",
                 namemanager->get_name(ha.hostname).c_str(),
                 ha.datapath_id.as_host(), ha.port,
                 ha.dladdr.string().c_str(), ipaddr(ha.nwaddr).string().c_str());
        nwentry->dlentry->status.waiters.push_back(
            boost::bind(&Authenticator::add_host, this, ha, cb, true));
        return;
    }

    // Remove any host currently authenticated at addresses
    if (nwentry->host != NULL
        && (!nwentry->authed || nwentry->host != hentry->entry))
    {
        remove_host(nwentry, Host_event::AUTHENTICATION_EVENT,
                    nwentry->host != hentry->entry);
    }

    // Automatically authenticate nwaddr == 0 if not already.
    if (ha.nwaddr != 0) {
        if (dlentry->is_router) {
            if (dlentry->zero == NULL || !dlentry->zero->authed) {
                BoolCb second_cb = boost::bind(&Authenticator::add_host,
                                               this, ha, cb, _1);
                ha.nwaddr = 0;
                get_host(ha.datapath_id, ha.port, ha.dladdr, 0, true,
                         boost::bind(&Authenticator::set_hname_and_add,
                                     this, _1, ha, second_cb), 0);
                return;
            }
        } else if (dlentry->zero == NULL
                   || !dlentry->zero->authed
                   || dlentry->zero->host != hentry->entry)
        {
            BoolCb second_cb = boost::bind(&Authenticator::add_host,
                                           this, ha, cb, _1);
            ha.nwaddr = 0;
            add_host(ha, second_cb, true);
            return;
        }
    }

    timeval curtime = { 0, 0 };
    gettimeofday(&curtime, NULL);

    std::string dlstr = ha.dladdr.string();
    // Add host to NWEntry
    if (nwentry->host == NULL) {
        const std::string& hostname = namemanager->get_name(ha.hostname);
        std::string nwstr = ipaddr(ha.nwaddr).string();
        nwentry->host = hentry->entry;
        nwentry->authed = true;
        if (hentry->nwentries.empty()) {
            hentry->entry->hard_timeout = ha.hard_timeout;
            hentry->entry->auth_time = hentry->entry->last_active = curtime.tv_sec;
            post(new Host_join_event(Host_join_event::JOIN, ha.hostname,
                                     ha.reason));
            snprintf(buf, 1024, "{sh} joined the network.");
            LogEntry to_log(app_name, LogEntry::INFO, buf);
            to_log.setName(hostname, Name::HOST, LogEntry::SRC);
            user_log->log(to_log);
        }
        hentry->nwentries.push_back(nwentry);
        if (ha.nwaddr != 0) {
            hosts_by_nwaddr[ha.nwaddr].push_front(nwentry);
            VLOG_DBG(lg, "Added %s %s to host %s.",
                     dlstr.c_str(), nwstr.c_str(), hostname.c_str());
            snprintf(buf, 1024, "{sh} authenticated%s %s.",
                     ha.nwaddr == 0 ? "" : (" " + nwstr + " on").c_str(),
                     dlstr.c_str());
            LogEntry to_log(app_name, LogEntry::INFO, buf);
            to_log.setName(hostname, Name::HOST, LogEntry::SRC);
            user_log->log(to_log);
        }
        bindings->store_host_binding(ha.hostname, ha.dladdr, ha.nwaddr);
        post(new Host_bind_event(Host_bind_event::ADD, ha.dladdr,
                                 ha.nwaddr, ha.hostname, ha.reason));
    }

    // Set host's hard_timeout to most relaxed
    if (hentry->entry->hard_timeout != 0
        && (ha.hard_timeout > hentry->entry->hard_timeout
            || ha.hard_timeout == 0))
    {
        hentry->entry->hard_timeout = ha.hard_timeout;
    }

    // Add location if not already present
    std::list<AuthedLocation>::iterator authed;
    std::vector<uint64_t> to_remove;
    Routing_module::RouteId rid;
    rid.src = ha.datapath_id;
    for (authed = dlentry->locations.begin();
         authed != dlentry->locations.end(); ++authed)
    {
        if (authed->location == lentry->entry) {
            if (authed->idle_timeout != 0
                && (ha.idle_timeout > authed->idle_timeout
                    || ha.idle_timeout == 0))
            {
                authed->idle_timeout = ha.idle_timeout;
            }
            cb(true);
            return;
        } else {
            rid.dst = datapathid::from_host(authed->location->dpport & DP_MASK);
            if (routing_mod->is_on_path_location(rid, ha.port,
                                                 (uint16_t)(authed->location->dpport >> 48)))
            {
                to_remove.push_back(authed->location->dpport);
            }
        }
    }

    AuthedLocation authed_loc = { lentry->entry, curtime.tv_sec, ha.idle_timeout };
    dlentry->locations.push_back(authed_loc);
    lentry->dlentries.push_back(dlentry);

    const std::string& hostname = namemanager->get_name(dlentry->zero->host->name);
    VLOG_DBG(lg, "%s added location %"PRIx64":%"PRIu16" to %s.",
             hostname.c_str(), ha.datapath_id.as_host(), ha.port,
             dlstr.c_str());
    bindings->store_location_binding(ha.dladdr, lentry->entry->name);
    post(new Host_bind_event(Host_bind_event::ADD, ha.datapath_id,
                             ha.port, ha.dladdr, dlentry->zero->host->name,
                             ha.reason));
    snprintf(buf, 1024, "{sh} authenticated %s on {sl}.", dlstr.c_str());
    const std::string& locname = namemanager->get_name(lentry->entry->name);
    LogEntry to_log(app_name, LogEntry::INFO, buf);
    to_log.setName(hostname, Name::HOST, LogEntry::SRC);
    to_log.setName(locname, Name::LOCATION, LogEntry::SRC);
    user_log->log(to_log);

    // Remove any internal locations on path of new location
    for (std::vector<uint64_t>::const_iterator iter = to_remove.begin();
         iter != to_remove.end(); ++iter)
    {
        remove_host_location(dlentry, *iter, false,
                             Host_event::INTERNAL_LOCATION, false);
    }

    cb(true);
}

// -----------------------------------------------------------------------------
// Deauthenticates a location on a dladdr, poisoning the location for the
// address if 'poison' == true.  'reason' should signal why location is being
// removed.  If dlentry's location list is empty after the removal, all hosts
// on dladdr are deauthenticated.
// -----------------------------------------------------------------------------

void
Authenticator::remove_host_location(DLEntry *dlentry,
                                    std::list<AuthedLocation>::iterator& authed,
                                    Host_event::Reason reason, bool poison)
{
    uint64_t loc = authed->location->dpport;
    datapathid dp = datapathid::from_host(loc & DP_MASK);
    uint16_t port = (uint16_t)(loc >> 48);

    LocEntry *lentry = &locations_by_dpport[loc];
    bool not_found = true;
    for (std::list<DLEntry*>::iterator diter = lentry->dlentries.begin();
         diter != lentry->dlentries.end(); ++diter)
    {
        if (*diter == dlentry) {
            lentry->dlentries.erase(diter);
            not_found = false;
            break;
        }
    }
    if (not_found) {
        VLOG_ERR(lg, "DLEntry %s not found in remove location "
                 "%"PRIx64":%"PRIu16" entry.",
                 dlentry->dladdr.string().c_str(), dp.as_host(), port);
    }

    const std::string& hostname = namemanager->get_name(dlentry->zero->host->name);
    const std::string& locname = namemanager->get_name(authed->location->name);
    std::string dlstr = dlentry->dladdr.string();
    const char *reason_str = Host_event::get_reason_string(reason);
    VLOG_DBG(lg, "Removed location %"PRIx64":%"PRIu16" from %s on host %s. (%s)",
             dp.as_host(), port, dlstr.c_str(), hostname.c_str(), reason_str);
    bindings->remove_location_binding(dlentry->dladdr, authed->location->name);
    post(new Host_bind_event(Host_bind_event::REMOVE, dp, port, dlentry->dladdr,
                             dlentry->zero->host->name, reason));
    snprintf(buf, 1024, "{sh} deauthenticated %s from {sl}. (%s)",
             dlstr.c_str(), reason_str);
    LogEntry to_log(app_name, LogEntry::INFO, buf);
    to_log.setName(hostname, Name::HOST, LogEntry::SRC);
    to_log.setName(locname, Name::LOCATION, LogEntry::SRC);
    user_log->log(to_log);

    authed = dlentry->locations.erase(authed);

    if (poison) {
        poison_location(dp, dlentry->dladdr, 0, true);
    }

    // deauthenticate dladdr
    if (dlentry->locations.empty()) {
        remove_host(dlentry->zero, reason, poison);
    }
}

// -----------------------------------------------------------------------------
// Deauthenticates location 'loc' on a dladdr, deauthenticating all of dladdr's
// locations if 'loc' == 0.
// -----------------------------------------------------------------------------

void
Authenticator::remove_host_location(DLEntry *dlentry, uint64_t loc, bool mask,
                                    Host_event::Reason reason, bool poison)
{
    bool not_found = true;
    uint64_t bmask = 0;
    if (loc != 0) {
        bmask = mask ? DP_MASK : (~((uint64_t)0));
    }
    std::list<AuthedLocation>::iterator authed;
    for (authed = dlentry->locations.begin();
         authed != dlentry->locations.end();)
    {
        if (loc == (authed->location->dpport & bmask)) {
            remove_host_location(dlentry, authed, reason, poison);
            not_found = false;
            if (bmask > DP_MASK) {
                break;
            }
        } else {
            ++authed;
        }
    }

    if (bmask > DP_MASK && not_found) {
        VLOG_DBG(lg, "Location %"PRIx64":%"PRIu16" not found on dl %s entry.",
                 loc & DP_MASK, (uint16_t)(loc >> 48), dlentry->dladdr.string().c_str());
    }
}

// -----------------------------------------------------------------------------
// Deauthenticates host on dladdr/nwaddr pair, poisoning the authenticated
// locations if 'poison' == true.  If nwaddr == 0, all nwaddrs and locations on
// the dladdr are deauthenticated.  'reason' should signal why the host is
// being deauthenticated.
// -----------------------------------------------------------------------------
void
Authenticator::remove_host(NWEntry *nwentry, Host_event::Reason reason,
                           bool poison)
{
    if (nwentry->nwaddr == 0) {
        if (!nwentry->dlentry->locations.empty()) {
            remove_host_location(nwentry->dlentry, 0, false, reason, poison);
            return;
        }
        for (DLNWMap::iterator nwiter = nwentry->dlentry->nwentries.begin();
             nwiter != nwentry->dlentry->nwentries.end(); ++nwiter)
        {
            if (nwiter->second.nwaddr != 0) {
                remove_host(&nwiter->second, reason, poison);
            }
        }
    }

    if (nwentry->host == NULL) {
        return;
    }

    HostEntry *host = &hosts[nwentry->host->name];
    bool not_found = true;
    std::list<NWEntry*> *hlist = nwentry->authed ?
        &host->nwentries : &host->cached_entries;
    for (std::list<NWEntry*>::iterator niter = hlist->begin();
         niter != hlist->end(); ++niter)
    {
        if (*niter == nwentry) {
            hlist->erase(niter);
            not_found = false;
            break;
        }
    }
    if (not_found) {
        VLOG_ERR(lg, "NWEntry %s %s not found in remove host entry %s.",
                 nwentry->dlentry->dladdr.string().c_str(),
                 ipaddr(nwentry->nwaddr).string().c_str(),
                 namemanager->get_name(nwentry->host->name).c_str());
    }

    not_found = nwentry->nwaddr != 0;
    NWMap::iterator nwaddr = hosts_by_nwaddr.find(nwentry->nwaddr);
    if (nwaddr != hosts_by_nwaddr.end()) {
        for (std::list<NWEntry*>::iterator niter = nwaddr->second.begin();
             niter != nwaddr->second.end(); ++niter)
        {
            if (*niter == nwentry) {
                nwaddr->second.erase(niter);
                if (nwaddr->second.empty()) {
                    hosts_by_nwaddr.erase(nwaddr);
                }
                not_found = false;
                break;
            }
        }
    }
    if (not_found) {
        VLOG_ERR(lg, "NWEntry %s %s not found in remove hosts_by_nwaddr.",
                 nwentry->dlentry->dladdr.string().c_str(),
                 ipaddr(nwentry->nwaddr).string().c_str());
    }

    if (nwentry->authed) {
        nwentry->authed = false;
        timeval curtime = { 0, 0 } ;
        gettimeofday(&curtime, NULL);
        nwentry->exp_time = curtime.tv_sec + NWADDR_TIMEOUT;
        bindings->remove_host_binding(nwentry->host->name,
                                      nwentry->dlentry->dladdr,
                                      nwentry->nwaddr);
        post(new Host_bind_event(Host_bind_event::REMOVE,
                                 nwentry->dlentry->dladdr, nwentry->nwaddr,
                                 nwentry->host->name, reason));
        const std::string& hostname = namemanager->get_name(nwentry->host->name);
        const char *reason_str = Host_event::get_reason_string(reason);
        if (nwentry->nwaddr != 0) {
            std::string dlstr = nwentry->dlentry->dladdr.string();
            std::string nwstr = ipaddr(nwentry->nwaddr).string();
            VLOG_DBG(lg, "Removed nwaddr %s from %s on %s. (%s)",
                     nwstr.c_str(), hostname.c_str(), dlstr.c_str(),
                     reason_str);
            snprintf(buf, 1024, "{sh} deauthenticated %s from %s. (%s)",
                     nwstr.c_str(), dlstr.c_str(), reason_str);
            LogEntry to_log(app_name, LogEntry::INFO, buf);
            to_log.setName(hostname, Name::HOST, LogEntry::SRC);
            user_log->log(to_log);
        }
        if (hlist->empty()) {
            post(new Host_join_event(Host_join_event::LEAVE,
                                     nwentry->host->name, reason));
            snprintf(buf, 1024, "{sh} left the network. (%s)",
                     reason_str);
            LogEntry to_log(app_name, LogEntry::INFO, buf);
            to_log.setName(hostname, Name::HOST, LogEntry::SRC);
            user_log->log(to_log);
        }
    }

    nwentry->host.reset();

    if (poison) {
        std::list<AuthedLocation>::iterator authed;
        for (authed = nwentry->dlentry->locations.begin();
             authed != nwentry->dlentry->locations.end(); ++authed)
        {
            poison_location(datapathid::from_host(authed->location->dpport & DP_MASK),
                            nwentry->dlentry->dladdr, nwentry->nwaddr, nwentry->nwaddr == 0);
        }
    }
}

// -----------------------------------------------------------------------------
// Deauthenticates host on nwentry for 'loc'.  If 'loc' == 0, deauthenticates
// nwentry fully.  Else if host is behind a router on the location,
// deauthenticates the host from the dladdr/nwaddr entry, keeping the location
// authenticated for the router.  Otherwise deauthenticates the location from
// the corresponding dladdr, preserving any other locations the nwentry is
// authenticated on on the dlentry for.  Poisons any deauthenticated locations.
// Returns true if anything was removed.
// -----------------------------------------------------------------------------

bool
Authenticator::remove_host(NWEntry *nwentry, uint64_t loc, bool mask,
                           Host_event::Reason reason)
{
    if (loc == 0) {
        remove_host(nwentry, reason, true);
    } else if (nwentry->authed
               && nwentry->host == nwentry->dlentry->zero->host)
    {
        remove_host_location(nwentry->dlentry, loc, mask, reason, true);
    } else {
        uint64_t bmask = mask ? DP_MASK : (~((uint64_t)(0)));
        std::list<AuthedLocation>::iterator authed;
        for (authed = nwentry->dlentry->locations.begin();
             authed != nwentry->dlentry->locations.end(); ++authed)
        {
            if ((authed->location->dpport & bmask) == loc) {
                remove_host(nwentry, reason, true);
                return true;
            }
        }
        return false;
    }
    return true;
}

// -----------------------------------------------------------------------------
// Deauthenticates host on location 'loc'.  If 'loc' == 0, fully
// deauthenticates host.  If host is behind a router on the location,
// deauthenticates the host from the dladdr/nwaddr entry, keeping the location
// authenticated for the router.  Otherwise deauthenticates the location from
// the dladdr, preserving any other locations the host is authenticated on on
// the dlentry.  Poisons any deauthenticated locations.
// -----------------------------------------------------------------------------

void
Authenticator::remove_host(HostEntry *hentry, uint64_t loc, bool mask,
                           Host_event::Reason reason)
{
    std::list<NWEntry*> hlist = hentry->nwentries;
    bool looped = false;
    while (true) {
        for (std::list<NWEntry*>::iterator niter = hlist.begin();
             niter != hlist.end(); ++niter)
        {
            remove_host(*niter, loc, mask, reason);
        }

        if (looped) {
            break;
        }
        looped = true;
        hlist = hentry->cached_entries;
    }
}

// -----------------------------------------------------------------------------
// Deletes 'host' from 'hosts' map, first deauthenticating it fully.  'host'
// should be unlocked when called.
// -----------------------------------------------------------------------------

void
Authenticator::delete_host(HostMap::iterator& host, Host_event::Reason reason)
{
    if (host->second.status.locked) {
        VLOG_ERR(lg, "Host should not be locked on deletion.");
        return;
    }
    remove_host(&host->second, 0, false, reason);
    remove_user(NULL, &host->second, User_event::HOST_DELETE, false);
    VLOG_DBG(lg, "Deleting host entry %s. (%s)",
             namemanager->get_name(host->second.entry->name).c_str(),
             Host_event::get_reason_string(reason));
    decrement_entry(host->second);
    host = hosts.erase(host);
}

// -----------------------------------------------------------------------------
// Waits for 'host' to be unlocked, then calling delete_host on the
// corresponding HostEntry.  Calls 'cb' on completion.
// -----------------------------------------------------------------------------

void
Authenticator::delete_host(uint32_t hostname, Host_event::Reason reason,
                           const EmptyCb& cb)
{
    HostMap::iterator host = hosts.find(hostname);
    if (host != hosts.end()) {
        if (host->second.status.locked) {
            host->second.status.waiters.push_back(
                boost::bind(&Authenticator::delete_host,
                            this, hostname, reason, cb));
            return;
        }
        delete_host(host, reason);
    }
    cb();
}

// -----------------------------------------------------------------------------
// Deauthenticates any hosts on location 'loc'.
// -----------------------------------------------------------------------------

void
Authenticator::remove_host(LocEntry *lentry, Host_event::Reason reason, bool poison)
{
    // make copy becuase could get modified
    std::list<DLEntry*> hosts = lentry->dlentries;

    uint64_t loc = lentry->entry->dpport;
    for (std::list<DLEntry*>::iterator diter = hosts.begin();
         diter != hosts.end(); ++diter)
    {
        remove_host_location(*diter, loc, false, reason, poison);
    }

    if (!lentry->dlentries.empty()) {
        VLOG_ERR(lg, "Expect any dlentries to still exist in location %"PRIx64":%"PRIu16"?",
                 loc & DP_MASK, (uint16_t)(loc >> 48));
    }
}

void
Authenticator::remove_host(uint64_t loc, Host_event::Reason reason, bool poison)
{
    DPPORTMap::iterator liter;
    if (loc == 0) {
        for (liter = locations_by_dpport.begin();
             liter != locations_by_dpport.end(); ++liter)
        {
            if (liter->first != 0) {
                remove_host(liter->first, reason, poison);
            }
        }
    }

    liter = locations_by_dpport.find(loc);
    if (liter == locations_by_dpport.end()) {
        VLOG_DBG(lg, "Location %"PRIx64":%"PRIu16" is not authenticated.",
                 loc & DP_MASK, (uint16_t)(loc >> 48));
        return;
    }

    remove_host(&liter->second, reason, poison);
}

// -----------------------------------------------------------------------------
// Deauthenticates any hosts on datapath 'dp'.
// -----------------------------------------------------------------------------

void
Authenticator::remove_host(const datapathid& dp, Host_event::Reason reason,
                           bool poison)
{
    DPIDMap::iterator siter = switches_by_dp.find(dp.as_host());
    if (siter == switches_by_dp.end()) {
        return;
    }
    SwitchEntry *sentry = &siter->second;

    for (std::list<LocEntry*>::iterator liter = sentry->locations.begin();
         liter != sentry->locations.end(); ++liter)
    {
        remove_host(*liter, reason, poison);
    }
}

// -----------------------------------------------------------------------------
// Removes any authentications matching the passed in criteria.  Certain values
// can be wildcarded (see Host_auth_event).
// -----------------------------------------------------------------------------

void
Authenticator::remove_host(const Host_auth_event& ha)
{
    if ((ha.enabled_fields & Host_auth_event::EF_DLADDR) != 0) {
        DLMap::iterator dliter = hosts_by_dladdr.find(ha.dladdr.hb_long());
        if (dliter == hosts_by_dladdr.end()) {
            return;
        }
        if ((ha.enabled_fields & Host_auth_event::EF_NWADDR) != 0) {
            DLNWMap::iterator nwiter = dliter->second.nwentries.find(ha.nwaddr);
            if (nwiter != dliter->second.nwentries.end()) {
                remove_host(ha, &nwiter->second);
            }
            return;
        } else if (dliter->second.zero != NULL) {
            // if removed anything, will have removed from other nwaddrs already
            if (remove_host(ha, dliter->second.zero)) {
                return;
            }
        }
        for (DLNWMap::iterator nwiter = dliter->second.nwentries.begin();
             nwiter != dliter->second.nwentries.end(); ++nwiter)
        {
            if (nwiter->first != 0) {
                remove_host(ha, &nwiter->second);
            }
        }
    } else if ((ha.enabled_fields & Host_auth_event::EF_NWADDR) != 0) {
        if (ha.nwaddr != 0) {
            NWMap::iterator nwiter = hosts_by_nwaddr.find(ha.nwaddr);
            if (nwiter == hosts_by_nwaddr.end()) {
                return;
            }
            // make copy bc remove could modify list
            std::list<NWEntry*> entries = nwiter->second;
            for (std::list<NWEntry*>::iterator nw = entries.begin();
                 nw != entries.end(); ++nw)
            {
                remove_host(ha, *nw);
            }
        } else {
            for (DLMap::iterator dliter = hosts_by_dladdr.begin();
                 dliter != hosts_by_dladdr.end(); ++dliter)
            {
                if (dliter->second.zero != NULL) {
                    remove_host(ha, dliter->second.zero);
                }
            }
        }
    } else if ((ha.enabled_fields & Host_auth_event::EF_HOSTNAME) != 0) {
        HostMap::iterator host = hosts.find(ha.hostname);
        if (host == hosts.end()) {
            return;
        }
        bool mask = false;
        uint64_t loc = 0;
        if ((ha.enabled_fields & Host_auth_event::EF_LOCATION) != 0) {
            loc = LOC_FROM_DP_PORT(ha.datapath_id, ha.port);
        } else if ((ha.enabled_fields & Host_auth_event::EF_SWITCH) != 0) {
            mask = true;
            loc = ha.datapath_id.as_host();
        }
        remove_host(&host->second, loc, mask, ha.reason);
    } else if ((ha.enabled_fields & Host_auth_event::EF_LOCATION) != 0) {
        remove_host(LOC_FROM_DP_PORT(ha.datapath_id, ha.port), ha.reason, true);
    } else if ((ha.enabled_fields & Host_auth_event::EF_SWITCH) != 0) {
        remove_host(ha.datapath_id, ha.reason, true);
    }
    // if no fields enabled should remove all hosts?
}

// -----------------------------------------------------------------------------
// Apply wildcards on single nwentry.
// -----------------------------------------------------------------------------

bool
Authenticator::remove_host(const Host_auth_event& ha, NWEntry *nwentry)
{
    if ((ha.enabled_fields & Host_auth_event::EF_HOSTNAME) != 0) {
        if (nwentry->host == NULL || nwentry->host->name != ha.hostname) {
            return false;
        }
    }

    if ((ha.enabled_fields
         & (Host_auth_event::EF_SWITCH | Host_auth_event::EF_LOCATION)) == 0)
    {
        remove_host(nwentry, ha.reason, true);
        return true;
    }

    uint64_t loc = LOC_FROM_DP_PORT(ha.datapath_id, ha.port);
    bool mask = ((ha.enabled_fields & Host_auth_event::EF_LOCATION) == 0);

    return remove_host(nwentry, loc, mask, ha.reason);
}

// -----------------------------------------------------------------------------
// Authenticate 'username' on 'hostname', calling 'cb' on successful
// authentication with 'true', else 'false. 'prev_success' signals the success
// of a previous operation the 'add_user' depends on.
// -----------------------------------------------------------------------------

void
Authenticator::add_user(const User_auth_event& ua, const BoolCb& cb,
                        bool prev_success)
{
    if (!prev_success) {
        cb(false);
        return;
    }

    UserMap::iterator uiter = users.find(ua.username);
    if (uiter == users.end()) {
        new_user(ua.username,
                 boost::bind(&Authenticator::add_user, this, ua, cb, _1));
        return;
    }

    UserEntry *uentry = &uiter->second;
    if (uentry->status.locked) {
        VLOG_DBG(lg, "Queuing add user %s to host %s for user entry.",
                 namemanager->get_name(ua.username).c_str(),
                 namemanager->get_name(ua.hostname).c_str());
        uentry->status.waiters.push_back(boost::bind(&Authenticator::add_user,
                                                     this, ua, cb, true));
        return;
    }

    HostMap::iterator hiter = hosts.find(ua.hostname);
    if (hiter == hosts.end()) {
        new_host(ua.hostname,
                 boost::bind(&Authenticator::add_user, this, ua, cb, _1));
        return;
    }

    HostEntry *hentry = &hiter->second;
    if (hentry->status.locked) {
        VLOG_DBG(lg, "Queuing add user %s to host %s for host entry.",
                 namemanager->get_name(ua.username).c_str(),
                 namemanager->get_name(ua.hostname).c_str());
        hentry->status.waiters.push_back(boost::bind(&Authenticator::add_user,
                                                     this, ua, cb, true));
        return;
    }

    timeval curtime = { 0, 0 };
    gettimeofday(&curtime, NULL);

    std::list<AuthedUser>::iterator authed;
    for (authed = hentry->entry->users.begin();
         authed != hentry->entry->users.end(); ++authed)
    {
        if (authed->user == uentry->entry) {
            if (authed->idle_timeout != 0
                && (ua.idle_timeout > authed->idle_timeout
                    || ua.idle_timeout == 0))
            {
                authed->idle_timeout = ua.idle_timeout;
            }
            if (authed->hard_timeout != 0
                && (ua.hard_timeout > authed->hard_timeout
                    || ua.hard_timeout == 0))
            {
                authed->hard_timeout = ua.hard_timeout;
            }
            authed->auth_time = curtime.tv_sec;
            cb(true);
            return;
        }
    }

    if (hentry->entry->users.size() == 1
        && hentry->entry->users.front().user->name == NameManager::UNAUTHENTICATED_ID)
    {
        remove_unauth_user(hentry);
    }
    AuthedUser au = { uentry->entry, curtime.tv_sec, ua.idle_timeout, ua.hard_timeout };
    hentry->entry->users.push_back(au);
    uentry->hostentries.push_back(hentry);
    const std::string& username = namemanager->get_name(ua.username);
    const std::string& hostname = namemanager->get_name(ua.hostname);
    VLOG_DBG(lg, "Added user %s to host %s.",
             username.c_str(), hostname.c_str());
    bindings->store_user_binding(ua.username, ua.hostname);
    post(new User_join_event(User_join_event::JOIN, ua.username,
                             ua.hostname, ua.reason));
    snprintf(buf, 1024, "{su} join on {sh}.");
    LogEntry to_log(app_name, LogEntry::INFO, buf);
    to_log.setName(username, Name::USER, LogEntry::SRC);
    to_log.setName(hostname, Name::HOST, LogEntry::SRC);
    user_log->log(to_log);

    cb(true);
}

// -----------------------------------------------------------------------------
// Remove unauthenticated user from host.
// -----------------------------------------------------------------------------
void
Authenticator::remove_unauth_user(HostEntry *hentry)
{
    UserEntry& unauth_entry = users[NameManager::UNAUTHENTICATED_ID];
    std::list<HostEntry*>::iterator uhost;
    bool not_found = true;
    for (uhost = unauth_entry.hostentries.begin();
         uhost != unauth_entry.hostentries.end(); ++uhost)
    {
        if (*uhost == hentry) {
            unauth_entry.hostentries.erase(uhost);
            not_found = false;
            break;
        }
    }
    if (not_found) {
        VLOG_ERR(lg, "Host %s not found in unauthenticated user entry for auth.",
                 namemanager->get_name(hentry->entry->name).c_str());
    }
    hentry->entry->users.pop_front();
}

// -----------------------------------------------------------------------------
// Remove user from host, adding unauthenticated user to the host if its user
// list becomes empty and add_unauth == true.  If user == NULL, all users are
// removed from host.  Poisons locations host is on if any users are removed.
// -----------------------------------------------------------------------------

void
Authenticator::remove_user(UserEntry *user, HostEntry *host,
                           User_event::Reason reason, bool add_unauth)
{
    UserEntry *uentry = user;
    bool not_found = true;
    bool first_user = true;
    for (std::list<AuthedUser>::iterator authed = host->entry->users.begin();
         authed != host->entry->users.end();)
    {
        if (user == NULL || authed->user == user->entry) {
            if (user == NULL) {
                uentry = &users[authed->user->name];
            }
            authed = host->entry->users.erase(authed);
            for (std::list<HostEntry*>::iterator hiter = uentry->hostentries.begin();
                 hiter != uentry->hostentries.end(); ++hiter)
            {
                if (*hiter == host) {
                    uentry->hostentries.erase(hiter);
                    not_found = false;
                    break;
                }
            }
            if (not_found) {
                VLOG_ERR(lg, "Could not find host %s in user %s entry.",
                         namemanager->get_name(host->entry->name).c_str(),
                         namemanager->get_name(uentry->entry->name).c_str());
                not_found = false;
            }
            if (first_user) {
                for (std::list<NWEntry*>::iterator niter = host->nwentries.begin();
                     niter != host->nwentries.end(); ++niter)
                {
                    std::list<AuthedLocation>::iterator authed_loc;
                    for (authed_loc = (*niter)->dlentry->locations.begin();
                         authed_loc != (*niter)->dlentry->locations.end(); ++authed_loc)
                    {
                        poison_location(datapathid::from_host(authed_loc->location->dpport),
                                        (*niter)->dlentry->dladdr, (*niter)->nwaddr, (*niter)->nwaddr != 0);
                    }
                }
            }
            if (uentry->entry->name != NameManager::UNAUTHENTICATED_ID) {
                const std::string& username = namemanager->get_name(uentry->entry->name);
                const std::string& hostname = namemanager->get_name(host->entry->name);
                const char *reason_str = User_event::get_reason_string(reason);
                VLOG_DBG(lg, "Removed user %s from host %s. (%s)",
                         username.c_str(), hostname.c_str(), reason_str);
                bindings->remove_user_binding(uentry->entry->name,
                                              host->entry->name);
                post(new User_join_event(User_join_event::LEAVE,
                                         uentry->entry->name,
                                         host->entry->name, reason));
                snprintf(buf, 1024, "{su} leave on {sh}. (%s)", reason_str);
                LogEntry to_log(app_name, LogEntry::INFO, buf);
                to_log.setName(username, Name::USER, LogEntry::SRC);
                to_log.setName(hostname, Name::HOST, LogEntry::SRC);
                user_log->log(to_log);
            }
            if (user != NULL) {
                break;
            }
            not_found = true;
            first_user = false;
        } else {
            ++authed;
        }
    }

    if (user != NULL && not_found) {
        VLOG_DBG(lg, "User %s not found on host %s.",
                 namemanager->get_name(user->entry->name).c_str(),
                 namemanager->get_name(host->entry->name).c_str());
    }

    if (add_unauth && host->entry->users.empty()) {
        timeval curtime = { 0, 0 };
        gettimeofday(&curtime, 0);
        AuthedUser au = { users[NameManager::UNAUTHENTICATED_ID].entry,
                          curtime.tv_sec, 0, 0 };
        host->entry->users.push_back(au);
        users[NameManager::UNAUTHENTICATED_ID].hostentries.push_back(host);
    }
}

// -----------------------------------------------------------------------------
// Remove user from host.  Either user or host can be wildcarded by setting to
// UNKNOWN_ID.
// -----------------------------------------------------------------------------

void
Authenticator::remove_user(uint32_t username, uint32_t hostname,
                           User_event::Reason reason)
{
    UserEntry *user = NULL;
    if (username != NameManager::UNKNOWN_ID) {
        UserMap::iterator uiter = users.find(username);
        if (uiter == users.end()) {
            VLOG_DBG(lg, "User %s not currently authenticated.",
                     namemanager->get_name(username).c_str());
            return;
        }
        user = &uiter->second;
    }

    if (hostname == NameManager::UNKNOWN_ID) {
        if (user == NULL) {
            VLOG_ERR(lg, "Must specify either user or host name when removing user(s)");
        }
        std::list<HostEntry*> hosts = user->hostentries;
        for (std::list<HostEntry*>::iterator hiter = hosts.begin();
             hiter != hosts.end(); ++hiter)
        {
            remove_user(user, *hiter, reason, true);
        }
    } else {
        HostMap::iterator hiter = hosts.find(hostname);
        if (hiter == hosts.end()) {
            VLOG_DBG(lg, "Host %s not currently authenticated.",
                     namemanager->get_name(hostname).c_str());
        } else {
            remove_user(user, &hiter->second, reason, true);
        }
    }
}

// -----------------------------------------------------------------------------
// Deletes 'user' from 'users' map, first deauthenticating it from all hosts.
// Not allowed if user == UNAUTHENTICATED_ID.
// -----------------------------------------------------------------------------

void
Authenticator::delete_user(UserMap::iterator& user, User_event::Reason reason)
{
    if (user->second.status.locked) {
        VLOG_ERR(lg, "User should not be locked on deletion.");
        return;
    } else if (user->second.entry->name == NameManager::UNAUTHENTICATED_ID) {
        VLOG_ERR(lg, "Cannot delete unauthenticated user.");
    }

    remove_user(user->second.entry->name, NameManager::UNKNOWN_ID, reason);
    VLOG_DBG(lg, "Deleting user entry %s. (%s)",
             namemanager->get_name(user->second.entry->name).c_str(),
             User_event::get_reason_string(reason));
    decrement_entry(user->second);
    user = users.erase(user);
}

// -----------------------------------------------------------------------------
// Waits for user to be unlocked, then calling delete_user on the UserEntry.
// Calls 'cb' on completion.
// -----------------------------------------------------------------------------

void
Authenticator::delete_user(uint32_t username, User_event::Reason reason,
                           const EmptyCb& cb)
{
    UserMap::iterator user = users.find(username);
    if (user != users.end()) {
        if (user->second.status.locked) {
            user->second.status.waiters.push_back(
                boost::bind(&Authenticator::delete_user,
                            this, username, reason, cb));
            return;
        }
        delete_user(user, reason);
    }
    cb();
}

// -----------------------------------------------------------------------------
// Creates a new dladdr entry, calling 'success' on successful creation, else
// 'fail'.
// -----------------------------------------------------------------------------

void
Authenticator::new_dlentry(const ethernetaddr& dladdr, const EmptyCb& success)
{
    uint64_t dl_hb = dladdr.hb_long();
    DLEntry& entry = hosts_by_dladdr[dl_hb] = DLEntry();
    entry.dladdr = dladdr;
    entry.is_router = false;
    entry.zero = NULL;
    entry.status.locked = true;
    BoolCb cb = boost::bind(&Authenticator::new_dlentry2, this,
                            _1, &entry, success);
    if (!dirmanager->is_router(dladdr, "", cb, boost::bind(cb, false))) {
        new_dlentry2(false, &entry, success);
    }
}

void
Authenticator::new_dlentry2(bool is_router, DLEntry *entry, const EmptyCb& cb)
{
    entry->is_router = is_router;
    unlock_status(&entry->status, cb);
}

// -----------------------------------------------------------------------------
// Creates a new nwentry, calling 'success' on successful creation, else
// 'fail'.
// -----------------------------------------------------------------------------

void
Authenticator::new_nwentry(DLEntry *dlentry, uint32_t nwaddr,
                           const EmptyCb& success)
{
    NWEntry& entry = dlentry->nwentries[nwaddr] = NWEntry();
    entry.nwaddr = nwaddr;
    entry.authed = false;
    entry.dlentry = dlentry;
    entry.dlentry->status.locked = true;
    if (nwaddr == 0) {
        entry.dlentry->zero = &entry;
    }
    BoolCb nw_cb = boost::bind(&Authenticator::new_nwentry2, this,
                             &entry, success, _1);
    boost::function<void(const std::list<uint32_t>&)> cb =
        boost::bind(&Authenticator::get_nwaddr_groups,
                    this, &entry, _1, nw_cb);
    get_dladdr_groups(entry.dlentry->dladdr, cb);
}

void
Authenticator::new_nwentry2(NWEntry *entry, const EmptyCb& cb, bool ignore)
{
    timeval curtime = { 0, 0 };
    gettimeofday(&curtime, NULL);
    entry->exp_time = curtime.tv_sec + NWADDR_TIMEOUT;
    unlock_status(&entry->dlentry->status, cb);
}


// -----------------------------------------------------------------------------
// Creates a new host entry, calling 'cb' with true on successful creation else
// with false.
// -----------------------------------------------------------------------------
void
Authenticator::new_host(uint32_t hostname, const BoolCb& cb)
{
    HostEntry& host = hosts[hostname] = HostEntry();
    host.entry.reset(new Host());
    namemanager->increment_id(hostname);
    host.entry->name = hostname;
    host.status.locked = true;
    get_host_groups(&host,
                    boost::bind(&Authenticator::new_host2,
                                this, &host, cb, _1));
}

void
Authenticator::new_host2(HostEntry *host, const BoolCb& cb, bool success)
{
    if (!success) {
        new_entry_fail(&hosts, host->entry->name, cb);
        return;
    }

    UserMap::iterator uiter = users.find(NameManager::UNAUTHENTICATED_ID);
    if (uiter == users.end()) {
        new_user(NameManager::UNAUTHENTICATED_ID,
                 boost::bind(&Authenticator::new_host2, this,
                             host, cb, _1));
        return;
    }

    UserEntry *uentry = &uiter->second;
    if (uentry->status.locked) {
        VLOG_DBG(lg, "Queuing new host %s for unauthenicated user.",
                 namemanager->get_name(host->entry->name).c_str());
        uentry->status.waiters.push_back(
            boost::bind(&Authenticator::new_host2, this,
                        host, cb, true));
        return;
    }

    timeval curtime = { 0, 0 };
    gettimeofday(&curtime, NULL);

    host->entry->auth_time = curtime.tv_sec;
    host->entry->last_active = 0;
    host->entry->hard_timeout = HOST_TIMEOUT;

    AuthedUser au = { uentry->entry, curtime.tv_sec, 0, 0 };
    host->entry->users.push_back(au);
    uentry->hostentries.push_back(host);
    unlock_status(&host->status, boost::bind(cb, true));
}

// -----------------------------------------------------------------------------
// Creates a new user entry, calling 'success' on successful creation, else
// 'fail'.
// -----------------------------------------------------------------------------

void
Authenticator::new_user(uint32_t username, const BoolCb& cb)
{
    UserEntry& user = users[username];
    user.entry.reset(new User());
    namemanager->increment_id(username);
    user.entry->name = username;
    user.status.locked = true;
    get_user_groups(&user,
                    boost::bind(&Authenticator::new_user2, this,
                                &user, cb, _1));
}

void
Authenticator::new_user2(UserEntry *uentry, const BoolCb& cb, bool success)
{
    if (!success) {
        new_entry_fail(&users, uentry->entry->name, cb);
        return;
    }
    unlock_status(&uentry->status, boost::bind(cb, true));
}

Authenticator::LocEntry*
Authenticator::new_location(const datapathid& dp, uint16_t port,
                            uint64_t loc, const std::string& portname)
{
    while (true) {
        DPPORTMap::iterator liter = locations_by_dpport.find(loc);
        if (liter != locations_by_dpport.end()) {
            DPIDMap::iterator siter = switches_by_dp.find(dp.as_host());
            if (siter == switches_by_dp.end()) {
                VLOG_ERR(lg, "Location %"PRIx64":%"PRIu16"exists but switch does not.",
                         dp.as_host(), port);
                return NULL;
            }
            if (siter->second.status.locked) {
                VLOG_DBG(lg, "Queuing new location %"PRIx64":%"PRIu16" for switch entry.",
                         dp.as_host(), port);
                siter->second.status.waiters.push_back(
                    boost::bind(&Authenticator::new_location, this, dp,
                                port, loc, portname));
                return NULL;
            }
            remove_location(dp, port, loc, true);
        } else {
            break;
        }
    }

    LocEntry& location = locations_by_dpport[loc] = LocEntry();
    location.entry.reset(new Location());
    location.entry->dpport = loc;
    location.portname = namemanager->get_principal_id(portname,
                                                      (directory::Principal_Type)(~((uint32_t)0)),
                                                      true, true);
    location.status.locked = true;
    new_location2(&location, dp, port);
    return &location;
}

void
Authenticator::new_location2(LocEntry *location, const datapathid& dp,
                             uint16_t port)
{
    DPIDMap::iterator sw = switches_by_dp.find(dp.as_host());
    if (sw == switches_by_dp.end()) {
        VLOG_ERR(lg, "Switch does not exist, cannot create "
                 "location %"PRIx64":%"PRIu16".",
                 dp.as_host(), port);
        UpdateStatus status;
        status.waiters.swap(location->status.waiters);
        namemanager->decrement_id(location->portname);
        locations_by_dpport.erase(location->entry->dpport);
        unlock_status(&status);
        return;
    }

    SwitchEntry *sentry = &sw->second;
    if (sentry->status.locked) {
        VLOG_DBG(lg, "Queuing new location %"PRIx64":%"PRIu16" for switch entry.",
                 dp.as_host(), port);
        sentry->status.waiters.push_back(boost::bind(&Authenticator::new_location2,
                                                     this, location, dp, port));
        return;
    }
    sentry->status.locked = true;
    sentry->locations.push_back(location);

    loc_info.dpid = dp;
    loc_info.port = port;
    EmptyCb fail = boost::bind(&Authenticator::new_location_name, this,
                               std::vector<std::string>(), sentry, location,
                               dp, port);
    if (!dirmanager->search_locations(loc_info, lockey, "",
                                      boost::bind(&Authenticator::new_location_name,
                                                  this, _1, sentry, location,
                                                  dp, port), fail))
    {
        fail();
    }
}

void
Authenticator::new_location_name(const std::vector<std::string>& names,
                                 SwitchEntry *sentry, LocEntry *location,
                                 const datapathid& dp, uint16_t port)
{
    if (names.empty()) {
        if (location->entry->dpport == 0) {
            new_location3(namemanager->get_unauthenticated_name(), port, sentry, location);
            return;
        }
        EmptyCb fail = boost::bind(&Authenticator::new_location3, this,
                                   namemanager->get_authenticated_name(),
                                   port, sentry, location);
        if (sentry->name == NameManager::AUTHENTICATED_ID
            || !dirmanager->get_discovered_location_name(namemanager->get_name(sentry->name),
                                                         namemanager->get_name(location->portname),
                                                         dp, port, true,
                                                         boost::bind(&Authenticator::new_location3,
                                                                     this, _1, port, sentry,
                                                                     location),
                                                         fail))
        {
            fail();
        }
    } else {
        new_location3(names[0], port, sentry, location);
    }
}

void
Authenticator::new_location3(const std::string& location_name, uint16_t port,
                             SwitchEntry *sentry, LocEntry *location)
{
    uint32_t id = namemanager->get_principal_id(location_name,
                                                directory::LOCATION_PRINCIPAL,
                                                true, true);
    location->entry->name = id;
    if (locations.find(id) != locations.end()) {
        if (id > NameManager::START_ID) {
            VLOG_WARN(lg, "Location entry for name %s already exists.",
                      location_name.c_str());
        }
        locations[id].push_back(location);
    } else {
        locations[id] = std::list<LocEntry*>(1, location);
    }

    if (sentry->dp.as_host() != 0) {
        bindings->add_name_for_location(sentry->dp, port, id, Name::LOCATION);
        bindings->add_name_for_location(sentry->dp, port, location->portname, Name::PORT);
    }
    get_location_groups(location, sentry->groups,
                        boost::bind(&Authenticator::new_location4,
                                    this, sentry, location, _1));
}

void
Authenticator::new_location4(SwitchEntry *sentry, LocEntry *location, bool ignore)
{
    VLOG_DBG(lg, "Added location %s %"PRIx64":%"PRIu16".",
             namemanager->get_name(location->entry->name).c_str(),
             location->entry->dpport & DP_MASK,
             (uint16_t)(location->entry->dpport >> 48));
    unlock_status(&location->status);
    unlock_status(&sentry->status);
}


Authenticator::SwitchEntry*
Authenticator::new_switch(const datapathid& dp)
{
    while (true) {
        DPIDMap::iterator siter = switches_by_dp.find(dp.as_host());
        if (siter != switches_by_dp.end()) {
            if (siter->second.status.locked) {
                VLOG_DBG(lg, "Queuing new switch %"PRIx64" for switch entry.",
                         dp.as_host());
                siter->second.status.waiters.push_back(
                    boost::bind(&Authenticator::new_switch, this, dp));
                return NULL;
            }
            remove_switch(dp, true);
        } else {
            break;
        }
    }
    SwitchEntry& sw = switches_by_dp[dp.as_host()];
    sw.dp = dp;
    sw.status.locked = true;
    EmptyCb fail = boost::bind(&Authenticator::new_switch_name, this,
                               std::vector<std::string>(), &sw);
    switch_info.dpid = dp;
    if (!dirmanager->search_switches(switch_info, switchkey, "",
                                     boost::bind(&Authenticator::new_switch_name,
                                                 this, _1, &sw), fail))
    {
        fail();
    }
    return &sw;
}

void
Authenticator::new_switch_name(const std::vector<std::string>& names,
                               SwitchEntry *sentry)
{
    if (names.empty()) {
        if (sentry->dp.as_host() == 0) {
            new_switch2(namemanager->get_unauthenticated_name(), sentry);
            return;
        }
        const std::string& auth_name = namemanager->get_authenticated_name();
        EmptyCb fail = boost::bind(&Authenticator::new_switch2, this,
                                   auth_name, sentry);
        if (!dirmanager->get_discovered_switch_name(sentry->dp, true,
                                                    boost::bind(&Authenticator::new_switch2,
                                                                this, _1, sentry),
                                                    fail))
        {
            fail();
        }
    } else {
        new_switch2(names[0], sentry);
    }
}

void
Authenticator::new_switch2(const std::string& switch_name,
                           SwitchEntry *sentry)
{
    uint32_t id = namemanager->get_principal_id(switch_name,
                                                directory::SWITCH_PRINCIPAL,
                                                true, true);
    sentry->name = id;
    if (switches.find(id) != switches.end()) {
        if (id > NameManager::START_ID) {
            VLOG_WARN(lg, "Switch entry for name %s already exists.",
                      switch_name.c_str());
        }
        switches[id].push_back(sentry);
    } else {
        switches[id] = std::list<SwitchEntry*>(1, sentry);
    }

    if (sentry->dp.as_host() != 0) {
        bindings->add_name_for_location(sentry->dp, 0, id, Name::SWITCH);
        LogEntry to_log = LogEntry(app_name, LogEntry::ALERT, "{ss} joined the network.");
        to_log.setName(switch_name, Name::SWITCH, LogEntry::SRC);
        user_log->log(to_log);
    }
    get_switch_groups(sentry,
                      boost::bind(&Authenticator::new_switch3,
                                  this, sentry, _1));
}

void
Authenticator::new_switch3(SwitchEntry *sentry, bool ignore)
{
    unlock_status(&sentry->status);
}

void
Authenticator::remove_location(const datapathid& dp, uint16_t port,
                               uint64_t loc, bool poison)
{
    get_location(dp, loc, boost::bind(&Authenticator::remove_location2, this,
                                      dp, port, loc, poison, _1, _2));
}

void
Authenticator::remove_location2(const datapathid& dp, uint16_t port,
                                uint64_t loc, bool poison,
                                DPIDMap::iterator& siter,
                                DPPORTMap::iterator& dppiter)
{
    if (siter == switches_by_dp.end()) {
        VLOG_ERR(lg, "Cannot remove location %"PRIx64":%"PRIu16", "
                 "switch does not exist.",
                 dp.as_host(), port);
        return;
    } else if (dppiter == locations_by_dpport.end()) {
        VLOG_ERR(lg, "Cannot remove location %"PRIx64":%"PRIu16", does not exist.",
                 dp.as_host(), port);
        return;
    }

    remove_host(loc, Host_event::LOCATION_LEAVE, poison);

    if (loc == 0) {
        VLOG_ERR(lg, "Cannot remove location 0.");
        return;
    }

    SwitchEntry *sentry = &siter->second;
    LocEntry *lentry = &dppiter->second;
    bool not_found = true;

    for (std::list<LocEntry*>::iterator siter = sentry->locations.begin();
         siter != sentry->locations.end(); ++siter)
    {
        if (*siter == lentry) {
            sentry->locations.erase(siter);
            not_found = false;
            break;
        }
    }

    if (not_found) {
        VLOG_ERR(lg, "Location %"PRIx64":%"PRIu16" not found in switch.",
                 dp.as_host(), port);
    } else {
        not_found = true;
    }

    LocMap::iterator niter = locations.find(lentry->entry->name);
    if (niter != locations.end()) {
        for (std::list<LocEntry*>::iterator nliter = niter->second.begin();
             nliter != niter->second.end(); ++nliter)
        {
            if (*nliter == lentry) {
                not_found = false;
                niter->second.erase(nliter);
                if (niter->second.size() == 0) {
                    locations.erase(niter);
                }
                break;
            }
        }
        if (not_found) {
            VLOG_ERR(lg, "Could not find location %"PRIx64":%"PRIu16" by name %s.",
                     dp.as_host(), port,
                     namemanager->get_name(lentry->entry->name).c_str());
        }
    } else {
        VLOG_ERR(lg, "No name %s entry on location %"PRIx64":%"PRIu16" remove.",
                 namemanager->get_name(lentry->entry->name).c_str(),
                 dp.as_host(), port);
    }
    if (dp.as_host() != 0) {
        bindings->remove_name_for_location(dp, port, 0, Name::LOCATION);
    }
    decrement_entry(dppiter->second);
    locations_by_dpport.erase(dppiter);
}

void
Authenticator::remove_switch(const datapathid& dp, bool poison)
{
    DPIDMap::iterator siter = switches_by_dp.find(dp.as_host());
    if (siter == switches_by_dp.end()) {
        return;
    }
    SwitchEntry *sentry = &siter->second;
    if (sentry->status.locked) {
        sentry->status.waiters.push_back(
            boost::bind(&Authenticator::remove_switch, this, dp, poison));
        return;
    }

    std::list<LocEntry*> locations = sentry->locations;
    for (std::list<LocEntry*>::iterator liter = locations.begin();
         liter != locations.end(); ++liter)
    {
        uint64_t loc = (*liter)->entry->dpport;
        remove_location(dp, (uint16_t)(loc >> 48), loc, poison);
    }

    if (siter->first == 0) {
        VLOG_ERR(lg, "Cannot remove switch 0.");
        return;
    }

    SwitchMap::iterator niter = switches.find(sentry->name);
    bool not_found = true;
    if (niter != switches.end()) {
        for (std::list<SwitchEntry*>::iterator nliter = niter->second.begin();
             nliter != niter->second.end(); ++nliter)
        {
            if (*nliter == sentry) {
                not_found = false;
                niter->second.erase(nliter);
                if (niter->second.size() == 0) {
                    switches.erase(niter);
                }
                break;
            }
        }
        if (not_found) {
            VLOG_ERR(lg, "Could not find switch %"PRIx64" by name %s.",
                     dp.as_host(), namemanager->get_name(sentry->name).c_str());
        }
    } else {
        VLOG_ERR(lg, "No name %s entry on switch %"PRIx64" remove.",
                 namemanager->get_name(sentry->name).c_str(), dp.as_host());
    }

    if (sentry->dp.as_host() != 0) {
        bindings->remove_name_for_location(sentry->dp, 0, 0, Name::SWITCH);
        LogEntry to_log = LogEntry(app_name, LogEntry::ALERT, "{ss} left the network.");
        to_log.setName(namemanager->get_name(sentry->name).c_str(),
                       Name::SWITCH, LogEntry::SRC);
        user_log->log(to_log);
    }
    decrement_entry(siter->second);
    switches_by_dp.erase(siter);
}

void
Authenticator::modify_sw_loc_group_ref(SwitchEntry &swentry,
                                       uint32_t cname,
                                       directory::Group_Type gtype)
{
    modify_sw_loc_group(&swentry, cname, gtype);
}

void
Authenticator::modify_sw_loc_group(SwitchEntry *swentry,
                                   uint32_t cname,
                                   directory::Group_Type gtype)
{
    if (swentry == NULL) {
        return;
    }

    if (cname != NameManager::UNKNOWN_ID) {
        if (gtype == directory::SWITCH_PRINCIPAL_GROUP) {
            std::list<uint32_t>::iterator pos;
            if (!contains_group(swentry->groups, cname, pos)) {
                return;
            }
        } else {
            std::vector<uint32_t>::iterator pos;
            for (std::list<LocEntry*>::iterator lentry = swentry->locations.begin();
                 lentry != swentry->locations.end(); ++lentry)
            {
                if (contains_group((*lentry)->entry->groups, cname, pos)) {
                    swentry->status.locked = true;
                    modify_sw_loc_group2(swentry, lentry, cname,
                                         true, NULL, true);
                    break;
                }
            }
            return;
        }
    }

    swentry->status.locked = true;
    get_switch_groups(swentry,
                      boost::bind(&Authenticator::modify_sw_loc_group2,
                                  this, swentry, swentry->locations.begin(),
                                  0, false, (LocEntry*)NULL, _1));
}

void
Authenticator::modify_sw_loc_group2(SwitchEntry *swentry,
                                    std::list<LocEntry*>::iterator& lentry,
                                    uint32_t group, bool group_change,
                                    LocEntry *unlock, bool success)
{
    if (unlock != NULL) {
        unlock_status(&unlock->status);
    }

    std::vector<uint32_t>::iterator pos;
    for (; lentry != swentry->locations.end(); ++lentry) {
        LocEntry *location = *lentry;
        if (!group_change || contains_group(location->entry->groups, group, pos)) {
            location->status.locked = true;
            ++lentry;
            get_location_groups(location, swentry->groups,
                                boost::bind(&Authenticator::modify_sw_loc_group2,
                                            this, swentry, lentry, group,
                                            group_change, location, _1));
            return;
        }
    }

    unlock_status(&swentry->status);
}

void
Authenticator::modify_location_group(DPIDMap::iterator& siter,
                                     DPPORTMap::iterator& dppiter)
{
    if (siter == switches_by_dp.end()) {
        return;
    } else if (dppiter == locations_by_dpport.end()) {
        return;
    }

    siter->second.status.locked = true;
    dppiter->second.status.locked = true;

    get_location_groups(&dppiter->second, siter->second.groups,
                        boost::bind(&Authenticator::modify_location_groups2,
                                    this, &siter->second, &dppiter->second, _1));
}

void
Authenticator::modify_location_groups2(SwitchEntry *swentry,
                                       LocEntry *lentry, bool success)
{
    unlock_status(&lentry->status);
    unlock_status(&swentry->status);
}

void
Authenticator::modify_host_group(HostEntry& hentry, uint32_t cname)
{
    if (cname != NameManager::UNKNOWN_ID) {
        std::vector<uint32_t>::iterator pos;
        if (!contains_group(hentry.entry->groups, cname, pos)) {
            return;
        }
    }

    hentry.status.locked = true;
    get_host_groups(&hentry,
                    boost::bind(&Authenticator::unlock_bool_status,
                                this, &hentry.status, _1));

}

void
Authenticator::modify_user_group(UserEntry& uentry, uint32_t cname)
{
    if (cname != NameManager::UNKNOWN_ID) {
        std::vector<uint32_t>::iterator pos;
        if (!contains_group(uentry.entry->groups, cname, pos)) {
            return;
        }
    }

    uentry.status.locked = true;
    get_user_groups(&uentry,
                    boost::bind(&Authenticator::unlock_bool_status,
                                this, &uentry.status, _1));
}

void
Authenticator::unlock_bool_status(UpdateStatus *status, bool ignore)
{
    unlock_status(status);
}


void
Authenticator::modify_addr_group(DLEntry& dlentry, uint32_t cname, uint32_t nwmask,
                                 directory::Group_Type gtype, bool group_change)
{
    if (dlentry.nwentries.empty()) {
        return;
    }
    if (!group_change) {
        if (gtype == directory::DLADDR_GROUP) {
            dlentry.status.locked = true;
            boost::function<void(const std::list<uint32_t>&, bool)> cb =
                boost::bind(&Authenticator::modify_addr_group2,
                            this, _1, &dlentry, dlentry.nwentries.begin(), 0,
                            0, false, _2);
            get_dladdr_groups(dlentry.dladdr, cb);
            return;
        } else if (nwmask == (~((uint32_t)0))) {
            DLNWMap::iterator nw = dlentry.nwentries.find(cname);
            if (nw != dlentry.nwentries.end()) {
                dlentry.status.locked = true;
                BoolCb unlock = boost::bind(&Authenticator::unlock_bool_status,
                                            this, &dlentry.status, _1);
                boost::function<void(const std::list<uint32_t>&)> cb =
                    boost::bind(&Authenticator::get_nwaddr_groups,
                                this, &nw->second, _1, unlock);
                get_dladdr_groups(dlentry.dladdr, cb);
            }
            return;
        }
    }

    std::vector<uint32_t>::iterator pos;

    for (DLNWMap::iterator nwentry = dlentry.nwentries.begin();
         nwentry != dlentry.nwentries.end(); ++nwentry)
    {
        bool modify = false;
        if (group_change) {
            modify = contains_group(*(nwentry->second.address_groups), cname, pos);
        } else {
            modify = (nwentry->first & nwmask) == cname;
        }
        if (modify) {
            dlentry.status.locked = true;
            boost::function<void(const std::list<uint32_t>&, bool)> cb =
                boost::bind(&Authenticator::modify_addr_group2,
                            this, _1, &dlentry, nwentry, cname,
                            nwmask, group_change, _2);
            get_dladdr_groups(dlentry.dladdr, cb);
            return;
        }
    }
}

void
Authenticator::modify_addr_group2(const std::list<uint32_t>& dlgroups,
                                  DLEntry *dlentry, DLNWMap::iterator& nw,
                                  uint32_t cname, uint32_t nwmask,
                                  bool group_change, bool success)
{
    std::vector<uint32_t>::iterator pos;
    for (; nw != dlentry->nwentries.end(); ++nw) {
        NWEntry *nwentry = &nw->second;
        bool modify = false;
        if (group_change) {
            modify = contains_group(*(nwentry->address_groups), cname, pos);
        } else {
            modify = (nw->first & nwmask) == cname;
        }
        if (modify) {
            ++nw;
            namemanager->increment_ids(dlgroups);
            get_nwaddr_groups(nwentry, dlgroups,
                              boost::bind(&Authenticator::modify_addr_group2,
                                          this, dlgroups, dlentry, nw, cname,
                                          nwmask, group_change, _1));
            return;
        }
    }

    namemanager->decrement_ids(dlgroups);
    unlock_status(&dlentry->status);
}


}
}
