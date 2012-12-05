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

#ifndef FLOW_IN_HH
#define FLOW_IN_HH 1

#include <boost/shared_ptr.hpp>
#include <list>
#include <vector>

#include "config.h"
#include "event.hh"
#include "flow.hh"
#include "hash_set.hh"
#include "packet-in.hh"
#include "pyrt/pyglue.hh"

namespace vigil {

struct Location {
    uint64_t dpport;
    uint32_t name;
    std::vector<uint32_t> groups;
};

struct AuthedLocation {
    boost::shared_ptr<Location> location;
    time_t last_active;
    uint32_t idle_timeout;
};

struct User {
    uint32_t name;
    std::vector<uint32_t> groups;
};

struct AuthedUser {
    boost::shared_ptr<User> user;
    time_t auth_time;
    uint32_t idle_timeout;
    uint32_t hard_timeout;
};

struct Host {
    uint32_t name;
    std::vector<uint32_t> groups;
    std::list<AuthedUser> users;
    time_t auth_time;
    time_t last_active;
    uint32_t hard_timeout;
};

struct Flow_in_event
    : public Event
{
    Flow_in_event(const timeval& received_,
                  const Packet_in_event& pi,
                  const Flow& flow_);

    Flow_in_event()
        : Event(static_get_name()) { }

    ~Flow_in_event() { }

    static const Event_name static_get_name() {
        return "Flow_in_event";
    }

    static const uint32_t NOT_ROUTED = UINT32_MAX - 1;
    static const uint32_t BROADCASTED = UINT32_MAX;

    struct DestinationInfo {
        AuthedLocation              authed_location;
        bool                        allowed;
        std::vector<uint32_t>       waypoints;
        hash_set<uint32_t>          rules;
    };

    typedef std::vector<DestinationInfo> DestinationList;

    // 'active' == true if flow can still be "acted" upon else it has been
    // consumed by some part of the system.

    bool                                      active;
    timeval                                   received;
    datapathid                                datapath_id;
    Flow                                      flow;
    boost::shared_ptr<Buffer>                 buf;
    size_t                                    total_len;
    uint32_t                                  buffer_id;
    uint8_t                                   reason;

    boost::shared_ptr<Host>                   src_host;
    AuthedLocation                            src_location;
    boost::shared_ptr<std::vector<uint32_t> > src_addr_groups;

    bool                                      dst_authed;
    boost::shared_ptr<Host>                   dst_host;
    DestinationList                           dst_locations;
    boost::shared_ptr<std::vector<uint32_t> > dst_addr_groups;

    boost::shared_ptr<Location>               route_source;
    std::vector<boost::shared_ptr<Location> > route_destinations;
    uint32_t                                  routed_to;

    Flow_in_event(const Flow_in_event&);
    Flow_in_event& operator=(const Flow_in_event&);

}; // class Flow_in_event

#ifdef TWISTED_ENABLED

template <>
PyObject*
to_python(const Location& location);

template <>
PyObject*
to_python(const AuthedLocation& alocation);

template <>
PyObject*
to_python(const User& user);

template <>
PyObject*
to_python(const AuthedUser& auser);

template <>
PyObject*
to_python(const Host& host);

template <>
PyObject*
to_python(const Flow_in_event::DestinationInfo& dinfo);

template <>
PyObject*
to_python(const Flow_in_event::DestinationList& dlist);

PyObject*
route_source_to_python(const boost::shared_ptr<Location>& location);

PyObject*
route_destinations_to_python(const std::vector<boost::shared_ptr<Location> >& dlist);

#endif

} // namespace vigil

#endif // FLOW_IN_HH
