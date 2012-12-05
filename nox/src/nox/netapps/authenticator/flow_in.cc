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

#include "flow_in.hh"

#include "vlog.hh"

namespace vigil {

static Vlog_module lg("flow_in");

Flow_in_event::Flow_in_event(const timeval& received_,
                             const Packet_in_event& pi,
                             const Flow& flow_)
    : Event(static_get_name()), active(true), received(received_),
      datapath_id(pi.datapath_id), flow(flow_), buf(pi.buf),
      total_len(pi.total_len), buffer_id(pi.buffer_id), reason(pi.reason),
      dst_authed(false), routed_to(NOT_ROUTED)
{ }

#ifdef TWISTED_ENABLED

template <>
PyObject*
to_python(const Location& location)
{
    PyObject *pylocation = PyDict_New();
    if (pylocation == NULL) {
        VLOG_ERR(lg, "Could not create Python dict for location.");
        Py_RETURN_NONE;
    }

    pyglue_setdict_string(pylocation, "dpport", to_python(location.dpport));
    pyglue_setdict_string(pylocation, "name", to_python(location.name));
    pyglue_setdict_string(pylocation, "groups", to_python_list(location.groups));
    return pylocation;
}

// collapses location into authed_location right now to save extra dictionary -
// should not do this?

template <>
PyObject*
to_python(const AuthedLocation& alocation)
{
    PyObject *pyalocation = to_python(*(alocation.location));
    if (pyalocation == Py_None) {
        return pyalocation;
    }
    pyglue_setdict_string(pyalocation, "last_active", to_python(alocation.last_active));
    pyglue_setdict_string(pyalocation, "idle_timeout", to_python(alocation.idle_timeout));
    return pyalocation;
}

template <>
PyObject*
to_python(const User& user)
{
    PyObject *pyuser = PyDict_New();
    if (pyuser == NULL) {
        VLOG_ERR(lg, "Could not create Python dict for user.");
        Py_RETURN_NONE;
    }
    pyglue_setdict_string(pyuser, "name", to_python(user.name));
    pyglue_setdict_string(pyuser, "groups", to_python_list(user.groups));
    return pyuser;
}

// collapses user into authed_user right now to save extra dictionary -
// should not do this?

template <>
PyObject*
to_python(const AuthedUser& auser)
{
    PyObject *pyauser = to_python(*(auser.user));
    if (pyauser == Py_None) {
        return pyauser;
    }
    pyglue_setdict_string(pyauser, "auth_time", to_python(auser.auth_time));
    pyglue_setdict_string(pyauser, "idle_timeout", to_python(auser.idle_timeout));
    pyglue_setdict_string(pyauser, "hard_timeout", to_python(auser.hard_timeout));
    return pyauser;
}

template <>
PyObject*
to_python(const Host& host)
{
    PyObject *pyhost = PyDict_New();
    if (pyhost == NULL) {
        VLOG_ERR(lg, "Could not create Python dict for host.");
        Py_RETURN_NONE;
    }
    pyglue_setdict_string(pyhost, "name", to_python(host.name));
    pyglue_setdict_string(pyhost, "groups", to_python_list(host.groups));
    pyglue_setdict_string(pyhost, "auth_time", to_python(host.auth_time));
    pyglue_setdict_string(pyhost, "last_active", to_python(host.last_active));
    pyglue_setdict_string(pyhost, "hard_timeout", to_python(host.hard_timeout));
    PyObject *pyusers = PyList_New(host.users.size());
    if (pyusers == NULL) {
        VLOG_ERR(lg, "Could not create user list for host.");
        Py_INCREF(Py_None);
        pyusers = Py_None;
    } else {
        std::list<AuthedUser>::const_iterator user = host.users.begin();
        for (uint32_t i = 0; user != host.users.end(); ++i, ++user) {
            if (PyList_SetItem(pyusers, i, to_python(*user)) != 0) {
                VLOG_ERR(lg, "Could not set user list in host.");
            }
        }
    }
    pyglue_setdict_string(pyhost, "users", pyusers);
    return pyhost;
}

template <>
PyObject*
to_python(const Flow_in_event::DestinationInfo& dinfo)
{
    PyObject *pydinfo = PyDict_New();
    if (pydinfo == NULL) {
        VLOG_ERR(lg, "Could not create Python dict for destination info.");
        Py_RETURN_NONE;
    }
    pyglue_setdict_string(pydinfo, "authed_location", to_python(dinfo.authed_location));
    pyglue_setdict_string(pydinfo, "allowed", to_python(dinfo.allowed));
    pyglue_setdict_string(pydinfo, "waypoints", to_python_list(dinfo.waypoints));
    pyglue_setdict_string(pydinfo, "rules", to_python_list(dinfo.rules));
    return pydinfo;
}

template <>
PyObject*
to_python(const Flow_in_event::DestinationList& dlist)
{
    PyObject *pydinfos = PyList_New(dlist.size());
    if (pydinfos == NULL) {
        VLOG_ERR(lg, "Could not create Python list for destinations.");
        Py_RETURN_NONE;
    }

    Flow_in_event::DestinationList::const_iterator dinfo = dlist.begin();
    for (uint32_t i = 0; dinfo != dlist.end(); ++i, ++dinfo) {
        if (PyList_SetItem(pydinfos, i, to_python(*dinfo)) != 0) {
            VLOG_ERR(lg, "Could not set destination info list.");
        }
    }
    return pydinfos;
}

PyObject*
route_source_to_python(const boost::shared_ptr<Location>& location)
{
    if (location == NULL) {
        Py_RETURN_NONE;
    }
    return to_python(location->dpport);
}

PyObject*
route_destinations_to_python(const std::vector<boost::shared_ptr<Location> >& dlist)
{
    PyObject *pydlist = PyList_New(dlist.size());
    if (pydlist == NULL) {
        VLOG_ERR(lg, "Could not create list for route destinations.");
        Py_RETURN_NONE;
    }

    std::vector<boost::shared_ptr<Location> >::const_iterator loc = dlist.begin();
    for (uint32_t i = 0; loc != dlist.end(); ++i, ++loc) {
        if (PyList_SetItem(pydlist, i, to_python((*loc)->dpport)) != 0) {
            VLOG_ERR(lg, "Could not set route destination list item.");
        }
    }
    return pydlist;
}

#endif

}
