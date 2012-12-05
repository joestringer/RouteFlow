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

#ifndef GROUP_EVENT_HH
#define GROUP_EVENT_HH 1

#include <boost/noncopyable.hpp>
#include <string>

#include "event.hh"
#include "principal_types.hh"

/*
 * Group events.
 */

namespace vigil {

/*
 * Group rename event.
 */

struct Group_rename_event
    : public Event,
      boost::noncopyable
{
    Group_rename_event(applications::directory::Group_Type type_,
                       uint32_t id_, const std::string& oldname_,
                       const std::string& newname_);

    // -- only for use within python
    Group_rename_event() : Event(static_get_name()) { }

    static const Event_name static_get_name() {
        return "Group_rename_event";
    }

    applications::directory::Group_Type type;
    uint32_t     id;
    std::string  oldname;
    std::string  newname;
};

/*
 * Group delete event.
 */

struct Group_delete_event
    : public Event,
      boost::noncopyable
{
    Group_delete_event(applications::directory::Group_Type type_,
                       uint32_t id_);

    // -- only for use within python
    Group_delete_event() : Event(static_get_name()) { }

    static const Event_name static_get_name() {
        return "Group_delete_event";
    }

    applications::directory::Group_Type type;
    uint32_t id;
};

struct Group_change_event
    : public Event,
      boost::noncopyable
{
    enum Change_Type {
        ADD_PRINCIPAL,
        DEL_PRINCIPAL,
        ADD_SUBGROUP,
        DEL_SUBGROUP
    };

    // Constructor if change entity has an id.
    Group_change_event(applications::directory::Group_Type type_,
                       uint32_t group_id_, Change_Type change_type_,
                       uint32_t change_id_);

    // Constructor if change entity is represented as a string
    // (for add/del principal with group type == DLADDR or NWADDR group)
    Group_change_event(applications::directory::Group_Type type_,
                       uint32_t group_id_, Change_Type change_type_,
                       const std::string& change_name_);

    // -- only for use within python
    Group_change_event() : Event(static_get_name()) { }

    static const Event_name static_get_name() {
        return "Group_change_event";
    }

    applications::directory::Group_Type group_type;    // Group's type
    uint32_t     group_id;
    Change_Type  change_type;   // Type of change
    uint32_t     change_id;     // Entity added/deleted
    std::string  change_name;   // Entity added/deleted if not a Principal_Type
                                // (i.e. for  dladdrs and nwaddrs)
};

} // namespace vigil

#endif /* group_event.hh */
