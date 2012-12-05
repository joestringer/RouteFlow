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

#include "group_event.hh"

using namespace vigil::applications;

namespace vigil {

Group_rename_event::Group_rename_event(applications::directory::Group_Type type_,
                                       uint32_t id_, const std::string& oldname_,
                                       const std::string& newname_)
    : Event(static_get_name()), type(type_), id(id_), oldname(oldname_),
      newname(newname_)
{}

Group_delete_event::Group_delete_event(applications::directory::Group_Type type_,
                                       uint32_t id_)
    : Event(static_get_name()), type(type_), id(id_)
{}

// Constructor if change entity has an id.
Group_change_event::Group_change_event(applications::directory::Group_Type group_type_,
                                       uint32_t group_id_,
                                       Change_Type change_type_,
                                       uint32_t change_id_)
    : Event(static_get_name()), group_type(group_type_), group_id(group_id_),
      change_type(change_type_), change_id(change_id_), change_name("")
{}

// Constructor if change entity is represented as a string
// (for add/del principal with group type == DLADDR or NWADDR group)
Group_change_event::Group_change_event(applications::directory::Group_Type group_type_,
                                       uint32_t group_id_, Change_Type change_type_,
                                       const std::string& change_name_)
    : Event(static_get_name()), group_type(group_type_), group_id(group_id_),
      change_type(change_type_), change_id(0), change_name(change_name_)
{}

}
