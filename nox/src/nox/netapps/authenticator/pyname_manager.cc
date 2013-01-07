/* Copyright 2009 (C) Nicira, Inc.
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

#include "pyname_manager.hh"

#include "swigpyrun.h"
#include "pyrt/pycontext.hh"

namespace vigil {
namespace applications {

PyName_manager::PyName_manager(PyObject* ctxt)
    : namemanager(0)
{
    SwigPyObject* swigo = SWIG_Python_GetSwigThis(ctxt);
    if (!swigo || !swigo->ptr) {
        throw std::runtime_error("Unable to access Python context.");
    }

    c = ((PyContext*)swigo->ptr)->c;
}

void
PyName_manager::configure(PyObject* configuration) {
    c->resolve(namemanager);
}

void
PyName_manager::reset_names()
{
    namemanager->reset_names();
}

uint32_t
PyName_manager::get_principal_id(const std::string& name,
                                 uint32_t ptype,
                                 bool increment, bool create)
{
    return namemanager->get_principal_id(name,
                                         (directory::Principal_Type) ptype,
                                         increment, create);
}

uint32_t
PyName_manager::get_group_id(const std::string& name,
                             uint32_t gtype,
                             bool increment, bool create)
{
    return namemanager->get_group_id(name,
                                     (directory::Group_Type) gtype,
                                     increment, create);
}

void
PyName_manager::increment_id(uint32_t id)
{
    namemanager->increment_id(id);
}

void
PyName_manager::decrement_id(uint32_t id)
{
    namemanager->decrement_id(id);
}

std::string
PyName_manager::get_name(uint32_t id)
{
    return namemanager->get_name(id);
}

bool
PyName_manager::get_principal_type(uint32_t id, uint32_t& ptype)
{
    return namemanager->get_principal_type(id,
                                           (directory::Principal_Type&) ptype);
}

bool
PyName_manager::get_group_type(uint32_t id, uint32_t& gtype)
{
    return namemanager->get_group_type(id, (directory::Group_Type&) gtype);
}

void
PyName_manager::rename_principal(const std::string& oldname,
                                 const std::string& newname,
                                 uint32_t ptype)
{
    namemanager->rename_principal(oldname,
                                  newname,
                                  (directory::Principal_Type) ptype);
}

void
PyName_manager::rename_group(const std::string& oldname,
                             const std::string& newname,
                             uint32_t gtype)
{
    namemanager->rename_group(oldname,
                              newname,
                              (directory::Group_Type) gtype);
}

void
PyName_manager::delete_id(uint32_t id)
{
    namemanager->delete_id(id);
}

}
}
