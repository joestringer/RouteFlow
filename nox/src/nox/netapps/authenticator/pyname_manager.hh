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
#ifndef PYNAME_MANAGER_HH
#define PYNAME_MANAGER_HH 1

#include <Python.h>

#include "name_manager.hh"
#include "component.hh"

namespace vigil {
namespace applications {

class PyName_manager {
public:
    PyName_manager(PyObject*);

    void configure(PyObject*);

    void reset_names();

    uint32_t get_principal_id(const std::string& name,
                              uint32_t ptype,
                              bool increment, bool create);
    uint32_t get_group_id(const std::string& name,
                          uint32_t gtype,
                          bool increment, bool create);
    void increment_id(uint32_t id);
    void decrement_id(uint32_t id);

    std::string get_name(uint32_t id);

    bool get_principal_type(uint32_t id, uint32_t& ptype);
    bool get_group_type(uint32_t id, uint32_t& gtype);

    void rename_principal(const std::string& oldname, const std::string& newname,
                          uint32_t ptype);
    void rename_group(const std::string& oldname, const std::string& newname,
                      uint32_t gtype);

    void delete_id(uint32_t id);

private:
    NameManager *namemanager;
    container::Component* c;
};

}
}

#endif
