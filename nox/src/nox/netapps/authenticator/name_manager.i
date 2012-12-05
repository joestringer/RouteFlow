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

%module "nox.netapps.authenticator.pynamemanager"

%{
#include "pyname_manager.hh"

using namespace vigil;
using namespace vigil::applications;
%}

%include "std_string.i"

%include "common-defs.i"

class NameManager {

public:
    // Reserved principal IDs
    static const uint32_t UNAUTHENTICATED_ID;
    static const uint32_t AUTHENTICATED_ID;
    static const uint32_t UNKNOWN_ID;
    static const uint32_t UNCREATED_ID;
    static const uint32_t START_ID;

    // Reserved principal name retrieval methods
    static const std::string& get_unauthenticated_name();
    static const std::string& get_authenticated_name();
    static const std::string& get_unknown_name();
};

%include "pyname_manager.hh"

%pythoncode
%{
    from nox.lib.core import Component

    class PyNameManager(Component):
        def __init__(self, ctxt):
            Component.__init__(self, ctxt)
            self.namemanager = PyName_manager(ctxt)
        
        def configure(self, configuration):
            self.namemanager.configure(configuration)

        def getInterface(self):
            return str(PyNameManager)
           
        def reset_names(self):
            self.namemanager.reset_names()

        def get_principal_id(self, name, ptype, increment, create):
            return self.namemanager.get_principal_id(name, ptype, increment, create)

        def get_group_id(self, name, gtype, increment, create):
            return self.namemanager.get_group_id(name, gtype, increment, create)

        def increment_id(self, id):
            self.namemanager.increment_id(id)

        def decrement_id(self, id):
            self.namemanager.decrement_id(id)

        def get_name(self, id):
            return self.namemanager.get_name(id)

        def get_principal_type(self, id, ptype):
            return self.namemanager.get_principal_type(id, ptype)

        def get_group_type(self, id, gtype):
            return self.namemanager.get_group_type(id, gtype)

        def rename_principal(self, oldname, newname, ptype):
            self.namemanager.rename_principal(oldname, newname, ptype)

        def rename_group(self, oldname, newname, gtype):
            self.namemanager.rename_group(oldname, newname, gtype)

        def delete_id(self, id):
            self.namemanager.delete_id(id)

    def getFactory():
        class Factory():
            def instance(self, context):
                return PyNameManager(context)

        return Factory()
%}
