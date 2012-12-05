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
%module "nox.netapps.directory.pydirmanager"

%{
#include "aggregate-stats-in.hh"
#include "desc-stats-in.hh"
#include "bootstrap-complete.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "echo-request.hh"
#include "flow-removed.hh"
#include "flow-mod-event.hh"
#include "packet-in.hh"
#include "port-stats-in.hh"
#include "port-status.hh"
#include "table-stats-in.hh"
#include "pyrt/pycontext.hh"
#include "pyrt/pyevent.hh"
#include "pyrt/pyglue.hh"

#include "group_event.hh"
#include "principal_event.hh"
#include "pydirmanager.hh"
using namespace vigil;
using namespace vigil::applications;
%}

%import "netinet/netinet.i"
%import "pyrt/event.i"

%include "common-defs.i"
%include "std_string.i"
%include "directory.i"
%include "pydirmanager.hh"

struct Principal_rename_event
    : public Event
{
    Principal_rename_event(vigil::applications::directory::Principal_Type type_,
                           uint32_t id_, const std::string& oldname_,
                           const std::string& newname_);

    // -- only for use within python
    Principal_rename_event();

    static const Event_name static_get_name();

    vigil::applications::directory::Principal_Type type;
    uint32_t     id;
    std::string  oldname;
    std::string  newname;

%pythoncode
%{
    def __str__(self):
        return 'Principal_rename_event '+ 'type: '+str(self.type) +\
               ' , oldname: ' + str(self.oldname) +\
               ' , newname: ' + str(self.newname) + ']'
%}

%extend {

    static void fill_python_event(const Event& e, PyObject* proxy) const 
    {
        const Principal_rename_event& pe = dynamic_cast<const Principal_rename_event&>(e);

        pyglue_setattr_string(proxy, "type", to_python((uint32_t)(pe.type)));
        pyglue_setattr_string(proxy, "id", to_python(pe.id));
        pyglue_setattr_string(proxy, "oldname", to_python(pe.oldname));
        pyglue_setattr_string(proxy, "newname", to_python(pe.newname));

        SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
        ((Event*)swigo->ptr)->operator=(e);
    }

    static void register_event_converter(PyObject *ctxt) {
        SwigPyObject* swigo = SWIG_Python_GetSwigThis(ctxt);
        if (!swigo || !swigo->ptr) {
            throw std::runtime_error("Unable to access Python context.");
        }
        
        vigil::applications::PyContext* pyctxt = 
            (vigil::applications::PyContext*)swigo->ptr;
        pyctxt->register_event_converter<Principal_rename_event>
            (&Principal_rename_event_fill_python_event);
    }
}

};

struct Principal_delete_event
    : public Event
{
    Principal_delete_event(vigil::applications::directory::Principal_Type type_,
                           uint32_t id_);

    // -- only for use within python
    Principal_delete_event();

    static const Event_name static_get_name();

    vigil::applications::directory::Principal_Type type;
    uint32_t id;

%pythoncode
%{
    def __str__(self):
        return 'Principal_delete_event '+ 'type: '+str(self.type) +\
               ' , id: ' + str(self.id) +']'
%}

%extend {

    static void fill_python_event(const Event& e, PyObject* proxy) const 
    {
        const Principal_delete_event& pd = dynamic_cast<const Principal_delete_event&>(e);

        pyglue_setattr_string(proxy, "type", to_python((uint32_t)(pd.type)));
        pyglue_setattr_string(proxy, "id", to_python(pd.id));

        SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
        ((Event*)swigo->ptr)->operator=(e);
    }

    static void register_event_converter(PyObject *ctxt) {
        SwigPyObject* swigo = SWIG_Python_GetSwigThis(ctxt);
        if (!swigo || !swigo->ptr) {
            throw std::runtime_error("Unable to access Python context.");
        }
        
        vigil::applications::PyContext* pyctxt = 
            (vigil::applications::PyContext*)swigo->ptr;
        pyctxt->register_event_converter<Principal_delete_event>
            (&Principal_delete_event_fill_python_event);
    }
}

};

struct Group_rename_event
    : public Event
{
    Group_rename_event(vigil::applications::directory::Group_Type type_,
                       uint32_t id_, const std::string& oldname_,
                       const std::string& newname_);

    // -- only for use within python
    Group_rename_event();

    static const Event_name static_get_name();

    vigil::applications::directory::Group_Type type;
    uint32_t     id;
    std::string  oldname;
    std::string  newname;

%pythoncode
%{
    def __str__(self):
        return 'Group_rename_event '+ 'type: '+str(self.type) +\
               ' , oldname: ' + str(self.oldname) +\
               ' , newname: ' + str(self.newname) + ']'
%}

%extend {

    static void fill_python_event(const Event& e, PyObject* proxy) const 
    {
        const Group_rename_event& ge = dynamic_cast<const Group_rename_event&>(e);

        pyglue_setattr_string(proxy, "type", to_python((uint32_t)(ge.type)));
        pyglue_setattr_string(proxy, "id", to_python(ge.id));
        pyglue_setattr_string(proxy, "oldname", to_python(ge.oldname));
        pyglue_setattr_string(proxy, "newname", to_python(ge.newname));

        SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
        ((Event*)swigo->ptr)->operator=(e);
    }

    static void register_event_converter(PyObject *ctxt) {
        SwigPyObject* swigo = SWIG_Python_GetSwigThis(ctxt);
        if (!swigo || !swigo->ptr) {
            throw std::runtime_error("Unable to access Python context.");
        }
        
        vigil::applications::PyContext* pyctxt = 
            (vigil::applications::PyContext*)swigo->ptr;
        pyctxt->register_event_converter<Group_rename_event>
            (&Group_rename_event_fill_python_event);
    }
}

};

struct Group_delete_event
    : public Event
{
    Group_delete_event(vigil::applications::directory::Group_Type type_,
                       uint32_t id_);

    // -- only for use within python
    Group_delete_event();

    static const Event_name static_get_name();

    vigil::applications::directory::Group_Type type;
    uint32_t id;

%pythoncode
%{
    def __str__(self):
        return 'Group_delete_event '+ 'type: '+str(self.type) +\
               ' , id: ' + str(self.id) + ']'
%}

%extend {

    static void fill_python_event(const Event& e, PyObject* proxy) const 
    {
        const Group_delete_event& ge = dynamic_cast<const Group_delete_event&>(e);

        pyglue_setattr_string(proxy, "type", to_python((uint32_t)(ge.type)));
        pyglue_setattr_string(proxy, "id", to_python(ge.id));

        SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
        ((Event*)swigo->ptr)->operator=(e);
    }

    static void register_event_converter(PyObject *ctxt) {
        SwigPyObject* swigo = SWIG_Python_GetSwigThis(ctxt);
        if (!swigo || !swigo->ptr) {
            throw std::runtime_error("Unable to access Python context.");
        }
        
        vigil::applications::PyContext* pyctxt = 
            (vigil::applications::PyContext*)swigo->ptr;
        pyctxt->register_event_converter<Group_delete_event>
            (&Group_delete_event_fill_python_event);
    }
}

};

struct Group_change_event
    : public Event
{
    enum Change_Type {
        ADD_PRINCIPAL,
        DEL_PRINCIPAL,
        ADD_SUBGROUP,
        DEL_SUBGROUP
    };

    // Constructor if change entity has an id.
    Group_change_event(vigil::applications::directory::Group_Type type_,
                       uint32_t group_id_, Change_Type change_type_,
                       uint32_t change_id_);

    // Constructor if change entity is represented as a string
    // (for add/del principal with group type == DLADDR or NWADDR group)
    Group_change_event(vigil::applications::directory::Group_Type type_,
                       uint32_t group_id_, Change_Type change_type_,
                       const std::string& change_name_);

    // -- only for use within python
    Group_change_event();

    static const Event_name static_get_name();

    vigil::applications::directory::Group_Type group_type;    // Group's type
    uint32_t     group_id;
    Change_Type  change_type;   // Type of change
    uint32_t     change_id;     // Entity added/deleted
    std::string  change_name;   // Entity added/deleted if not a Principal_Type
                                // (i.e. for  dladdrs and nwaddrs)
%pythoncode
%{
    def __str__(self):
        return 'Group_change_event '+ 'group_type: '+str(self.group_type) +\
               ' , group id: ' + str(self.group_id) +\
               ' , change type: ' + str(self.change_type) +\
               ' , change id: ' + str(self.change_id) +\
               ' , change name: ' + str(self.change_name) + ']'
%}

%extend {

    static void fill_python_event(const Event& e, PyObject* proxy) const 
    {
        const Group_change_event& gce = dynamic_cast<const Group_change_event&>(e);

        pyglue_setattr_string(proxy, "group_type", to_python((uint32_t)(gce.group_type)));
        pyglue_setattr_string(proxy, "group_id", to_python(gce.group_id));
        pyglue_setattr_string(proxy, "change_type", to_python((uint32_t)(gce.change_type)));
        pyglue_setattr_string(proxy, "change_id", to_python(gce.change_id));
        pyglue_setattr_string(proxy, "change_name", to_python(gce.change_name));

        SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
        ((Event*)swigo->ptr)->operator=(e);
    }

    static void register_event_converter(PyObject *ctxt) {
        SwigPyObject* swigo = SWIG_Python_GetSwigThis(ctxt);
        if (!swigo || !swigo->ptr) {
            throw std::runtime_error("Unable to access Python context.");
        }
        
        vigil::applications::PyContext* pyctxt = 
            (vigil::applications::PyContext*)swigo->ptr;
        pyctxt->register_event_converter<Group_change_event>
            (&Group_change_event_fill_python_event);
    }
}

};

%pythoncode
%{
    from nox.lib.core import Component

    class PyDirManager(Component):
        def __init__(self, ctxt):
            Component.__init__(self, ctxt)
            self.dm = PyDirectoryManager(ctxt)
        
        def configure(self, configuration):
            self.dm.configure(configuration)
            Principal_rename_event.register_event_converter(self.ctxt)
            Principal_delete_event.register_event_converter(self.ctxt)
            Group_rename_event.register_event_converter(self.ctxt)
            Group_delete_event.register_event_converter(self.ctxt)
            Group_change_event.register_event_converter(self.ctxt)

        def install(self):
            self.dm.install()

        def getInterface(self):
            return str(PyDirManager)

        def set_py_dm(self, dm_):
            return self.dm.set_py_dm(dm_)

        def set_create_dp(self, dp_):
            return self.dm.set_create_dp(dp_)

        def set_create_eth(self, eth_):
            return self.dm.set_create_eth(eth_)

        def set_create_ip(self, ip_):
            return self.dm.set_create_ip(ip_)
        
        def set_create_cidr(self, cidr_):
            return self.dm.set_create_cidr(cidr_)
        
        def set_create_cred(self, cred_):
            return self.dm.set_create_cred(cred_)

    def getFactory():
        class Factory():
            def instance(self, context):
                return PyDirManager(context)

        return Factory()
%}
