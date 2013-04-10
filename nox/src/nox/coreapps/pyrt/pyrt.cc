/* Copyright 2008 (C) Nicira, Inc.
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
#include "pyrt.hh"

#include <signal.h>
#include <stdexcept>

#ifndef SWIGPYTHON
#include "swigpyrun.h"
#endif // SWIGPYTHON

#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>

#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "bootstrap-complete.hh"
#include "aggregate-stats-in.hh"
#include "desc-stats-in.hh"
#include "table-stats-in.hh"
#include "port-stats-in.hh"
#include "flow-removed.hh"
#include "flow-mod-event.hh"
#include "packet-in.hh"
#include "port-status.hh"
#include "pyevent.hh"
#include "pyglue.hh"
#include "shutdown-event.hh"

#include "dso-deployer.hh"
#include "fault.hh"
#include "pycomponent.hh"
#include "pycontext.hh"
#include "vlog.hh"
#include "xml-util.hh"

using namespace std;
using namespace vigil;
using namespace vigil::applications;
using namespace vigil::container;
using namespace xercesc;

static Vlog_module lg("pyrt");

namespace vigil {
namespace applications {

const string pretty_print_python_exception() {
    PyObject* ptype = 0;
    PyObject* pvalue = 0;
    PyObject* ptraceback = 0;

    if (!PyErr_Occurred()) {
        return "";
    }

    PyErr_Fetch(&ptype, &pvalue, &ptraceback);
    PyErr_Clear();

    assert(ptype);

    if (!pvalue) {
        pvalue = Py_None;
        Py_INCREF(pvalue);
    }

    if (!ptraceback) {
        ptraceback = Py_None;
        Py_INCREF(ptraceback);
    }

    /* Import the traceback module */
    PyObject* m = PyImport_ImportModule("traceback");
    if (!m) {
        PyErr_Clear();
        Py_XDECREF(ptype);
        Py_XDECREF(pvalue);
        Py_XDECREF(ptraceback);
        return "unable to import 'traceback' module and parse the exception";
    }
    
    /* d is borrowed from GetDict, don't DECREF */
    PyObject* d = PyModule_GetDict(m);
    if (!d){
        PyErr_Clear();
        Py_DECREF(m);
        Py_XDECREF(ptype);
        Py_XDECREF(pvalue);
        Py_XDECREF(ptraceback);
        return "unable to pull module dictionary from 'traceback' "
            "and parse the exception";
    }

    /* func is borrowed from PyDict_GetItemString, don't DECREF */
    PyObject* func = PyDict_GetItemString(d, "format_exception");
    if (!func){
        PyErr_Clear();
        Py_DECREF(m);
        Py_XDECREF(ptype);
        Py_XDECREF(pvalue);
        Py_XDECREF(ptraceback);
        return "unable to pull method 'format_exception' from 'traceback' "
            "and parse the exception";
    }

    PyObject* py_args = PyTuple_New(3);
    if (!py_args) {
        Py_DECREF(m);
        Py_XDECREF(ptype);
        Py_XDECREF(pvalue);
        Py_XDECREF(ptraceback);
        return "unable to construct a tuple parameter for 'format_exception'"
            " of 'traceback' and parse the exception";
    }

    /* PyTuple_SetItem steals the references */
    PyTuple_SetItem(py_args, 0, ptype);
    PyTuple_SetItem(py_args, 1, pvalue);
    PyTuple_SetItem(py_args, 2, ptraceback);

    PyObject* strings = PyObject_CallObject(func, py_args);

    Py_DECREF(py_args);
    Py_DECREF(m);

    if (!strings || !PyList_Check(strings)) {
        Py_XDECREF(strings);
        PyErr_Clear();
        return "'traceback' is unable to format the exception";
    }


    /* Combine the strings */
    string err_message;

    for (int i = 0; i < PyList_Size(strings); ++i) {
        if (!PyString_Check(PyList_GET_ITEM(strings, i))) {
            Py_DECREF(strings);
            return "'traceback' returned non-strings and was unable to "
                "format the exception";
        }

        const string s = string(PyString_AsString(PyList_GET_ITEM(strings, i)));
        err_message += demangle_undefined_symbol(s);
    }

    Py_DECREF(strings);

    return err_message;
}

}
}

static void convert_datapath_join(const Event& e, PyObject* proxy) {
    const Datapath_join_event& sfe 
                = dynamic_cast<const Datapath_join_event&>(e);

    pyglue_setattr_string(proxy, "datapath_id", to_python(sfe.datapath_id));
    pyglue_setattr_string(proxy, "n_tables",    to_python(sfe.n_tables));
    pyglue_setattr_string(proxy, "n_buffers",  to_python(sfe.n_buffers));
    pyglue_setattr_string(proxy, "capabilities", to_python(sfe.capabilities));
    pyglue_setattr_string(proxy, "actions",    to_python(sfe.actions));
    pyglue_setattr_string(proxy, "ports", to_python<vector<Port> >(sfe.ports));

    SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
    ((Event*)swigo->ptr)->operator=(e);
}

static void convert_table_stats_in(const Event& e, PyObject* proxy) {
    const Table_stats_in_event& tsi 
                = dynamic_cast<const Table_stats_in_event&>(e);

    pyglue_setattr_string(proxy, "datapath_id", to_python(tsi.datapath_id));
    pyglue_setattr_string(proxy, "tables"    , to_python<vector<Table_stats> >(tsi.tables));

    SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
    ((Event*)swigo->ptr)->operator=(e);
}

static void convert_aggregate_stats_in(const Event& e, PyObject* proxy) {
    const Aggregate_stats_in_event& asi 
                = dynamic_cast<const Aggregate_stats_in_event&>(e);

    pyglue_setattr_string(proxy, "datapath_id",  to_python(asi.datapath_id));
    pyglue_setattr_string(proxy, "packet_count", to_python(asi.packet_count));
    pyglue_setattr_string(proxy, "byte_count", to_python(asi.byte_count));
    pyglue_setattr_string(proxy, "flow_count", to_python(asi.flow_count));

    SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
    ((Event*)swigo->ptr)->operator=(e);
}

static void convert_desc_stats_in(const Event& e, PyObject* proxy) {
    const Desc_stats_in_event& dsi 
                = dynamic_cast<const Desc_stats_in_event&>(e);

    pyglue_setattr_string(proxy, "datapath_id",  to_python(dsi.datapath_id));
    pyglue_setattr_string(proxy, "mfr_desc", to_python(dsi.mfr_desc));
    pyglue_setattr_string(proxy, "hw_desc", to_python(dsi.hw_desc));
    pyglue_setattr_string(proxy, "sw_desc", to_python(dsi.sw_desc));
    pyglue_setattr_string(proxy, "dp_desc", to_python(dsi.dp_desc));
    pyglue_setattr_string(proxy, "serial_num", to_python(dsi.serial_num));

    SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
    ((Event*)swigo->ptr)->operator=(e);
}

static void convert_port_stats_in(const Event& e, PyObject* proxy) {
    const Port_stats_in_event& psi 
                = dynamic_cast<const Port_stats_in_event&>(e);

    pyglue_setattr_string(proxy, "datapath_id", to_python(psi.datapath_id));
    pyglue_setattr_string(proxy, "ports"    , to_python<vector<Port_stats> >(psi.ports));

    SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
    ((Event*)swigo->ptr)->operator=(e);
}

static void convert_datapath_leave(const Event&e, PyObject* proxy) {
    const Datapath_leave_event& dple = 
        dynamic_cast<const Datapath_leave_event&>(e);

    pyglue_setattr_string(proxy, "datapath_id", to_python(dple.datapath_id));

    SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
    ((Event*)swigo->ptr)->operator=(e);
}

static void convert_bootstrap_complete(const Event&e, PyObject* proxy) {
    SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
    ((Event*)swigo->ptr)->operator=(e);
}

static void convert_flow_removed(const Event& e, PyObject* proxy) {
    const Flow_removed_event& fre = dynamic_cast<const Flow_removed_event&>(e);

    pyglue_setattr_string(proxy, "cookie", to_python(fre.cookie));
    pyglue_setattr_string(proxy, "duration_sec", to_python(fre.duration_sec));
    pyglue_setattr_string(proxy, "duration_nsec", to_python(fre.duration_nsec));
    pyglue_setattr_string(proxy, "byte_count", to_python(fre.byte_count));
    pyglue_setattr_string(proxy, "packet_count", to_python(fre.packet_count));
    pyglue_setattr_string(proxy, "datapath_id", to_python(fre.datapath_id));
    assert(fre.get_flow());
    pyglue_setattr_string(proxy, "flow", to_python(*fre.get_flow()));

    SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
    ((Event*)swigo->ptr)->operator=(e);
}   

static void convert_flow_mod(const Event& e, PyObject* proxy) {
    const Flow_mod_event& fme = dynamic_cast<const Flow_mod_event&>(e);

    pyglue_setattr_string(proxy, "datapath_id", to_python(fme.datapath_id));
    pyglue_setattr_string(proxy, "flow_mod", to_python(*fme.get_flow_mod()));

    SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
    ((Event*)swigo->ptr)->operator=(e);
}

static void convert_packet_in(const Event& e, PyObject* proxy) {
    const Packet_in_event& pie = dynamic_cast<const Packet_in_event&>(e);

    pyglue_setattr_string(proxy, "in_port",     to_python(pie.in_port));
    pyglue_setattr_string(proxy, "buffer_id",   to_python(pie.buffer_id));
    pyglue_setattr_string(proxy, "total_len",   to_python(pie.total_len));
    pyglue_setattr_string(proxy, "reason",      to_python(pie.reason));
    pyglue_setattr_string(proxy, "datapath_id", to_python(pie.datapath_id));
    pyglue_setattr_string(proxy, "buf", to_python<boost::shared_ptr<Buffer> >
                          (pie.get_buffer()));

    SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
    ((Event*)swigo->ptr)->operator=(e);
}

static void convert_port_status(const Event& e, PyObject* proxy) {
    const Port_status_event& pse = dynamic_cast<const Port_status_event&>(e);

    pyglue_setattr_string(proxy, "reason", to_python(pse.reason));
    pyglue_setattr_string(proxy, "port",   to_python<Port>(pse.port));
    pyglue_setattr_string(proxy, "datapath_id", to_python(pse.datapath_id));

    SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
    ((Event*)swigo->ptr)->operator=(e);
}   

static void convert_shutdown(const Event& e, PyObject* proxy) {
    //const Shutdown_event& se = dynamic_cast<const Shutdown_event&>(e);

    SwigPyObject* swigo = SWIG_Python_GetSwigThis(proxy);
    ((Event*)swigo->ptr)->operator=(e);
}

PyRt::PyRt(const Context* c,
           const xercesc::DOMNode*)
    : Component(c), Deployer() {
    using namespace boost::filesystem;

    // Python is very grabby about SIGINT.  Py_Initialize() sets up a
    // handler for it by default, which can be disabled by using
    // Py_InitializeEx() instead and passing false.  But even if you
    // do that, loading the Python "signal" module sets up a handler
    // anyway.  The easiest way to deal with it is to save and restore
    // the SIGINT handler around Py_Initialize() and the initial
    // import of the signal module, so that's what we do.
    struct sigaction sa;
    sigaction(SIGINT, NULL, &sa);

    // Initialize Python
    Py_Initialize();    
    PySys_SetArgv(c->get_kernel()->argc, c->get_kernel()->argv);
    PyRun_SimpleString("import sys\n"
                       "pkgdatadir = '"PKGDATADIR"'\n"
                       "pkglibdir = '"PKGLIBDIR"'\n"
                       "sys.path.append('.')\n"
                       "sys.path.append(pkgdatadir)\n"
                       "sys.path.append(pkglibdir)\n"

                       // Let the Python script finish the
                       // initialization now that it can be found.
                       "from nox.coreapps.pyrt import init_python\n"
                       "init_python()\n"
                       );       
    if (PyErr_Occurred()) {
        throw runtime_error("Unable to initialize the Python runtime:\n" +
                            pretty_print_python_exception());
    }

    // Install our reactor right away, otherwise any script which
    // imports reactor will set the default reactor in stone.
    initialize_oxide_reactor();
    
    sigaction(SIGINT, &sa, NULL);

    // Fetch the library paths from the core DSO deployer
    DSO_deployer* dso_deployer = 
        dynamic_cast<DSO_deployer*>(c->get_by_name("built-in DSO deployer"));
    list<string> libdirs = dso_deployer->get_search_paths();

    // Find the Python components
    list<path> description_files;
    BOOST_FOREACH(string directory, libdirs) {
        Path_list results = scan(directory);
        description_files.insert(description_files.end(), 
                                 results.begin(), results.end());
    }

    BOOST_FOREACH(path p, description_files) {
        const string f = p.string();
        path directory = p;
        directory.remove_leaf();
        
        lg.dbg("Loading a component description file '%s'.", f.c_str());

        string error_msg;
        const DOMDocument* d =
            xml::load_document(COMPONENTS_CONFIGURATION_SCHEMA, f, error_msg);
        if (!d) {
            lg.err("Can't load and parse '%s': %s",
                   f.c_str(), error_msg.c_str());
            continue;
        }
        const DOMNode* n = xml::get_child_by_tag(d, "components");
        const DOMNodeList* l = n->getChildNodes();
        for (XMLSize_t j = 0; j < l->getLength(); ++j) {
            DOMNode* cc_xml = l->item(j);

            if (cc_xml->getNodeType() == DOMNode::ELEMENT_NODE) {
                try {
                    Component_context* ctxt =
                        new Python_component_context(c->get_kernel(),
                                                     c->get_name(),
                                                     directory.string(),cc_xml);
                    uninstalled_contexts[ctxt->get_name()] = ctxt;
                } catch (const bad_cast& e) {
                    /* Not a Python component, skip. */
                    continue;
                }
            }
        }
    }

    // Finally, register itself as a deployer responsible for Python
    // components.
    c->get_kernel()->attach_deployer(this);

    // Register the system event converters
    register_event_converter(Datapath_join_event::static_get_name(), 
                             &convert_datapath_join);
    register_event_converter(Datapath_leave_event::static_get_name(), 
                             &convert_datapath_leave);
    register_event_converter(Flow_removed_event::static_get_name(), 
                             &convert_flow_removed);
    register_event_converter(Flow_mod_event::static_get_name(), 
                             &convert_flow_mod);
    register_event_converter(Packet_in_event::static_get_name(), 
                             &convert_packet_in);
    register_event_converter(Port_status_event::static_get_name(), 
                             &convert_port_status);
    register_event_converter(Shutdown_event::static_get_name(), 
                             &convert_shutdown);
    register_event_converter(Bootstrap_complete_event::static_get_name(), 
                             &convert_bootstrap_complete);
    register_event_converter(Table_stats_in_event::static_get_name(), 
                             &convert_table_stats_in);
    register_event_converter(Port_stats_in_event::static_get_name(), 
                             &convert_port_stats_in);
    register_event_converter(Aggregate_stats_in_event::static_get_name(), 
                             &convert_aggregate_stats_in);
    register_event_converter(Desc_stats_in_event::static_get_name(), 
                             &convert_desc_stats_in);
}

void
PyRt::initialize_oxide_reactor()
{
    // Construct the pyoxidereactor "by hand" so that it can set itself
    // as the twisted reactor right away
    PyObject* m = PyImport_ImportModule("nox.coreapps.pyrt.pyoxidereactor");

    if (!m) {
        throw runtime_error("Could not import pyvigilreactor from "
                            "nox.coreapps.pyrt.pyoxidereactor:\n" +
                            pretty_print_python_exception());
    }
    PyObject* d = PyModule_GetDict(m);
    // d is borrowed from GetDict, don't DECREF

    if(!d){
        const string exception_msg = pretty_print_python_exception();
        Py_DECREF(m);
        throw runtime_error("Unable to pull module dictionary from "
                            "pyvigilreactor:\n" + exception_msg);
    }

    PyObject* func = PyDict_GetItemString(d, "getFactory");
    // func is borrowed from PyDict_GetItemString, don't DECREF

    if (!func) {
        const string exception_msg = pretty_print_python_exception();
        Py_DECREF(m);
        throw runtime_error("Unable to find pyvigilreactor class constructor:"
                            "\n" + exception_msg);
    }

    PyObject* pyf = PyObject_CallObject(func, 0);
    if (!pyf) {
        const string exception_msg = pretty_print_python_exception();
        Py_DECREF(m);
        throw runtime_error("Unable to instantiate a Python factory class:\n" +
                            exception_msg);
    }

    Py_DECREF(m);
    // pyf is only live object from here that needs to be DECREF'd ..

    PyObject* method = PyString_FromString("instance");
    if (!method) {
        const string exception_msg = pretty_print_python_exception();
        Py_DECREF(pyf);
        throw runtime_error("Unable to construct a 'instance' method name:\n" +
                            exception_msg);
    }

    PyObject* pyctxt = create_python_context(ctxt, this);
    PyObject* pyobj = PyObject_CallMethodObjArgs(pyf, method, pyctxt, 0);
    if (!pyobj) {
        const string exception_msg = pretty_print_python_exception();
        Py_DECREF(pyf);
        Py_DECREF(method);
        throw runtime_error("Unable to construct a Python component:\n" +
                            exception_msg);
    }

    Py_DECREF(pyf);
    Py_DECREF(method);

    // XXX We leak the reactor instance (stored in pyobj) be that's OK
    // since it functions as a singleton and lasts the duration of the
    // program
}

void 
PyRt::getInstance(const Context* ctxt, PyRt*& pyrt) {
    pyrt = dynamic_cast<PyRt*>
        (ctxt->get_by_interface(container::Interface_description
                                (typeid(PyRt).name())));
}

void
PyRt::configure(const Configuration*) {
        
}

void
PyRt::install() {

}

Python_event_manager::~Python_event_manager() {
    
}

void
Python_event_manager::register_event_converter(const Event_name& name,
                                             const Event_converter& converter) {
    if (converters.find(name) != converters.end()) {
        throw runtime_error("C++ to Python event converter " + name + 
                            " already registered.");
    }

    converters[name] = converter;
}

// --
// Helper function to grab the pyevent contstructor from the 
// vigil module.  Only want to do this once ..
// --
static
PyObject*
get_pyevent_ctor()
{
    PyObject* pname = PyString_FromString("nox.coreapps.pyrt.pycomponent");
    if (!pname) {
        throw runtime_error("unable to create a module string");
    }

    PyObject* pmod = PyImport_Import(pname);
    if (!pmod || !PyModule_Check(pmod)){
        Py_DECREF(pname);
        Py_XDECREF(pmod);
        throw runtime_error("unable to import pycomponent module");
    }
    Py_DECREF(pname);

    PyObject* pfunc = PyObject_GetAttrString(pmod, (char*)"pyevent");
    if (!pfunc || !PyCallable_Check(pfunc)) {
        Py_DECREF(pmod);
        Py_XDECREF(pfunc);
        throw runtime_error("unable to pull in a pyevent constructor");
    }
    Py_DECREF(pmod);

    return pfunc;
}

//-----------------------------------------------------------------------------
// XXX FIXME
//
// This is a horrid hack to handle pyevents going from C to python.  The
// problem is that swig does not provide a convenient way for creating a
// new wrapped object from C to pass into python.  Instead, we call into
// python to create the object, then dig through the return proxy to get
// the newly created object, and copy over the fired event.  Yuck!
//
// Hopefully we'll find a more elegant way to handle this ...
//
//-----------------------------------------------------------------------------
Disposition
Python_event_manager::call_python_handler(const Event& e, 
                                       boost::intrusive_ptr<PyObject>& callable)
{
    try {
        using namespace std;

        Co_critical_section critical;
        static PyObject* pfunc = get_pyevent_ctor(); // leaked
        
        // Call the PyEvent constructor in Python.
        PyObject* py_event = PyObject_CallObject(pfunc, 0);
        if (!py_event) {
            throw runtime_error("call_python_handler "
                                "unable to construct a PyEvent: " + 
                                pretty_print_python_exception());
        }
        
        SwigPyObject* swigo = SWIG_Python_GetSwigThis(py_event);
        if (!swigo || ((SwigPyObject*)swigo)->ptr == NULL) {
            Py_DECREF(py_event);   
            throw runtime_error("call_python_handler unable "
                                "to recover C++ object from PyEvent.");
        }
        
        // Copy over the C++ portions of the event, and set the python
        // attributes in the proxy object.
        try {
            if (converters.find(e.get_name()) == converters.end()) {
                throw runtime_error(e.get_name()+" has no C++ to Python event " 
                                    "converter.");
            }
            
            converters[e.get_name()](e, py_event);
        } catch (const exception& e) {
            Py_DECREF(py_event);
            throw;
        }

        PyObject* py_args = PyTuple_New(1);
        if (!py_args) {
            Py_DECREF(py_event);
            throw runtime_error("unable to create arg tuple");
        }
        
        if (PyTuple_SetItem(py_args, 0, py_event) != 0) {
            Py_DECREF(py_event);
            Py_DECREF(py_args);
            throw runtime_error("unable to put proxy in args tuple");
        }
        
        PyObject* py_ret = PyObject_CallObject(callable.get(), py_args);
        Py_DECREF(py_args);
        
        if (py_ret) {
            uint32_t ret = PyInt_AsLong(py_ret);
            Py_DECREF(py_ret);
            if (ret == STOP) {
                return STOP;
            } else if (ret != CONTINUE) {
                throw runtime_error("Python handler returned invalid "
                                    "Disposition.");
            }
        } else {
            throw runtime_error("unable to invoke a Python event handler:\n" +
                                pretty_print_python_exception());
        }
    }
    catch (const runtime_error& e) {
        vlog().log(vlog().get_module_val("pyrt"), Vlog::LEVEL_ERR, "%s",
                   e.what());
    }

    return CONTINUE;
}

PyObject*
Python_event_manager::create_python_context(const Context* ctxt, 
                                            container::Component* c)
{
    PyObject* m = PyImport_ImportModule("nox.coreapps.pyrt.pycomponent");
    if (!m) {
        throw runtime_error("Could not retrieve a Python context module:\n" +
                            pretty_print_python_exception());
    }

    PyContext* p = new PyContext(const_cast<Context*>(ctxt), c, this);
    swig_type_info* s = SWIG_TypeQuery("_p_vigil__applications__PyContext");
    if (!s) {
        //Py_DECREF(m);
        throw runtime_error("Could not find PyContext SWIG type_info:\n" +
                            pretty_print_python_exception());
    }

    PyObject* pyctxt = SWIG_Python_NewPointerObj(p, s, 0);
    Py_INCREF(pyctxt); // XXX needed?

    //Py_DECREF(m);

    return pyctxt;
}

Python_component_context::Python_component_context(Kernel* kernel, 
                                                   const Component_name& pyrt,
                                                   const std::string& home_path,
                                                  xercesc::DOMNode* description)
    : Component_context(kernel) {
    using namespace boost;
    using namespace xml;

    install_actions[DESCRIBED] = 
        bind(&Python_component_context::describe, this);
    install_actions[LOADED] = bind(&Python_component_context::load, this);
    install_actions[FACTORY_INSTANTIATED] = 
        bind(&Python_component_context::instantiate_factory, this);
    install_actions[INSTANTIATED] = 
        bind(&Python_component_context::instantiate, this);
    install_actions[CONFIGURED] = 
        bind(&Python_component_context::configure, this);
    install_actions[INSTALLED] = 
        bind(&Python_component_context::install, this);
    
    // Determine the configuration, including dependencies
    name = to_string(get_child_by_tag(description, "name")->getTextContent());
    if (!get_child_by_tag(description, "python")) {
        throw bad_cast();
    }

    this->home_path = home_path;

    BOOST_FOREACH(DOMNode* n, get_children_by_tag(description, "dependency")) {
        const container::Component_name dep_name =
            to_string(xml::get_child_by_tag(n, "name")->getTextContent());
        dependencies.push_back(new Name_dependency(dep_name));
    }

    // Add a depedency to the Python runtime itself
    dependencies.push_back(new Name_dependency(pyrt));
    
    configuration = new Component_configuration(description, 
                                                kernel->get_arguments(name));
    xml_description = description;
}

void 
Python_component_context::describe() {
    // Dependencies were already introduced in the constructor
    current_state = DESCRIBED;
}

void 
Python_component_context::load() {
    current_state = LOADED;
}

void 
Python_component_context::instantiate_factory() {
    current_state = FACTORY_INSTANTIATED;
}

void 
Python_component_context::instantiate() {
    try {
        PyComponent* p = new PyComponent(this, xml_description);
        component = p;
        interface = p->get_interface();
        current_state = INSTANTIATED;
    }
    catch (const std::runtime_error& e) {
        error_message = e.what();
        current_state = ERROR;
    }
}

void 
Python_component_context::configure() {
    try {
        component->configure(configuration);
        current_state = CONFIGURED;
    }
    catch (const std::runtime_error& e) {
        error_message = e.what();
        current_state = ERROR;
    }
}

void 
Python_component_context::install() {
    try {
        component->install();
        current_state = INSTALLED;
    }
    catch (const std::runtime_error& e) {
        error_message = e.what();
        current_state = ERROR;
    }
}

REGISTER_COMPONENT(container::Simple_component_factory<PyRt>, PyRt);
