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
#include "dso-deployer.hh"

#ifndef USE_LTDL
#include <dlfcn.h>
#endif

#include <boost/bind.hpp>
#include <boost/foreach.hpp>

#include "fault.hh"
#include "vlog.hh"
#include "xml-util.hh"

using namespace vigil;
using namespace std;
using namespace xercesc;

static Vlog_module lg("dso-deployer");

#ifdef USE_LTDL
static ::lt_dlhandle 
open_library(const char* library, const char** error_msg) {
    ::lt_dlhandle h = ::lt_dlopenext(library);
    *error_msg = h ? "" : ::lt_dlerror();
    return h;
}
#else
static void*
open_library(const char* library, const char** error_msg) {
    void* h = ::dlopen((string(library) + ".so").c_str(), 
                       RTLD_GLOBAL | RTLD_NOW);
    *error_msg = h ? "" : ::dlerror();
    return h;
}
#endif

DSO_deployer::DSO_deployer(Kernel* kernel, const list<string>& lib_dirs_)
    : Component(0), lib_dirs(lib_dirs_) {
    using namespace boost::filesystem;
  
#ifdef USE_LTDL
    /* Initialize preloaded symbol table */
    LTDL_SET_PRELOADED_SYMBOLS();

    /* Initialize the libtool dynamic library loading facilities */
    if (::lt_dlinit()) {
        throw runtime_error("lt_dlinit() failed: " + 
                            demangle_undefined_symbol(::lt_dlerror()));
    }

    if (!::lt_dlopen(0)) {
        throw runtime_error("lt_dlopen() for the main() failed: " + 
                            demangle_undefined_symbol(::lt_dlerror()));
    }
#else
    /* Initialize the dlopen() dynamic library loading facilities */
    if (!::dlopen(0, RTLD_NOW | RTLD_GLOBAL)) {
        throw runtime_error("dlopen() for the main() failed: " + 
                            demangle_undefined_symbol(::dlerror()));
    }
#endif

    list<path> description_files;
    BOOST_FOREACH(string directory, lib_dirs) {
        list<path> results = scan(directory);
        description_files.insert(description_files.end(), 
                                results.begin(), results.end());
    }

    BOOST_FOREACH(path p, description_files) {
        const string f = p.string();
        path directory = p;
        directory.remove_leaf();

        string error_msg;
        const DOMDocument* d =
            xml::load_document(COMPONENTS_CONFIGURATION_SCHEMA, f, error_msg);
        if (!d) {
            lg.err("Can't load and parse '%s': %s",
                   f.c_str(), error_msg.c_str());
            continue;
        }
        const DOMNode* c = xml::get_child_by_tag(d, "components");
        const DOMNodeList* l = c->getChildNodes();

        for (XMLSize_t j = 0; j < l->getLength(); ++j) {
            DOMNode* cc_xml = l->item(j);
            if (cc_xml->getNodeType() == DOMNode::ELEMENT_NODE) {
                try {
                    Component_context* ctxt =
                        new DSO_component_context(kernel, directory.string(),
                                                  cc_xml);
                    uninstalled_contexts[ctxt->get_name()] = ctxt;
                } catch (const bad_cast& e) {
                    /* Not a DSO component, skip. */
                    continue;
                }
            }
        }
    }

    /* Finally, register itself as a deployer responsible for DSO
       components. */
    kernel->attach_deployer(this);
}

DSO_deployer::~DSO_deployer() {

}

container::Component*
DSO_deployer::instantiate(Kernel* kernel, const Path_list& lib_search_paths,
                          const container::Context*, const xercesc::DOMNode*) {
    return new DSO_deployer(kernel, lib_search_paths);
}

void
DSO_deployer::configure(const container::Configuration*) {
        
}

void
DSO_deployer::install() {

}

DSO_deployer::Path_list 
DSO_deployer::get_search_paths() const {
    return lib_dirs;
}

DSO_component_context::DSO_component_context(Kernel* kernel,
                                             const string& home_path,
                                             DOMNode* description)
    : Component_context(kernel) {
    using namespace boost;
    using namespace xml;

    install_actions[DESCRIBED] = bind(&DSO_component_context::describe, this);
    install_actions[LOADED] = bind(&DSO_component_context::load, this);
    install_actions[FACTORY_INSTANTIATED] = 
        bind(&DSO_component_context::instantiate_factory, this);
    install_actions[INSTANTIATED] = 
        bind(&DSO_component_context::instantiate, this);
    install_actions[CONFIGURED] = bind(&DSO_component_context::configure, this);
    install_actions[INSTALLED] = 
        bind(&DSO_component_context::install, this);
    
    /* Determine the configuration */
    name = to_string(get_child_by_tag(description, "name")->getTextContent());

    const DOMNode* n = get_child_by_tag(description, "library");
    if (!n) {
        throw bad_cast();
    }

    this->home_path = home_path;
    library = to_string(n->getTextContent());

    if (library.length() > 3 && library.find(".so") == library.length() - 3) {
        lg.warn("Dropped an unneccessary '.so' suffix in a shared library "
                "file definition: %s", library.c_str());
        library = library.substr(0, library.size() - 3);
    }

    BOOST_FOREACH(DOMNode* n, get_children_by_tag(description, "dependency")) {
        const container::Component_name dep_name =
            to_string(xml::get_child_by_tag(n, "name")->getTextContent());
        dependencies.push_back(new Name_dependency(dep_name));
    }

    configuration = new Component_configuration(description, 
                                                kernel->get_arguments(name));
    xml_description = description;
}

void 
DSO_component_context::describe() {
    /* Dependencies were introduced in the constructor */
    current_state = DESCRIBED;
}

void 
DSO_component_context::load() {
    const char* error_msg;
    handle = open_library((home_path + library).c_str(), &error_msg);
    string error(demangle_undefined_symbol(error_msg));

    /* A little extra check for libtool build directory */
    if (!handle) {
        handle = 
            open_library((home_path + ".libs/" + library).c_str(), &error_msg);
        error = "'" + error + "' or '"+demangle_undefined_symbol(error_msg)+"'";
    }

    if (!handle) {
        current_state = ERROR;
        error_message = "Can't open a dynamic library: " + error;
    } else {
        current_state = LOADED;
    }
}

DSO_component_context::component_factory_function* 
DSO_component_context::find_factory_function(const char* name) const {
#ifdef USE_LTDL
    component_factory_function* f = 
        reinterpret_cast<component_factory_function*>(::lt_dlsym(handle, name));
#else
    component_factory_function* f = 
        reinterpret_cast<component_factory_function*>(::dlsym(handle, name));
#endif
    return f;
}

static const string replace(const string& s, const char c, const string& n) {
    string v = s;
    while (true) {
        string::size_type p = v.find(c, 0);
        if (p == string::npos) {
            return v;
        }
        
        v = v.replace(p, 1, n);
    }
}

void 
DSO_component_context::instantiate_factory() {
    component_factory_function* f = 0; 

    /* Prefer a factory function with the embedded component name, but if
       that's not found, default to one without the name. */    
    string function_with_component_name = 
        replace(library, '-', "_") + "_get_factory";

    f = find_factory_function(function_with_component_name.c_str()); 
    if (!f) { f = find_factory_function("get_factory"); }
    if (!f) {
        current_state = ERROR;
        error_message = library + " does not implement " + 
            function_with_component_name + "() nor get_factory() function";
        return;
    }
    
    factory = f();
    interface = factory->get_interface();
    current_state = FACTORY_INSTANTIATED;
}

void 
DSO_component_context::instantiate() {
    try {
        component = factory->instance(this, xml_description);
        current_state = INSTANTIATED;
    }
    catch (const std::exception& e) {
        error_message = e.what();
        current_state = ERROR;
    }
}

void 
DSO_component_context::configure() {
    try {
        component->configure(configuration);
        current_state = CONFIGURED;
    }
    catch (const std::exception& e) {
        error_message = e.what();
        current_state = ERROR;
    }
}

void 
DSO_component_context::install() {
    try {
        component->install();
        current_state = INSTALLED;
    }
    catch (const std::exception& e) {
        error_message = e.what();
        current_state = ERROR;
    }
}

