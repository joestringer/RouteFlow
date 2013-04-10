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
#include "deployer.hh"

#include "xml-util.hh"

using namespace std;
using namespace vigil;
using namespace vigil::container;

Deployer::~Deployer() { 

}

bool
Deployer::deploy(Kernel* kernel, const Component_name& name) {
    Component_name_context_map::iterator i = uninstalled_contexts.find(name);
    if (i == uninstalled_contexts.end()) {
        return false;
    }
    
    Component_context* ctxt = i->second;
    uninstalled_contexts.erase(i);
    
    kernel->install(ctxt, NOT_INSTALLED);
    return true;
}

const char*
Deployer::XML_DESCRIPTION = "meta.xml";

Deployer::Path_list
Deployer::scan(boost::filesystem::path p) {
    using namespace boost::filesystem;

    Path_list description_files;

    if (!exists(p)) {
        return description_files;
    }

    directory_iterator end;
    for (directory_iterator j(p); j != end; ++j) {
        try {
            if (!is_directory(j->status()) && 
                j->path().leaf() == XML_DESCRIPTION) {
                description_files.push_back(j->path());
                continue;
            }
            
            if (is_directory(j->status())) {
                Path_list result = scan(*j);
                description_files.insert(description_files.end(), 
                                         result.begin(), result.end());
            }
        } catch (...) {
            /* Ignore any directory browsing errors. */
        } 
    }

    return description_files;
}

Component_configuration::Component_configuration() {
}

Component_configuration::Component_configuration(xercesc::DOMNode* d,
                                            const Component_argument_list& args)
    : xml_description(d), arguments(args)
{
    using namespace vigil::container;

    name = xml::to_string(xml::get_child_by_tag(d, "name")->getTextContent());

    // TODO: parse keys
}

const string 
Component_configuration::get(const string& key) const {
    return kv[key];
}

const bool
Component_configuration::has(const string& key) const {
    return kv.find(key) != kv.end();
}

const list<string>
Component_configuration::keys() const {
    list<string> keys;
    
    for (hash_map<string, string>::iterator i = kv.begin(); 
         i != kv.end(); ++i) {
        keys.push_back(i->first);
    }
    
    return keys;
}

const Component_argument_list
Component_configuration::get_arguments() const {
    return arguments;
}
