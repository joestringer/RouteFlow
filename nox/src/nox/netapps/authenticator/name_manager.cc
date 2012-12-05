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
#include "name_manager.hh"

#include <boost/bind.hpp>
#include "vlog.hh"

// seconds after which deleted principal id will be deallocated

#define ID_TIMEOUT             300

#define UNAUTHENTICATED_NAME   "discovered;unauthenticated"
#define AUTHENTICATED_NAME     "discovered;authenticated"
#define UNKNOWN_NAME           "discovered;unknown"

namespace vigil {
namespace applications {

static Vlog_module lg("name_manager");

const uint32_t NameManager::UNAUTHENTICATED_ID;
const uint32_t NameManager::AUTHENTICATED_ID;
const uint32_t NameManager::UNKNOWN_ID;
const uint32_t NameManager::UNCREATED_ID;
const uint32_t NameManager::START_ID;

// Mangling suffixes

static const char *switch_s    = "_s";
static const char *location_s  = "_l";
static const char *host_s      = "_h";
static const char *user_s      = "_u";

static const char *switch_gs   = "_sg";
static const char *location_gs = "_lg";
static const char *host_gs     = "_hg";
static const char *user_gs     = "_ug";
static const char *dladdr_gs   = "_dg";
static const char *nwaddr_gs   = "_ng";

static const char *unknown_s   = "_u";
static const char *empty_s     = "";

static
inline
const char *
get_suffix(directory::Principal_Type ptype)
{
    switch (ptype) {
    case directory::SWITCH_PRINCIPAL:
        return switch_s;
    case directory::LOCATION_PRINCIPAL:
        return location_s;
    case directory::HOST_PRINCIPAL:
        return host_s;
    case directory::USER_PRINCIPAL:
        return user_s;
    default:
        VLOG_DBG(lg, "Cannot mangled unknown principal type %u.", ptype);
    }
    return unknown_s;
}

static
inline
const char *
get_suffix(directory::Group_Type gtype)
{
    switch (gtype) {
    case directory::SWITCH_PRINCIPAL_GROUP:
        return switch_gs;
    case directory::LOCATION_PRINCIPAL_GROUP:
        return location_gs;
    case directory::HOST_PRINCIPAL_GROUP:
        return host_gs;
    case directory::USER_PRINCIPAL_GROUP:
        return user_gs;
    case directory::DLADDR_GROUP:
        return dladdr_gs;
    case directory::NWADDR_GROUP:
        return nwaddr_gs;
    default:
        VLOG_ERR(lg, "Cannot mangle unknown grouptype %u.", gtype);
    }
    return unknown_s;
}

const std::string&
NameManager::get_unauthenticated_name()
{
    static const std::string name(UNAUTHENTICATED_NAME);
    return name;
}

const std::string&
NameManager::get_authenticated_name()
{
    static const std::string name(AUTHENTICATED_NAME);
    return name;
}

const std::string&
NameManager::get_unknown_name()
{
    static const std::string name(UNKNOWN_NAME);
    return name;
}

NameManager::NameManager(const container::Context *c, const xercesc::DOMNode*)
    : Component(c), counter(START_ID)
{
    reset_names();
}

void
NameManager::getInstance(const container::Context* ctxt, NameManager*& manager)
{
    manager = dynamic_cast<NameManager*>
        (ctxt->get_by_interface(container::Interface_description
                                (typeid(NameManager).name())));
}

void
NameManager::reset_names()
{
    names.clear();
    ids.clear();
    names[UNAUTHENTICATED_NAME] = UNAUTHENTICATED_ID;
    ids[UNAUTHENTICATED_ID] = IDEntry(1, UNAUTHENTICATED_NAME, empty_s);
    names[AUTHENTICATED_NAME] = AUTHENTICATED_ID;
    ids[AUTHENTICATED_ID] = IDEntry(1, AUTHENTICATED_NAME, empty_s);
    names[UNKNOWN_NAME] = UNKNOWN_ID;
    ids[UNKNOWN_ID] = IDEntry(1, UNKNOWN_NAME, empty_s);
    counter = START_ID;
}

uint32_t
NameManager::get_principal_id(const std::string& name,
                              directory::Principal_Type ptype, bool increment,
                              bool create)
{
    NameMap::iterator name_entry = names.find(name);
    if (name_entry != names.end() && name_entry->second < START_ID) {
        return name_entry->second;
    }

    return get_id(name, get_suffix(ptype), increment, create);
}

uint32_t
NameManager::get_group_id(const std::string& name, directory::Group_Type gtype,
                          bool increment, bool create)
{
    if (name == UNKNOWN_NAME) {
        return UNKNOWN_ID;
    }

    return get_id(name, get_suffix(gtype), increment, create);
}

uint32_t
NameManager::get_id(const std::string& name, const char *suffix, bool increment,
                    bool create)
{
    std::string mangled = name + suffix;

    NameMap::const_iterator found = names.find(mangled);
    if (found != names.end()) {
        uint32_t id = found->second;
        if (increment) {
            ++(ids[id].refcount);
        }
        return id;
    } else if (!create) {
        return UNCREATED_ID;
    }

    uint32_t loop = counter;
    do {
        if (ids.find(counter) == ids.end()) {
            names[mangled] = counter;
            ids[counter] = IDEntry(increment ? 1 : 0, name, suffix);
            if (counter == UINT32_MAX) {
                counter = START_ID;
                return UINT32_MAX;
            }
            return counter++;
        }
        if (counter == UINT32_MAX) {
            counter = START_ID;
        } else {
            ++counter;
        }
    } while (loop != counter);

    VLOG_ERR(lg, "No more name IDs to allocate, returning UNKNOWN_ID.");
    return UNKNOWN_ID;
}

void
NameManager::increment_id(uint32_t id)
{
    if (id < START_ID) {
        return;
    }

    IDMap::iterator entry = ids.find(id);
    if (entry == ids.end()) {
        VLOG_WARN(lg, "ID %"PRIu32" does not exist in IDMap to increment.", id);
        return;
    }

    // check for MAX?
    ++entry->second.refcount;
}

void
NameManager::increment_ids(const std::vector<uint32_t>& ids)
{
    for (std::vector<uint32_t>::const_iterator iter = ids.begin();
         iter != ids.end(); ++iter)
    {
        increment_id(*iter);
    }
}

void
NameManager::increment_ids(const std::list<uint32_t>& ids)
{
    for (std::list<uint32_t>::const_iterator iter = ids.begin();
         iter != ids.end(); ++iter)
    {
        increment_id(*iter);
    }
}

void
NameManager::decrement_id(uint32_t id)
{
    decrement_id(id, false);
}

void
NameManager::decrement_id(uint32_t id, bool delete_if_zero)
{
    if (id < START_ID) {
        return;
    }

    IDMap::iterator id_entry = ids.find(id);
    if (id_entry == ids.end()) {
        VLOG_WARN(lg, "ID %"PRIu32" does not exist in IDMap to decrement.", id);
    } else if (id_entry->second.refcount == 0) {
        VLOG_WARN(lg, "ID %"PRIu32" already at refcount 0 - cannot decrement.", id);
    } else if ((--(id_entry->second.refcount)) == 0) {
        NameMap::iterator name_entry =
            names.find(id_entry->second.name + id_entry->second.suffix);
        if (name_entry == names.end() || name_entry->second != id) {
            VLOG_DBG(lg, "Deleting name-id pair %s %"PRIu32".",
                     id_entry->second.name.c_str(), id);
            ids.erase(id_entry);
        } else if (delete_if_zero) {
            delete_id(id);
        }
    }
}

void
NameManager::decrement_ids(const std::vector<uint32_t>& ids)
{
    for (std::vector<uint32_t>::const_iterator iter = ids.begin();
         iter != ids.end(); ++iter)
    {
        decrement_id(*iter);
    }
}

void
NameManager::decrement_ids(const std::list<uint32_t>& ids)
{
    for (std::list<uint32_t>::const_iterator iter = ids.begin();
         iter != ids.end(); ++iter)
    {
        decrement_id(*iter);
    }
}

const std::string&
NameManager::get_name(uint32_t id) const
{
    IDMap::const_iterator entry = ids.find(id);
    if (entry != ids.end()) {
        return entry->second.name;
    }
    VLOG_WARN(lg, "No name stored for id %"PRIu32", returning unknown name.", id);
    return get_unknown_name();
}

bool
NameManager::get_principal_type(uint32_t id, directory::Principal_Type& ptype) const
{
    IDMap::const_iterator entry = ids.find(id);
    if (entry == ids.end()) {
        return false;
    }
    const char *s = entry->second.suffix;
    if (s == switch_s) {
        ptype = directory::SWITCH_PRINCIPAL;
    } else if (s == location_s) {
        ptype = directory::LOCATION_PRINCIPAL;
    } else if (s == host_s) {
        ptype = directory::HOST_PRINCIPAL;
    } else if (s == user_s) {
        ptype = directory::USER_PRINCIPAL;
    } else {
        return false;
    }
    return true;
}

bool
NameManager::get_group_type(uint32_t id, directory::Group_Type& gtype) const
{
    IDMap::const_iterator entry = ids.find(id);
    if (entry == ids.end()) {
        return false;
    }
    const char *s = entry->second.suffix;
    if (s == switch_gs) {
        gtype = directory::SWITCH_PRINCIPAL_GROUP;
    } else if (s == location_gs) {
        gtype = directory::LOCATION_PRINCIPAL_GROUP;
    } else if (s == host_gs) {
        gtype = directory::HOST_PRINCIPAL_GROUP;
    } else if (s == user_gs) {
        gtype = directory::USER_PRINCIPAL_GROUP;
    } else if (s == dladdr_gs) {
        gtype = directory::DLADDR_GROUP;
    } else if (s == nwaddr_gs) {
        gtype = directory::NWADDR_GROUP;
    } else {
        return false;
    }
    return true;
}

void
NameManager::rename_principal(const std::string& oldname,
                              const std::string& newname,
                              directory::Principal_Type ptype)
{
    NameMap::iterator name_entry = names.find(oldname);
    if (name_entry != names.end() && name_entry->second < START_ID) {
        VLOG_ERR(lg, "Cannot rename reserved name.");
        return;
    }
    name_entry = names.find(newname);
    if (name_entry != names.end() && name_entry->second < START_ID) {
        VLOG_ERR(lg, "Cannot rename to reserved name.");
        return;
    }

    rename(oldname, newname, get_suffix(ptype));
}

void
NameManager::rename_group(const std::string& oldname,
                          const std::string& newname,
                          directory::Group_Type gtype)
{
    if (oldname == UNKNOWN_NAME || newname == UNKNOWN_NAME) {
        VLOG_ERR(lg, "Cannot rename with reserved name.");
        return;
    }
    rename(oldname, newname, get_suffix(gtype));
}

void
NameManager::rename(const std::string& oldname, const std::string& newname,
                    const char *suffix)
{
    NameMap::iterator name_entry = names.find(oldname + suffix);
    if (name_entry == names.end()) {
        return;
    }

    uint32_t id = name_entry->second;
    ids[id].name = newname;
    names.erase(name_entry);

    name_entry = names.find(newname + suffix);
    if (name_entry != names.end()) {
        VLOG_WARN(lg, "Overwriting old %s entry for rename.", newname.c_str());
        // make sure old id not timed out immediately
        increment_id(name_entry->second);
        timeval dec_timer = { ID_TIMEOUT, 0 };
        post(boost::bind(&NameManager::decrement_id, this, name_entry->second),
             dec_timer);
        name_entry->second = id;
    } else {
        names[newname + suffix] = id;
    }
}

void
NameManager::delete_id(uint32_t id)
{
    if (id < START_ID) {
        VLOG_ERR(lg, "Cannot delete reserved id %u.", id);
        return;
    }

    IDMap::iterator id_entry = ids.find(id);
    if (id_entry == ids.end()) {
        VLOG_ERR(lg, "ID %u already deleted.", id);
        return;
    }

    NameMap::iterator name_entry = names.find(id_entry->second.name
                                              + id_entry->second.suffix);
    if (name_entry == names.end()) {
        VLOG_ERR(lg, "ID %u already deleted.", id);
        return;
    }
    names.erase(name_entry);

    // make sure old id not timed out immediately
    ++(id_entry->second.refcount);
    timeval dec_timer = { ID_TIMEOUT, 0 };
    post(boost::bind(&NameManager::decrement_id, this, id), dec_timer);
}

}
}

REGISTER_COMPONENT(vigil::container::Simple_component_factory<vigil::applications::NameManager>,
                   vigil::applications::NameManager);
