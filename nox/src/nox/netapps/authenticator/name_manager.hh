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
#ifndef NAME_MANAGER_HH
#define NAME_MANAGER_HH 1

#include <list>
#include <string>
#include <vector>

#include "component.hh"
#include "directory/principal_types.hh"
#include "hash_map.hh"

namespace vigil {
namespace applications {

class NameManager
    : public container::Component {

public:
    // Reserved principal IDs
    static const uint32_t UNAUTHENTICATED_ID = 0;
    static const uint32_t AUTHENTICATED_ID = 1;
    static const uint32_t UNKNOWN_ID = 2;
    static const uint32_t UNCREATED_ID = 3;
    static const uint32_t START_ID = 4;

    // Reserved principal name retrieval methods
    static const std::string& get_unauthenticated_name();
    static const std::string& get_authenticated_name();
    static const std::string& get_unknown_name();

    NameManager(const container::Context*, const xercesc::DOMNode*);
    NameManager() : Component(0) { }

    static void getInstance(const container::Context*, NameManager*&);

    void configure(const container::Configuration*) { };
    void install() { };

    void reset_names();

    uint32_t get_principal_id(const std::string& name,
                              directory::Principal_Type ptype,
                              bool increment, bool create);
    uint32_t get_group_id(const std::string& name,
                          directory::Group_Type gtype, bool increment,
                          bool create);

    void increment_id(uint32_t id);
    void increment_ids(const std::list<uint32_t>& ids);
    void increment_ids(const std::vector<uint32_t>& ids);

    void decrement_id(uint32_t id);
    void decrement_id(uint32_t id, bool delete_if_zero);
    void decrement_ids(const std::list<uint32_t>& ids);
    void decrement_ids(const std::vector<uint32_t>& ids);

    const std::string& get_name(uint32_t id) const;

    bool get_principal_type(uint32_t id, directory::Principal_Type& ptype) const;
    bool get_group_type(uint32_t id, directory::Group_Type& gtype) const;

    void rename_principal(const std::string& oldname, const std::string& newname,
                          directory::Principal_Type ptype);
    void rename_group(const std::string& oldname, const std::string& newname,
                      directory::Group_Type gtype);

    void delete_id(uint32_t id);

private:
    struct IDEntry {
        uint32_t refcount;
        std::string name;
        const char *suffix;

        IDEntry(uint32_t r, const std::string& n,
                const char *s)
            : refcount(r), name(n), suffix(s) { }
        IDEntry() : refcount(0), suffix(NULL) { }
        ~IDEntry() { }
    };

    typedef hash_map<std::string, uint32_t> NameMap;
    typedef hash_map<uint32_t, IDEntry> IDMap;

    NameMap names;
    IDMap ids;
    uint32_t counter;

    uint32_t get_id(const std::string& name, const char *suffix, bool increment,
                    bool create);
    void rename(const std::string& oldname, const std::string& newname,
                const char *suffix);
}; // class NameManager

}
}

#endif
