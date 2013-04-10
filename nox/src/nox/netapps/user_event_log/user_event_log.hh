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

#ifndef USER_EVENT_LOG_HH
#define USER_EVENT_LOG_HH 1

#include "component.hh"
#include "storage/storage.hh"
#include "bindings_storage/bindings_storage.hh" 
#include <string>
#include "log_entry.hh" 

namespace vigil {
namespace applications {

using namespace std;


// The following structures are internal helpers to encapsulate the state of
// a particular operation 

enum AddEntryState { READ_SRC_LOCNAMES, READ_DST_LOCNAMES, 
                     READ_SRC_NAMES,READ_DST_NAMES,
                     WRITE_MAIN_ENTRY,WRITE_NAMES }; 

struct AddEntryInfo { 
  AddEntryInfo(const storage::Query &skq, const storage::Query &dkq, 
        const storage::Query &slq, const storage::Query &dlq, 
        const NameList &sn, const NameList &dn):
                  src_key_query(skq), dst_key_query(dkq),
                  src_locname_query(slq), dst_locname_query(dlq), 
                  src_names(sn), dst_names(dn), 
                  cur_state(READ_SRC_LOCNAMES) {} 

  AddEntryInfo() { cur_state = WRITE_MAIN_ENTRY; } // for log_simple()  

  storage::Row log_row; 
  storage::Query src_key_query,dst_key_query,src_locname_query,dst_locname_query; 
  NameList src_names, dst_names; // filled in by Bindings_Storage query
  AddEntryState cur_state;
}; 
typedef boost::shared_ptr<AddEntryInfo> AddEntryInfo_ptr; 

// callback for applications that ask for a particular log entry
typedef boost::function<void(int64_t logid, int64_t ts, const string &app, 
            int level, const string &msg, const NameList &src_names,
            const NameList &dst_names)> Log_entry_callback;

struct GetEntryInfo {
  GetEntryInfo(int64_t id, Log_entry_callback cb): 
                logid(id),ts(0),level(LogEntry::INVALID),
                msg("no message") ,callback(cb) {} 
  int64_t logid; 
  int64_t ts; 
  int level; 
  string msg; 
  string app; 
  Log_entry_callback callback; 
  NameList src_names, dst_names;
}; 

typedef boost::shared_ptr<GetEntryInfo> GetEntryInfo_ptr; 

typedef boost::function<void(const list<int64_t> &)> Get_logids_callback; 

struct GetLogidsInfo {
  GetLogidsInfo(Get_logids_callback &cb): callback(cb) {} 
  list<int64_t> logids; 
  Get_logids_callback callback; 
} ; 
typedef boost::shared_ptr<GetLogidsInfo> GetLogidsInfo_ptr; 


typedef boost::function<void(const storage::Result &r)> Clear_log_callback;  


// for explanation of the user_event_log, see log_entry.hh

class User_Event_Log : 
  public container::Component {

public:

      // NDB table names
     static const string NAME_TABLE_NAME;
     static const string MAIN_TABLE_NAME;


     User_Event_Log(const container::Context* c,
                    const xercesc::DOMNode*)
        : Component(c), is_ready(false), next_log_id(1),
          max_num_entries(100),min_existing_logid(0) {
    }

    void configure(const container::Configuration*);
    void install(); 

    // simple log call that performs no name-lookup
    void log_simple(const string &app_name, LogEntry::Level level, 
                                                const string &msg);

    // main interface to add entries to the log.  The user_event_log 
    // will use the bindings_storage component to find what 
    // high-level names are currently associated with those
    // network identifiers, and add them to the message. 
    // see log_entry.hh for details on how the configuration
    // of 'entry' determines the resulting log message
    void log(const LogEntry &entry); 

    // interface to looking up log entries
    // the names associated with log entries are non-trivial 
    // to retrieve directly from NDB, so this wrapper helps.
    // The callback function can check if the level of the row
    // is LEVEL_INVALID 
    void get_log_entry(int64_t logid, Log_entry_callback &cb);

    // get the greatest possible logid value, helpful if you want to 
    // then ask for the most recent X log entries
    // NOTE: these values are "suggestions".  A call to get_log_entry
    // for a get_min_logid() <= logid <= get_max_logid() is likely, but 
    // not guarenteed to return a valid entry.  There is a race 
    // condition due to the asynchronous nature of the NDB
    int64_t get_max_logid() { return next_log_id - 1; } 
    int64_t get_min_logid() { return min_existing_logid; } 

    // finds all logids associated with a particular (name,type) pair.
    // For example ("bob",USER).  Results are returned as a list
    // to the provided callback function
    void get_logids_for_name(const string &name, Name::Type t,
                                    Get_logids_callback &cb); 

    // deletes the specified row
    void remove(int64_t logid, Clear_log_callback &cb); 
    void clear(Clear_log_callback &cb); 

    // see explanation of max_num_entries below
    void set_max_num_entries(int num) { 
      max_num_entries = num; 
    } 

    static void getInstance(const container::Context*, User_Event_Log *&);


private:
    storage::Async_storage* np_store;
    Bindings_Storage *b_store; 
    bool is_ready; 
    int64_t next_log_id;

    // if log contains more than this many entries, older entries
    // will be deleted until it does.  If this value is negative,
    // the size is unlimited
    int max_num_entries; 
    // updated when older entries are deleted to let us 
    // keep track of how many entries exist without querying NDB
    int64_t min_existing_logid; 

    void create_table();
    void drop_table();
    
    // helper functions for inserting log entries     
    void run_log_fsm(AddEntryInfo_ptr info); 
    void write_callback(const storage::Result &r,AddEntryInfo_ptr info);
    void get_names_cb(const NameList &names,AddEntryInfo_ptr info);
    bool init_main_row(storage::Row &log_entry, const string &app_name, 
          LogEntry::Level level, const string &msg); 
    void write_single_name_entry(AddEntryInfo_ptr info);
    void write_name_row(AddEntryInfo_ptr info, const Name &n, int dir);
    void merge_names(NameList &existing, const NameList &from_lookup);

    // helper functions for fetching log entries
    void read_main_cb(const storage::Result & result, const storage::Context & ctx, 
                      const storage::Row &row, GetEntryInfo_ptr info);
    void read_names_cb(const storage::Result & result, const storage::Context & ctx, 
                       const storage::Row &row, GetEntryInfo_ptr info);
    void finish_get_entry(GetEntryInfo_ptr info);
   
    // helper functions for getting logids associated with a name
    void get_logids_cb(const storage::Result & result, const storage::Context & ctx, 
                       const storage::Row &row, GetLogidsInfo_ptr info); 

    // helpers related to clearing all uel state
    void remove_cb1(const storage::Result &r,Clear_log_callback cb, int64_t logid); 
    void remove_cb2(const storage::Result &r, Clear_log_callback cb); 
    void internal_clear_cb(const storage::Result &r, int64_t cur_logid, 
      int retry_count, int64_t stop_logid, Clear_log_callback final_cb); 
    void internal_clear_finished(); 

    // enforces a cap on the max number of entries contained
    // in the UEL, removing entries in FIFO order if needed
    // This function is called every 
    void check_excess_entries(); 
};



} 
} 

#endif
