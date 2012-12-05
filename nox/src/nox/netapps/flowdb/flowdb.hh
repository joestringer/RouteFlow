#ifndef FLOWDB_HH
#define FLOWDB_HH  1

#include <iostream>

#include "component.hh"
#include "config.h"
#include "netinet++/ethernet.hh"
#include "netinet++/datapathid.hh"
#include "flow-mod-event.hh"
#include <string.h>
#include <pthread.h>
#include <map>
#include "hash_map.hh"
#include "topology/topology.hh"

#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <xercesc/dom/DOM.hpp>
#include "openflow/openflow.h"


#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"

#else
#include "vlog.hh"
#endif

#include "assert.hh"
#include "datapath-leave.hh"
#include "error-event.hh"
#include "flow-stats-in.hh"
#include "nox.hh"

using namespace std;
using namespace vigil::container;

namespace vigil {
   namespace applications {

	   /* for the type of Flowdb_event*/
	   enum FlowdbEvents{
                ADD,
                DELETE
           };
	   struct Flowdb_event : public Event
	   {
		   /** Constructor.
		    * Allocate memory for message.
		    * @param message message
		    * @param socket socket message is received with
		    */
		   Flowdb_event(int type_, bool exit_, datapathid dp_,
                                uint32_t srcip_,  uint32_t dstip_,
                                ethernetaddr srcmac_, ethernetaddr dstmac_);

		   /** Destructor.
		    */
		   ~Flowdb_event();

		   /** Empty constructor.
		    * For use within python.
		    */
		   Flowdb_event() : Event(static_get_name())
		   { }

		   /** Static name required in NOX.
		    */
		   static const Event_name static_get_name()
		   {
			   return "Flowdb_event";
		   }

		   /**
		    Defined by FlowdbEvents, ADD:0, DELETE:1
		    */
		   int type;

		   /**
		    Indicate whether this event is issued by the entry router or the exit router
		    */
		   bool exit;
		   /** Associated switch
                    */
                   datapathid dp;

                   /** information about the flow
                     */
                   uint32_t srcip;
                   uint32_t dstip;
                   ethernetaddr srcmac;
                   ethernetaddr dstmac;
	   };


	   /** \brief Status for periodically check.
	    *  when a flow entry stays in flowdb more than CHECK_INTERVEL,
	    *  then nox will issue a stats_request to openflow switches, and mark the entry as CHECKING
	    *  When nox get the confirm from switch, it will mark the entry as OK;
	    *  otherwise, the entry will remain be marked as CHECKING.
	    *  When next time nox checks for the entry, if nox found that it is marked as CHECKING,
	    *  nox will delete the entry, since it does not receive confirmation during CHECK_INTERVAL
	    */
	   enum FlowEntryStatus{
		OK,
		CHECKING
	   };
	   /** \brief Entry of flow in database.
	    */
	   struct FlowEntry
	   {
		   /** The whole ofp_mod_cmd sent to switch
		    */
		   boost::shared_array<char> flow_mod_cmd;
		   /** Associated switch
		    */
		   datapathid dp;

		   /** information about the flow
		     */
		   uint32_t srcip;
		   uint32_t dstip;
		   ethernetaddr srcmac;
		   ethernetaddr dstmac;
		   /**
		    * timestamp (unit: second)
		    */
		   struct timeval timestamp;

		   /**
		    *  OK or CHECKING, defined in FlowEntryStatus
		    */
		   int status;
		   bool exit;
	   };

	   typedef boost::shared_ptr<FlowEntry> FlowEntryPtr;
	   typedef hash_map<uint32_t, FlowEntryPtr> DB;
	   typedef hash_map<uint32_t, DB> IPTable;
	   typedef hash_map<uint64_t, DB> macTable;
	   typedef list<FlowEntryPtr> FlowEntryList;

	   /** \brief C/C++ component to store database of flows.
	    * Store the flow entry when handling flow_mod_event from edge switches
	    * Delete the entry when flow_expried_event is triggered, or the periodcal check is issued
	    * Data structure: Two-Level of map.
	    * First level : <ip/mac, a map of associate flow>
	    * Second level: <flow hash code, a pointer to flowEntry>
	    */
	   class FlowDB :
		   public Component
	   {
		   public:
			   /** Constructor
			    * @param c context
			    */
			   FlowDB(const Context* c, const xercesc::DOMNode*);

			   /** Destructor
			    */
			   ~FlowDB();


	                   /** Get instance.
			    * @param ctxt context
			    * @param component reference to flowdb
			    */
	                   static void getInstance(const container::Context*, FlowDB*& component);

			   void checkFlowEntry(void);
			   /** Register handlers.
			    */
			   void configure(const Configuration* config);

			   /** Start the component.
			    */
			   void install()
			   {}

			   //static void* cleanup(void* param);
			   Disposition handle_flow_stats_in(const Event& e);
			   /** Handle flow mod event and add associated ofp_mod_cmd to database tables
			    *  Broadcast messages will be discarded, and
			    *  Only event triggered from Edge Switches will be handled
			    */
			   Disposition handle_flow_mod(const Event& e);

			   /** Handle flow expired
			    *  To remove flow from database
			    *  This event need to be enabled in openflow.cc
			    */
			   Disposition handle_flow_removed(const Event& e);

			   /** Return list of flow associated with some mac destination.
			    *  Only return the information in Edge Switches
			    */
			   std::list<FlowEntryPtr> flowWithDst(ethernetaddr mac);

			   /** Return list of flow associated with some mac source.
			    *  Only return the information in Edge Switches
			    */
			   std::list<FlowEntryPtr> flowWithSrc(ethernetaddr mac);

			   /** Return list of flow associated with some ip destination.
			    *  Only return the information in Edge Switches
			    */
			   std::list<FlowEntryPtr> flowWithDst(uint32_t ip_dst);

			   /** Return list of flow associated with some ip source.
			    *  Only return the information in Edge Switches
			    */
			   std::list<FlowEntryPtr> flowWithSrc(uint32_t ip_src);

			   std::list<FlowEntryPtr> flowWithSrcDst(ethernetaddr src, ethernetaddr dst);

			   Flow create_flow_instance(FlowEntryPtr fe);
			   /** Return the hash value of one FlowEntry
			    *  @ param: shared_ptr to the FlowEntry
			    *  @ return: hashed value of datapathid and ofp_match inside the FlowEntry
			    */
			   uint32_t hash_flow_entry(const FlowEntryPtr fe);

			   /** Return the hash value of one FlowEntry
			    *  @ param: datapathid, ofp_match in the ofp_flow_mod message
			    *  @ return: hashed value of datapathid and ofp_match inside the FlowEntry
			    */
			   uint32_t hash_flow_entry(datapathid dp, ofp_match *ofm);

			   void print_flowEntry(FlowEntry* fe, string* msg);
			   /** Print out the value inside a flow entry
			    *  @ param: shared_ptr to the FlowEntry
			    */
			   void print_flowEntry(ofp_match* match, datapathid& dp);
			   void print_flowEntry(ofp_match* match, datapathid& dp, string* msg);
			   void print_flowEntry(FlowEntry* fe);

			   /** Delete flow entry in four databases whose ip/mac in ofp_match and datapath_id
			    *  @ param: match
			    *  @ param: datapath id
			    */
			   void delFlowEntry(ofp_match *match, datapathid dp);
			   //void delFlowEntry(uint32_t ip);
			   //void delFlowEntry(ethernetaddr mac);

			   /** Dump out all the entries is all of the tables
			    */
			   void dump_db(void);

			   long num_of_flows(void);
			   /**
			    * First-Level Map <destination ip, second-level map of flow>
			    */
			   IPTable dstip_table;
			   /**
			    * First-Level Map <source ip, second-level map of flow>
			    */
			   IPTable srcip_table;
			   /**
			    * First-Level Map <destination mac, second-level map of flow>
			    */
			   macTable dstmac_table;
			   /**
			    * First-Level Map <source mac, second-level map of flow>
			    */
			   macTable srcmac_table;
			   /**
			    * List of Flow Entries inside the tables
			    */
			   DB allFlow;
		   private:
			   /**
			    * Pointer to under topology, used to resolve internal/edge switch
			    */
			   Topology *topology;
			   /* read/write lock for tables in DB
			    */
		           //pthread_mutex_t db_lock;
			   //boost::mutex db_lock;
	   };
   }; //aplication namespace
};

#endif
