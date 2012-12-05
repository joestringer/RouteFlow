#ifndef MOBILEDB_HH
#define MOBILEDB_HH  1

#include <iostream>

#include "component.hh"
#include "config.h"
#include "netinet++/ethernet.hh"
#include "netinet++/datapathid.hh"
#include "routeinstaller/network_graph.hh"
#include "wimaxwifihandover/wimaxmsg.hh"
#include "flow-mod-event.hh"
#include <string.h>
#include <pthread.h>
#include <map>
#include "hash_map.hh"
#include <time.h>

#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <xercesc/dom/DOM.hpp>
#include "openflow/openflow.h"
#include "snmp/snmptrap.hh"
#include "snmp/snmp.hh"
#include "snmp/snmp-message.hh"
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
	   /** \brief Database for the mapping between mobile Host and the associated AP
	    *
	    * Copyright (C) Stanford University, 2009.
	    * @author Te-Yuan Huang
	    * @date February 2009
	    */
	   class BindPoint{
		public:
		  datapathid dp;
		  uint16_t port;
		  struct timeval timestamp;

	          /** Provide switch/port.
	           */
		  friend bool operator<(const BindPoint& a, const BindPoint& b){
			  return (a.timestamp.tv_sec < b.timestamp.tv_sec) ||
                                                (a.timestamp.tv_sec == b.timestamp.tv_sec &&
                                                 a.timestamp.tv_usec < b.timestamp.tv_usec);
		  }
	          network::termination network_point()
	          {
		    return network::termination(dp, port);
	          }
	   };
	   /** \brief Entry of flow in database.
	    */
	   /*struct BindEntry
	   {
		   vector<BindPoint> dpList;
		   double timestamp;
	   };*/

	   struct streq {
		   bool operator()(string s1, string s2) const
		   {
			   return (s1 == s2);
		   }
	   };

	   struct strhash {
		   size_t operator()(const string& s) const
		   {
			   HASH_NAMESPACE::hash<const char*> h;
			   return h(s.c_str());
		   }
	   };

	   typedef boost::shared_ptr<BindPoint> BindPointPtr;
	   struct earlierEntry{
		   bool operator()(const BindPointPtr &a, const BindPointPtr &b){
			   return (a->timestamp.tv_sec < b->timestamp.tv_sec) ||
				   (a->timestamp.tv_sec == b->timestamp.tv_sec &&
				    a->timestamp.tv_usec < b->timestamp.tv_usec);
		   }
	   };

	   typedef list<BindPointPtr> BindPointPtrList;
	   typedef hash_map<uint32_t, BindPointPtr> LOCMAP;
	   typedef hash_map<uint64_t, LOCMAP> MDB;
	   //typedef list<BindEntryPtr> BindEntryList;

	   /** \brief C/C++ component to store database of flows.
	    * Store the flow entry when handling flow_mod_event from edge switches
	    * Delete the entry when flow_expried_event is triggered, or the periodcal check is issued
	    * Data structure: Two-Level of map.
	    * First level : <ip/mac, a map of associate flow>
	    * Second level: <flow hash code, a pointer to flowEntry>
	    *
	    */
	   class MobileDB :
		   public Component
	   {
		   public:
			   /** Constructor
			    * @param c context
			    */
			   MobileDB(const Context* c, const xercesc::DOMNode*);

			   /** Destructor
			    */
			   ~MobileDB();

			   /** Register handlers.
			    */
			   void configure(const Configuration* config);

			   /** Start the component.
			    */
			   void install()
			   {}

			   /** Handle flow expired
			    *  To remove flow from database
			    *  This event need to be enabled in openflow.cc
			    */
			   Disposition handle_snmp_host_event(const Event& e);

			   //Disposition handle_wimax_msg(const Event& e);
			   /** Print out the value inside a flow entry
			    *  @ param: shared_ptr to the FlowEntry
			    */
			   void print_entry(BindPoint* fe);

			   uint32_t hash_bind_entry(datapathid dp, uint16_t port);

			   /** Dump out all the entries is all of the tables
			    */
			   void dump_db(void);

			   /**
			    * List of Flow Entries inside the tables
			    */
			   MDB mobiledb;

			   bool set_max_map_size(int new_size);
			   BindPointPtrList BindPoints_of_host(ethernetaddr hostMac);
			   BindPointPtrList BindPoints_of_host_with_priority(ethernetaddr hostMac);
			   bool del_oldest_entry(uint64_t hostmac);
			   /** Get instance.
			    * @param ctxt context
			    * @param component reference to $1
			    */
			   static void getInstance(const container::Context*, MobileDB*& component);
		   private:
			   int MAX_MAP_SIZE;
			   void map_size_maintainance(uint64_t hostmac);
	   };
   }; //aplication namespace
};

#endif
