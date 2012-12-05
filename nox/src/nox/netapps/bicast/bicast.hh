#ifndef BICAST_HH
#define BICAST_HH  1

#include <iostream>

#include "component.hh"
#include "config.h"
#include "netinet++/ethernet.hh"
#include "netinet++/datapathid.hh"
#include "flow-mod-event.hh"
#include "authenticator/flow_in.hh"
#include <string.h>
#include <pthread.h>
#include <map>
#include "hash_map.hh"
#include "topology/topology.hh"
#include "flow.hh"
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <xercesc/dom/DOM.hpp>
#include "openflow/openflow.h"
#include "flowdb/flowdb.hh"
#include "mobiledb/mobiledb.hh"
#include "routing/routing.hh"
#include "routeinstaller/routeinstaller.hh"
#include "routeinstaller/network_graph.hh"
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
#include "storage/storage.hh"
#include "bindings_storage/bindings_storage.hh"
using namespace std;
using namespace vigil::container;

namespace vigil {
   namespace applications {
	   struct bicast_msg
	   {
		   /** BiCast subtype.
		    *  0: leave
		    *  1: join
		    */
		   //uint8_t type;
		   /** Host mac address.
		    */
		   uint64_t host_mac;
	   }__attribute__ ((packed));

	   class BiCast :
		   public Component
	   {
		   public:
			   /** Constructor
			    * @param c context
			    */
			   BiCast(const Context* c, const xercesc::DOMNode*);

			   /** Destructor
			    */
			   ~BiCast();

			   /** Register handlers.
			    */
			   void configure(const Configuration* config);

			   /** Start the component.
			    */
			   void install()
			   {}
			   Disposition handle_flow_in(const Event& e);
			   Disposition handle_snmp_host_event(const Event& e);
			   //Disposition handle_wimax_msg(const Event& e);
			   Disposition handle_bicast_msg(const Event& e);
			   bool reinstall_route(uint64_t hostmac);
			   bool is_myAP(datapathid& dpid, BindPointPtrList assocAP);
		   private:
			   FlowDB *flowdb;
			   MobileDB *mobiledb;
			   routeinstaller *rinstaller;
			   int state;

	   };
   }; //aplication namespace
};

#endif
