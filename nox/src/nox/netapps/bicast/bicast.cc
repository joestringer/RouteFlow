#include "bicast.hh"

#include <boost/bind.hpp>
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <sstream>


#include "assert.hh"
#include "netinet++/ethernet.hh"
#include "vlog.hh"
#include <string.h>
#include "fnv_hash.hh"

#define FLOW_TIMEOUT        5
#define BROADCAST_TIMEOUT   5

#define DP_FROM_AP(loc) ((loc) & 0xffffffffffffULL)

/** \brief Class for Flow Database
 *
 * This component saves all the flow entries installed in the edge switches.
 * When host is moved, Mobility Management will use this database to find out
 * which flows they have to reroute.
 *
 * Copyright (C) Stanford University, 2009.
 * @author Te-Yuan Huang
 * @date Feburary 2009
 */
using namespace vigil::container;
namespace vigil {
	namespace applications {
	static Vlog_module log("bicast");
	BiCast::BiCast(const Context* c, const xercesc::DOMNode* d)
		       :Component(c), flowdb(0), mobiledb(0), rinstaller(0), state(0){}
	BiCast::~BiCast(){}
	void BiCast::configure(const container::Configuration*){
		resolve(flowdb);
		resolve(mobiledb);
		resolve(rinstaller);
		register_handler<Msg_event>
		        (boost::bind(&BiCast::handle_bicast_msg, this, _1));
		register_handler<SNMP_host_event>
		        (boost::bind(&BiCast::handle_snmp_host_event, this, _1));
		//register_handler<Msg_event>
                //        (boost::bind(&BiCast::handle_wimax_msg, this, _1));
		register_handler<Flow_in_event>
		        (boost::bind(&BiCast::handle_flow_in, this, _1));

	}
	bool BiCast::is_myAP(datapathid& dpid, BindPointPtrList assocAP){
		BindPointPtrList::iterator bppit = assocAP.begin();
		for( ; bppit!= assocAP.end(); bppit++){
			if(dpid == (*bppit)->dp) return true;
		}
		return false;
	}

	Disposition BiCast::handle_bicast_msg(const Event& e){
		const Msg_event& me = assert_cast<const Msg_event&>(e);
		((Msg_event*) &me)->dumpBytes();
		log.dbg("Got a message from messenger");
		if( me.msg->type == MSG_BICAST ){
		      bicast_msg* bmsg = (bicast_msg*) me.msg->body;
		      log.dbg("Got Bicast msg from host %"PRIx64" delete the oldest entry from mobiledb",
												ntohll(bmsg->host_mac));
		      BindPointPtrList assocAP = mobiledb->BindPoints_of_host(ntohll(bmsg->host_mac));
		      if( assocAP.size() > 1){
				mobiledb->del_oldest_entry(ntohll(bmsg->host_mac));
		      }
		      reinstall_route(ntohll(bmsg->host_mac));
	      //printout the assocaited entry
			/*ethernetaddr hostMac(ethernetaddr(string("00:1C:F0:EE:5A:D1")));
			assocAP = mobiledb->BindPoints_of_host(hostMac);
			BindPointPtrList::iterator bppit = assocAP.begin();
			string dbgmsg;
			for( ; bppit!= assocAP.end(); bppit++){
				char buffer[300]="\0";
				BindPointPtr bp = *bppit;
				snprintf(buffer, sizeof buffer, "@%"PRIx64"port:%"PRIu16" ", bp->dp.as_host(), bp->port);
				dbgmsg += string(buffer);
			}
			log.dbg("After GotDelete Message: HOST(%"PRIx64") is associated with %s",
								hostMac.hb_long(), dbgmsg.c_str());
			*/
		}
		return CONTINUE;
	}
	Disposition BiCast::handle_flow_in(const Event& e){

		Flow_in_event& fie = const_cast<Flow_in_event&>(dynamic_cast<const Flow_in_event&>(e));
		ethernetaddr host = fie.flow.dl_dst;

	      /*ethernetaddr host(ethernetaddr(string("00:1C:F0:ED:98:5A")));
		ethernetaddr mac_host(ethernetaddr(string("00:22:41:FA:73:01"))); */

		log.dbg("got flow-in event from %s to %s", fie.flow.dl_src.string().c_str()
							   ,fie.flow.dl_dst.string().c_str());

			log.dbg("got a flow-in event dst to NEC notebook!");
			BindPointPtrList assocAP = mobiledb->BindPoints_of_host(host);
			list<network::termination> hostAP;
			BindPointPtrList::iterator bppit = assocAP.begin();
                        for( ; bppit!= assocAP.end(); bppit++){
                                BindPointPtr bp = *bppit;
				log.dbg("Unicast to %"PRIx64" port:%"PRIu16" ", bp->dp.as_host(), bp->port);
                                hostAP.push_back(network::termination(bp->dp, bp->port));
                        }

			//log.dbg("state = %d", state);
			if( !hostAP.empty() ){
				//install single route
				network::route sroute( fie.datapath_id, ntohs(fie.flow.in_port));
				log.dbg("Unicast from %"PRIx64" port:%"PRIu16" ",fie.datapath_id.as_host(),
									ntohs(fie.flow.in_port));
				if( rinstaller->get_shortest_path(hostAP, sroute)){
						//successfully get a route
                                                hash_map<datapathid,ofp_action_list> act;
                                                rinstaller->install_route(fie.flow, sroute, fie.buffer_id, act);
                                                log.dbg("Unicast Route Installed!");
				}
				return STOP;
			}else{
				log.dbg("No binding point found for destination host(%s)",
							fie.flow.dl_dst.string().c_str());
			}
		return CONTINUE;
	}

	bool BiCast::reinstall_route(uint64_t hostmac){
		ethernetaddr hostMac(hostmac);
		FlowEntryList assocFlow = flowdb->flowWithDst(hostMac);
		BindPointPtrList assocAP = mobiledb->BindPoints_of_host(hostMac);
		list<network::termination> hostAP;
			BindPointPtrList::iterator bppit = assocAP.begin();
			string dbgmsg;
			for( ; bppit!= assocAP.end(); bppit++){
				char buffer[300]="\0";
				BindPointPtr bp = *bppit;
				snprintf(buffer, sizeof buffer, "@%"PRIx64"port:%"PRIu16" ", bp->dp.as_host(), bp->port);
				dbgmsg += string(buffer);
				hostAP.push_back(network::termination(bp->dp, bp->port));
			}
			if( assocAP.size() > 1){
				log.dbg("Start BiCast to %zu APs: HOST(%"PRIx64")%s",
						assocAP.size(), hostMac.hb_long(), dbgmsg.c_str());
				state = 1;
			}else if( assocAP.size() == 1){
				state = 0;
				log.dbg("Stop BiCast (now UNICAST): HOST(%"PRIx64")%s", hostMac.hb_long(), dbgmsg.c_str());
			}else if(assocAP.size() == 0){
				state = 0;
				log.dbg("Cannot BiCast: HOST(%"PRIx64") does not associate with any AP",
												hostMac.hb_long());
				return CONTINUE;
			}
			FlowEntryList::iterator feit = assocFlow.begin();
			if(feit == assocFlow.end()){
				log.dbg("No flow associated to the host %"PRIx64, hostMac.hb_long());
			}
			for( ; feit != assocFlow.end(); feit++){
				if( !(*feit)->exit ){
					//install route from this AP (source AP) to all of my AP
					FlowEntryPtr fe = *feit;
					flowdb->print_flowEntry(fe.get(), new string("Bicast for Flow:"));
					ofp_flow_mod *ofp = (ofp_flow_mod*)fe->flow_mod_cmd.get();
					ofp_match ofm = ofp->match;
					Flow flow = flowdb->create_flow_instance(fe);
					network::route sroute( fe->dp, flow.in_port);
					log.dbg("Do Bicast from @%"PRIx64"port:%"PRIu16, fe->dp.as_host(), flow.in_port);
					if(rinstaller->get_shortest_path(hostAP, sroute)){
						//successfully get a route
						hash_map<datapathid,ofp_action_list> act;
						rinstaller->install_route(flow, sroute, htonl(-1), act);
						log.dbg("Bicast Route Installed!");
					}else{
						log.dbg("Couldn't get a route from %"PRIx64" to Host(%"PRIx64")",
								fe->dp.as_host(), hostMac.hb_long());
					}
				}else{
						log.dbg("associated Flow is from internal switch");
				}
			}
		return true;
	}
        /*
	Disposition BiCast::handle_wimax_msg(const Event& e)
        {
                const Msg_event& me = assert_cast<const Msg_event&>(e);

                if (me.msg->type == MSG_WIMAX)
                {
			log.dbg("WiMAX message received");
                        wimax_msg* wmsg = (wimax_msg*) me.msg->body;
                        //translate network order to host order
                        datapathid bs_dpid = datapathid::from_net(wmsg->bs_mac);
                        uint64_t hostMac = ntohll(wmsg->host_mac);
                        //uint16_t bs_port = ntohs(wmsg->port);
                        if (wmsg->subtype == WIMAX_JOIN)
                        {
	                   log.dbg("host(%"PRIx64") join WiMAX BS:%012"PRIx64, hostMac, bs_dpid.as_host());
			}
			else{ //leave
			   log.dbg("host(%"PRIx64") leave WiMAX BS:%012"PRIx64, hostMac, bs_dpid.as_host());
			}
			reinstall_route(hostMac);
		}
		return CONTINUE;
	}
	*/

	Disposition BiCast::handle_snmp_host_event(const Event& e){
		SNMP_host_event& snmphe = const_cast<SNMP_host_event&>(dynamic_cast<const SNMP_host_event&>(e));
		ethernetaddr hostMac = snmphe.hostMac;
		FlowEntryList assocFlow = flowdb->flowWithDst(hostMac);
		BindPointPtrList assocAP = mobiledb->BindPoints_of_host(hostMac);
		list<network::termination> hostAP;
		if(snmphe.join){//join event
			log.dbg("host(%"PRIx64") join AP:%012"PRIx64, hostMac.hb_long(), snmphe.dpid.as_host());
		}else{
			log.dbg("host(%"PRIx64") leave AP:%012"PRIx64, hostMac.hb_long(), snmphe.dpid.as_host());
		}
		reinstall_route(snmphe.hostMac.hb_long());
		/*
			BindPointPtrList::iterator bppit = assocAP.begin();
			string dbgmsg;
			for( ; bppit!= assocAP.end(); bppit++){
				char buffer[300]="\0";
				BindPointPtr bp = *bppit;
				snprintf(buffer, sizeof buffer, "@%"PRIx64"port:%"PRIu16" ", bp->dp.as_host(), bp->port);
				dbgmsg += string(buffer);
				hostAP.push_back(network::termination(bp->dp, bp->port));
			}
			if( assocAP.size() > 1){
				log.dbg("Start BiCast: HOST(%"PRIx64")%s", hostMac.hb_long(), dbgmsg.c_str());
				state = 1;
			}else if( assocAP.size() == 1){
				state = 0;
				log.dbg("Stop  BiCast: HOST(%"PRIx64")%s", hostMac.hb_long(), dbgmsg.c_str());
			}else if(assocAP.size() == 0){
				state = 0;
				log.dbg("Cannot BiCast: HOST(%"PRIx64") does not associate with any AP",
												hostMac.hb_long());
				return CONTINUE;
			}
			FlowEntryList::iterator feit = assocFlow.begin();
			if(feit == assocFlow.end()){
				log.dbg("No flow associated to the host %"PRIx64, hostMac.hb_long());
			}
			for( ; feit != assocFlow.end(); feit++){
				if( !(*feit)->exit ){
					//install route from this AP (source AP) to all of my AP
					FlowEntryPtr fe = *feit;
					flowdb->print_flowEntry(fe.get(), new string("Bicast for Flow:"));
					ofp_flow_mod *ofp = (ofp_flow_mod*)fe->flow_mod_cmd.get();
					ofp_match ofm = ofp->match;
					Flow flow = flowdb->create_flow_instance(fe);
					network::route sroute( fe->dp, flow.in_port);
					log.dbg("Do Bicast from @%"PRIx64"port:%"PRIu16, fe->dp.as_host(), flow.in_port);
					if(rinstaller->get_shortest_path(hostAP, sroute)){
						//successfully get a route
						hash_map<datapathid,ofp_action_list> act;
						rinstaller->install_route(flow, sroute, htonl(-1), act);
						log.dbg("Bicast Route Installed!");
					}else{
						log.dbg("Couldn't get a route from %"PRIx64" to Host(%"PRIx64")",
								fe->dp.as_host(), hostMac.hb_long());
					}
				}
			}*/
		return CONTINUE;
	}
     }//end of application
}//end of vigil
REGISTER_COMPONENT(vigil::container::Simple_component_factory
		<vigil::applications::BiCast>,
		vigil::applications::BiCast);
