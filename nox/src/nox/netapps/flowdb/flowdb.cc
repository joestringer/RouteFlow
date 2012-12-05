#include "flowdb.hh"

#include <boost/bind.hpp>
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <sstream>

#include "flow.hh"
#include "assert.hh"
#include "netinet++/ethernet.hh"
#include "vlog.hh"
#include <string.h>
#include "fnv_hash.hh"
#include <flow-removed.hh>
#include <flow-stats-in.hh>
#define FLOW_TIMEOUT        5
#define CHECK_INTERVAL	    5*FLOW_TIMEOUT
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

	static Vlog_module log("flowdb");

	/*constructor for Flwodb_Event*/
	Flowdb_event::Flowdb_event(int type_, bool exit_, datapathid dp_,
				uint32_t srcip_,  uint32_t dstip_,
				ethernetaddr srcmac_, ethernetaddr dstmac_):
		Event(static_get_name())
		{
			type = type_;
			exit = exit_;
			dp = dp_;
			srcip = srcip_;
			dstip = dstip_;
			srcmac = srcmac_;
			dstmac = dstmac_;
			//VLOG_DBG(lg, "Received packet of length %zu", size);
		}

	Flowdb_event::~Flowdb_event()
	{  }

	void FlowDB::getInstance(const container::Context* ctxt,
				 FlowDB*& ofp)
	{
	  ofp = dynamic_cast<FlowDB*>
	    (ctxt->get_by_interface(container::Interface_description
				    (typeid(FlowDB).name())));
	}

	/**
	 *  checkFlowEntry : Periodically Check the Flow Entries which are inactive for 2*TIMEOUT
	 */
	void FlowDB::checkFlowEntry(void){
		struct timeval tim;
		list<uint32_t> deferredDeleteList;
		gettimeofday(&tim, NULL);
		//double now = tim.tv_sec+(tim.tv_usec/1000000.0);

		DB::iterator dbit = allFlow.begin();
		for(;dbit!= allFlow.end(); dbit++){
			FlowEntry* fe = dbit->second.get();
			if( fe->status == CHECKING ){
				//didn't receive feeback from switch, assume no flow entry anymore
				ofp_flow_mod* ofm = (ofp_flow_mod*)fe->flow_mod_cmd.get();

				// Defer deletion to prevent iterator corruption
				deferredDeleteList.push_back(dbit->first);
			}else if( (tim.tv_sec - fe->timestamp.tv_sec) > 2*FLOW_TIMEOUT){
				fe->status = CHECKING;
				ofp_flow_mod* ofm = (ofp_flow_mod*)fe->flow_mod_cmd.get();
				//send out messages to check
				size_t size = sizeof(ofp_stats_request) + sizeof(ofp_flow_stats_request);
				boost::shared_array<char> raw_of(new char[size]);
				ofp_stats_request *ost = (ofp_stats_request*)raw_of.get();
				ost->header.version = OFP_VERSION;
				ost->header.type = OFPT_STATS_REQUEST;
				ost->header.length = htons(size);
				ost->header.xid = 0;
				ost->type = htons(OFPST_FLOW);
				ost->flags = htons(0);

				ofp_flow_stats_request* ofsr = (ofp_flow_stats_request*)(((uint8_t*)ost->body)+0);
				ofsr->table_id = 0xff; //request for all tables
				memcpy(&ofsr->match, &ofm->match, sizeof(ofp_match));
				ofsr->out_port = OFPP_NONE;

				send_openflow_command(fe->dp, &ost->header, false);
			}
		}

		// Process the deferred delete list
		if (deferredDeleteList.size() > 0) {
			list<uint32_t>::iterator it = deferredDeleteList.begin();
			for (; it != deferredDeleteList.end(); it++) {
				dbit = allFlow.find(*it);
				if (dbit != allFlow.end()) {
					FlowEntry* fe = dbit->second.get();
					ofp_flow_mod* ofm = (ofp_flow_mod*)fe->flow_mod_cmd.get();
					delFlowEntry(&ofm->match, fe->dp);
				}
			}
		}

		post(boost::bind(&FlowDB::checkFlowEntry, this), make_timeval(CHECK_INTERVAL,0));
	}
	/**
	 * FlowDB constructor:
	 *  cleanup thread is created here
	 */
	FlowDB::FlowDB(const Context* c, const xercesc::DOMNode* d)
		       :Component(c), topology(0)
	{
		 post(boost::bind(&FlowDB::checkFlowEntry, this), make_timeval(CHECK_INTERVAL, 0));

	}

	FlowDB::~FlowDB(){
	}

	void FlowDB::configure(const container::Configuration*){
		resolve(topology);
		register_handler<Flow_stats_in_event>
			(boost::bind(&FlowDB::handle_flow_stats_in, this, _1));
		register_handler<Flow_mod_event>
		        (boost::bind(&FlowDB::handle_flow_mod, this, _1));
		register_handler<Flow_removed_event>
			(boost::bind(&FlowDB::handle_flow_removed, this, _1));
		register_event(Flowdb_event::static_get_name());
	}

	std::list<FlowEntryPtr> FlowDB::flowWithSrcDst(ethernetaddr src, ethernetaddr dst){
		std::list<FlowEntryPtr> AssocFlows;
		macTable::iterator macit = srcmac_table.find(src.hb_long());
		if( macit != srcmac_table.end()){
			DB::iterator dbit = macit->second.begin();
			for( ; dbit != macit->second.end(); dbit++ ){
				if( dbit->second->dstmac == dst){
					AssocFlows.push_back(dbit->second);
				}
			}
		}
		return AssocFlows;
	}
	/**
	 * flowWithSrc :
	 * @ mac : the mac address of the source
	 * @ return : a list of shared_pointer to flows origniated from mac
	 */
	std::list<FlowEntryPtr> FlowDB::flowWithSrc(ethernetaddr mac){
		std::list<FlowEntryPtr> flowsToSrc;
		macTable::iterator macit = srcmac_table.find(mac.hb_long());
		if( macit != srcmac_table.end()){
			DB::iterator dbit = macit->second.begin();
			while(dbit != macit->second.end()){
				flowsToSrc.push_back(dbit->second);
				dbit++;
			}
		}
		return flowsToSrc;

	}
	/**
	 * flowWithDst :
	 * @ mac: the mac address of the destination
	 * @ return : a list of shared_pointer to flows destinated to mac
	 */
	std::list<FlowEntryPtr> FlowDB::flowWithDst(ethernetaddr mac){
		std::list<FlowEntryPtr> flowsToDst;
		macTable::iterator macit = dstmac_table.find(mac.hb_long());
		if( macit != dstmac_table.end()){
			DB::iterator dbit = macit->second.begin();
			while(dbit != macit->second.end()){
				flowsToDst.push_back(dbit->second);
				dbit++;
			}
		}
		return flowsToDst;
	}
	/**
	 * flowWithDst :
	 * @ mac: the mac address of the destination
	 * @ return : a list of shared_pointer to flows destinated to mac
	 */
	std::list<FlowEntryPtr> FlowDB::flowWithDst(uint32_t nw_dst){
		std::list<FlowEntryPtr> flowsToDst;
		IPTable::iterator ipit = dstip_table.find(nw_dst);
		if(ipit!=dstip_table.end()){
			DB::iterator dbit = ipit->second.begin();
			while(dbit != ipit->second.end()){
				flowsToDst.push_back(dbit->second);
				dbit++;
			}
		}
		return flowsToDst;
	}
	/**
	 * flowWithSrc :
	 * @ mac : the mac address of the source
	 * @ return : a list of shared_pointer to flows origniated from mac
	 */
	std::list<FlowEntryPtr> FlowDB::flowWithSrc(uint32_t nw_src){
		std::list<FlowEntryPtr> flowsToSrc;
		IPTable::iterator ipit = srcip_table.find(nw_src);
		if(ipit!=srcip_table.end()){
			DB::iterator dbit = ipit->second.begin();
			while(dbit != ipit->second.end()){
				flowsToSrc.push_back(dbit->second);
				dbit++;
			}
		}
		return flowsToSrc;
	}

	/** Return the hash value of one FlowEntry
	 *  @ param: shared_ptr to the FlowEntry
	 *  @ return: hashed value of datapathid and ofp_match inside the FlowEntry
	 */
	uint32_t FlowDB::hash_flow_entry(FlowEntryPtr fe){
		uint32_t x;
		x = vigil::fnv_hash(&fe->dp, sizeof(datapathid));
		ofp_flow_mod* ofm = (ofp_flow_mod*)fe->flow_mod_cmd.get();
		x = vigil::fnv_hash(&ofm->match, sizeof(ofp_match), x);
		return x;
	}

	/** Return the hash value of one FlowEntry
	 *  @ param: datapathid, ofp_match in the ofp_flow_mod message
	 *  @ return: hashed value of datapathid and ofp_match inside the FlowEntry
	 */
	uint32_t FlowDB::hash_flow_entry(datapathid dp, ofp_match *ofm){
		uint32_t x;
		x = vigil::fnv_hash(&dp, sizeof(datapathid));
		x = vigil::fnv_hash(ofm, sizeof(ofp_match), x);
		return x;
	}

	/** Dump out all the entries is all of the tables
	 */
	void FlowDB::dump_db(void){

		log.dbg("\n\n\n START DUMPING!\n\n");

		log.dbg("\ndstIP Table:\n");
		IPTable::iterator ipit = dstip_table.begin();
		for( ;ipit != dstip_table.end(); ipit++){
			DB::iterator dbit = ipit->second.begin();
			for( ; dbit != ipit->second.end(); dbit++){
				FlowEntry* fe = dbit->second.get();
				print_flowEntry(fe, new string("DUMP:"));
			}
		}

		log.dbg("\nsrcIP Table:\n");
		ipit = srcip_table.begin();
		for( ;ipit != srcip_table.end(); ipit++){
			DB::iterator dbit = ipit->second.begin();
			for( ; dbit != ipit->second.end(); dbit++){
				FlowEntry* fe = dbit->second.get();
				print_flowEntry(fe, new string("DUMP:"));
			}
		}

		//dump from dst mac
		log.dbg("\ndstMac Table:\n");
		macTable::iterator macit = dstmac_table.begin();
		for(;macit!= dstmac_table.end(); macit++){
			DB::iterator dbit = macit->second.begin();
			for( ; dbit != macit->second.end(); dbit++){
				FlowEntry* fe = dbit->second.get();
				print_flowEntry(fe, new string("DUMP:"));
			}
		}

		//dump from src mac
		log.dbg("\nsrcMac Table:\n");
		macit = srcmac_table.begin();
		for(;macit!= srcmac_table.end(); macit++){
			DB::iterator dbit = macit->second.begin();
			for( ; dbit != macit->second.end(); dbit++){
				FlowEntry* fe = dbit->second.get();
				print_flowEntry(fe, new string("DUMP:"));
			}
		}
	}
	/** Print out the value inside a flow entry
	 *  @ param: shared_ptr to the FlowEntry
	 */
	void FlowDB::print_flowEntry(FlowEntry* fe, string *msg){
		ofp_flow_mod* ofm = (ofp_flow_mod*)fe->flow_mod_cmd.get();
		datapathid dp = fe->dp;
		print_flowEntry(&ofm->match, dp, msg);
	}
	void FlowDB::print_flowEntry(ofp_match* match, datapathid& dp, string* msg){
		uint32_t nw_dst = match->nw_dst;
		uint32_t nw_src = match->nw_src;
		ethernetaddr srcmac(match->dl_src);
		ethernetaddr dstmac(match->dl_dst);
		uint32_t hash_value = hash_flow_entry(dp, match);
		//only for debug purpose
		char ip_dst[30] = "\0";
		char ip_src[30] = "\0";
		snprintf(ip_dst, sizeof ip_dst, "%u.%u.%u.%u",
				((unsigned char *)&nw_dst)[0],
				((unsigned char *)&nw_dst)[1],
				((unsigned char *)&nw_dst)[2],
				((unsigned char *)&nw_dst)[3]);
		snprintf(ip_src, sizeof ip_src, "%u.%u.%u.%u",
				((unsigned char *)&nw_src)[0],
				((unsigned char *)&nw_src)[1],
				((unsigned char *)&nw_src)[2],
				((unsigned char *)&nw_src)[3]);
		log.dbg("%s @%012"PRIx64" inport:%"PRIu16" %s("EA_FMT")->%s("EA_FMT") hash:%"PRIu32"\n",
				msg->c_str(), dp.as_host(), ntohs(match->in_port), ip_src, EA_ARGS(&(srcmac)),
					      ip_dst, EA_ARGS(&(dstmac)), hash_value);

	}

	Flow FlowDB::create_flow_instance(FlowEntryPtr fe){
		//Flow* flow = NULL;
		ofp_flow_mod *ofp = (ofp_flow_mod*)fe->flow_mod_cmd.get();
		ofp_match ofm = ofp->match;

		Flow flow(ntohs(ofm.in_port), ofm.dl_vlan, ofm.dl_vlan_pcp,
				fe->srcmac, fe->dstmac, ofm.dl_type,
				fe->srcip, fe->dstip,
				ofm.nw_proto, ofm.nw_tos, ofm.tp_src, ofm.tp_dst);
		return flow;
	}
	long FlowDB::num_of_flows(void){
		/* since for each flow, we record two entries:
		   one for the ingress edge switch, the other for the egress switch
		   Therefore, the number of flow is equal to table size divied by two.
		   However, sometimes, it is possible that the flow entry in one edge switch is installed,
		   the flow entry is not yet installed in the other.
		   Thus, the it will result in size % 2 > 0, this corner case is handled as following.
		 */
		long size = allFlow.size();
		if( size % 2 > 0 ){
			size = size/2 +1;
		}else{
			size = size / 2;
		}
		return size;
	}
	Disposition FlowDB::handle_flow_stats_in(const Event& e){
		Flow_stats_in_event& fsie = const_cast<Flow_stats_in_event&>(dynamic_cast<const Flow_stats_in_event&>(e));
		datapathid dp = fsie.datapath_id;
		log.dbg("FlowDB: FLOW_STATS_IN @ %012"PRIx64"\t", 	dp.as_host());
		std::vector<Flow_stats>::iterator fit = fsie.flows.begin();
		while(fit != fsie.flows.end()){
			uint32_t hash_value = hash_flow_entry(dp, &fit->match);
			//log.dbg("hash value=%"PRIu32" OK\n", hash_value);
			DB::iterator dbit = allFlow.find(hash_value);
			if(dbit != allFlow.end()){
				FlowEntryPtr fe = allFlow[hash_value];
				fe->status = OK;
				struct timeval tim;
				gettimeofday(&tim, NULL);
				fe->timestamp = tim;
			}
			fit++;
		}
		return CONTINUE;
	}
	/** Handle flow expired
	 *  To remove flow from database
	 *  This event need to be enabled in openflow.cc
	 */
	Disposition FlowDB::handle_flow_removed(const Event& e){
		const Flow_removed_event& fee =  dynamic_cast<const Flow_removed_event&>(e);
		datapathid datapath_id = fee.datapath_id;
		ofp_match *ofm = const_cast<ofp_match*>(fee.get_flow());

		log.dbg("FlowDB: FLOW_REMOVED @ %012"PRIx64"\t", datapath_id.as_host());
		log.dbg("reason:%d  priority:%"PRIx16"", fee.reason, fee.priority );
		delFlowEntry(ofm, datapath_id);

		return CONTINUE;
	}

	/** Handle flow mod event and add associated ofp_mod_cmd to database tables
	 *  Broadcast messages will be discarded, and
	 *  Only event triggered from Edge Switches will be handled
	 */
	Disposition FlowDB::handle_flow_mod(const Event& e){
      /*
		//const Flow_in_event& fi = assert_cast<const Flow_in_event&>(e);
		const Flow_mod_event& fme = dynamic_cast<const Flow_mod_event&>(e);
		const ofp_flow_mod *ofm = fme.get_flow_mod();
		datapathid datapath_id = fme.datapath_id;
		uint16_t inport = ntohs(ofm->match.in_port);
		size_t size = ntohs(ofm->header.length);


		//number of actions in the ofp_flow_mod
		double n_action  = ((ntohs(ofm->header.length) - sizeof(ofp_flow_mod))/sizeof(ofp_action_output));
		uint32_t nw_dst = ofm->match.nw_dst;
		uint32_t nw_src = ofm->match.nw_src;
		ethernetaddr srcmac(ofm->match.dl_src);
		ethernetaddr dstmac(ofm->match.dl_dst);

		log.dbg("Got a Flow Mod EVENT from %"PRIx64, datapath_id.as_host());
		if( ofm->header.type == OFPT_FLOW_MOD && n_action > 0 ){ //&& nw_dst > 0 && nw_src > 0){
			if( ofm->command == OFPFC_ADD || ofm->command == OFPFC_MODIFY
						      || ofm->command == OFPFC_MODIFY_STRICT){

				log.dbg("Got a Flow Mod EVENT with FLOW_MOD header from %"PRIx64, datapath_id.as_host());
				//filter out broadcast messages
				if( !srcmac.is_multicast() && !dstmac.is_multicast()){

					bool is_internal = false;
					//check inport and each outport to see whether it is internal
					is_internal = topology->is_internal(datapath_id, inport);
					int i = 1;
					while( i <= n_action ){
						ofp_action_output *action = (ofp_action_output*)
							(((uint8_t*)ofm->actions) + (i-1)* sizeof(ofp_action_output));
						if(action->type == htons(OFPAT_OUTPUT)){
							if( is_internal == true ){
								is_internal = topology->is_internal(datapath_id, ntohs(action->port));
							}
						}
						i++;
					}

					//add these into the flow database
					if(!is_internal){
						//copy and save the ofm as a whole
						boost::shared_array<char> raw_of(new char[size]);
						ofp_flow_mod *new_ofm = (ofp_flow_mod*) raw_of.get();
						memcpy(new_ofm, ofm, size);

						FlowEntryPtr fe(new FlowEntry);
						fe->flow_mod_cmd = raw_of;
						fe->dp = datapath_id;
						//fe->inport = inport;
						fe->status = OK;
						fe->srcip  = nw_src;
						fe->dstip  = nw_dst;
						fe->srcmac = srcmac;
						fe->dstmac = dstmac;
						fe->exit = topology->is_internal(datapath_id, inport);

						struct timeval tim;
						gettimeofday(&tim, NULL);
						fe->timestamp = tim;//tim.tv_sec+(tim.tv_usec/1000000.0);

						uint32_t hash_value = hash_flow_entry(fe);

						print_flowEntry(fe.get(), new string("Add:"));
						//add to allFlow table
						allFlow[hash_value] = fe;
						//add into dst ip table
						IPTable::iterator ipit = dstip_table.find(nw_dst);
						if( ipit == dstip_table.end()){
							//create new map
							DB db;
							db[hash_value] = fe;
							dstip_table[nw_dst] = db;
						}else{
							//map is already existed
							ipit->second[hash_value] = fe;
						}


						//add into src ip table
						ipit = srcip_table.find(nw_src);
						if( ipit == srcip_table.end()){
							//create new map
							DB db;
							db[hash_value] = fe;
							srcip_table[nw_src] = db;
						}else{
							//map is already existed
							ipit->second[hash_value] = fe;
						}
						//add into src mac table
						macTable::iterator macit = dstmac_table.find(dstmac.hb_long());
						if( macit == dstmac_table.end()){
							//create new map
							DB db;
							db[hash_value] = fe;
							dstmac_table[dstmac.hb_long()] = db;
						}else{
							//map is already existed
							macit->second[hash_value] = fe;
						}
						//add into dst mac table
						macit = srcmac_table.find(srcmac.hb_long());
						if( macit == srcmac_table.end()){
							//create new map
							DB db;
							db[hash_value] = fe;
							srcmac_table[srcmac.hb_long()] = db;
						}else{
							//map is already existed
							macit->second[hash_value] = fe;
						}
						post(new Flowdb_event(ADD,fe->exit, datapath_id, nw_src, nw_dst, srcmac, dstmac));
					}
				}
			}else if(ofm->command == OFPFC_DELETE || ofm->command == OFPFC_DELETE_STRICT){
				//delete from table
				ofp_match* match = const_cast<ofp_match*>(&ofm->match);
				delFlowEntry(match, datapath_id);
			}
		}//end of OFPT_FLOW_MOD
		*/
		return CONTINUE;
	}

	void FlowDB::delFlowEntry(ofp_match *match, datapathid dp){

		print_flowEntry(match, dp, new string("Delete:"));
		uint32_t nw_dst = match->nw_dst;
		uint32_t nw_src = match->nw_src;
		ethernetaddr srcmac(match->dl_src);
		ethernetaddr dstmac(match->dl_dst);
		uint32_t hash_value = hash_flow_entry(dp, match);
		bool exit = false;
		bool entryInDB = false;
		//delete from allFlow
		DB::iterator fit = allFlow.find(hash_value);
		if(fit != allFlow.end()){
			exit = fit->second->exit;
			entryInDB = true;
			allFlow.erase(fit);
		}
		//delete from dst ip
		IPTable::iterator ipit = dstip_table.find(nw_dst);
		if(ipit!=dstip_table.end()){
			DB::iterator dbit = ipit->second.find(hash_value);
			if(dbit != ipit->second.end()){
				ipit->second.erase(dbit);
			}
			if(ipit->second.empty()){
				dstip_table.erase(ipit);
			}
		}
		//log.dbg(" dstip size: %d\n",dstip_table.size() );

		//delete from src ip
		ipit = srcip_table.find(nw_src);
		if(ipit!=srcip_table.end()){
			DB::iterator dbit = ipit->second.find(hash_value);
			if(dbit != ipit->second.end()){
				ipit->second.erase(dbit);
			}
			if(ipit->second.empty()){
				srcip_table.erase(ipit);
			}

		}
		//log.dbg(" srcip size: %d\n",srcip_table.size() );
		//delete from dst mac
		macTable::iterator macit = dstmac_table.find(dstmac.hb_long());
		if(macit!=dstmac_table.end()){
			DB::iterator dbit = macit->second.find(hash_value);
			if(dbit != macit->second.end()){
				macit->second.erase(dbit);
			}
			if(macit->second.empty()){
				dstmac_table.erase(macit);
			}
		}
		//log.dbg(" dstmac size: %d\n",dstmac_table.size() );
		//delete from src mac
		macit = srcmac_table.find(srcmac.hb_long());
		if(macit != srcmac_table.end()){
			DB::iterator dbit = macit->second.find(hash_value);
			if(dbit != macit->second.end()){
				macit->second.erase(dbit);
			}
			if(macit->second.empty()){
				srcmac_table.erase(macit);
			}
		}
		if (entryInDB == true){
			post(new Flowdb_event(DELETE,exit, dp, nw_src, nw_dst, srcmac, dstmac));
		}
		//log.dbg(" srcmac size: %d\n",srcmac_table.size() );
	}
     }//end of application
}//end of vigil

REGISTER_COMPONENT(vigil::container::Simple_component_factory
		<vigil::applications::FlowDB>,
		vigil::applications::FlowDB);
