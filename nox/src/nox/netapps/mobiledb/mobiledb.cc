#include "mobiledb.hh"

#include <boost/bind.hpp>
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <sstream>

#include "assert.hh"
#include "vlog.hh"
#include <string.h>
#include <queue>
#include "fnv_hash.hh"

#define FLOW_TIMEOUT        5
#define BROADCAST_TIMEOUT   5

#define DP_FROM_AP(loc) ((loc) & 0xffffffffffffULL)

/** \brief Class for Mobile Database
 *
 *
 * Copyright (C) Stanford University, 2009.
 * @author Te-Yuan Huang
 * @date Feburary 2009
 */
using namespace vigil::container;

namespace vigil {
	namespace applications {

	static Vlog_module log("mobiledb");

	/**
	 * MobileDB constructor:
	 */
	MobileDB::MobileDB(const Context* c, const xercesc::DOMNode* d)
		       :Component(c)
	{
		MAX_MAP_SIZE = 4;
	}

	MobileDB::~MobileDB(){
	}

	void MobileDB::configure(const container::Configuration*){
		register_handler<SNMP_host_event>
			(boost::bind(&MobileDB::handle_snmp_host_event, this, _1));
	        //register_handler<Msg_event>
		//	(boost::bind(&MobileDB::handle_wimax_msg, this, _1));

	}

	/** Dump out all the entries is all of the tables
	 */
	void MobileDB::dump_db(void){
		log.dbg("\n\n\n\nMobile DB Table:\n");
		MDB::iterator dbit = mobiledb.begin();
		string msg;
		for( ;dbit != mobiledb.end(); dbit++){
			msg = "";
			char buffer[1000] = "\0";
			snprintf(buffer, sizeof buffer, "host(%"PRIx64")@", dbit->first);
			msg += buffer;
			LOCMAP::iterator mapit = dbit->second.begin();
			for( ; mapit != dbit->second.end(); mapit++){
				BindPoint* bp = mapit->second.get();
				snprintf(buffer, sizeof buffer, "%012"PRIx64":%"PRIu16", ", bp->dp.as_host(), bp->port);
				msg += buffer;
			}

			log.dbg("%s", msg.c_str());
		}

	}
	/** Print out the value inside a flow entry
	 *  @ param: shared_ptr to the FlowEntry
	 */
	void MobileDB::print_entry(BindPoint* bp){

	}

	/** Return the hash value of one entry
	 *  @ param: datapathid, port
	 *  @ return: hashed value of datapathid and port inside the FlowEntry
	 */
	uint32_t MobileDB::hash_bind_entry(datapathid dp, uint16_t port){
		uint32_t x;
		x = vigil::fnv_hash(&dp, sizeof(datapathid));
		x = vigil::fnv_hash(&port, sizeof(uint16_t), x);
		return x;
	}
	bool MobileDB::del_oldest_entry(uint64_t hostmac){
		 MDB::iterator dbit = mobiledb.find(hostmac);
		log.dbg("Try to Delete association with %"PRIx64, hostmac);
		 if( dbit != mobiledb.end()){
			LOCMAP::iterator lmit = dbit->second.begin();
			LOCMAP::iterator earliest = dbit->second.begin();
			if( dbit->second.size() == 1){
				dbit->second.erase(earliest);
				mobiledb.erase(dbit);
			}else if(dbit->second.size() > 1){
				//find the earliest entry and erase it
				for(;lmit != dbit->second.end();lmit++){
					BindPoint* ebp = earliest->second.get();
					BindPoint* lbp = lmit->second.get();
					if( (ebp->timestamp.tv_sec > lbp->timestamp.tv_sec) ||
							(ebp->timestamp.tv_sec == lbp->timestamp.tv_sec &&
							 ebp->timestamp.tv_usec > lbp->timestamp.tv_usec) ){
						earliest = lmit;
					}
				}
				log.dbg("Delete: (%"PRIx64")@%"PRIx64"port:%"PRIu16,
						hostmac, earliest->second->dp.as_host(), earliest->second->port);
				dbit->second.erase(earliest);
			}
			return true;
		 }else{
			log.dbg("Cannot find the associated point of host%"PRIx64, hostmac);
			return false;
		 }
		return false;
	}
	bool MobileDB::set_max_map_size(int new_size){
		if(new_size < 1){
			log.dbg("cannot set max map size less than 1");
			return false;
		}
		MAX_MAP_SIZE = new_size;
		MDB::iterator dbit = mobiledb.begin();
		for(;dbit != mobiledb.end(); dbit++){
			map_size_maintainance(dbit->first);
		}
		return true;
	}

	void MobileDB::map_size_maintainance(uint64_t hostmac){
		MDB::iterator dbit = mobiledb.find(hostmac);
		while( dbit->second.size() > MAX_MAP_SIZE ){
			LOCMAP::iterator lmit = dbit->second.begin();
			LOCMAP::iterator earliest;
			//find the earliest entry and erase it
			if(lmit != dbit->second.end()){
				lmit++;
				earliest = lmit;
			}
			for(;lmit != dbit->second.end();lmit++){
				BindPoint* ebp = earliest->second.get();
				BindPoint* lbp = lmit->second.get();
				if( (ebp->timestamp.tv_sec > lbp->timestamp.tv_sec) ||
						(ebp->timestamp.tv_sec == lbp->timestamp.tv_sec &&
						 ebp->timestamp.tv_usec > lbp->timestamp.tv_usec) ){
					earliest = lmit;
				}
			}
			dbit->second.erase(earliest);
		}
		return;
	}
	/** Handle SNMP host join/leave event
	 *  @ param: Event
	 */
	Disposition MobileDB::handle_snmp_host_event(const Event& e){
		//every thing in snmp_host_event is in host order
		SNMP_host_event& snmphe = const_cast<SNMP_host_event&>(dynamic_cast<const SNMP_host_event&>(e));
		//snmphe.port = 0;

		uint32_t hash_value = hash_bind_entry(snmphe.dpid, snmphe.port);
		if(snmphe.join){//join event
			log.dbg("Join: (%"PRIx64")@%"PRIx64"port:%"PRIu16" hash:%"PRIu32"\n",
					snmphe.hostMac.hb_long(), snmphe.dpid.as_host(), snmphe.port, hash_value);
			MDB::iterator dbit = mobiledb.find(snmphe.hostMac.hb_long());
			struct timeval tim;
			gettimeofday(&tim, NULL);
			BindPointPtr bep(new BindPoint);
			bep->dp = snmphe.dpid;
			bep->port = snmphe.port;
			bep->timestamp = tim;
			if(dbit != mobiledb.end()){
				//there is already an entry for the host
				dbit->second[hash_value] = bep;
			}else{
				//new entry for this host
				LOCMAP locmap;
				locmap[hash_value] = bep;
				mobiledb[snmphe.hostMac.hb_long()] = locmap;
			}
			//Maintain only < MAX_MAP_SIZE for each host in mobiledb
			map_size_maintainance(snmphe.hostMac.hb_long());
		}else{//leave event
			log.dbg("LEAVE: HOST(%"PRIx64")@%"PRIx64"port:%"PRIu16" hash:%"PRIu32"\n",
					snmphe.hostMac.hb_long(), snmphe.dpid.as_host(), snmphe.port, hash_value);
			MDB::iterator dbit = mobiledb.find(snmphe.hostMac.hb_long());
			if( dbit != mobiledb.end()){
				LOCMAP::iterator lmit = dbit->second.find(hash_value);
				if(lmit != dbit->second.end()){
					log.dbg("ERASING: hash%"PRIu32"\n", hash_value);
					dbit->second.erase(lmit);
				}else{
					log.dbg("Not able to find the location entry!");
				}
				if( dbit->second.empty()){
					mobiledb.erase(dbit);
				}
			}else{
					log.dbg("Couldn't find host entry for host:%"PRIx64, snmphe.hostMac.hb_long());
			}
		}
		//dump_db();
		return CONTINUE;
	}
	/*
	Disposition MobileDB::handle_wimax_msg(const Event& e)
	{
		const Msg_event& me = assert_cast<const Msg_event&>(e);

		if (me.msg->type == MSG_WIMAX)
		{
			log.dbg("WiMAX message received");
			wimax_msg* wmsg = (wimax_msg*) me.msg->body;
			//translate network order to host order
			datapathid bs_dpid = datapathid::from_net(wmsg->bs_mac);
			uint64_t hostMac = ntohll(wmsg->host_mac);
			uint16_t bs_port = ntohs(wmsg->port);

			uint32_t hash_value = hash_bind_entry(bs_dpid, bs_port);
			if (wmsg->subtype == WIMAX_JOIN)
			{
				//inWiMAX=true;

				log.dbg("WiMAX joins with host mac %"PRIx64" and bs mac %"PRIx64"",
						hostMac, bs_dpid.as_host());

				MDB::iterator dbit = mobiledb.find(hostMac);
				struct timeval tim;
				gettimeofday(&tim, NULL);
				BindPointPtr bep(new BindPoint);
				bep->dp = bs_dpid;
				bep->port = bs_port;
				bep->timestamp = tim;
				if(dbit != mobiledb.end()){
					//there is already an entry for the host
					dbit->second[hash_value] = bep;
				}else{
					//new entry for this host
					LOCMAP locmap;
					locmap[hash_value] = bep;
					mobiledb[hostMac] = locmap;
				}
				//Maintain only < MAX_MAP_SIZE for each host in mobiledb
				map_size_maintainance(hostMac);

			}
			else //leave message
			{
				//inWiMAX=false;
				log.dbg("WiMAX leaves with host mac %"PRIx64" and bs mac %"PRIx64"",
						hostMac, bs_dpid.as_host());
				MDB::iterator dbit = mobiledb.find(hostMac);
				if( dbit != mobiledb.end()){
					LOCMAP::iterator lmit = dbit->second.find(hash_value);
					if(lmit != dbit->second.end()){
						log.dbg("ERASING: hash%"PRIu32"\n", hash_value);
						dbit->second.erase(lmit);
					}else{
						log.dbg("Not able to find the location entry!");
					}
					if( dbit->second.empty()){
						mobiledb.erase(dbit);
					}
				}else{
					log.dbg("Couldn't find host entry for host:%"PRIx64, hostMac);
				}
			}
		}
		dump_db();
		return CONTINUE;
	}
*/
	BindPointPtrList MobileDB::BindPoints_of_host(ethernetaddr hostMac){
		BindPointPtrList bppl;
		priority_queue<BindPointPtr, vector<BindPointPtr>, earlierEntry> bp;
		//priority_queue<BindPointPtr> bp;
		MDB::iterator dbit = mobiledb.find(hostMac.hb_long());
		if( dbit != mobiledb.end()){
			LOCMAP::iterator lmit = dbit->second.begin();
			for(;lmit != dbit->second.end(); lmit++){
				bp.push(lmit->second);
			}
		}

		while( !bp.empty() ){
			bppl.push_back(bp.top());
			bp.pop();
		}
		return bppl;
	}

	/*BindPointPtrList MobileDB::BindPoints_of_host(ethernetaddr hostMac){
		BindPointPtrList bppl;
		MDB::iterator dbit = mobiledb.find(hostMac.hb_long());
		if( dbit != mobiledb.end()){
			LOCMAP::iterator lmit = dbit->second.begin();
			for(;lmit != dbit->second.end(); lmit++){
				bppl.push_back(lmit->second);
			}
		}
		return bppl;
	}*/

	void MobileDB::getInstance(const container::Context* ctxt,
			MobileDB*& ofp)
	{
		ofp = dynamic_cast<MobileDB*>
			(ctxt->get_by_interface(container::Interface_description
						(typeid(MobileDB).name())));
	}

     }//end of application
}//end of vigil

REGISTER_COMPONENT(vigil::container::Simple_component_factory
		<vigil::applications::MobileDB>,
		vigil::applications::MobileDB);
