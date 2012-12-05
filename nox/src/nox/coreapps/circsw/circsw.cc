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


#include "circsw.hh"
#include "circsw_config.hh"
#include "flow.hh"
#include "buffer.hh"
#include "packets.h"
#include "aggregation/aggregation-message.hh"
#include "aggregation/aggregationmsg.hh"


namespace vigil {

  using namespace vigil::container;

  Vlog_module log("circsw");


  switch_elem::switch_elem(const Datapath_join_event& dj) {
    datapath_id = dj.datapath_id;
    n_buffers = dj.n_buffers;
    n_tables = dj.n_tables;
    capabilities = dj.capabilities;
    actions = dj.actions;
    n_cports = dj.n_cports;

    suppLcas = capabilities & OFPC_LCAS;
    suppVcat = capabilities & OFPC_VIR_CONCAT;
    suppGfp  = capabilities & OFPC_GFP;
    nextvcgnum = 0xfb00;

    VLOG_DBG(log, "datapath supports lcas: %d, vcat: %d, gfp: %d", \
             suppLcas, suppVcat, suppGfp);

    for (std::vector<Port>::const_iterator iter = dj.ports.begin();
         iter != dj.ports.end(); ++iter) {
      if( iter->port_no < OFPP_MAX ) {
        ethports.insert( std::make_pair( iter->port_no, *iter ));
      }
      else {
        VLOG_ERR(log, "*** port number %d not valid ethport***", iter->port_no);
      }
    }
    for (std::vector<CPort>::const_iterator iter = dj.cports.begin();
         iter != dj.cports.end(); ++iter) {
      if( iter->port_no < OFPP_MAX ) {
        tdmports.insert( std::make_pair( iter->port_no, *iter ));
      }
      else if( iter->port_no < 0xfb00 ) {
        internalports.insert( std::make_pair( iter->port_no, *iter ));
      }
      else if( iter->port_no < 0xff00 ) {
        // vcgports.insert( std::make_pair( iter->port_no, *iter ));
        VLOG_ERR(log, "*** vcg %d reported by datapath ***", iter->port_no);
      }
      else {
        VLOG_ERR(log, "*** datapath port number %d not valid ***", iter->port_no);
      }
    }

    VLOG_DBG(log, "datapath reported: ethports %d, tdmports %d, internalports: %d,",
             ethports.size(), tdmports.size(),internalports.size() );
    VLOG_DBG(log, " virtualports: %d", vcgports.size() );


  }


  void
  Circsw::configure(const Configuration* conf) {
    resolve( cswgui );

    tsig = tsig_;
    tsignal_incr  = tsig_incr_;
    num_bw_incr = num_bw_incr_;
    wait_to_start_polling = wait_to_start_polling_;
    stat_polling_interval = stat_polling_interval_;
    bw_incr_threshold = bw_incr_threshold_;
    num_above_tx_threshold = num_above_tx_threshold_;
    pause = pause_;

    increased_bandwidth = false;
    continue_monitoring = false;
    monitorlink3id = 0;
    monitorvlpathid = 0;
    monitordp1 = monitordp2 = 0;
    monitorvcg2 = monitorvcg2 = 0xffff;
    sendStatReq1 = sendStatReq2 = false;
    tx_bytes1= tx_bytes2 = last_tx_bytes = 0;
    above_tx_threshold_counter1 = 0;
    above_tx_threshold_counter2 = 0;

    wait_for_xconn_delete = wait_for_xconn_delete_;
    wait_for_vcomp_delete = wait_for_vcomp_delete_;
    wait_for_vmem_delete = wait_for_vmem_delete_;

    flowid = 0;
    flow2id = 0x2000;
    linkid = 0x1000;
    link2id = 0x2000;
    link3id = 0x3000 + num_vplinks;
    vlpathid = 0x4000;
  }

  void
  Circsw::install() {

    register_handler<Datapath_join_event>
      (boost::bind(&Circsw::handle_datapath_join, this, _1));

    //register_handler<Datapath_leave_event>
    //  (boost::bind(&Vbpl::handle_datapath_leave, this, _1));

    register_handler<Packet_in_event>
      (boost::bind(&Circsw::handle_packet_in, this, _1));

    //register_handler<L1_flow_drag_event>
    //  (boost::bind(&Vbpl::handle_L1flow_drag, this, _1));

    register_handler<Agg_msg_py_event>
      (boost::bind(&Circsw::handle_Agg_msg_py, this, _1));

    register_handler<Port_stats_in_event>
      (boost::bind(&Circsw::handle_port_stats_in, this, _1));

    register_handler<Port_status_event>
      (boost::bind(&Circsw::handle_port_status, this, _1));

    //register_handler<CPort_status_event>
    //  (boost::bind(&Circsw::handle_cport_status, this, _1));


  }


  void
  Circsw::debugDpJoin( const Datapath_join_event& dj, uint64_t dpint ) {
    Port *p = NULL;
    CPort *cp = NULL;

    for (std::vector<Port>::const_iterator iter = dj.ports.begin();
         iter != dj.ports.end(); ++iter ) {
      p = &switch_db[dpint][0].ethports[iter->port_no];
      std::string porttype =  "";
      if( !p->hw_addr.is_zero() )
        porttype = "Ethernet";
      VLOG_DBG(log, "\nport number & name: %d(0x%"PRIx16"), %s (%s)", \
               p->port_no, p->port_no, p->name.c_str(), porttype.c_str());
      VLOG_DBG(log, "port feature (speed): %d (%d Mbps)",p->curr, p->speed);
    }

    for (std::vector<CPort>::const_iterator iter = dj.cports.begin();
         iter != dj.cports.end(); ++iter ) {
      if (iter->port_no < OFPP_MAX)
        cp = &switch_db[dpint][0].tdmports[iter->port_no];
      else
        cp = &switch_db[dpint][0].internalports[iter->port_no];
      std::string cporttype =  "";
      if ( cp->port_no < OFPP_MAX )
        cporttype = "SONET";
      else
        cporttype = "Mapper";

      VLOG_DBG(log, "\nport number & name: %d(0x%"PRIx16"), %s (%s)", \
               cp->port_no, cp->port_no, cp->name.c_str(), cporttype.c_str());
      VLOG_DBG(log, "port feature (speed): %d (%d Mbps)",cp->curr, cp->speed);
      VLOG_DBG(log, "switching type: %d", cp->supp_swtype);
      VLOG_DBG(log, "tdm granularity: %d", cp->supp_sw_tdm_gran);
      VLOG_DBG(log, "peer port number: %d(0x%"PRIx16")", cp->peer_port_no,
               cp->peer_port_no);
      VLOG_DBG(log, "peer datapath id: %"PRIx64"", cp->peer_datapath_id);
      VLOG_DBG(log, "bwbitmaps: %"PRIx64" %"PRIx64" %"PRIx64" ", cp->bwbmp1,
               cp->bwbmp2, cp->bwbmp3);

    }
  }


  Disposition
  Circsw::handle_datapath_join(const Event& e) {
    const Datapath_join_event& dj = assert_cast<const Datapath_join_event&>(e);

    if(!dj.n_cports) {
      VLOG_DBG(log, "No circuit ports - circuit discovery ignoring switch");
      return CONTINUE;
    }

    uint64_t dpint = dj.datapath_id.as_host();

    if(switch_db.find(dpint) != switch_db.end()){
      VLOG_ERR(log, "DP join of existing switch %"PRIu64"", dpint);
      switch_db.erase(dpint);
    } else {
      dpids.push_back(dpint);//register datapath_id
    }
    VLOG_DBG(log, "***********************************************************");
    VLOG_DBG(log, "Datapath join of switch: %"PRIx64"", dpint);


    struct switch_elem sw_elem(dj);
    switch_db[dpint].push_back(sw_elem);
    VLOG_DBG(log, "n_buffers: %d, n_tables: %d", \
             switch_db[dpint][0].n_buffers, switch_db[dpint][0].n_tables);

    debugDpJoin( dj, dpint );
    showDpJoin( HYBRID_SWITCH, dpint );
    discoverCktTopo();
    showCktTopo();

    //VLOG_DBG(log, "*************");
    //VLOG_DBG(log, "Starting Unit Test for switch %"PRIx64"", dpint);
    //unitTest( dpint );

    VLOG_DBG(log, "***********************************************************");

    return STOP;
  }

  Disposition
  Circsw::handle_cport_status(const Event& e) {
    const CPort_status_event& cpse = assert_cast<const CPort_status_event&>(e);
    uint64_t dpint = cpse.datapath_id.as_host();
    VLOG_WARN( log, " --- *** Got a cport-status in msg from dpid:%"PRIx64" *** --- ",
               dpint);
    return STOP;
  }


  Disposition
  Circsw::handle_port_status(const Event& e) {
    const Port_status_event& pse = assert_cast<const Port_status_event&>(e);
    uint64_t dpint = pse.datapath_id.as_host();
    VLOG_WARN( log, " --- *** Got a port-status in msg from dpid:%"PRIx64" *** --- ",
               dpint);
    bool found = false;
    for ( int i=0; i<dpids.size(); i++ ) {
      if ( dpids[i] == dpint ) {
        found = true;
        break;
      }
    }
    if ( !found ) {
      return CONTINUE;
    }
    if ( (pse.reason == OFPPR_MODIFY) && (pse.port.state == OFPPS_LINK_DOWN) ) {
      VLOG_WARN( log, " reporting LINK_DOWN on port:%d ", pse.port.port_no );
      confirmLinkDown( dpint, pse );
    }
    if ( (pse.reason == OFPPR_MODIFY) && (pse.port.state == 0) ) {
      VLOG_WARN( log, " reporting LINK_UP on port:%d ", pse.port.port_no );
      confirmLinkUp( dpint, pse );
    }

    return STOP;
  }

  /*

  Disposition
  Vbpl::handle_datapath_leave(const Event& e) {
    const Datapath_leave_event& dl = assert_cast<const Datapath_leave_event&>(e);
    uint64_t dpint = dl.datapath_id.as_host();

    if( switch_db.find(dpint) != switch_db.end() ) {
      VLOG_DBG(log, "***********************************************************");
      VLOG_ERR(log, "DP leave of existing switch %"PRIx64"", dpint);
      --switchcounter;
      topoVerified = false;
      VLOG_DBG(log, "Topology down ... removing switch state");
      // switch_db.erase(dpint);
      VLOG_DBG(log, "Topology down ... removing all existing flows");
      //vbgui->removeAllFlows();
      //removeAllState();
      VLOG_DBG(log, "***********************************************************");
    }
    return CONTINUE;

  }
  */

  Disposition
  Circsw::handle_packet_in(const Event& e) {
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    uint64_t indpid = pi.datapath_id.as_host();
    uint16_t inport = pi.in_port;
    if( switch_db.find( indpid ) == switch_db.end() ) {
      //VLOG_DBG(log, "Packet-in not from a circuit switch.. passing it on");
      return CONTINUE;
    }
    //VLOG_DBG( log, "indpid:%"PRIx64" inport:%"PRIx16"", indpid, inport );
    //VLOG_DBG( log, "len:%d buf:%"PRIx32" reason:%d", pi.total_len,
    //          pi.buffer_id, pi.reason );

    Nonowning_buffer b(*pi.get_buffer());
    const eth_header* eth = b.try_pull<eth_header>();
    /*
    VLOG_DBG( log, "eth_dst:0x%x:%x:%x:%x:%x:%x",
              eth->eth_dst[0],eth->eth_dst[1],eth->eth_dst[2],
              eth->eth_dst[3],eth->eth_dst[4],eth->eth_dst[5]
              );
    VLOG_DBG( log, "eth_src:0x%x:%x:%x:%x:%x:%x",
              eth->eth_src[0],eth->eth_src[1],eth->eth_src[2],
              eth->eth_src[3],eth->eth_src[4],eth->eth_src[5]
              );
    VLOG_DBG( log, "Eth-type:0x%"PRIx16"", ntohs(eth->eth_type) );
    */

    if( eth->eth_type != ethernet::LLDP ) {
      //only handling LLDP packets for now
      VLOG_DBG( log, "PKT-IN indpid:%"PRIx64" inport:%"PRIx16"", indpid, inport );
      VLOG_WARN( log, "Packet type not LLDP..ignoring ethtype:0x%"PRIx16"",
                ntohs(eth->eth_type) );
      return STOP;
    }

    if( pi.total_len < 60 ) {
      VLOG_DBG( log, "PKT-IN indpid:%"PRIx64" inport:%"PRIx16"", indpid, inport );
      VLOG_DBG( log, "len:%d buf:%"PRIx32" reason:%d", pi.total_len,
                pi.buffer_id, pi.reason );
      VLOG_DBG( log, "Eth-type:0x%"PRIx16"", ntohs(eth->eth_type) );
      VLOG_WARN( log, "malformed lldp packet... ignoring" );
      return STOP;
    }

    lldpin* next = b.try_pull<lldpin>();
    /*
    VLOG_DBG( log, "lldp tlv typelen ch:%x:%x prt:%x:%x ttl:%x:%x end:%x:%x",
              next->type1, next->len1, next->type2, next->len2,
              next->type3, next->len3, next->type4, next->len4);
    */

    uint64_t psdpid = 0;
    if( next->value1[0] == 4 ) {
      psdpid = next->value1[6] | next->value1[5]<<8 | next->value1[4]<<16 | \
        next->value1[3]<<24 | ( (uint64_t)next->value1[2]<<32 ) | \
        ( (uint64_t)next->value1[1]<<40 );
    }
    //VLOG_DBG( log,"packet-switch dpid:%"PRIx64"", psdpid);

    uint16_t psportid = 0xffff;
    if( next->value2[0] == 2 ) {
      psportid = next->value2[1]<<8 | next->value2[2];
    }
    //VLOG_DBG( log,"packet-switch portid:%"PRIx16"", psportid);

    processPacketLink( indpid, inport, psdpid, psportid );

    return STOP;
  }

  Disposition
  Circsw::handle_Agg_msg_py(const Event& e) {
    const Agg_msg_py_event& amp = assert_cast<const Agg_msg_py_event&>(e);
    VLOG_DBG( log, "received type:0x%x xid:%d size:%d", amp.type,
              amp.xid, amp.raw_msg.get()->size() );

    if( bme_xid_db.find( amp.xid ) != bme_xid_db.end() ) {
      VLOG_DBG( log, "-- Rcvd Agg_msg_py_event from self...passing it on --" );
      VLOG_DBG( log, "-- at time:%d --", (int) time(NULL) );
      bme_xid_db.erase( amp.xid );
      return CONTINUE;
    }
    VLOG_DBG( log, "-- bookman message type is: 0x%x --", amp.type );
    bool waiting = false;
    if ( amp.type == BOOKT_BUNDLE_REQ ) {
      std::vector<uint64_t> pathvec;
      bundlereq* breq = (bundlereq*)amp.raw_msg.get()->data();
      VLOG_DBG( log, "req criteria: 0x%"PRIx32"", ntohl(breq->criteria) );
      VLOG_DBG( log, "vlanid:%d pathlen:%d", ntohl(breq->vlanid),
                ntohl(breq->pathlen) );
      for ( int i=0; i<ntohl(breq->pathlen); i++ ) {
        VLOG_DBG( log, "path: node%d: 0x%"PRIx64"", i, ntohll(breq->path[i]) );
        pathvec.push_back( ntohll(breq->path[i]) );
      }
      waiting = registerAndActOnBundle( ntohl(breq->criteria),
                                        ntohl(breq->vlanid), pathvec );

    } else if ( amp.type == BOOKT_BUNDLE_MODIFY ) {
      std::vector<uint64_t> pathv;
      bundlemod* bmod = (bundlemod*)amp.raw_msg.get()->data();
      VLOG_DBG( log, "vlanid:%d pathlen:%d", ntohl(bmod->vlanid),
                ntohl(bmod->pathlen) );
      for ( int i=0; i<ntohl(bmod->pathlen); i++ ) {
        VLOG_DBG( log, "path: node%d: 0x%"PRIx64"", i, ntohll(bmod->path[i]) );
        pathv.push_back( ntohll(bmod->path[i]) );
      }
      waiting = modifyBundle( ntohl(bmod->vlanid), pathv);

    } else if ( amp.type == BOOKT_BUNDLE_DELETE ) {
      bundledel* bdel = (bundledel*)amp.raw_msg.get()->data();
      waiting = deleteBundle( ntohl(bdel->vlanid) );

    } else if ( amp.type == BOOKT_AGGR_CLEAR ) {
      VLOG_DBG( log, "clearing dynamic links delayed" );
      VLOG_DBG( log, "--- at time:%d ---", (int) time(NULL) );
      timeval tv={10,0};
      post(boost::bind(&Circsw::clear_dynamic_vlinks, this), tv);

    } else {
      VLOG_DBG( log, "currently dont care" );
    }

    if ( waiting ) {
      // need to store info by recreating original book_message
      uint8_t size = sizeof(book_header) + amp.raw_msg.get()->size();
      bme_msg_holder.reset(new Array_buffer::Array_buffer(size));
      struct book_header bh;
      bh.type = amp.type;
      bh.xid = htonl(amp.xid);
      bh.length = htons(size);
      VLOG_DBG( log, "setting type:0x%x xid:%d size:%d", amp.type,
                amp.xid, size );
      memcpy( bme_msg_holder.get()->data(), &bh, sizeof(book_header) );
      uint8_t* bme_body = (uint8_t*)bme_msg_holder.get()->data() + sizeof(book_header);
      memcpy( bme_body, amp.raw_msg.get()->data(), amp.raw_msg.get()->size() );
      // need to post timer
      VLOG_DBG( log, "--- starting timer at time:%d ---", (int) time(NULL) );
      timeval tv={4,0};
      post(boost::bind(&Circsw::repost_book_msg, this), tv);
      // need to register seeing this event
      bme_xid_db.insert( std::make_pair(amp.xid, true) );
      return STOP;
    } else {
      return CONTINUE;
    }
  }

  void
  Circsw::repost_book_msg( void ){
    VLOG_DBG( log, "-- timer expired: returned size:%d --",
              ntohs(*( (uint16_t*)bme_msg_holder.get()->data() ) ) );
    post(new Agg_msg_py_event((book_message*) bme_msg_holder.get()->data()));
  }

  void
  Circsw::delete_vlan_rule( void ){
    struct vlandelete_elem& vde = vlandelete_db.front();
    VLOG_DBG( log, "-- timer expired: deleting vlan %d now --", vde.vlanid );
    struct vlink_elem& ve = vlink_db[vde.vlink_];
    struct vlinkpath& vlp = ve.vlpaths[vde.vlpath_];

    // ensure vlan rule is there
    bool vlanrule = false;
    for ( int k=0; k<vlp.vlpathvlans.size(); k++ ) {
      if ( vlp.vlpathvlans[k] == vde.vlanid ) {
        vlanrule = true;
        vlp.vlpathvlans.erase( vlp.vlpathvlans.begin() + k ); //and remove it
        break;
      }
    }
    if ( vlanrule ) {
      // remove vlan rules in the switches
      std::vector<node>& route1 = vlp.vlpathroutes.begin()->second;
      for( int k=0; k<route1.size(); k++ ) {
        if ( ( route1[k].nodetype == CKT_PATH_END1 ) ||
             ( route1[k].nodetype == CKT_PATH_END2 ) ) {
          addOrRemoveVlanRules( route1[k].dpid, route1[k].ethport, vde.vlanid,
                                route1[k].vcgport, false, true, false );
          VLOG_DBG( log, "Deleting vlan rule for vlan:%d in %"PRIx16"::%"PRIx16"",
                    vde.vlanid, vde.vlink_, vde.vlpath_ );
          //waiting = true;
        }
      }
    } else {
      VLOG_DBG( log, "No vlan rule to delete for vlan:%d in %"PRIx16"::%"PRIx16"",
                vde.vlanid, vde.vlink_, vde.vlpath_ );
    }
    vlandelete_db.erase( vlandelete_db.begin() );
  }

  void
  Circsw::clear_dynamic_vlinks( void ){
    // removing all dynamic virtual-link paths
    // if no vlpaths left then removes registry for vlink
    continue_monitoring = false; //reset
    wait_for_vmem_delete = wait_for_vmem_delete_; //reset
    std::vector<uint16_t> deletedlink3ids;
    std::vector<uint16_t> deletedvlpathids;
    for( std::map<uint16_t, vlink_elem>::iterator iter = vlink_db.begin();
         iter != vlink_db.end(); ++iter ) {
      int count=0;
      for( std::map<uint16_t, vlinkpath>::iterator iter2 = iter->second.vlpaths.begin();
           iter2 != iter->second.vlpaths.end(); ++iter2 ) {
        if ( iter2->second.vlpathtype != STATIC ) {
          VLOG_DBG( log, "Removing Dynamic vlinkpath::%"PRIx16":%"PRIx16"",
                    iter->first, iter2->first );
          deleteDynamicVirtualLinkPath( iter->first, iter2->first );
          deletedvlpathids.push_back( iter2->first );
          count++;
        }
      }
      if ( count == iter->second.vlpaths.size() ) {
        // all dynamic vlinkpaths deleted and there we no static vlinkpaths
        // so we should remove registry of vlink
        deletedlink3ids.push_back( iter->first );
      }
      // now remove the deleted vlink-paths from the vlpaths map for this vlink
      for( int k=0; k<deletedvlpathids.size(); k++ ) {
        vlink_db[iter->first].vlpaths.erase( deletedvlpathids[k] );
      }
    }
    for( int j=0; j<deletedlink3ids.size(); j++ ) {
      //JJJ link_db.erase( deletedlink3ids[j] );
      VLOG_WARN( log, " ----------------- vlink:%"PRIx16" DELETED ---------------",
                 deletedlink3ids[j] );
      vlink_db.erase( deletedlink3ids[j] );
    }
  }

  bool
  Circsw::registerAndActOnBundle( uint32_t criteria, uint32_t vlanid,
                                  std::vector<uint64_t> pathvec ) {
    // for what is meant by criteria see pyaggmsg.py - our interest is
    // only in determining traffic type .
    // register bundle
    struct bundle_elem be;
    if ( criteria & 0x20 ) be.bundletype = HTTP;
    else if ( criteria & 0x40 ) be.bundletype = VOIP;
    else if ( criteria & 0x2000 ) be.bundletype = VIDEO;
    else be.bundletype = ALL;
    be.pktpath = pathvec;
    bundle_db.insert( std::make_pair(vlanid, be) );
    VLOG_DBG( log, " Registered bundle %d of type %d", vlanid, be.bundletype );
    VLOG_DBG( log, " Creating new bundle" );
    return ( actOnBundle( vlanid, false ) );
  }

  bool
  Circsw::modifyBundle( uint32_t vlanid, std::vector<uint64_t> pathvec ) {
    // check if really modify
    if ( bundle_db.find(vlanid) == bundle_db.end() ) {
      VLOG_ERR( log, "Bundle %d does not exist", vlanid );
      return false;
    }
    struct bundle_elem& be = bundle_db[vlanid];
    bool pathchanged = false;
    if ( be.pktpath.size() == pathvec.size() ) {
      // need to check elem by elem
      for ( int i=0; i<pathvec.size(); i++ ) {
        if ( be.pktpath[i] != pathvec[i] ) {
          pathchanged = true;
          break;
        }
      }
    } else {
      pathchanged = true;
    }

    if( pathchanged ) {
      VLOG_DBG( log, " Bundle %d of type %d has changed paths", vlanid, be.bundletype );
      VLOG_DBG( log, " Removing old path" );
      actOnBundle( vlanid, true );
      // register new path
      be.pktpath = pathvec;
      VLOG_DBG( log, "Creating new path" );
      return ( actOnBundle( vlanid, false ) );
    } else {
      VLOG_DBG( log, " Bundle %d of type %d same ... ignoring modify",
                vlanid, be.bundletype );
      return false;
    }
  }

  bool
  Circsw::deleteBundle( uint32_t vlanid ) {
    if ( bundle_db.find(vlanid) == bundle_db.end() ) {
      VLOG_WARN( log, "Nothing to delete - bundle %d does not exist", vlanid );
      return false;
    }
    VLOG_DBG( log, " De-registering bundle %d of type %d", vlanid,
              bundle_db[vlanid].bundletype );
    bool waiting = actOnBundle( vlanid, true );
    bundle_db.erase( bundle_db.find(vlanid) );
    return waiting;
  }

  bool
  Circsw::actOnBundle( uint32_t vlanid, bool deletebundle ) {
    // Compare each hop of the pktPath to existing vlinks and paths in the vlink_db
    // A match is when the hop-ends are the same as the vlink pkt ends
    // and the bundletype is the same as the vlpathtype, or the vlpathtype
    // is STATIC ( which allows all bundletypes )
    // 1. for a match,
    //     --if deletebundle,
    //         ensure vlan is there and send commands to delay delete
    //         we do not delete vlpath here
    //     --if !deletebundle,
    //         ensure vlan not there and add
    // 2. for no match
    //     -- if deletebundle, nothing to do
    //     -- if !deletebundle, create the vlink or vlinkpath in the existing vlink
    //        depending on whether vlinkends were found or not(and WAIT)
    //           --for bundle_type == VOIP, go shortest path
    //           --for bundle_type == VIDEO, go indirect bypass path with monitoring

    bool waiting = false;
    uint32_t bundletype = bundle_db[vlanid].bundletype;
    std::vector<uint64_t>& pktpath = bundle_db[vlanid].pktpath;
    for ( int i=0; i<(pktpath.size()-1); i++ ) {
      uint64_t ethdpid1 = pktpath[i];
      uint64_t ethdpid2 = pktpath[i+1];
      VLOG_DBG( log, "comparing 0x%"PRIx64" and 0x%"PRIx64"", ethdpid1, ethdpid2 );
      bool foundvlinkends = false;
      bool foundvlpath = false;
      uint16_t link3idfound;
      uint16_t vlpathidfound;
      for( std::map<uint16_t, vlink_elem>::iterator iter = vlink_db.begin();
           iter != vlink_db.end(); ++iter ) {
        VLOG_DBG( log, "to 0x%"PRIx64" and 0x%"PRIx64"", iter->second.ethdpid1,
                  iter->second.ethdpid2 );
        if ( ( (ethdpid1 == iter->second.ethdpid1) &&
               (ethdpid2 == iter->second.ethdpid2) ) ||
             ( (ethdpid1 == iter->second.ethdpid2) &&
               (ethdpid2 == iter->second.ethdpid1) ) ) {
          foundvlinkends = true;
          link3idfound = iter->first;
          for( std::map<uint16_t, vlinkpath>::iterator iter2 = iter->second.vlpaths.begin();
               iter2 != iter->second.vlpaths.end(); ++iter2 ) {
            if ( ( (bundletype == VIDEO) && (iter2->second.vlpathtype == DYNAMIC_VIDEO) ) ||
                 ( (bundletype == VOIP)  && (iter2->second.vlpathtype == DYNAMIC_VOIP)  ) ||
                 ( (iter2->second.vlpathtype == STATIC)                                 ) ) {
              foundvlpath = true;
              vlpathidfound = iter2->first;
              break;
            }
          }
          if ( foundvlpath ) break;
        }
      }

      if ( foundvlpath ) {
        VLOG_DBG( log, "vlink:%"PRIx16"::path:%"PRIx16" found for hop:%d",
                  link3idfound, vlpathidfound, i );
        struct vlink_elem& ve = vlink_db[link3idfound];
        struct vlinkpath& vlp = ve.vlpaths[vlpathidfound];
        if ( deletebundle ) {
          struct vlandelete_elem vde = { vlanid, link3idfound, vlpathidfound };
          vlandelete_db.push_back( vde );
          VLOG_DBG( log, "vlanid: %d deletion delayed", vlanid );
          VLOG_DBG( log, "--- at time:%d ---", (int) time(NULL) );
          timeval tv={8,0};
          post(boost::bind(&Circsw::delete_vlan_rule, this), tv);
        } else {
          // !delete bundle for existing vlink == adding a bundle
          // ensure vlan is not there
          bool vlanrule = false;
          for ( int k=0; k<vlp.vlpathvlans.size(); k++ )
            if ( vlp.vlpathvlans[k] == vlanid ) vlanrule = true;
          if ( !vlanrule ) {
            // add vlan rules to the switches
            std::vector<node>& route2 = vlp.vlpathroutes.begin()->second;
            for( int k=0; k<route2.size(); k++ ) {
              if ( ( route2[k].nodetype == CKT_PATH_END1 ) ||
                   ( route2[k].nodetype == CKT_PATH_END2 ) ) {
                addOrRemoveVlanRules( route2[k].dpid, route2[k].ethport, vlanid,
                                      route2[k].vcgport, true, true, false );
                VLOG_DBG( log, "Adding vlan rule for vlan:%d in %"PRIx16"::%"PRIx16"",
                          vlanid, link3idfound, vlpathidfound );
                vlp.vlpathvlans.push_back( vlanid ); // update database with new vlanrule
                //waiting = true;
              }
            }
          } else {
            VLOG_DBG( log, "Vlan rule already there for vlan:%d in %"PRIx16"::%"PRIx16"",
                      vlanid, link3idfound, vlpathidfound );
          }
        }
        // end of actions for existing vlink paths

      } else {
        VLOG_DBG( log, "vlinkpath NOT found for hop:%d", i );
        if ( deletebundle ) {
          VLOG_DBG( log, "not deleting anything for this hop" );
        } else {
          // !deletebundle == create dynamic vlink or vlinkpath for VOIP/VIDEO bundletypes
          if ( bundletype == VOIP ) {
            if( !foundvlinkends || forcenewvlinkcreation ) {
              VLOG_DBG( log, "-- Creating vlink for VOIP bundle using shortest path --" );
              VLOG_DBG( log, "<--  at time:%d -->", (int) time(NULL) );
              if ( createDynamicVirtualLink( ethdpid1, ethdpid2, vlanid, false ) )
                waiting = true;
            } else {
              VLOG_DBG( log, "-- Creating vlink-PATH for VOIP bundle using shortest path --" );
              VLOG_DBG( log, "-- on existing vlink: %"PRIx16" --", link3idfound );
              VLOG_DBG( log, "<--  at time:%d -->", (int) time(NULL) );
              if ( createDynamicVirtualLinkPath( link3idfound, vlanid, false ) )
                waiting = true;
            }
          } else if ( bundletype == VIDEO ) {
            if( !foundvlinkends || forcenewvlinkcreation ) {
              VLOG_DBG( log, "-- Creating variable bw vlink for VIDEO bundle  --" );
              VLOG_DBG( log, "<--  at time:%d -->", (int) time(NULL) );
              if ( createDynamicVirtualLink( ethdpid1, ethdpid2, vlanid, true ) )
                waiting = true;
            } else {
              VLOG_DBG( log, "-- Creating variable bw vlink-PATH for VIDEO bundle  --" );
              VLOG_DBG( log, "-- on existing vlink: %"PRIx16" --", link3idfound );
              VLOG_DBG( log, "<--  at time:%d -->", (int) time(NULL) );
              if ( createDynamicVirtualLinkPath( link3idfound, vlanid, true ) )
                waiting = true;
            }
          }
        }
        // end of actions for non-existing vlinks or vlinkpaths

      }


    } //end of for loop for hops
    return ( waiting );
  } // end of method



  Disposition
  Circsw::handle_port_stats_in(const Event& e) {
    const Port_stats_in_event& psi = assert_cast<const Port_stats_in_event&>(e);
    uint64_t dpid = psi.datapath_id.as_host();
    int datarate = 0;
    if( ( dpid == monitordp1 ) || ( dpid == monitordp2 ) ) {
      uint16_t monitorvcg = ( dpid == monitordp1 ) ? monitorvcg1 : monitorvcg2;
      for ( std::vector<Port_stats>::const_iterator iter = psi.ports.begin();
            iter != psi.ports.end(); ++iter ) {
        if( iter->port_no == monitorvcg ) {
          if ( dpid == monitordp1 ) {
            last_tx_bytes = tx_bytes1;
            tx_bytes1 = iter->tx_bytes;
            datarate = ( (tx_bytes1-last_tx_bytes)*8/stat_polling_interval/1000000 );
          } else {
            last_tx_bytes = tx_bytes2;
            tx_bytes2 = iter->tx_bytes;
            datarate = ( (tx_bytes2-last_tx_bytes)*8/stat_polling_interval/1000000 );
          }

          if ( datarate > bw_incr_threshold ) {
            if ( dpid == monitordp1 )
              above_tx_threshold_counter1++;
            else
              above_tx_threshold_counter2++;
          } else {
            if ( dpid == monitordp1 )
              above_tx_threshold_counter1 = 0;
            else
              above_tx_threshold_counter2 = 0;
          }
          if ( datarate )
            VLOG_DBG( log, "from dpid: %"PRIx64" vcgnum: %"PRIx16", -- drate: %d Mbps",
                      dpid, monitorvcg, datarate );
          //VLOG_DBG( log, "lastTxB:%"PRId64", newTxB:%"PRId64"",
          //          last_tx_bytes, iter->tx_bytes,
          //VLOG_DBG( log, "abThDrCtr1: %d abThDrCtr2: %d", above_tx_threshold_counter1,
          //          above_tx_threshold_counter2 );
          //VLOG_DBG( log, "tx_packets:%"PRId64", rx_bytes:%"PRId64", tx_dropped:%"PRId64"",
          //          iter->tx_packets, iter->rx_bytes, iter->tx_dropped );
          break;

        }
      }

      // act on port stats to incr bw
      if ( !increased_bandwidth ) {
        if ( ( above_tx_threshold_counter1 >= num_above_tx_threshold ) ||
             ( above_tx_threshold_counter2 >= num_above_tx_threshold ) ) {
          VLOG_DBG( log, "**** CONGESTION Detected ****......adding Bandwidth ****");
          increaseBandwidth( monitorlink3id, monitorvlpathid, num_bw_incr );
          increased_bandwidth = true;
        }
      }

    } else {
     VLOG_WARN(log, "*** Strange port_stats_in from un-monitored switch ***");
    }

    return CONTINUE;

  }


  void
  Circsw::stat_req_poll( void ) {
    if ( continue_monitoring ) {
      if ( sendStatReq1 ) {
        sendStatReq1 = false;
        sendStatReq2 = true;
        sendPortStatsReq( monitordp1, monitorvcg1 );
      } else if ( sendStatReq2 ) {
        sendStatReq2 = false;
        sendStatReq1 = true;
        sendPortStatsReq( monitordp2, monitorvcg2 );
      }
      timeval tv={stat_polling_interval/2,0};
      post(boost::bind(&Circsw::stat_req_poll, this), tv);
    } else {
      VLOG_DBG( log, "no longer monitoring bandwidth usage on vlink:%"PRIx16"",
                monitorlink3id );
    }
  }


  void
  Circsw::increaseBandwidth( uint16_t link3id_, uint16_t vlpathid_, int num_cflows ) {
    uint64_t loccktsw=0, midcktsw=0, remcktsw=0;
    uint16_t loccktport=0, midtdmport1=0, midtdmport2=0, remcktport=0;
    uint16_t locvcg=0, remvcg=0;
    struct vlink_elem& vle = vlink_db[link3id_];
    struct vlinkpath& vlp = vle.vlpaths[vlpathid_];
    assert( vlp.vlpathtype == DYNAMIC_VIDEO );
    // only increasing bandwidth along the original vlpathroute
    std::vector<node>& vlpathroute = vlp.vlpathroutes.begin()->second;
    std::vector<node> routecopy = vlpathroute;
    for ( int k=0; k<vlpathroute.size(); k++ ) {
      if ( vlpathroute[k].nodetype == CKT_PATH_END1 ) {
        loccktsw   = vlpathroute[k].dpid;
        locvcg     = vlpathroute[k].vcgport;
        loccktport = vlpathroute[k].tdmport1;
      } else if ( vlpathroute[k].nodetype == CKT_PATH_END2 ) {
        remcktsw   = vlpathroute[k].dpid;
        remvcg     = vlpathroute[k].vcgport;
        remcktport = vlpathroute[k].tdmport1;
      } else if ( vlpathroute[k].nodetype == CKT_PATH_INTERMEDIATE ) {
        midcktsw   = vlpathroute[k].dpid;
        midtdmport1= vlpathroute[k].tdmport1;
        midtdmport2= vlpathroute[k].tdmport2;
      }
    }
    VLOG_DBG( log, " loc=%"PRIx64":%"PRIx16":%"PRIx16" ", loccktsw, locvcg, loccktport );
    VLOG_DBG( log, " mid=%"PRIx64":%"PRIx16":%"PRIx16" ", midcktsw, midtdmport1, midtdmport2 );
    VLOG_DBG( log, " rem=%"PRIx64":%"PRIx16":%"PRIx16" ", remcktsw, remvcg, remcktport );

    uint16_t cktlinknear, cktlinkfar;
    cktlinknear = getCktLink( loccktsw, midcktsw, loccktport, midtdmport1 );
    cktlinkfar  = getCktLink( midcktsw, remcktsw, midtdmport2, remcktport );

    uint16_t tslotnear=0xffff, tslotfar=0xffff;
    for (int  i = 0; i < num_cflows; i++ ) {
      findMatchingTimeSlots( loccktsw, loccktport, midcktsw, midtdmport1, tsig, tslotnear);
      findMatchingTimeSlots( midcktsw, midtdmport2, remcktsw, remcktport, tsig, tslotfar);
      addVcgComponent( loccktsw, locvcg, loccktport, tsig, tslotnear, false, flowid );
      if ( midcktsw )
        addXconn( midcktsw, midtdmport1, tslotnear, midtdmport2, tslotfar, tsig, flowid );
      addVcgComponent( remcktsw, remvcg, remcktport, tsig, tslotfar, false, flowid );

      // update vlinkpath with new route
      // since we have chosen to increase bandwidth along the same route
      // and assuming there is enough bandwidth available, we can simply duplicate the
      // original route with a new cflowid when updating vlinkpathroutes
      vlp.vlpathroutes.insert( std::make_pair(flowid, routecopy) );

      //update GUI
      showIndirectCflow( loccktsw, loccktport, midcktsw, midtdmport1, midtdmport2,
                         remcktsw, remcktport, VIDEO_CFLOW );

      registerVirtualLinkOnL1Link( cktlinknear, link3id_, vlpathid_, flowid, DYNAMIC_VIDEO );
      registerVirtualLinkOnL1Link( cktlinkfar, link3id_, vlpathid_, flowid, DYNAMIC_VIDEO );

      flowid++;
    }

  }

  void
  Circsw::confirmLinkDown( uint64_t dpint, const Port_status_event& pse ) {
    bool confirmeddown = false;
    uint16_t link1id_ = 0;
    for( std::map<uint16_t, link1_elem>::iterator iter = link1_db.begin();
         iter != link1_db.end(); ++iter ) {
      if ( ( (iter->second.thissw == dpint) && (iter->second.thisport == pse.port.port_no) ) ||
           ( (iter->second.thatsw == dpint) && (iter->second.thatport == pse.port.port_no) ) ) {
        confirmeddown = checkIfBroken( dpint, pse.port.port_no, iter->first );
        link1id_ = iter->first;
        break;
      }
    }

    if ( confirmeddown ) {
      VLOG_WARN( log, "Link %"PRIx16" is confirmed DOWN", link1id_ );
      reRouteVlinks( link1id_ );
    }
  }


  void
  Circsw::confirmLinkUp( uint64_t dpint, const Port_status_event& pse ) {
    bool confirmedup = false;
    uint16_t link1id_ = 0;
    for( std::map<uint16_t, link1_elem>::iterator iter = link1_db.begin();
         iter != link1_db.end(); ++iter ) {
      if ( ( (iter->second.thissw == dpint) && (iter->second.thisport == pse.port.port_no) ) ||
           ( (iter->second.thatsw == dpint) && (iter->second.thatport == pse.port.port_no) ) ) {
        confirmedup = checkIfFixed( dpint, pse.port.port_no, iter->first );
        link1id_ = iter->first;
        break;
      }
    }

    if ( confirmedup ) {
      VLOG_WARN( log, "Link %"PRIx16" is confirmed UP", link1id_ );

      // XXX update GUI of link down

    }
  }

  bool
  Circsw::checkIfFixed( uint64_t dpid, uint16_t port, uint16_t linkid_ ) {
    if ( broken_db.find( linkid_ ) != broken_db.end() ) {

      if ( !broken_db[linkid_].confirmeddown ) {
        if ( (dpid == broken_db[linkid_].confirmedsw) &&
             (port == broken_db[linkid_].confirmedport) ) {
          //report linkup and erase entry
          broken_db.erase( linkid_ );
          return true;
        } else {
          VLOG_ERR( log, "CIF:0 Mismatch in broken link database for link:%"PRIx16"",
                    linkid_ );
          return false;
        }
      } else {
        // link was previously confirmed as Down
        if ( ( (dpid == broken_db[linkid_].confirmedsw) &&
               (port == broken_db[linkid_].confirmedport) ) ||
             ( (dpid == broken_db[linkid_].farendsw) &&
               (port == broken_db[linkid_].farendport) ) ) {
          if ( broken_db[linkid_].onesideup ) {
            // report linkup and erase entry
            broken_db.erase( linkid_ );
            return true;
          } else {
            // register as onesideup
            broken_db[linkid_].onesideup = true;
            return false;
          }
        } else {
          VLOG_ERR( log, "CIF:1 Mismatch in broken link database for link:%"PRIx16"",
                    linkid_ );
          return false;
        }
      }

    } else {
      VLOG_ERR( log, "Link:%"PRIx16" reported up, but not in broken db", linkid_ );
      return false;
    }
  }

  bool
  Circsw::checkIfBroken( uint64_t dpid, uint16_t port, uint16_t linkid_ ) {
    if ( broken_db.find( linkid_ ) != broken_db.end() ) {
      if ( (broken_db[linkid_].farendsw == dpid) &&
           (broken_db[linkid_].farendport == port) ) {
        broken_db[linkid_].confirmeddown = true;
        return true;
      } else {
        VLOG_ERR( log, "CIB: Mismatch in broken link database for link:%"PRIx16"",
                  linkid_ );
        return false;
      }
    } else {
      struct broken_elem be;
      be.confirmedsw = dpid;
      be.confirmedport = port;
      assert( switch_db[dpid][0].L1links[linkid_].thisport == port );
      be.farendsw = switch_db[dpid][0].L1links[linkid_].thatsw;
      be.farendport = switch_db[dpid][0].L1links[linkid_].thatport;
      be.confirmeddown = false;
      be.onesideup = false;
      broken_db.insert( std::make_pair( linkid_, be ) );
      return false;
    }
  }

  void
  Circsw::reRouteVlinks( uint16_t link1id_ ) {
    std::map<uint16_t, regvlink> rv = link1_db[link1id_].regvlinks;
    // crude prioritization of video path recovery before voip and before http
    for( std::map<uint16_t, regvlink>::iterator iter = rv.begin();
         iter != rv.end(); ++iter ) {
      if ( iter->second.vlpathtype == DYNAMIC_VIDEO )
        reRouteCflow( iter->second );
    }
    for( std::map<uint16_t, regvlink>::iterator iter = rv.begin();
         iter != rv.end(); ++iter ) {
      if ( iter->second.vlpathtype == DYNAMIC_VOIP )
        reRouteCflow( iter->second );
    }
    for( std::map<uint16_t, regvlink>::iterator iter = rv.begin();
         iter != rv.end(); ++iter ) {
      if ( iter->second.vlpathtype == STATIC )
        reRouteCflow( iter->second );
    }
  }

  void
  Circsw::reRouteCflow( struct regvlink& rv ) {
    uint64_t loccktsw=0, midcktsw=0, remcktsw=0;
    uint16_t loccktport=0, midtdmport1=0, midtdmport2=0, remcktport=0;
    uint16_t locvcg=0, remvcg=0;
    uint16_t locethport=0, remethport=0;
    struct vlink_elem& vle = vlink_db[rv.link3id];
    struct vlinkpath& vlp = vle.vlpaths[rv.vlpathid];
    std::vector<node>& vlpr = vlp.vlpathroutes[rv.cflowid];
    for ( int k=0; k<vlpr.size(); k++ ) {
      if ( vlpr[k].nodetype == CKT_PATH_END1 ) {
        loccktsw   = vlpr[k].dpid;
        locvcg     = vlpr[k].vcgport;
        loccktport = vlpr[k].tdmport1;
        locethport = vlpr[k].ethport;
      } else if ( vlpr[k].nodetype == CKT_PATH_END2 ) {
        remcktsw   = vlpr[k].dpid;
        remvcg     = vlpr[k].vcgport;
        remcktport = vlpr[k].tdmport1;
        remethport = vlpr[k].ethport;
      } else if ( vlpr[k].nodetype == CKT_PATH_INTERMEDIATE ) {
        midcktsw   = vlpr[k].dpid;
        midtdmport1= vlpr[k].tdmport1;
        midtdmport2= vlpr[k].tdmport2;
      }
    }
    if ( midcktsw ) {
      reRouteIndirectCflow( loccktsw, midcktsw, remcktsw,
                            loccktport, midtdmport1, midtdmport2, remcktport,
                            locvcg, remvcg, rv.link3id, rv.vlpathid, rv.vlpathtype,
                            locethport, remethport, rv.cflowid );
    } else {
      reRouteDirectCflow( loccktsw, remcktsw, loccktport, remcktport,
                          locvcg, remvcg, rv.link3id, rv.vlpathid, rv.vlpathtype,
                          locethport, remethport, rv.cflowid );
    }

  }


  void
  Circsw::reRouteIndirectCflow( uint64_t loccktsw, uint64_t midcktsw, uint64_t remcktsw,
                                uint16_t loccktport, uint16_t midtdmport1, uint16_t midtdmport2,
                                uint16_t remcktport, uint16_t locvcg, uint16_t remvcg,
                                uint16_t link3id_, uint16_t vlpathid_, uint16_t vlpathtype_,
                                uint16_t locethport, uint16_t remethport, uint16_t cflowid_ ) {
    showNoCflow( cflowid_ );
    // create new circuit-flow
    uint16_t nloccktport=0, nremcktport=0;
    uint16_t tslot = 0xffff;
    uint16_t cktlinkdirect = getCktLink( loccktsw, remcktsw, nloccktport, nremcktport );
    findMatchingTimeSlots( loccktsw, nloccktport, remcktsw, nremcktport, tsig, tslot);
    addVcgComponent( loccktsw, locvcg, nloccktport, tsig, tslot, false, flowid );
    addVcgComponent( remcktsw, remvcg, nremcktport, tsig, tslot, false, flowid );
    registerVirtualLinkOnL1Link( cktlinkdirect, link3id_, vlpathid_, flowid, vlpathtype_ );
    showCflow( loccktsw, nloccktport, remcktsw, nremcktport, vlpathtype_+1 );
    addNodesToPath( link3id_, vlpathid_, loccktsw, CKT_PATH_END1, locethport,
                    locvcg, nloccktport, 0xffff, flowid );
    addNodesToPath( link3id_, vlpathid_, remcktsw, CKT_PATH_END2, remethport,
                    remvcg, nremcktport, 0xffff, flowid );
    flowid++;

    // delete old circuit-flow
    deleteVcgComponent( loccktsw, locvcg, cflowid_ );
    deleteVcgComponent( remcktsw, remvcg, cflowid_ );
    deleteXconn( midcktsw, cflowid_ );
    std::vector<uint16_t> cflowids;
    cflowids.push_back( cflowid_ );
    deRegisterVirtualLinkOnL1Link( cflowids );
    vlink_db[link3id_].vlpaths[vlpathid_].vlpathroutes.erase( cflowid_ );
  }

  void
  Circsw::reRouteDirectCflow( uint64_t loccktsw, uint64_t remcktsw, uint16_t loccktport,
                              uint16_t remcktport, uint16_t locvcg, uint16_t remvcg,
                              uint16_t link3id_, uint16_t vlpathid_, uint16_t vlpathtype_,
                              uint16_t locethport, uint16_t remethport, uint16_t cflowid_ ) {
    uint16_t cktlinknear=0, cktlinkfar=0;
    uint16_t nloccktport=0, nremcktport=0, midtdmport1=0, midtdmport2=0;
    uint64_t midcktsw=0;
    bool foundindirectpath = false;
    for ( int i= 0; i<dpids.size(); i++ ) {
      if ( (dpids[i] == loccktsw) || (dpids[i] == remcktsw) ) {
        continue;
      } else {
        midcktsw = dpids[i];
        cktlinknear = getCktLink( loccktsw, midcktsw, nloccktport, midtdmport1 );
        cktlinkfar  = getCktLink( midcktsw, remcktsw, midtdmport2, nremcktport );
        if ( (cktlinknear >= 0x1000) && (cktlinknear < 0x2000) &&
             (cktlinkfar  >= 0x1000) && (cktlinkfar  < 0x2000) ) {
          foundindirectpath = true;
          break;
        }
      }
    }
    if ( foundindirectpath ) {
      showNoCflow( cflowid_ );
      // create new circuit-flow
      uint16_t tslotnear=0xffff, tslotfar=0xffff;
      findMatchingTimeSlots( loccktsw, nloccktport, midcktsw, midtdmport1, tsig, tslotnear);
      findMatchingTimeSlots( midcktsw, midtdmport2, remcktsw, nremcktport, tsig, tslotfar);
      addVcgComponent( loccktsw, locvcg, nloccktport, tsig, tslotnear, false, flowid );
      addXconn( midcktsw, midtdmport1, tslotnear, midtdmport2, tslotfar, tsig, flowid );
      addVcgComponent( remcktsw, remvcg, nremcktport, tsig, tslotfar, false, flowid );
      registerVirtualLinkOnL1Link( cktlinknear, link3id_, vlpathid_, flowid, vlpathtype_ );
      registerVirtualLinkOnL1Link( cktlinkfar, link3id_, vlpathid_, flowid, vlpathtype_ );
      showIndirectCflow( loccktsw, nloccktport, midcktsw, midtdmport1, midtdmport2,
                         remcktsw, nremcktport, vlpathtype_+1 );
      addNodesToPath( link3id_, vlpathid_, loccktsw, CKT_PATH_END1, locethport,
                      locvcg, nloccktport, 0xffff, flowid );
      addNodesToPath( link3id_, vlpathid_, midcktsw, CKT_PATH_INTERMEDIATE, 0xffff,
                      0xffff, midtdmport1, midtdmport2, flowid );
      addNodesToPath( link3id_, vlpathid_, remcktsw, CKT_PATH_END2, remethport,
                      remvcg, nremcktport, 0xffff, flowid );
      flowid++;

      // delete old circuit-flow
      deleteVcgComponent( loccktsw, locvcg, cflowid_ );
      deleteVcgComponent( remcktsw, remvcg, cflowid_ );
      std::vector<uint16_t> cflowids;
      cflowids.push_back( cflowid_ );
      deRegisterVirtualLinkOnL1Link( cflowids );
      vlink_db[link3id_].vlpaths[vlpathid_].vlpathroutes.erase( cflowid_ );
    }
  }

  /*

  Disposition
  Vbpl::handle_L1flow_drag(const Event& e) {
    const L1_flow_drag_event& fde = assert_cast<const L1_flow_drag_event&>(e);
    uint32_t dragflowid = fde.flowid;
    std::vector<uint64_t> waypath = fde.dpids;

    VLOG_DBG(log, "##### A flow drag just happened for flow:%d ####", dragflowid);
    vbgui->removeAFlow( dragflowid, true );
    if ( waypath.size() == 2 ) {
      increaseBandwidth( 1, INDIRECT );
      sleep( pause );
      decreaseBandwidth( dragflowid, DIRECT );
      vbgui->removeAFlow( dragflowid, false );
    } else {
      increaseBandwidth( 1, DIRECT );
      sleep( pause );
      decreaseBandwidth( dragflowid, INDIRECT );
      vbgui->removeAFlow( dragflowid, false );
    }

    return CONTINUE;
  }

  void
  Vbpl::decreaseBandwidth( uint32_t dragflowid, uint32_t pathchoice ) {

    //send vcg component delete to ingress and egress switch
    deleteVcgComponent( ingressdp, ingressvcg, dragflowid );
    deleteVcgComponent( monitordp, monitorvcg, dragflowid );

    if( pathchoice == INDIRECT ) {
      uint64_t dpid = dpids[0]; //(2)
      deleteXconn( dpid, dragflowid );
    }

  }

  */

  ////////////////////////////////////////////////////////////////////////////////////////
  //////////////////////// Hybrid Packet-Circuit Switch API //////////////////////////////
  ////////////////////////////////////////////////////////////////////////////////////////

  void
  Circsw::addXconn( uint64_t dpid, uint16_t in_tport, uint16_t m_tstart,
                    uint16_t out_tport, uint16_t t_tstart, uint32_t tsignal,
                    uint32_t flowid_ ) {
    struct ofp_tdm_port mpt = { in_tport, m_tstart, tsignal };
    struct ofp_tdm_port tpt = { out_tport, t_tstart, tsignal };
    if( sendXconn(dpid, mpt, tpt, true) ) {
      updateTslots(dpid, mpt, false);
      updateTslots(dpid, tpt, false);
      updateXconnsWithCflow(dpid, mpt, tpt, true, flowid_);
    }
  }

  void
  Circsw::deleteXconn( uint64_t dpid, uint32_t dragflowid ) {
    struct switch_elem& sw = switch_db[dpid][0];
    bool deleted = false;
    for ( int i = 0; i < sw.xconns.size(); i++ ) {
      if ( sw.xconns[i].flowid == dragflowid ) {
        struct ofp_tdm_port t1 = sw.xconns[i].tport1;
        struct ofp_tdm_port t2 = sw.xconns[i].tport2;
        sendXconn( dpid, t1, t2, false );
        updateTslots(dpid, t1, true);
        updateTslots(dpid, t2, true);
        updateXconnsWithCflow(dpid, t1, t2, false, dragflowid);
        deleted = true;
        break;
      }
    }
    if ( !deleted ) {
      VLOG_WARN( log, "No xconn for flow:%d in dpid:%"PRIx64"",
                 dragflowid, dpid );
    }
  }

  bool
  Circsw::sendXconn( uint64_t dpid, struct ofp_tdm_port& mpt, \
                   struct ofp_tdm_port& tpt, bool addormodify ) {
    struct ofp_cflow_mod* cflowX;
    size_t size = sizeof( *cflowX ) + ( 2*sizeof(struct ofp_tdm_port) );
    boost::shared_array<char> raw_of(new char[size]);
    cflowX = (ofp_cflow_mod*) raw_of.get();
    memset( cflowX, 0, sizeof(ofp_cflow_mod) );

    cflowX->header.version = OFP_VERSION;
    cflowX->header.type = OFPT_CFLOW_MOD;
    cflowX->header.length = htons(size);
    if ( addormodify ) cflowX->command = htons(OFPFC_ADD);
    else cflowX->command = htons(OFPFC_DELETE_STRICT);
    cflowX->hard_timeout = htons(0);
    cflowX->connect.wildcards = htons(0x0033);
    cflowX->connect.num_components = htons(1);

    struct ofp_tdm_port* intp = (struct ofp_tdm_port*)cflowX->connect.in_port;
    intp->tport = htons(mpt.tport);
    intp->tstart = htons(mpt.tstart);
    intp->tsignal = htonl(mpt.tsignal);

    struct ofp_tdm_port* outtp = ++intp;
    outtp->tport = htons(tpt.tport);
    outtp->tstart = htons(tpt.tstart);
    outtp->tsignal = htonl(tpt.tsignal);

    VLOG_DBG( log, "Sending Xconn to dpid %"PRIx64" to add:%d or del:%d", \
              dpid, addormodify, !addormodify );
    VLOG_DBG( log, "In_port data: p %"PRIx16", start(d) %d, sgnl %"PRIx16"", \
              mpt.tport, mpt.tstart, mpt.tsignal );
    VLOG_DBG( log, "Out_port data: p %"PRIx16", start(d) %d, sgnl %"PRIx16"",  \
              tpt.tport, tpt.tstart, tpt.tsignal );

    if(send_openflow_command(switch_db[dpid][0].datapath_id, &cflowX->header, true)) {
      VLOG_ERR(log, "*** Could not make or remove xconn ***");
      return false;
    }

    return true;
  }

  void
  Circsw::sendPortStatsReq( uint64_t dpid, uint16_t vcgnum ) {
    struct ofp_stats_request *statReq;
    size_t size = sizeof( *statReq );
    boost::shared_array<char> raw_of(new char[size]);
    statReq = (ofp_stats_request*) raw_of.get();
    memset( statReq, 0, sizeof(ofp_stats_request) );

    statReq->header.version = OFP_VERSION;
    statReq->header.type = OFPT_STATS_REQUEST;
    statReq->header.length = htons(sizeof(*statReq));
    statReq->type = htons(OFPST_PORT);
    statReq->flags = htons( vcgnum ); // overloading flags - changed in 1.0
    if(send_openflow_command(switch_db[dpid][0].datapath_id, &statReq->header, true))
      VLOG_ERR(log, "*** Could not send port stat request ***");
  }


  uint16_t
  Circsw::findInternalPort( uint64_t dpid, uint16_t ethintf ) {
    // this function is useful only if there is more than one Ethernet linecard
    struct switch_elem& sw = switch_db[dpid][0];
    for ( std::map<uint16_t, CPort>::const_iterator iter = sw.internalports.begin();
          iter != sw.internalports.end(); ++iter ) {
      int i = 0, counter = 0;
      bool found = false;
      while( true ) {
        if( sw.ethports[ethintf].name[i] !=
            sw.internalports[iter->first].name[i] )
          break;
        if( sw.ethports[ethintf].name[i] == 0x2d )
          counter++;
        if( counter == 3 ) {
          found = true;
          break;
        }
        i++;
      }
      if ( found ) {
        return iter->first;
      }
    }
    VLOG_ERR( log, "Internal Port not found for ethintf:%"PRIx16"", ethintf );
    return 0;
  }


  uint16_t
  Circsw::createEmptyVcg( uint64_t switchid, uint16_t internalport ) {
    // NOTE: an empty VCG is defined as one in which a single mapper signal has been
    // allocated but has not yet been cross-connected. Thus component_cflows is
    // still empty and num_components is still 0, in the vcgPort struct.
    vcgPort vcgport;
    memset( &vcgport, 0, sizeof(vcgPort) );
    uint16_t vcgnum;
    for( vcgnum = switch_db[switchid][0].nextvcgnum; vcgnum < 0xff00; vcgnum++ ) {
      if( switch_db[switchid][0].vcgports.find(vcgnum) == \
          switch_db[switchid][0].vcgports.end() )
        break;
    }
    if( vcgnum == 0xff00 ) {
      VLOG_ERR(log, "*** Could not create VCG - all nums taken ***");
      return 0;
    }

    vcgport.vcgnum = vcgnum;
    vcgport.num_components = 0;
    vcgport.internal_port = internalport;
    vcgport.m_tstart = 0xffff;
    bool mfound = findStartTslot(switch_db[switchid][0], internalport, \
                                 tsig, vcgport.m_tstart);
    if (mfound) {
      VLOG_DBG( log, "Added VCG#%"PRIx16" <--> Mapper#%"PRIx16" in dp:%"PRIx64"",\
             vcgnum, internalport, switchid );
      VLOG_DBG( log, " Starting internal port timeslot: %d", vcgport.m_tstart);
    } else {
      VLOG_ERR(log, "*** Could not create VCG - no mapper slot found ***");
    }
    switch_db[switchid][0].vcgports.insert( std::make_pair(vcgnum, vcgport) );
    sendEmptyVcg( switchid, 0, vcgnum );
    switch_db[switchid][0].nextvcgnum = vcgnum+1;
    return vcgnum;

  }

  void
  Circsw::sendEmptyVcg( uint64_t dpid, uint16_t htimeout, uint16_t vcgnum ) {
    struct ofp_cflow_mod* cflow;
    size_t size = sizeof( *cflow ) + sizeof(uint16_t) + sizeof(struct ofp_tdm_port) \
      + sizeof(struct ofp_action_ckt_output);
    boost::shared_array<char> raw_of(new char[size]);
    cflow = (ofp_cflow_mod*) raw_of.get();
    memset( cflow, 0, sizeof(ofp_cflow_mod) );

    cflow->header.version = OFP_VERSION;
    cflow->header.type = OFPT_CFLOW_MOD;
    cflow->header.length = htons(size);
    cflow->command = htons(OFPFC_ADD);
    cflow->hard_timeout = htons(htimeout);
    cflow->connect.wildcards = htons(0x0036);
    cflow->connect.num_components = htons(1);
    cflow->connect.in_port[0] = htons(vcgnum);

    void* temp = (char *)cflow->connect.in_port + sizeof(uint16_t);
    struct ofp_tdm_port* tp = ( struct ofp_tdm_port* ) temp;
    tp->tport = htons(switch_db[dpid][0].vcgports[vcgnum].internal_port);
    tp->tstart = htons(switch_db[dpid][0].vcgports[vcgnum].m_tstart);
    tp->tsignal = htonl(tsig);

    ofp_action_ckt_output *act = (ofp_action_ckt_output *)(++tp);
    act->type = htons(OFPAT_CKT_OUTPUT);
    act->len = htons(24);
    if(switch_db[dpid][0].suppGfp)
      act->adaptation = htons(OFPCAT_GFP);
    if(switch_db[dpid][0].suppLcas)
      act->tlcas_enable = htons(1);
    act->cport = htons(switch_db[dpid][0].vcgports[vcgnum].internal_port);

    if(send_openflow_command(switch_db[dpid][0].datapath_id, &cflow->header, true))
      VLOG_ERR(log, "*** Could not send cflow_mod for empty vcg creation ***");

  }

  bool
  Circsw::addVcgComponent( uint64_t dpid, uint16_t vcgnum, uint16_t tport,
                           uint32_t tsig, uint16_t t_tstart, bool firsttime,
                           uint32_t flowid_ ) {
    // This funtion will find an internal port time-slot but it needs to be told
    // the sonet port timeslot as the latter must match the time-slot at the other
    // end of the circuit
    struct switch_elem& sw = switch_db[dpid][0];
    uint16_t mport = sw.vcgports[vcgnum].internal_port;
    uint16_t m_tstart = 0xffff;
    bool mfound = false;

    if (firsttime) {
      // mapper slots have already been sent on creation of vcg
      mfound = true;
      m_tstart = sw.vcgports[vcgnum].m_tstart;
    } else {
      mfound = findStartTslot(sw, mport, tsig, m_tstart);
    }
    struct ofp_tdm_port mpt = { mport, m_tstart, tsig };
    struct ofp_tdm_port tpt = { tport, t_tstart, tsig };
    if( mfound ) {
      if ( !firsttime ) {
        if( !sendVcgComponent( dpid, vcgnum, 0,  mpt, true ) ) return false;
        sleep( pause ); //XXX is this required?
      }
      if( !sendXconn( dpid, mpt, tpt, true ) ) {
        // to be clean, should delete vcg mapper slots already sent
        if ( !firsttime ) sendVcgComponent( dpid, vcgnum, 0,  mpt, false );
        return false;
      }
    } else {
      VLOG_WARN( log, "*** No available mapper ts; dpid:%"PRIx64" VCG:%"PRIx16"", \
                 dpid, vcgnum );
      return false;
    }

    // if it gets here then adding was sucessful - update database
    // if it doesn't get here then it returned false, but the calling function
    // does not have to cleanup as no state in controller or switch changed

    updateTslots(dpid, mpt, false);
    updateTslots(dpid, tpt, false);
    updateVcgWithCflow(dpid, vcgnum, mpt, tpt, true, flowid_);

    return true;
  }

  void
  Circsw::deleteVcgComponent( uint64_t dpid, uint16_t vcgnum, uint32_t dragflowid ) {
    if( switch_db[dpid][0].vcgports.find(vcgnum) != \
        switch_db[dpid][0].vcgports.end() ) {
      bool deleted = false;
      vcgPort& vcgp = switch_db[dpid][0].vcgports[vcgnum];
      for ( std::vector<cflow>::iterator iter = vcgp.component_cflows.begin();
            iter != vcgp.component_cflows.end(); ++iter ) {
        if( iter->flowid == dragflowid ) {
          ofp_tdm_port t1 = iter->tport1;
          ofp_tdm_port t2 = iter->tport2;
          sendXconn( dpid, t1, t2, false );
          // delay the deletion of the vcg component
          struct vcgcompdelete_elem vcde = { dpid, vcgnum, t1 };
          vcgcompdelete_db.push_back( vcde );
          timeval tv={++wait_for_vmem_delete,0};
          VLOG_DBG( log, "Delaying delete of vcg member by %d secs",
                    wait_for_vmem_delete );
          post(boost::bind(&Circsw::deleteVcgMember, this), tv);
          deleted = true;
          updateTslots( dpid, t2, true );
          updateVcgWithCflow(dpid, vcgnum, t1, t2, false, dragflowid);
          break;
        }
      }
      if( !deleted ) {
        VLOG_ERR( log, "dpid:%"PRIx64" VCG:%"PRIx16" flow %d not found...", \
                  dpid, vcgnum, dragflowid );
      }

    } else {
      VLOG_ERR( log, "dpid:%"PRIx64" VCG:%"PRIx16" not found...",   \
                dpid, vcgnum );
    }

  }

  void
  Circsw::deleteVcgMember( void ) {
    if ( vcgcompdelete_db.size() ) {
      sendVcgComponent( vcgcompdelete_db[0].dpid, vcgcompdelete_db[0].vcgnum,
                        0, vcgcompdelete_db[0].t1, false );
      updateTslots( vcgcompdelete_db[0].dpid, vcgcompdelete_db[0].t1, true );
      vcgcompdelete_db.erase( vcgcompdelete_db.begin() );
    }
  }

  bool
  Circsw::sendVcgComponent( uint64_t dpid, uint16_t vcgnum, uint16_t htimeout, \
                          struct ofp_tdm_port& mpt, bool addormodify ) {
    struct ofp_cflow_mod* cflow;
    size_t size = sizeof( *cflow ) + sizeof(uint16_t) + \
      (sizeof( struct ofp_tdm_port));
    boost::shared_array<char> raw_of(new char[size]);
    cflow = (ofp_cflow_mod*) raw_of.get();
    memset( cflow, 0, sizeof(ofp_cflow_mod) );

    cflow->header.version = OFP_VERSION;
    cflow->header.type = OFPT_CFLOW_MOD;
    cflow->header.length = htons(size);
    if ( addormodify ) cflow->command = htons(OFPFC_MODIFY_STRICT);
    else cflow->command = htons(OFPFC_DELETE_STRICT);
    cflow->hard_timeout = htons(htimeout);
    cflow->connect.wildcards = htons(0x0036);
    cflow->connect.num_components = htons(1);
    cflow->connect.in_port[0] = htons(vcgnum);

    void* temp = (char *)cflow->connect.in_port + sizeof(uint16_t);
    struct ofp_tdm_port* tp = ( struct ofp_tdm_port* ) temp;
    tp->tport = htons(mpt.tport);
    tp->tstart = htons(mpt.tstart);
    tp->tsignal = htonl(mpt.tsignal);

    VLOG_DBG( log, "Sending VCG %"PRIx16" component dpid %"PRIx64" add:%d del:%d",\
              vcgnum, dpid, addormodify, !addormodify );
    VLOG_DBG( log, "Mapper data: %"PRIx16", start(d) %d sgnl %"PRIx16"", \
              mpt.tport, mpt.tstart, mpt.tsignal );

    if(send_openflow_command(switch_db[dpid][0].datapath_id, &cflow->header, true)) {
      VLOG_ERR(log, "*** Could not send cflow_mod for vcg add or delete***");
      return false;
    }

    return true;
  }


  bool
  Circsw::findMatchingTimeSlots( uint64_t loccktsw, uint16_t loccktport,
                                 uint64_t remcktsw, uint16_t remcktport,
                                 uint32_t tsig, uint16_t& startts) {
    struct switch_elem& sw1 = switch_db[loccktsw][0];
    struct switch_elem& sw2 = switch_db[remcktsw][0];
    uint16_t init1, init2;
    findStartTslot( sw1, loccktport, tsig, init1 );
    findStartTslot( sw2, remcktport, tsig, init2 );
    VLOG_DBG( log, "port%d:%d port%d:%d", loccktport, init1, remcktport, init2 );
    if ( init1 == init2 ) {
      startts = init1;
      VLOG_DBG( log, "matching time slot:%d", init1 );
      return true;
    }
    struct switch_elem& testsw = sw1;
    struct switch_elem& querysw = sw2;
    uint64_t testdpid, querydpid;
    uint16_t testp, queryp, init;
    if ( init1 > init2 ) {
      if ( !usedTimeSlot(sw2, remcktport, tsig, init1) ) {
        startts = init1;
        VLOG_DBG( log, "matching time slot:%d", init1 );
        return true;
      }
      testsw = sw1; testp = loccktport; testdpid = loccktsw;
      querysw = sw2; queryp = remcktport; querydpid = remcktsw;
      init = init1;
    } else {
      if ( !usedTimeSlot(sw1, loccktport, tsig, init2) ) {
        startts = init2;
        VLOG_DBG( log, "matching time slot:%d", init2 );
        return true;
      }
      testsw = sw2; testp = remcktport; testdpid = remcktsw;
      querysw = sw1; queryp = loccktport; querydpid = loccktsw;
      init = init2;
    }
    ofp_tdm_port tdmp;
    tdmp.tsignal = tsig;
    tdmp.tport = testp;
    tdmp.tstart = init;
    uint16_t tryslot = 0;
    std::vector<ofp_tdm_port> tempslots;
    int x=0;
    //VLOG_DBG( log, "testp:%d init:%d", testp, init );
    while( true ) {
      // temp update as 'used' on test sw
      updateTslots( testdpid, tdmp, false );
      // register the slots that were temporarily marked 'used'
      tempslots.push_back( tdmp );
      findStartTslot( testsw, testp, tsig, tryslot );
      if ( !usedTimeSlot(querysw, queryp, tsig, tryslot) ) {
        //release all temp registered slots
        int size = tempslots.size();
        for ( int i=0; i<size; i++ ) {
          updateTslots( testdpid, tempslots.back(), true );
          tempslots.pop_back();
        }
        startts = tryslot;
        VLOG_DBG( log, "matching time slot:%d", tryslot );
        return true;
      }
      tdmp.tstart = tryslot;
      if (++x == 32) assert(0);
    }
    return false;
  }

  bool
  Circsw::findStartTslot(struct switch_elem& sw, uint16_t port, uint32_t tsig, \
                 uint16_t& tstart) {
    CPort* cp;
    if( port < OFPP_MAX )
      cp = &sw.tdmports[port];
    else
      cp = &sw.internalports[port];
    uint64_t mask;
    int shift;
    switch ( tsig )
      {
      case OFPTSG_STS_1:
        mask = 0x1;
        shift = 1;
        for (int i = 0; i < 30; i++ ) {
          if( cp->bwbmp1 & ( mask << (shift * i) ) ) {
            tstart =  shift * i;
            return true;
          }
        }
        return false;
      case OFPTSG_STS_3c:
        mask = 0x7;
        shift = 3;
        for (int i = 0; i < 10; i++ ) {
          if( ( cp->bwbmp1 & ( mask << (shift * i) ) ) == \
              ( mask << (shift * i) ) ) {
            tstart = shift * i;
            return true;
          }
        }
      default: return false;
      }
    // should not get here - XXX currently very incomplete but ok for demo
    assert(0);
  }

  bool
  Circsw::usedTimeSlot( struct switch_elem& sw, uint16_t port,
                        uint32_t tsig, uint16_t tstart ) {
    CPort* cp;
    if( port < OFPP_MAX )
      cp = &sw.tdmports[port];
    else
      cp = &sw.internalports[port];
    uint64_t mask;
    switch ( tsig )
      {
      case OFPTSG_STS_1:
        mask = 0x1;
        if( cp->bwbmp1 & (mask<<tstart) )
          return false;

      case OFPTSG_STS_3c:
        mask = 0x7;
        if( (cp->bwbmp1 & (mask<<tstart)) == \
              (mask<<tstart) )
          return false;
      default: return true;
      }
  }

  void
  Circsw::updateTslots( uint64_t dpid, struct ofp_tdm_port& tpt, bool turnon ) {
    struct switch_elem& sw = switch_db[dpid][0];
    CPort* cp;
    if( tpt.tport < OFPP_MAX )
      cp = &sw.tdmports[tpt.tport];
    else
      cp = &sw.internalports[tpt.tport];
    uint64_t mask = 0x0;
    switch ( tpt.tsignal )
      {
      case OFPTSG_STS_1:
        mask = 0x1 << tpt.tstart;
        break;
      case OFPTSG_STS_3c:
        mask = 0x7 << tpt.tstart;
        break;
      }
    cp->bwbmp1 = ( turnon )? cp->bwbmp1 | mask : cp->bwbmp1 & ~mask;
    VLOG_DBG( log, "updated tslots on dp %"PRIx64" port 0x%"PRIx16" %"PRIx64"", \
              dpid, tpt.tport,  cp->bwbmp1 );

  }

  void
  Circsw::updateVcgWithCflow( uint64_t dpid, uint16_t vcgnum, struct ofp_tdm_port& mpt,\
                            struct ofp_tdm_port& tpt, bool insert, uint32_t flowid_ ) {
    vcgPort& vp = switch_db[dpid][0].vcgports[vcgnum];
    if( insert ) {
      cflow cf = { { mpt.tport, mpt.tstart, mpt.tsignal } , \
                   { tpt.tport, tpt.tstart, tpt.tsignal } , \
                   flowid_ } ;
      vp.component_cflows.push_back(cf);
      vp.num_components++;
      VLOG_DBG( log, "dpid: %"PRIx64" updated VCG %"PRIx16" with Cflow insert flowid: %d", \
                dpid, vcgnum, flowid_ );
    } else {
    int size = vp.component_cflows.size();
      for ( std::vector<cflow>::iterator iter = vp.component_cflows.begin();
            iter != vp.component_cflows.end(); ++iter ) {
        if( (iter->tport1.tport == mpt.tport) && (iter->tport2.tport == tpt.tport) &&
            (iter->tport1.tstart == mpt.tstart) && (iter->tport2.tstart == tpt.tstart)
            ) {
          iter = vp.component_cflows.erase(iter);
          break;
        }
      }
      if ( size == vp.component_cflows.size() ) {
        VLOG_ERR( log, "*** could not find cflow to erase in vcgport %"PRIx16" ***",\
                  vcgnum );
      } else {
        // erase done, update num_components - check if erased one was last
        vp.num_components--;
        VLOG_DBG( log, "dpid: %"PRIx64" updated VCG %"PRIx16" with Cflow delete: %d",\
                  dpid, vcgnum, flowid_ );
        if (vp.num_components == 0) {
          VLOG_DBG( log, "deleted last component in vcgport - removing virtual port: %d",\
                    vcgnum );
          if ( (vp.num_pflows_in) || (vp.num_pflows_out) ) {
            VLOG_WARN( log, "*** Packet flows still mapped to deleted virtual port: %d ***", \
                       vcgnum );
            VLOG_WARN( log, "*** Removing them now ***" );

            if ( vp.num_pflows_in ) {
              int totalpflowsin = vp.num_pflows_in;
              std::vector<pflow> pin = vp.component_pflows_in;
              for ( int k = 0; k < totalpflowsin; k++ ) {
                uint16_t vlanid1 = pin[k].vlanid;
                uint16_t ethport1 = pin[k].ethport;
                bool matchtag1 = pin[k].matchtag;
                sendPflowOutToVcg( dpid, ethport1, vlanid1, vcgnum, 0, false,
                                   matchtag1, false );
                //sleep( pause );
              }
            }
            if ( vp.num_pflows_out ) {
              int totalpflowsout = vp.num_pflows_out;
              std::vector<pflow> po = vp.component_pflows_out;
              for ( int j = 0; j < totalpflowsout; j++ ) {
                uint16_t vlanid2 = po[j].vlanid;
                uint16_t ethport2 = po[j].ethport;
                bool matchtag2 = po[j].matchtag;
                sendPflowOutToEth( dpid, vcgnum, vlanid2, ethport2,
                                   false, matchtag2, false );
                //sleep( pause );
              }
            }

          }
          // now we can erase record for vcgport
          switch_db[dpid][0].vcgports.erase(vcgnum);

        } // non-zero num_components - no need to do anything
      } // num_components updated & checked for empty vcg
    } // erase component cflow
  }

  void
  Circsw::updateVcgWithPflow( uint64_t dpid, uint16_t vcgnum, uint16_t ethport,
                              uint16_t vlanid, bool insert, bool incoming,
                              bool matchtag ) {
    vcgPort& vp = switch_db[dpid][0].vcgports[vcgnum];
    if( insert ) {
      pflow pf = { ethport, vlanid, matchtag };
      if (incoming) {
        vp.component_pflows_in.push_back( pf );
        vp.num_pflows_in++;
      } else {
        vp.component_pflows_out.push_back( pf );
        vp.num_pflows_out++;
      }
    } else {
      if (incoming) {
        int sizei = vp.component_pflows_in.size();
        for ( std::vector<pflow>::iterator iter = vp.component_pflows_in.begin();
              iter != vp.component_pflows_in.end(); ++iter ) {
          if( (iter->ethport == ethport) && (iter->vlanid == vlanid) &&
              (iter->matchtag == matchtag) ) {
            iter = vp.component_pflows_in.erase(iter);
            break;
          }
        }
        if ( sizei == vp.component_pflows_in.size() ) {
          VLOG_ERR( log, "*** could not find pflow_in to erase in vcgport %"PRIx16" ***", \
                    vcgnum );
        } else {
          vp.num_pflows_in--;
        }
      } else {
        int sizeo = vp.component_pflows_out.size();
        for ( std::vector<pflow>::iterator iter = vp.component_pflows_out.begin();
              iter != vp.component_pflows_out.end(); ++iter ) {
          if( (iter->ethport == ethport) && (iter->vlanid == vlanid) &&
              (iter->matchtag == matchtag) ) {
            iter = vp.component_pflows_out.erase(iter);
            break;
          }
        }
        if ( sizeo == vp.component_pflows_out.size() ) {
          VLOG_ERR( log, "*** could not find pflow_out to erase in vcgport %"PRIx16" ***", \
                    vcgnum );
        } else {
          vp.num_pflows_out--;
        }
      }
    } // removing from database
    VLOG_DBG( log, "dpid: %"PRIx64" updated VCG %"PRIx16" with Pflow", dpid, vcgnum );

  }

  void
  Circsw::updateXconnsWithCflow( uint64_t dpid, struct ofp_tdm_port& mpt, \
                               struct ofp_tdm_port& tpt, bool insert,   \
                               uint32_t flowid_ ) {
    std::vector<cflow>& xc = switch_db[dpid][0].xconns;
    if( insert ) {
      cflow cf = { { mpt.tport, mpt.tstart, mpt.tsignal },     \
                   { tpt.tport, tpt.tstart, tpt.tsignal },     \
                   flowid_ } ;
      xc.push_back(cf);
      VLOG_DBG( log, "dpid: %"PRIx64" updated Xconn with Cflow insert: %d", \
                dpid, flowid_ );
    } else {
      int size = xc.size();
      for ( std::vector<cflow>::iterator iter = xc.begin(); iter != xc.end(); \
            ++iter ) {
        if( (iter->tport1.tport == mpt.tport) && (iter->tport2.tport == tpt.tport) &&
            (iter->tport1.tstart == mpt.tstart) && (iter->tport2.tstart == tpt.tstart)
            ) {
          iter = xc.erase(iter);
          break;
        }
      }
      if ( size == xc.size() ) {
        VLOG_ERR( log, "*** could not find cflow to erase in xconns" );
      } else {
        VLOG_DBG( log, "dpid: %"PRIx64" updated Xconn with Cflow delete: %d", \
                  dpid, flowid_ );
      }
    }

  }

  bool
  Circsw::sendPflowOutToEth( uint64_t dpid, uint16_t vcgnum, uint16_t vlanid,
                             uint16_t ethport, bool addormodify,
                             bool matchtag, bool striptag ) {
    ofp_flow_mod* ofm;
    size_t size;
    if ( addormodify ) {
      if (vlanid && striptag)
        size = sizeof( *ofm ) + ( 2 * sizeof(struct ofp_action_header) );
      else
        size = sizeof( *ofm ) + sizeof(struct ofp_action_header) ;
    } else {
      size = sizeof( *ofm );
    }
    boost::shared_array<char> raw_of(new char[size]);
    ofm = (ofp_flow_mod*) raw_of.get();
    memset( ofm, 0, sizeof(ofp_flow_mod) );

    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(size);
    if (vlanid && matchtag)
      ofm->match.wildcards = htonl( OFPFW_ALL & ~OFPFW_IN_PORT & ~OFPFW_DL_VLAN );
    else
      ofm->match.wildcards = htonl( OFPFW_ALL & ~OFPFW_IN_PORT );
    ofm->match.in_port = htons( vcgnum );
    ofm->match.dl_vlan = htons( vlanid );
    if ( addormodify ) ofm->command = htons(OFPFC_ADD);
    else ofm->command = htons(OFPFC_DELETE_STRICT);
    ofm->idle_timeout = htons(0);
    ofm->hard_timeout = htons(0);
    ofm->priority = htons(0);
    ofm->buffer_id = htonl(0);
    ofm->out_port = htons(OFPP_NONE);

    if (addormodify) {
      ofp_action_output *actionOutput = NULL;
      if (vlanid && striptag) {
        ofp_action_vlan_vid *actionVlan = (ofp_action_vlan_vid*)(ofm->actions);
        memset( actionVlan, 0, sizeof(ofp_action_vlan_vid) );
        actionVlan->type = htons(OFPAT_STRIP_VLAN);
        actionVlan->len = htons(sizeof(ofp_action_vlan_vid));
        actionVlan->vlan_vid = htons( vlanid ); // not necessary, all vlan tags stripped
        actionOutput =                                                  \
          (ofp_action_output*)( (char*)actionVlan + sizeof(ofp_action_vlan_vid) );
      } else {
        actionOutput = (ofp_action_output*)(ofm->actions);
      }
      memset( actionOutput, 0, sizeof(ofp_action_output) );
      actionOutput->type = htons(OFPAT_OUTPUT);
      actionOutput->len = htons(sizeof(ofp_action_output));
      actionOutput->port = htons( ethport );
      actionOutput->max_len = htons(0);
    }
    VLOG_DBG( log, "Sending pflowToEth to dpid %"PRIx64" to add:%d or delete:% d", \
              dpid, addormodify, !addormodify );
    if (vlanid && matchtag) {
      VLOG_DBG( log, "WildCard is %"PRIx32"", OFPFW_ALL & ~OFPFW_IN_PORT & ~OFPFW_DL_VLAN );
      VLOG_DBG( log, "matching on InVlan %d", vlanid );
    } else {
      VLOG_DBG( log, "WildCard is %"PRIx32"", OFPFW_ALL & ~OFPFW_IN_PORT );
    }
    VLOG_DBG( log, " matching on inVCG %"PRIx16", Action: OpEth %"PRIx16"", vcgnum,
              ethport );
    if(addormodify && striptag)
      VLOG_DBG( log, "ACTION: Stripping Vlan %d", vlanid );

    if( send_openflow_command(switch_db[dpid][0].datapath_id, &ofm->header, true) ) {
      VLOG_ERR(log, "*** Could not send flow_mod for pflowToEth add ***");
      return false;
    }

    updateVcgWithPflow( dpid, vcgnum, ethport, vlanid, addormodify, false, matchtag );

    return true;

  }


  bool
  Circsw::sendPflowOutToVcg( uint64_t dpid, uint16_t ethport, uint16_t vlanid,
                             uint16_t vcgnum , uint32_t bufferid, bool addormodify,
                             bool matchtag, bool inserttag ) {

    ofp_flow_mod* ofm;
    size_t size;
    if ( addormodify ) {
      if ( vlanid && inserttag )
        size = sizeof( *ofm ) + sizeof( struct ofp_action_header ) +    \
          sizeof( struct ofp_action_ckt_output ) ;
      else
        size = sizeof( *ofm ) + sizeof( struct ofp_action_ckt_output ) ;
    } else {
      size = sizeof( *ofm );
    }
    boost::shared_array<char> raw_of(new char[size]);
    ofm = (ofp_flow_mod*) raw_of.get();
    memset( ofm, 0, sizeof(ofp_flow_mod) );

    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(size);
    if (vlanid && matchtag)
      ofm->match.wildcards = htonl( OFPFW_ALL & ~OFPFW_IN_PORT & ~OFPFW_DL_VLAN );
    else
      ofm->match.wildcards = htonl( OFPFW_ALL & ~OFPFW_IN_PORT );
    ofm->match.in_port = htons( ethport );
    ofm->match.dl_vlan = htons( vlanid );
    if ( addormodify ) ofm->command = htons(OFPFC_ADD);
    else ofm->command = htons(OFPFC_DELETE_STRICT);
    ofm->idle_timeout = htons(0);
    ofm->hard_timeout = htons(0);
    ofm->priority = htons(0);
    ofm->buffer_id = htonl(bufferid);
    ofm->out_port = htons(OFPP_NONE);

    if ( addormodify ) {
      ofp_action_ckt_output *actionOutput = NULL;
      if ( vlanid && inserttag ) {
        ofp_action_vlan_vid *actionVlan = (ofp_action_vlan_vid*)(ofm->actions);
        memset( actionVlan, 0, sizeof(ofp_action_vlan_vid) );
        actionVlan->type = htons( OFPAT_SET_VLAN_VID );
        actionVlan->len = htons(sizeof(ofp_action_vlan_vid));
        actionVlan->vlan_vid = htons( vlanid );
        actionOutput =                                                  \
          (ofp_action_ckt_output*)( (char*)actionVlan + sizeof(ofp_action_vlan_vid) );
      } else {
        actionOutput = (ofp_action_ckt_output*)(ofm->actions);
      }
      memset( actionOutput, 0, sizeof(ofp_action_ckt_output) );
      actionOutput->type = htons(OFPAT_CKT_OUTPUT);
      actionOutput->len = htons(sizeof(ofp_action_ckt_output));
      actionOutput->cport = htons( vcgnum );
    }

    VLOG_DBG( log, "Sending pflowToVCG to dpid %"PRIx64" to add:%d or delete:% d", \
              dpid, addormodify, !addormodify );
    if (vlanid && matchtag) {
      VLOG_DBG( log, "WildCard is %"PRIx32"", OFPFW_ALL & ~OFPFW_IN_PORT & ~OFPFW_DL_VLAN);
      VLOG_DBG( log, "matching on InVlan %d", vlanid );
    } else {
      VLOG_DBG( log, "WildCard is %"PRIx32"", OFPFW_ALL & ~OFPFW_IN_PORT );
    }
    VLOG_DBG( log, "matching on inEth %"PRIx16", ACTION: OpVCG %"PRIx16", bufid %"PRIx32"", \
              ethport, vcgnum, bufferid );
    if(addormodify && inserttag)
      VLOG_DBG( log, "ACTION: Inserting Vlan tag %d", vlanid );


    if( send_openflow_command(switch_db[dpid][0].datapath_id, &ofm->header, true) ) {
      VLOG_ERR(log, "*** Could not send flow_mod for pflowtoVCG add ***");
      return false;
    }

    updateVcgWithPflow( dpid, vcgnum, ethport, vlanid, addormodify, true, matchtag );

    return true;

  }

/*
  // This method returns the switches to the state they were in right after
  // datapath-join, ie all vcgs cflows and pflows are removed and all xconns are
  // removed. Earlier the only signal that remained was the mapper signal with with
  // the vcg was created. This caused problems with new vcg creation.
  // The best option was in removing all slots - vcg becomes disfunctional.
  // In deleteVcgComponent, delete the component and go to updateVcgWithCflow
  // In there if num_components=0, then we remove associated pflows and erase vcgport
  // We also remove vcg port by clearing in removeAllState

  void
  Circsw::removeAllState(void) {
    for (int i = 0; i < dpids.size(); i ++ ) {
      if( switch_db.find( dpids[i] ) != switch_db.end() ) {
        struct switch_elem& sw = switch_db[dpids[i]][0];
        uint64_t dpid = dpids[i];

        for ( std::map<uint16_t, vcgPort>::iterator iter = sw.vcgports.begin();
              iter != sw.vcgports.end(); ++iter ) {
          uint16_t vcgnum = iter->second.vcgnum;
          if ( iter->second.num_pflows_in ) {
            for ( int pfi = 0; pfi < iter->second.num_pflows_in; pfi++ ) {
              uint16_t vlanid1 = iter->second.component_pflows_in[pfi].vlanid;
              uint16_t ethport1 = iter->second.component_pflows_in[pfi].ethport;
              bool matchtag1 = iter->second.component_pflows_in[pfi].matchtag;
              sendPflowOutToVcg( dpid, ethport1, vlanid1, vcgnum, 0, false,
                                 matchtag1, false );
              sleep( pause );
            }
            iter->second.num_pflows_in = 0;
            iter->second.component_pflows_in.clear();
          }
          if ( iter->second.num_pflows_out ) {
            for ( int pfo = 0; pfo < iter->second.num_pflows_out; pfo++ ) {
              uint16_t vlanid2 = iter->second.component_pflows_out[pfo].vlanid;
              uint16_t ethport2 = iter->second.component_pflows_out[pfo].ethport;
              bool matchtag2 = iter->second.component_pflows_out[pfo].matchtag;
              sendPflowOutToEth( dpid, vcgnum, vlanid2, ethport2,
                                 false, matchtag2, false );
              sleep( pause );
            }
            iter->second.num_pflows_out = 0;
            iter->second.component_pflows_out.clear();
          }
          if ( iter->second.num_components ) {
            for ( int cf = 0; cf < iter->second.num_components; cf++ ) {
              ofp_tdm_port t1 = iter->second.component_cflows[cf].tport1;
              ofp_tdm_port t2 = iter->second.component_cflows[cf].tport2;
              sendXconn( dpid, t1, t2, false );
              sleep( pause );
              sendVcgComponent( dpid, vcgnum, 0, t1, false );
              sleep( pause );
              updateTslots( dpid, t1, true );
              updateTslots( dpid, t2, true );
            }
            iter->second.num_components = 0;
            iter->second.component_cflows.clear();
          }

        }
        //remove all virtual ports
        sw.vcgports.clear();

        bool removed_xconn = false;
        for ( int j = 0; j < sw.xconns.size(); j++ ) {
          ofp_tdm_port tt1 = sw.xconns[j].tport1;
          ofp_tdm_port tt2 = sw.xconns[j].tport2;
          sendXconn( dpid, tt1, tt2, false );
          sleep( pause );
          updateTslots( dpid, tt1, true );
          updateTslots( dpid, tt2, true );
          removed_xconn = true;
        }
        if ( removed_xconn )
          sw.xconns.clear();

      }
    }

  }

*/

  bool
  Circsw::removeVcgPort( uint64_t dpid,  uint16_t vcgnum ) {
    if( switch_db.find( dpid ) != switch_db.end() ) {
      struct switch_elem& sw = switch_db[dpid][0];
      if ( sw.vcgports.find( vcgnum ) != sw.vcgports.end() ) {
        vcgPort& v = sw.vcgports[vcgnum];
        if ( v.num_pflows_in ) {
          for ( int pfi = 0; pfi < v.num_pflows_in; pfi++ ) {
            uint16_t vlanid1 = v.component_pflows_in[pfi].vlanid;
            uint16_t ethport1 = v.component_pflows_in[pfi].ethport;
            bool matchtag1 = v.component_pflows_in[pfi].matchtag;
            sendPflowOutToVcg( dpid, ethport1, vlanid1, vcgnum, 0, false,
                               matchtag1, false );
          }
          v.num_pflows_in = 0;
          v.component_pflows_in.clear();
        }
        if ( v.num_pflows_out ) {
          for ( int pfo = 0; pfo < v.num_pflows_out; pfo++ ) {
            uint16_t vlanid2 = v.component_pflows_out[pfo].vlanid;
            uint16_t ethport2 = v.component_pflows_out[pfo].ethport;
            bool matchtag2 = v.component_pflows_out[pfo].matchtag;
            sendPflowOutToEth( dpid, vcgnum, vlanid2, ethport2,
                               false, matchtag2, false );
          }
          v.num_pflows_out = 0;
          v.component_pflows_out.clear();
        }

        for ( int i=0; i<pflow_db.size(); i++ ) {
          showNoPflow( pflow_db[i] );
        }
        if ( pflow_db.size() ) pflow_db.clear();

        if ( v.num_components ) {
          //go thru list to get all cflowids
          for ( int cf = 0; cf < v.num_components; cf++ ) {
            showNoCflow( v.component_cflows[cf].flowid );
          }
          //seed the graceful deletion
          struct delete_elem de;
          de.dpid = dpid; de.vcgnum = vcgnum;
          de.num_components = v.num_components;
          de.curr_component = 0;
          de.next_state = START_DELETE;
          uint64_t index = dpid + vcgnum;
          VLOG_DBG( log, "-- Seeding graceful deletion dpid:%"PRIx64" vcgport:%"PRIx16"",
                    dpid, vcgnum );
          VLOG_DBG( log, " with index: %"PRIx64" and num_comp:%d", index,
                    v.num_components );
          vcgdelete_db.insert( std::make_pair(index, de) );
          if ( vcgdelete_db.size() == 1 ) {
            removeVcgComponents();
          }
        }

        return true;

      } else {
        VLOG_WARN( log, "Vcgport:%"PRIx16" not found in dpid:%"PRIx64"",
                   vcgnum, dpid );
        return false;
      }
    } else {
      VLOG_ERR( log, "dpid:%"PRIx64" not found", dpid );
      return false;
    }


  }


  void
  Circsw:: removeVcgComponents( void ) {
    // This state-machine assumes that the pflows mapped into the vcg have
    // already been removed. It gracefully sends commands out to removed the cflows
    // and then erases the virtual port from the switch_db's map of vcgports.
    uint64_t index=0;
    for ( std::map<uint64_t, delete_elem>::iterator iter = vcgdelete_db.begin();
          iter != vcgdelete_db.end(); ++iter ) {
        index = iter->first;
        break;
    }
    if ( index ) {
      struct delete_elem& de = vcgdelete_db[index];
      uint64_t dpid = de.dpid;
      uint16_t vcgnum = de.vcgnum;
      struct switch_elem& sw = switch_db[dpid][0];
      struct vcgPort& v = sw.vcgports[vcgnum];

      ofp_tdm_port t1 = v.component_cflows[de.curr_component].tport1;
      ofp_tdm_port t2 = v.component_cflows[de.curr_component].tport2;

      if ( vcgdelete_db[index].next_state == START_DELETE ) {
        VLOG_DBG( log, "ST -- :START_DELETE dpid:%"PRIx64" vcg:%"PRIx16" comp:%d",
                  dpid, vcgnum, de.curr_component );
        sendXconn( dpid, t1, t2, false );
        de.next_state = DEL_COMPONENT;
        timeval tv={wait_for_xconn_delete,0};
        post(boost::bind(&Circsw::removeVcgComponents, this), tv);
        VLOG_DBG( log, " STATE START_DELETE DONE " );

      } else if ( vcgdelete_db[index].next_state == DEL_COMPONENT ) {
        VLOG_DBG( log, "ST -- :DEL_COMPONENT dpid:%"PRIx64" vcg:%"PRIx16" comp:%d",
                  dpid, vcgnum, de.curr_component );
        sendVcgComponent( dpid, vcgnum, 0, t1, false );
        updateTslots( dpid, t1, true );
        updateTslots( dpid, t2, true );
        if ( --de.num_components == 0 ) {
          de.next_state = FINISH;
          VLOG_DBG( log, " STATE DEL_COMPONENT DONE --> FINISH" );
        } else {
          de.curr_component++;
          de.next_state = START_DELETE;
          VLOG_DBG( log, " STATE DEL_COMPONENT DONE --> START_DELETE" );
        }
        timeval tv={wait_for_vcomp_delete,0};
        post(boost::bind(&Circsw::removeVcgComponents, this), tv);


      } else if ( vcgdelete_db[index].next_state == FINISH ) {
        VLOG_DBG( log, "ST -- :FINISH dpid:%"PRIx64" vcg:%"PRIx16" comp:%d",
                  dpid, vcgnum, de.curr_component );
        sw.vcgports.erase( vcgnum );
        vcgdelete_db.erase( index );
        if ( vcgdelete_db.size() ) {
          VLOG_DBG( log, "more vcgs-RECURSIVE CALL" );
          removeVcgComponents();
        }
        VLOG_DBG( log, " STATE FINISH DONE " );
      }
    }

  }


  // *** end API *** //


  //-------------------------------------------------------------------------//
  //                    Discovery & Topology Module                          //
  //-------------------------------------------------------------------------//

  void
  Circsw::discoverCktTopo(void) {
    //if( dpids.size() < 2 ) return;
    for(int i=0; i<dpids.size(); i++ ) {
      struct switch_elem& sw = switch_db[dpids[i]][0];
      for( std::map<uint16_t, CPort>::iterator iter = sw.tdmports.begin();
           iter != sw.tdmports.end(); ++iter ) {
        uint16_t tp = iter->second.port_no;
        if( !iter->second.linkid ) {
          // find peer switch
          bool foundpeer = false;
          uint64_t pd = iter->second.peer_datapath_id;
          for( int k=0; k<dpids.size(); k++) {
            if( dpids[k] == pd ) {
              foundpeer = true;
              break;
            }
          }
          if( foundpeer ) {
             uint16_t pp = iter->second.peer_port_no;
            // find peer port
            if( switch_db[pd][0].tdmports.find(pp) != \
                switch_db[pd][0].tdmports.end() ) {
              struct CPort& cp = switch_db[pd][0].tdmports[pp];
              if( ( cp.peer_datapath_id != dpids[i] ) ||
                  ( cp.peer_port_no != tp ) ||
                  ( cp.speed != iter->second.speed ) ||
                  ( cp.linkid != 0 ) ) {
                VLOG_WARN( log, "*** Datapath Peer Port Error ***" );
                VLOG_WARN( log, "sw:%"PRIx64" peer sw:%"PRIx64" peer_port:%"PRIx16"",
                           dpids[i], pd, pp );
                VLOG_WARN( log, "Peer port mismatch" );
              } else {
                VLOG_DBG( log, " New circuit link added to topology " );
                updateCktTopo( dpids[i], tp, pd, pp, cp.speed );
              }
            } else {
              VLOG_WARN( log, "*** Datapath Peer Port Error ***" );
              VLOG_WARN( log, "sw:%"PRIx64" peer sw:%"PRIx64" peer_port:%"PRIx16"",
                         dpids[i], pd, pp );
              VLOG_WARN( log, "Peer port not found" );
            }
          } //can't find peer switch
        } // link has already been discovered
      } // for all ports on this switch
    } // for all switches
  }

  void
  Circsw::updateCktTopo( uint64_t thissw, uint16_t thisport, uint64_t thatsw,
                         uint16_t thatport, uint32_t linkspeed ) {
    struct link1_elem entry;
    struct link1_elem reverse;
    entry.thissw = reverse.thatsw = thissw;
    entry.thatsw = reverse.thissw = thatsw;
    entry.thisport = reverse.thatport = thisport;
    entry.thatport = reverse.thisport = thatport;
    entry.linkspeed = reverse.linkspeed = linkspeed;
    entry.linkid = reverse.linkid = linkid;

    switch_db[thissw][0].L1links.insert( std::make_pair(linkid, entry) );
    switch_db[thissw][0].tdmports[thisport].linkid = linkid;
    switch_db[thatsw][0].L1links.insert( std::make_pair(linkid, reverse) );
    switch_db[thatsw][0].tdmports[thatport].linkid = linkid;
    link1_db.insert( std::make_pair(linkid, entry) );
    linkid++;

  }


  void
  Circsw::processPacketLink( uint64_t loccktsw, uint16_t locethport,
                              uint64_t psdpid, uint16_t psportid ) {
    registerPacketLink( loccktsw, locethport, psdpid, psportid );
    uint64_t remotedpid = 0;
    uint16_t remoteportid = 0, link3idconf = 0 ;
    link3idconf = checkForVirtualLink( psdpid, psportid, remotedpid, remoteportid );
    if( link3idconf >= 0x3000 ) {
      // found a configured virtual link
      if( vlink_db.find( link3idconf ) == vlink_db.end() ) {
        // virtual link has not been created yet
        uint64_t remcktsw = 0;
        uint16_t remethport = 0, rem2link = 0;
        rem2link = checkPacketSwRegistry( remotedpid, remoteportid, remcktsw,
                                          remethport );
        if( rem2link ) {
          // remote switch has registered
          uint16_t loccktport = 0, remcktport = 0;
          uint16_t cktlink = getCktLink( loccktsw, remcktsw, loccktport, remcktport );
          if( cktlink ) {
            uint16_t locvcgnum, remvcgnum;
            bool done = createDirectVLink( loccktsw, locethport, loccktport,
                                           remcktsw, remethport, remcktport,
                                           true, 0, locvcgnum, remvcgnum );
            if (done) {
              struct vlink_elem vle;
              vle.ethdpid1 = psdpid; vle.ethdpid2 = remotedpid;
              vle.ethport1 = psportid; vle.ethport2 = remoteportid;
              vle.link1ids.push_back( cktlink );
              struct vlinkpath vlp;
              vlp.vlpathid = vlpathid;
              vlp.vlpathtype = STATIC;
              vle.vlpaths.insert( std::make_pair(vlpathid, vlp) );
              vlink_db.insert( std::make_pair(link3idconf, vle) );
              addNodesToPath( link3idconf, vlpathid, psdpid, PKT_PATH_END1, psportid,
                              0xffff, 0xffff, 0xffff, flowid );
              addNodesToPath( link3idconf, vlpathid, loccktsw, CKT_PATH_END1, locethport,
                              locvcgnum, loccktport, 0xffff, flowid );
              addNodesToPath( link3idconf, vlpathid, remcktsw, CKT_PATH_END2, remethport,
                              remvcgnum, remcktport, 0xffff, flowid );
              addNodesToPath( link3idconf, vlpathid, remotedpid, PKT_PATH_END2,
                              remoteportid, 0xffff, 0xffff, 0xffff, flowid );

              registerVirtualLinkOnL1Link( cktlink, link3idconf, vlpathid, flowid, STATIC );

              showCflow( loccktsw, loccktport, remcktsw, remcktport, STATIC_CFLOW );
              showPflow( psdpid, psportid, loccktsw, locethport,
                         remcktsw, remethport, remotedpid, remoteportid,
                         PFLOW );
              VLOG_DBG( log, " -------- new virtual-link created with STATIC vlinkpath ---------" );
              VLOG_DBG( log, "id%"PRIx16":%"PRIx16":: %"PRIx64":%d <--> %"PRIx64":%d on id%"PRIx16"",
                        link3idconf, vlpathid, psdpid, psportid, remotedpid, remoteportid, cktlink );
              VLOG_DBG( log, "-- at time:%d --", (int) time(NULL) );

              flowid++;
              vlpathid++;
            }
          } else {
            VLOG_WARN( log, "Remote circuit switch or ckt link not found" );
          }
        } else {
          VLOG_DBG( log, "Remote packet switch not discovered yet" );
        }
      } else {
        VLOG_WARN( log, "Virtual link already created" );
      }
    } else {
      //VLOG_DBG( log, " Virtual link not configured" );
    }

  }


  bool
  Circsw::findFreeEthPort( uint64_t psdpid, std::vector<uint16_t>& ethports,
                           uint16_t& freeethport ) {
    // tries to find an ethernet port on which a vlink has not already been
    // created - makes an exception for reserved port
    VLOG_DBG( log, "trying packet switch 0x%"PRIx64"", psdpid );
    for ( int j = 0; j < ethports.size(); j++ ) {
      VLOG_DBG( log, "trying ethport %d", ethports[j] );
      bool invlinkdb = false;
      for( std::map<uint16_t, vlink_elem>::iterator iter = vlink_db.begin();
           iter != vlink_db.end(); ++iter ) {
        if ( ( (iter->second.ethdpid1 == psdpid) &&
               (iter->second.ethport1 == ethports[j]) ) ||
             ( (iter->second.ethdpid2 == psdpid) &&
               (iter->second.ethport2 == ethports[j]) ) ) {
          invlinkdb = true;
          VLOG_DBG( log, "It is in vlinkdb with linkid:0x%"PRIx16"", iter->first );
          break;
        }
      }
      if ( (!invlinkdb) && (ethports[j] != reserved_port1) &&
           (ethports[j] != reserved_port2) ) {
        // we found a free ethport
        freeethport = ethports[j];
        return true;
      }
    }
    return false;
  }

  void
  Circsw::registerVirtualLinkOnL1Link( uint16_t link1id, uint16_t link3id_,
                                       uint16_t vlpathid_, uint16_t cflowid_,
                                       uint16_t vlpathtype_) {
    struct regvlink rv;
    rv.link3id = link3id_;
    rv.vlpathid = vlpathid_;
    rv.cflowid = cflowid_;
    rv.vlpathtype = vlpathtype_;
    link1_db[link1id].regvlinks.insert( std::make_pair(cflowid_, rv) );
  }

  void
  Circsw::deRegisterVirtualLinkOnL1Link( std::vector<uint16_t>& cflowids ) {
    for ( int i=0; i<cflowids.size(); i++ ) {
      for ( std::map<uint16_t, link1_elem>::iterator iter = link1_db.begin();
            iter != link1_db.end(); ++iter ) {
        if ( iter->second.regvlinks.erase(cflowids[i]) )
          VLOG_DBG( log, "de-registering cflow:%d in L1 link:%"PRIx16"",
                    cflowids[i], iter->first );
      }
    }
  }


  uint16_t
  Circsw::registerPacketLink( uint64_t ingressdpid, uint16_t ingressport,
                              uint64_t sendingdpid, uint16_t sendingport ) {
    //ensure packet-link not already discovered
    uint64_t dummy1; uint16_t dummy2;
    uint16_t ethlink = checkPacketSwRegistry( sendingdpid, sendingport, dummy1, dummy2);
    if ( ethlink ) {
      //VLOG_WARN( log, "Packet-switch/link already registered link2id:%"PRIx16"", ethlink );
      return ethlink;
    }
    struct link2_elem plink;
    plink.thissw = ingressdpid; // transport switch that sent packet_in for lldp pkt
    plink.thisport = ingressport; // ingress transport switch eth port
    plink.thatsw = sendingdpid; // packet-switch that sent lldp packet
    plink.thatport = sendingport; // packet-switch port
    plink.linkspeed = OFPPF_1GB_FD;
    plink.linkid = link2id;
    switch_db[ingressdpid][0].L2links.insert( std::make_pair(link2id, plink) );
    link2_db.insert( std::make_pair(link2id, plink) );
    showDpJoin( PACKET_SWITCH, sendingdpid );
    VLOG_DBG( log, " ---------------- new packet-link discovered --------------" );
    VLOG_DBG( log, "id%"PRIx16":: %"PRIx64":%"PRIx16"(%s) <--> %"PRIx64":%d",
              link2id, ingressdpid, ingressport,
              switch_db[ingressdpid][0].ethports[ingressport].name.c_str(),
              sendingdpid, sendingport
              );
    showPacketLink( ingressdpid, ingressport, sendingdpid, sendingport, link2id );
    link2id++;
    return (link2id-1);
  }

  uint16_t
  Circsw::checkForVirtualLink( uint64_t psdpid, uint16_t psportid, uint64_t& remotedpid,
                               uint16_t& remoteportid ) {
    // checks configured vlinks in circsw_config.hh
    int index = 0, num_found = 0;
    bool thisisit = true;
    for( int i = 0; i < num_vplinks; i++ ) {
      if( (vplinks[i].thissw == psdpid) && (vplinks[i].thisport == psportid ) ) {
        index = i;
        num_found++;
      }
      if( (vplinks[i].thatsw == psdpid) && (vplinks[i].thatport == psportid ) ) {
        index = i;
        num_found++;
        thisisit = false;
      }
    }
    assert( num_found < 2 );
    if( num_found && thisisit ) {
      remotedpid = vplinks[index].thatsw;
      remoteportid = vplinks[index].thatport;
      return vplinks[index].linkid;
    }
    if( num_found && !thisisit ) {
      remotedpid = vplinks[index].thissw;
      remoteportid = vplinks[index].thisport;
      return vplinks[index].linkid;
    }
    return 0;
  }

  bool
  Circsw::getRegisteredPorts( uint64_t pktswdpid, std::vector<uint16_t>& ethports) {
    // for ethernet links (linkid 0x2000-0x2fff) the registry
    // in link2_db is such that the packet switch is always thatsw/thatport
    // There could be multiple entries per packetsw
    bool foundpktswitch = false;
    for( int i=0x2000; i < link2id; i++ ) {
      if (link2_db[i].thatsw == pktswdpid) {
        ethports.push_back( link2_db[i].thatport );
        foundpktswitch = true;
      }
    }
    return foundpktswitch;
  }

  uint16_t
  Circsw::checkPacketSwRegistry( uint64_t pktswdpid, uint16_t pktswport,
                                 uint64_t& cktswdpid, uint16_t& cktswethport ) {
    // for ethernet links (linkid 0x2000-0x2fff) the registry
    // in link2_db is such that the packet switch is always thatsw/thatport
    // Also only one registry allowed for packetsw/port combination
    for( int i=0x2000; i < link2id; i++ ) {
      if( (link2_db[i].thatsw == pktswdpid) &&
          (link2_db[i].thatport == pktswport) ) {
        cktswdpid = link2_db[i].thissw;
        cktswethport = link2_db[i].thisport;
        return link2_db[i].linkid;
      }
    }

    return 0;
  }

  uint16_t
  Circsw::getCktLink( uint64_t loccktsw, uint64_t remcktsw, uint16_t& loccktport,
                      uint16_t& remcktport ) {
    // there could be multiple links between the circuit switches
    // just pick first one now, could hash later
    struct switch_elem& sw = switch_db[loccktsw][0];
    for ( std::map<uint16_t, link1_elem>::iterator iter = sw.L1links.begin();
          iter != sw.L1links.end(); ++iter ) {
      if ( iter->second.thatsw == remcktsw ) {
        if ( (loccktport==0) && (remcktport==0) ) {
          loccktport = iter->second.thisport;
          remcktport = iter->second.thatport;
        }
        return iter->second.linkid;
      }
    }
    return 0;
  }

  bool
  Circsw::createDirectVLink( uint64_t loccktsw, uint16_t locethport, uint16_t loccktport,
                             uint64_t remcktsw, uint16_t remethport, uint16_t remcktport,
                             bool adduntaggedrules, uint32_t vlanid, uint16_t& vcgnum1,
                             uint16_t& vcgnum2 ) {
    uint16_t locintport = findInternalPort( loccktsw, locethport );
    uint16_t locvcg = createEmptyVcg( loccktsw, locintport );
    uint16_t remintport = findInternalPort( remcktsw, remethport );
    uint16_t remvcg = createEmptyVcg( remcktsw, remintport );
    sleep( pause );
    uint16_t tslot;
    findMatchingTimeSlots( loccktsw, loccktport, remcktsw, remcktport, tsig, tslot);
    addVcgComponent( loccktsw, locvcg, loccktport, tsig, tslot, true, flowid );
    addVcgComponent( remcktsw, remvcg, remcktport, tsig, tslot, true, flowid );
    if ( adduntaggedrules ) {
      sendPflowOutToVcg( loccktsw, locethport, 0, locvcg, 0, true, false, false );
      sendPflowOutToVcg( remcktsw, remethport, 0, remvcg, 0, true, false, false );
      sendPflowOutToEth( loccktsw, locvcg, 0, locethport, true, false, false );
      sendPflowOutToEth( remcktsw, remvcg, 0, remethport, true, false, false );
    }
    if ( vlanid ) {
      //add rules for matching to packets with incoming vlan tags
      addOrRemoveVlanRules( loccktsw, locethport, vlanid, locvcg, true, true, false );
      addOrRemoveVlanRules( remcktsw, remethport, vlanid, remvcg, true, true, false );
    }
    vcgnum1 = locvcg; vcgnum2 = remvcg;
    return true;
  }


  bool
  Circsw::createIndirectVLink( uint64_t loccktsw, uint16_t locethport, uint16_t loccktport,
                               uint64_t midcktsw, uint16_t midtdmport1, uint16_t midtdmport2,
                               uint64_t remcktsw, uint16_t remethport, uint16_t remcktport,
                               bool adduntaggedrules, uint32_t vlanid, uint16_t& vcgnum1,
                               uint16_t& vcgnum2 ) {
    uint16_t locintport = findInternalPort( loccktsw, locethport );
    uint16_t locvcg = createEmptyVcg( loccktsw, locintport );
    uint16_t remintport = findInternalPort( remcktsw, remethport );
    uint16_t remvcg = createEmptyVcg( remcktsw, remintport );
    sleep( pause );
    uint16_t tslotnear, tslotfar;
    findMatchingTimeSlots( loccktsw, loccktport, midcktsw, midtdmport1, tsig, tslotnear);
    findMatchingTimeSlots( midcktsw, midtdmport2, remcktsw, remcktport, tsig, tslotfar);
    addVcgComponent( loccktsw, locvcg, loccktport, tsig, tslotnear, true, flowid );
    addXconn( midcktsw, midtdmport1, tslotnear, midtdmport2, tslotfar, tsig, flowid );
    addVcgComponent( remcktsw, remvcg, remcktport, tsig, tslotfar, true, flowid );
    if ( adduntaggedrules ) {
      sendPflowOutToVcg( loccktsw, locethport, 0, locvcg, 0, true, false, false );
      sendPflowOutToVcg( remcktsw, remethport, 0, remvcg, 0, true, false, false );
      sendPflowOutToEth( loccktsw, locvcg, 0, locethport, true, false, false );
      sendPflowOutToEth( remcktsw, remvcg, 0, remethport, true, false, false );
    }
    if ( vlanid ) {
      //add rules for matching to packets with incoming vlan tags
      addOrRemoveVlanRules( loccktsw, locethport, vlanid, locvcg, true, true, false );
      addOrRemoveVlanRules( remcktsw, remethport, vlanid, remvcg, true, true, false );
    }
    vcgnum1 = locvcg; vcgnum2 = remvcg;
    return true;
  }

  void
  Circsw::addOrRemoveVlanRules( uint64_t dpid, uint16_t ethport, uint16_t vlanid,
                                uint16_t vcgport, bool add, bool matchtag,
                                bool striptag ) {
    // Warning - caller should use this method only for symmetric rules
    if ( matchtag || striptag ) assert( vlanid );
    sendPflowOutToVcg( dpid, ethport, vlanid, vcgport, 0, add, matchtag, striptag );
    sendPflowOutToEth( dpid, vcgport, vlanid, ethport, add, matchtag, striptag );
  }


  uint16_t
  Circsw::createDynamicVirtualLink( uint64_t psdpid1, uint64_t psdpid2, uint32_t vid,
                                    bool videolink ) {
    //get registered ports
    std::vector<uint16_t> ethports1, ethports2;
    bool found1 = getRegisteredPorts( psdpid1, ethports1 );
    bool found2 = getRegisteredPorts( psdpid2, ethports2 );
    if ( !(found1 && found2) ) {
      VLOG_ERR( log, "Could not find registry for packet switch" );
      VLOG_ERR( log, "dpid:%"PRIx64"==%d dpid:%"PRIx64"==%d",
                psdpid1, found1, psdpid2, found2 );
      return 0;
    }

    uint16_t freeeth1, freeeth2;
    if ( videolink && usereservedports) {
      // use reserved ports
      for( int i=0; i<ethports1.size(); i++ ) {
        if ( ethports1[i] == reserved_port1 ) freeeth1 = reserved_port1;
        if ( ethports1[i] == reserved_port2 ) freeeth1 = reserved_port2;
      }
      for( int i=0; i<ethports2.size(); i++ ) {
        if ( ethports2[i] == reserved_port1 ) freeeth2 = reserved_port1;
        if ( ethports2[i] == reserved_port2 ) freeeth2 = reserved_port2;
      }
    } else {
      // determine if the ethernet ports already have a virtual link provisioned
      // - find a port that doesn't
      found1 = found2 = false;
      found1 = findFreeEthPort( psdpid1, ethports1, freeeth1 );
      found2 = findFreeEthPort( psdpid2, ethports2, freeeth2 );
      if ( !(found1 && found2) ) {
        VLOG_ERR( log, "Could not find free eth port for packet switch" );
        VLOG_ERR( log, "dpid:%"PRIx64"==%d dpid:%"PRIx64"==%d",
                  psdpid1, found1, psdpid2, found2 );
        return 0;
      }
    }

    // get the transport NE's eth port that the free ports are connected to
    uint64_t cktsw1 = 0, cktsw2 =0;
    uint16_t cktsweth1 = 0, cktsweth2 = 0;
    checkPacketSwRegistry( psdpid1, freeeth1, cktsw1, cktsweth1 );
    checkPacketSwRegistry( psdpid2, freeeth2, cktsw2, cktsweth2 );

    uint16_t result = 0;
    if ( videolink ) {
      result = createVideoCkt( cktsw1, cktsweth1, cktsw2, cktsweth2, true, vid,
                               psdpid1, freeeth1, psdpid2, freeeth2,
                               link3id, vlpathid, true );
    } else {
      result = createVoipCkt( cktsw1, cktsweth1, cktsw2, cktsweth2, true, vid,
                              psdpid1, freeeth1, psdpid2, freeeth2,
                              link3id, vlpathid, true );
    }
    VLOG_DBG( log, " -- new virtual link %"PRIx16"created --", link3id );
    link3id++;
    vlpathid++;
    return result;

  }

  uint16_t
  Circsw::createDynamicVirtualLinkPath( uint16_t link3idfound, uint32_t vid,
                                        bool videolink ) {
    // use the first vlpath route to get the pkt and ckt_path endpoints
    struct vlinkpath& vlp = vlink_db[link3idfound].vlpaths.begin()->second;
    uint64_t psdpid1 = vlink_db[link3idfound].ethdpid1;
    uint64_t psdpid2 = vlink_db[link3idfound].ethdpid2;
    uint16_t pseth1 = vlink_db[link3idfound].ethport1;
    uint16_t pseth2 = vlink_db[link3idfound].ethport2;
    uint64_t cktsw1=0, cktsw2=0;
    uint16_t cktsweth1=0, cktsweth2=0;
    std::vector<node>& firstroute = vlp.vlpathroutes.begin()->second;
    for ( int i=0; i<firstroute.size(); i++ ) {
      if ( firstroute[i].nodetype == CKT_PATH_END1 ) {
        cktsw1 = firstroute[i].dpid;
        cktsweth1 = firstroute[i].ethport;
      } else if ( firstroute[i].nodetype == CKT_PATH_END2 ) {
        cktsw2 = firstroute[i].dpid;
        cktsweth2 = firstroute[i].ethport;
      }
    }

    uint16_t result = 0;
    if ( videolink ) {
      result = createVideoCkt( cktsw1, cktsweth1, cktsw2, cktsweth2, false, vid,
                               psdpid1, pseth1, psdpid2, pseth2,
                               link3idfound, vlpathid, false );
    } else {
      result = createVoipCkt( cktsw1, cktsweth1, cktsw2, cktsweth2, false, vid,
                              psdpid1, pseth1, psdpid2, pseth2,
                              link3idfound, vlpathid, false );
    }
    vlpathid++;
    return result;
  }


  bool
  Circsw::createVoipCkt( uint64_t cktsw1, uint16_t cktsweth1, uint64_t cktsw2,
                         uint16_t cktsweth2, bool adduntaggedrules,
                         uint32_t vid, uint64_t psdpid1, uint16_t freeeth1,
                         uint64_t psdpid2, uint16_t freeeth2,
                         uint16_t link3id_, uint16_t vlpathid_, bool newvlink ) {
    //get Direct path CktLink
    uint16_t cktswtdm1 = 0, cktswtdm2 = 0;
    uint16_t cktlink = getCktLink( cktsw1, cktsw2, cktswtdm1, cktswtdm2 );
    if ( cktlink ) {
      // if all the above works:
      // create a direct path Virtual Link between the pkt switches
      // register the vlink, show cflow and pflow and increment flowid
      uint16_t vcgnum1, vcgnum2;
      bool done = createDirectVLink( cktsw1, cktsweth1, cktswtdm1,
                                     cktsw2, cktsweth2, cktswtdm2,
                                     adduntaggedrules, vid, vcgnum1, vcgnum2 );
      if (done) {
        if ( newvlink ) {
          struct vlink_elem vle;
          vle.ethdpid1 = psdpid1; vle.ethdpid2 = psdpid2;
          vle.ethport1 = freeeth1; vle.ethport2 = freeeth2;
          vle.link1ids.push_back( cktlink );
          vlink_db.insert( std::make_pair(link3id_, vle) );
        }
        struct vlinkpath vlp;
        vlp.vlpathid = vlpathid_;
        vlp.vlpathtype = DYNAMIC_VOIP;
        vlp.vlpathvlans.push_back( vid );
        vlink_db[link3id_].vlpaths.insert( std::make_pair(vlpathid_, vlp) );
        addNodesToPath( link3id_, vlpathid_, psdpid1, PKT_PATH_END1, freeeth1,
                        0xffff, 0xffff, 0xffff, flowid );
        addNodesToPath( link3id_, vlpathid_, cktsw1, CKT_PATH_END1, cktsweth1,
                        vcgnum1, cktswtdm1, 0xffff, flowid );
        addNodesToPath( link3id_, vlpathid_, cktsw2, CKT_PATH_END2, cktsweth2,
                        vcgnum2, cktswtdm2, 0xffff, flowid );
        addNodesToPath( link3id_, vlpathid_, psdpid2, PKT_PATH_END2, freeeth2,
                        0xffff, 0xffff, 0xffff, flowid );

        registerVirtualLinkOnL1Link( cktlink, link3id_, vlpathid_, flowid, DYNAMIC_VOIP );

        showCflow( cktsw1, cktswtdm1, cktsw2, cktswtdm2, VOIP_CFLOW );
        showPflow( psdpid1, freeeth1, cktsw1, cktsweth1,
                   cktsw2, cktsweth2, psdpid2, freeeth2, PFLOW );

        VLOG_DBG( log, " ----------------- new virtual link-path created ---------------" );
        VLOG_DBG( log, "id%"PRIx16":%"PRIx16":: %"PRIx64":%d <--> %"PRIx64":%d on id%"PRIx16"",
                  link3id_, vlpathid_, psdpid1, freeeth1, psdpid2, freeeth2, cktlink );
        VLOG_DBG( log, "-- at time:%d --", (int) time(NULL) );

        pflow_db.push_back( flow2id-1 ); // GUI related - flow2id is incr by showPflow
        pflow_db.push_back( flow2id-2 ); // GUI related
        flowid++;
        return true;
      } else {
        VLOG_WARN( log, "Could not create direct-path Virtual Link Path" );
        return false;
      }
    } else {
      VLOG_WARN( log, "Remote circuit switch or ckt link not found" );
      return false;
    }
  }

  bool
  Circsw::createVideoCkt( uint64_t loccktsw, uint16_t locethport, uint64_t remcktsw,
                          uint16_t remethport, bool adduntaggedrules,
                          uint32_t vlanid, uint64_t locpktsw, uint16_t locpkteth,
                          uint64_t rempktsw, uint16_t rempkteth,
                          uint16_t link3id_, uint16_t vlpathid_, bool newvlink ) {
    // we need to figure out these
    uint64_t midcktsw=0;
    uint16_t loccktport=0, midtdmport1=0, midtdmport2=0, remcktport=0;
    bool foundindirectpath = false;
    uint16_t cktlinknear=0, cktlinkfar=0;
    for ( int i= 0; i<dpids.size(); i++ ) {
      if ( (dpids[i] == loccktsw) || (dpids[i] == remcktsw) ) {
        continue;
      } else {
        midcktsw = dpids[i];
        cktlinknear = getCktLink( loccktsw, midcktsw, loccktport, midtdmport1 );
        cktlinkfar  = getCktLink( midcktsw, remcktsw, midtdmport2, remcktport );
        if ( (cktlinknear >= 0x1000) && (cktlinknear < 0x2000) &&
             (cktlinkfar  >= 0x1000) && (cktlinkfar  < 0x2000) ) {
          foundindirectpath = true;
          break;
        }
      }
    }
    if ( foundindirectpath ) {
      uint16_t vcgnum1, vcgnum2;
      bool done = createIndirectVLink( loccktsw, locethport, loccktport, midcktsw,
                                       midtdmport1, midtdmport2, remcktsw, remethport,
                                       remcktport, adduntaggedrules, vlanid, vcgnum1,
                                       vcgnum2 );
      if (done) {
        if ( newvlink ) {
          struct vlink_elem vle;
          vle.ethdpid1 = locpktsw; vle.ethdpid2 = rempktsw;
          vle.ethport1 = locpkteth; vle.ethport2 = rempkteth;
          vle.link1ids.push_back( cktlinknear );
          vle.link1ids.push_back( cktlinkfar );
          vlink_db.insert( std::make_pair(link3id_, vle) );
        }
        struct vlinkpath vlp;
        vlp.vlpathid = vlpathid_;
        vlp.vlpathtype = DYNAMIC_VIDEO;
        vlp.vlpathvlans.push_back( vlanid );
        vlink_db[link3id_].vlpaths.insert( std::make_pair(vlpathid_, vlp) );

        addNodesToPath( link3id_, vlpathid_, locpktsw, PKT_PATH_END1, locpkteth,
                        0xffff, 0xffff, 0xffff, flowid );
        addNodesToPath( link3id_, vlpathid_, loccktsw, CKT_PATH_END1, locethport,
                        vcgnum1, loccktport, 0xffff, flowid );
        addNodesToPath( link3id_, vlpathid_, midcktsw, CKT_PATH_INTERMEDIATE, 0xffff,
                        0xffff, midtdmport1, midtdmport2, flowid );
        addNodesToPath( link3id_, vlpathid_, remcktsw, CKT_PATH_END2, remethport,
                        vcgnum2, remcktport, 0xffff, flowid );
        addNodesToPath( link3id_, vlpathid_, rempktsw, PKT_PATH_END2, rempkteth,
                        0xffff, 0xffff, 0xffff, flowid );

        registerVirtualLinkOnL1Link( cktlinknear, link3id_, vlpathid_, flowid, DYNAMIC_VIDEO );
        registerVirtualLinkOnL1Link( cktlinkfar, link3id_, vlpathid_, flowid, DYNAMIC_VIDEO );

        showIndirectCflow( loccktsw, loccktport, midcktsw, midtdmport1, midtdmport2,
                           remcktsw, remcktport, VIDEO_CFLOW );
        showPflow( locpktsw, locpkteth, loccktsw, locethport,
                   remcktsw, remethport, rempktsw, rempkteth, PFLOW );

        VLOG_DBG( log, " ----------------- new virtual link-path created ---------------" );
        VLOG_DBG( log, "id%"PRIx16":%"PRIx16":: %"PRIx64":%d <--> %"PRIx64":%d on ids%"PRIx16" %"PRIx16"",
                  link3id_, vlpathid_, locpktsw, locpkteth, rempktsw, rempkteth, cktlinknear, cktlinkfar );
        VLOG_DBG( log, "-- at time:%d --", (int) time(NULL) );

        flowid++;

        pflow_db.push_back( flow2id-1 ); // GUI related
        pflow_db.push_back( flow2id-2 ); // GUI related

        // post timer to start monitoring bandwidth usage
        monitorlink3id = link3id_;
        monitorvlpathid = vlpathid_;
        monitorvcg1 = vcgnum1;
        monitordp1  = loccktsw;
        monitorvcg2 = vcgnum2;
        monitordp2  = remcktsw;
        continue_monitoring = true;
        sendStatReq1 = true;
        timeval tv={wait_to_start_polling,0};
        post(boost::bind(&Circsw::stat_req_poll, this), tv);
        return true;
      }
      VLOG_WARN( log, "Could not create VIDEO ckt" );
      return false;
    } else {
      VLOG_WARN( log, "Could not create VIDEO ckt - no indirect path found" );
      // could fall back to direct path, but not implemented
      return false;
    }

  }


  bool
  Circsw::deleteDynamicVirtualLinkPath( uint16_t link3idtodel, uint16_t vlpathtodel ) {
    bool waiting = false;
    if ( vlink_db.find(link3idtodel) != vlink_db.end() ) {
      struct vlink_elem& ve = vlink_db[link3idtodel];
      struct vlinkpath& vlp = ve.vlpaths[vlpathtodel];
      assert( vlp.vlpathtype != STATIC );
      std::vector<uint16_t> cflowids;

      if ( vlp.vlpathtype == DYNAMIC_VIDEO ) {
        // reset parameters
        continue_monitoring = false;
        increased_bandwidth = false;
        monitorlink3id = 0;
        monitordp1 = monitordp2 = 0;
        monitorvcg2 = monitorvcg2 = 0xffff;
        sendStatReq1 = sendStatReq2 = false;
        tx_bytes1 = tx_bytes2 = last_tx_bytes = 0;
        above_tx_threshold_counter1 = 0;
        above_tx_threshold_counter2 = 0;
      }

      // use the first vlpath route to remove the ckt_path endpoints
      std::vector<node>& firstroute = vlp.vlpathroutes.begin()->second;
      for ( int i=0; i<firstroute.size(); i++ ) {
        if ( ( firstroute[i].nodetype == CKT_PATH_END1 ) ||
             ( firstroute[i].nodetype == CKT_PATH_END2 ) ) {
          removeVcgPort( firstroute[i].dpid, firstroute[i].vcgport );
        }
      }

      // use all vlpath routes to remove the intermediate nodes
      for( std::map<uint16_t, std::vector<node> >::iterator iter = vlp.vlpathroutes.begin();
           iter != vlp.vlpathroutes.end(); ++iter ) {
        cflowids.push_back( iter->first );
        std::vector<node>& vlpr = iter->second;
        for( int j=0; j<vlpr.size(); j++ ) {
          if ( vlpr[j].nodetype == CKT_PATH_INTERMEDIATE ) {
            deleteXconn( vlpr[j].dpid, iter->first );
          }
        }
      }

      deRegisterVirtualLinkOnL1Link( cflowids );

      VLOG_WARN( log, " ----------------- virtual-link path DELETED ---------------" );
      VLOG_WARN( log, "id%"PRIx16":: %"PRIx64":%d <--> %"PRIx64":%d :pathid%"PRIx16"",
                 link3idtodel, ve.ethdpid1, ve.ethport1, ve.ethdpid2, ve.ethport2,
                 vlpathtodel );
      //caller must deregister vlink-path in vlink_db

    }
    return waiting;
  }

  void
  Circsw::addNodesToPath( uint16_t link3id_, uint16_t vlpathid_, int64_t dpid,
                          uint16_t nodetype, uint16_t ethport, uint16_t vcgport,
                          uint16_t tdmport1, uint16_t tdmport2, uint16_t cflowid_ ) {
    std::map<uint16_t, vlink_elem>::iterator iter = vlink_db.find(link3id_);
    assert( iter != vlink_db.end() );
    struct vlinkpath& vlp = iter->second.vlpaths[vlpathid_];
    struct node n;
    n.dpid = dpid; n.nodetype = nodetype;
    n.ethport = ethport; n.vcgport = vcgport;
    n.tdmport1 = tdmport1; n.tdmport2 = tdmport2;
    if ( vlp.vlpathroutes.find( cflowid_ ) == vlp.vlpathroutes.end() ) {
      std::vector<node> nvec;
      nvec.push_back( n );
      vlp.vlpathroutes.insert( std::make_pair(cflowid_, nvec) );
    } else {
      vlp.vlpathroutes[cflowid_].push_back( n );
    }
  }


  const std::vector<uint64_t>&
  Circsw::getDpids(void) {
    return dpids;
  }


  void
  Circsw::getInstance(const container::Context* ctxt, Circsw*& component) {
    component = dynamic_cast<Circsw*>(ctxt->get_by_interface              \
                                    (container::Interface_description   \
                                     (typeid(Circsw).name())));
  }



  //-------------------------------------------------------------------------//
  //                         GUI Interaction Module                          //
  //-------------------------------------------------------------------------//

  void
  Circsw::showDpJoin( uint16_t bnt, uint64_t dpid ) {
    dpid &= 0xffffffff;
    if ( bnt == HYBRID_SWITCH ) {
      cswgui->registerNodes( BOOKN_CIENA_SWITCH, dpid );
    } else if ( bnt == PACKET_SWITCH ) {
      cswgui->registerNodes( BOOKN_PRONTO_SWITCH, dpid );
    }

  }

  void
  Circsw::showCktTopo( void ) {
    VLOG_DBG( log, "------------------Current Circuit Topology------------------" );
    for ( std::map<uint16_t, link1_elem>::iterator iter = link1_db.begin();
          iter != link1_db.end(); ++iter ) {
      if ( (iter->first >= 0x1000) && (iter->first < 0x2000) ) {
        uint64_t ts = iter->second.thissw;
        uint64_t ps = iter->second.thatsw;
        uint16_t tp = iter->second.thisport;
        uint16_t pp = iter->second.thatport;
        uint16_t linkid = iter->first;
        VLOG_DBG( log, "id%"PRIx16":: %"PRIx64":%"PRIx16"(%s) <==> %"PRIx64":%"PRIx16"(%s)",
                  linkid, ts, tp, switch_db[ts][0].tdmports[tp].name.c_str(),
                  ps, pp, switch_db[ps][0].tdmports[pp].name.c_str()
                  );
        ps &= 0xffffffff;
        ts &= 0xffffffff;
        cswgui->registerLinks( BOOKL_CIRCUIT, ts, tp, ps, pp, linkid );
      }
    }
  }

  void
  Circsw::showPacketLink( uint64_t cs, uint16_t cp, uint64_t ps, uint16_t pp,
                          uint16_t lid ) {
    ps &= 0xffffffff;
    cs &= 0xffffffff;
    cswgui->registerLinks( BOOKL_PACKET, cs, cp, ps, pp, lid );
  }

  void
  Circsw::showCflow( uint64_t dpid1, uint16_t tdmport1, uint64_t dpid2,
                     uint16_t tdmport2, uint16_t flowtype ) {
    dpid1 &= 0xffffffff; dpid2 &= 0xffffffff;
    struct Route_hopd srvSw( 0xffff, datapathid::from_host(dpid1), tdmport1 );
    struct Route_hopd cliSw( tdmport2, datapathid::from_host(dpid2), 0xffff );
    single_routed sr;
    sr.push_back( srvSw );
    sr.push_back( cliSw );
    std::list<single_routed> routes;
    routes.push_back( sr );
    cswgui->addAFlow( routes, flowid, flowtype );
  }

  void
  Circsw::showPflow( uint64_t dpid1, uint16_t ethport1, uint64_t dpid2, uint16_t ethport2,
                     uint64_t dpid3, uint16_t ethport3, uint64_t dpid4, uint16_t ethport4,
                     uint16_t flowtype ) {
    dpid1 &= 0xffffffff; dpid2 &= 0xffffffff;
    dpid3 &= 0xffffffff; dpid4 &= 0xffffffff;
    struct Route_hopd srvPkt( 0xffff, datapathid::from_host(dpid1), ethport1 );
    struct Route_hopd srvCkt( ethport2, datapathid::from_host(dpid2), 0xffff );
    single_routed sr;
    sr.push_back( srvPkt );
    sr.push_back( srvCkt );
    std::list<single_routed> routes;
    routes.push_back( sr );
    cswgui->addAFlow( routes, flow2id++, flowtype );

    struct Route_hopd cliCkt( 0xffff, datapathid::from_host(dpid3), ethport3 );
    struct Route_hopd cliPkt( ethport4, datapathid::from_host(dpid4), 0xffff );
    single_routed srr;
    srr.push_back( cliCkt );
    srr.push_back( cliPkt );
    std::list<single_routed> routesr;
    routesr.push_back( srr );
    cswgui->addAFlow( routesr, flow2id++, flowtype );

  }

  void
  Circsw::showIndirectCflow( uint64_t dpid1, uint16_t tdmport1, uint64_t mdpid,
                             uint16_t mtport1, uint16_t mtport2, uint64_t dpid2,
                             uint16_t tdmport2, uint16_t flowtype ) {
    dpid1 &= 0xffffffff; dpid2 &= 0xffffffff; mdpid &= 0xffffffff;
    struct Route_hopd srvSw( 0xffff, datapathid::from_host(dpid1), tdmport1 );
    struct Route_hopd midSw( mtport1, datapathid::from_host(mdpid), mtport2 );
    struct Route_hopd cliSw( tdmport2, datapathid::from_host(dpid2), 0xffff );
    single_routed sr;
    sr.push_back( srvSw );
    sr.push_back( midSw );
    sr.push_back( cliSw );
    std::list<single_routed> routes;
    routes.push_back( sr );
    cswgui->addAFlow( routes, flowid, flowtype );

  }

  void
  Circsw::showNoCflow( uint16_t flowid_ ) {
    cswgui->removeAFlow( flowid_, false );
  }

  void
  Circsw::showNoPflow( uint16_t flowid_ ) {
    cswgui->removeAFlow( flowid_, false );
  }

  //-------------------------------------------------------------------------//
  //                         CoreDirector Uint Tests                         //
  //-------------------------------------------------------------------------//

  uint64_t utmonitordp = 0;
  uint16_t utmonitorvcg = 0;

  void
  Circsw::unitTest( uint64_t switchid ) {
    // Create a virtual port
    uint16_t vcgnum = 0;
    if( switch_db[switchid][0].internalports.size() ) {
      for (std::map<uint16_t, CPort>::const_iterator iter = \
             switch_db[switchid][0].internalports.begin();
           iter != switch_db[switchid][0].internalports.end(); ++iter ) {
        vcgnum = createEmptyVcg( switchid, iter->second.port_no );
        break;
      }
    }

    /**** Unit Test Script ****/

    if( switchid == UINT64_C(0x0000000110020001)) {
      utmonitordp= switchid;
      utmonitorvcg=vcgnum;
      sleep( 2 );
      addVcgComponent( switchid, vcgnum, 0x000a, OFPTSG_STS_1, 0, false, 84 );
      sleep( 2 );
      sendPflowOutToVcg( switchid, 0x1013, 0, vcgnum, 0, true, false, false);
      sleep( 2 );
      sendPflowOutToEth( switchid, vcgnum, 0, 0x1013, true, false, false );
      sleep( 2 );
      addXconn( switchid, 0x0009, 3, 0x000a, 3, OFPTSG_STS_3c, 37 );
      sleep( 10 );
      deleteXconn( switchid, 37 );
      uint16_t secondvcg = createEmptyVcg( switchid, 0xfa04 );
      addVcgComponent( switchid, secondvcg, 0x000a, OFPTSG_STS_1, 1, true, 0 );

    } else if ( switchid == UINT64_C(0x0000000110030001)) {
      addVcgComponent( switchid, vcgnum, 0x0009, tsig, 0, true, 0 );
      //sleep( 20 ); // pause to manually get to shell prompt

      //Case1:no tags - basic case of port(eth) to port(vcg) mapping
      //sleep( 2 );
      sendPflowOutToVcg( switchid, 0x1c13, 0, vcgnum, 0, true, false, false);
      //sleep( 2 );
      sendPflowOutToEth( switchid, vcgnum, 0, 0x1c13, true, false, false );
      //Case2: multiplexing into the same vcg from diff eth ports
      // untagged packets coming in but need to insert tag(333) for mux/demux
      // matchoneth, nomatchtag, inserttag, matchonvcgandtag, striptag (SC09)
      //sleep( 2 );
      sendPflowOutToVcg( switchid, 0x1c72, 333, vcgnum, 0, true, false, true );
      //sleep( 2 );
      sendPflowOutToEth( switchid, vcgnum, 333, 0x1c72, true, true, true );
      //Case3: Matching on incoming vlan tagged packets(1001) to same vcg as in Case1
      //matchonethandtag, noinsert, matchonvcgandtag, nostrip
      //sleep( 2 );
      sendPflowOutToVcg( switchid, 0x1c13, 1001, vcgnum, 0, true, true, false );
      //sleep( 2 );
      sendPflowOutToEth( switchid, vcgnum, 1001, 0x1c13, true, true, false );
      //Case4: Same incoming eth port but demux to different vcg
      //matchonethandtag, noinsert, matchonvcgandtag, nostrip
      VLOG_DBG( log, "***Adding a second VCG" );
      //sleep( 2 );
      uint16_t secondvcg = createEmptyVcg( switchid, 0xfa07 );
      //sleep( 2 );
      addVcgComponent( switchid, secondvcg, 0x0009, tsig, 1, true, 0 );
      sleep( 2 );
      sendPflowOutToVcg( switchid, 0x1c13, 555, secondvcg, 0, true, true, false);
      //sleep( 2 );
      sendPflowOutToEth( switchid, secondvcg, 555, 0x1c13, true, true, false );
      //Case4b: Small variation on case4 - on egress just matching on port
      // will this port matching handle the other tagged packets - no
      //matchonethandtag, noinsert, matchonvcg, nostrip - same1c13 or diff1c39 eth output
      //sleep( 2 );
      sendPflowOutToVcg( switchid, 0x1c13, 4044, secondvcg, 0, true, true, false );
      //sleep( 2 );
      sendPflowOutToEth( switchid, secondvcg, 4044, 0x1c13, true, true, false );
      //sleep( 2 );
      sendPflowOutToEth( switchid, secondvcg, 0, 0x1c39, true, false, false );


      VLOG_DBG( log, "***Adding and deleting a pure STS-3c xconn " );
      sleep( 2 );
      addXconn( switchid, 0x0009, 3, 0x000a, 3, OFPTSG_STS_3c, 3 );
      sleep( 2 );
      deleteXconn( switchid, 3 );

      VLOG_DBG( log, "***Adding and Deleting a pure xconn " );
      sleep( 2 );
      addXconn( switchid, 0x0009, 1, 0x000a, 1, tsig, 24 );
      sleep( 2 );
      deleteXconn( switchid, 24 );

      VLOG_DBG( log, "***Adding and Deleting a vcg component " );
      sleep( 2 );
      addVcgComponent( switchid, vcgnum, 0x0009, tsig, 3, false, 42 );
      sleep( 2 );
      deleteVcgComponent( switchid, vcgnum, 42 );

      //VLOG_DBG( log, "disabling and in-effect deleting original vcg" );
      //should clean up all pflows
      //sleep( 2 );
      //deleteVcgComponent( switchid, vcgnum, 0 );


      // Do either this
      //VLOG_DBG( log, "*** Verifying Stats support " );
      //sleep( 20 );
      //sendPortStatsReq( utmonitordp, utmonitorvcg );

      // Or this
      //VLOG_DBG( log, "***Removing all state after 20 secs " );
      //sleep( 20 );
      //removeAllState();
    }
  }

  REGISTER_COMPONENT(container::Simple_component_factory<Circsw>, Circsw);

} // unnamed namespace


// TTD list:
// 100: switch features does not send virtual ports

// 101: When creating do createEmptyVcg first then addVcgComponent
//      remove the firsttime business, check internally and make
//      internal bookeeping of mapper slots consistent

// 102: get matching time slots

// 103: would be cool to have switch_db.links be a map indexed by
//      peer switch

// 104: Can CD do action sendToController, and packet_out and packet_in from vcg?

// 105: can we re-learn  packet links and virtual links?

// 106: need to think  if exposing mapper to OpenFlow is a good idea?
//      problems also arise with multiple mappers and their association to the eth
//      ports -- current association is with name which is cumbersome

// 107: this app does not handle static virtual links that go thru multiple transport
//        elements

// 108: Need to separate out API member functions into their own Class

// 109: Ignored the whole thing about mapper modes - cont, 50M virt, 150M virt

// 110: static signals are single timeslot only in this app

// 111: timeslot manipulations only work upto 32bits - update for 64 bits

// 112: a delete all flows for cflows and virtual ports is required

// 113: port matching should really be all-packets - how about flow priorities?

// 114: deleteVcGComponent and  removeAllState not used because of sleeps
