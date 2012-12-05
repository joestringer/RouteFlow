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


#include "mpls.hh"
#include "mpls_config.hh"
#include "buffer.hh"
#include "packets.h"
#include "openflow-default.hh"
#include <sstream>

#define AUTOBW_STEPS 5;
namespace vigil {

  using namespace vigil::container;

  Vlog_module log("mpls");

  #define CHECK_OFM_ERR(error, dp)                                          \
    if (error) {                                                            \
      if (error == EAGAIN) {                                                \
        VLOG_DBG(log, "Add flow entry to dp:%"PRIx64" failed with EAGAIN.", \
                 dp.as_host());                                             \
      } else {                                                              \
        VLOG_ERR(log, "Add flow entry to dp:%"PRIx64" failed with %d:%s.",  \
                 dp.as_host(), error, strerror(error));                     \
      }                                                                     \
      return false;                                                         \
    }

  void
  Mpls::configure(const Configuration* conf) {
    resolve( mplsgui );
    resolve( routing );
    resolve( cspfrouting );
    resolve( topo );
    resolve( lmarie );

    register_handler<Book_msg_event>
      (boost::bind(&Mpls::handle_bme_message, this, _1));

    register_handler<Flow_stats_in_event>
      (boost::bind(&Mpls::handle_fstatsin_message, this, _1));

    register_handler<Packet_in_event>
      (boost::bind(&Mpls::handle_packet_in, this, _1));

  }

  void
  Mpls::install() {
    xidcounter = 0;
    tunnel_port_number = MPLS_TUNNEL_ID_START + num_tunnels;
    for( int i=0; i<num_prefixes; i++ ) {
      destASBR br =  { pe[i].router, pe[i].outport };
      bgpTable[ pe[i].ip ] = br;
    }
    initialized = false;
    demostepper = 0;
    conf_tunnel_index = 0;
  }


  void
  Mpls::runSwitchInit( void ) {
    VLOG_DBG(log, "Checking for switches...");
    topo->get_switches();
    mswSet = topo->swSet;
    if ( mswSet.empty() ) {
      timeval tv={3,0};
      post(boost::bind(&Mpls::runSwitchInit, this), tv);
      return;
    }
    VLOG_DBG(log, "Initializing label allocation database");
    init_label_alloc_db();

    VLOG_DBG(log, "Initializing label start numbers");
    init_start_labels();
    debugTopology();

    VLOG_DBG(log, "Initializing Rib");
    init_rib();

    initialized = true;
  }

  Disposition
  Mpls::handle_bme_message(const Event& e){
    const Book_msg_event& bme = assert_cast<const Book_msg_event&>(e);

    switch(bme.msg->header.type)
      {
      case BOOKT_MPLS_CONF_TUNN_REQ:

        if (demostepper == 0) {
          runSwitchInit();
        } else if(demostepper <= num_tunnels+1){
          applyConfTunnels();
        }
        demostepper++;
        //demostepper = (demostepper+1) % (num_tunnels + 1)
        return STOP;

      default:
        break;
      }

    return CONTINUE;
  }

  void
  Mpls::applyConfTunnels( void ) {
    //install pre-configured tunnels defined in mpls_config.hh
    Cspf::RoutePtr route;
    Cspf::RouteId routeid;
    std::vector<uint16_t> ejected;

    int i = conf_tunnel_index++;
    if (i >= num_tunnels) {
      VLOG_DBG(log, "All tunnels configured");
      return;
    }
    VLOG_DBG(log, "Configuring TE tunnel id 0x%"PRIx16"", conf_tunn[i].tid);
    routeid.src = datapathid::from_host( conf_tunn[i].hdpid );
    routeid.dst = datapathid::from_host( conf_tunn[i].tdpid );
    if( routeid.src == routeid.dst ) return;
    if( tunnel_db.find(conf_tunn[i].tid) != tunnel_db.end() ) {
      VLOG_ERR(log, "Tunnel %"PRIx16" already configured", conf_tunn[i].tid );
      return;
    }
    if( cspfrouting->get_route( routeid, route, conf_tunn[i].tid,
                                conf_tunn[i].resbw,
                                conf_tunn[i].priority,
                                ejected ) ) {
      debugTunnelRoute( route );
      // create an entry in the tunnel database
      tunn_char tc;
      tc.telem = conf_tunn[i];
      tc.troute.clear();
      tc.tstats.curr_resbw = tc.telem.resbw;
      time(&tc.tstats.last_poll);
      tc.tstats.byte_count = 0;
      tunnel_db.insert( std::make_pair(conf_tunn[i].tid, tc) );
      // setup the LSPs
      if( !setupLsp( route, conf_tunn[i], ETHTYPE_LLDP ) ||
          !setupLsp( route, conf_tunn[i], ETH_TYPE_IP ) ) {
        VLOG_ERR(log, "Couldn't set up static LSP for configured tunnel %"PRIx16"",
                 conf_tunn[i].tid);
        // XXX should remove tunnel_db entry and clear route in cspf
      } else {
        //throw port status event for head-end switch
        throwPortStatusEvent( datapathid::from_host(conf_tunn[i].hdpid),
                              conf_tunn[i].tid, true );
        timeval tv={3,0};
        post(boost::bind(&Mpls::debugTopology, this), tv);
        temp_tunnel_list.push_back(conf_tunn[i].tid);
        post(boost::bind(&Mpls::processThisTunnel,this), tv);
      }

      // handle ejected tunnels if any
      for (int i=0; i<ejected.size(); i++ ) {
        rerouteEjectedTunnels(ejected[i]);
      }

    } else {
      VLOG_ERR(log, "Could not find route that met all constraints for %s %d",
               "configured tunnel", i );
    }

  }

  void
  Mpls::throwPortStatusEvent( datapathid head, tunnid tid, bool add ) {
    uint16_t outport = tunnel_db[tid].troute[0].outport;
    // port status is thrown for discovery - so outlabel used should be for the
    // lldp tunnel (which is one less than the one used for the IP tunnel)
    uint32_t outlabel = tunnel_db[tid].troute[0].outlabel - 1;
    uint16_t tunnport = tid;
    uint8_t reason = (add)? OFPPR_ADD : OFPPR_DELETE;
    Port tunnelport;
    tunnelport.port_no = tunnport;
    tunnelport.name = "tunnel interface";
    tunnelport.supported = outport;
    tunnelport.peer = outlabel;

    bool found = false;
    const Topology::PortVector& pv = topo->get_dpinfo(head).ports;
    for ( std::vector<Port>::const_iterator iter = pv.begin();
          iter != pv.end(); ++iter ) {
      if ( iter->port_no == outport ) {
        tunnelport.hw_addr = iter->hw_addr;
        found = true;
        break;
      }
    }
    if (found) {
      post(new Port_status_event(head, reason, tunnelport));
    } else {
      VLOG_DBG(log, "Corresponding phy port 0x%"PRIx16" %s 0x%"PRIx16" %s",
               outport, "for tunnel port", tunnport, "not found.. aborting throw" );
    }
  }

  void
  Mpls::processThisTunnel(void) {
    tunnid thistunn = temp_tunnel_list.front();
    showTunnel( thistunn );
    startTunnelStats( thistunn );
    datapathid srcBr = datapathid::from_host( tunnel_db[thistunn].telem.hdpid );
    datapathid dstBr = datapathid::from_host( tunnel_db[thistunn].telem.tdpid );
    tunnid oldtid = registerTunnelInRib( thistunn, srcBr, dstBr );
    rerouteFlows( thistunn, srcBr, dstBr, oldtid );
    temp_tunnel_list.pop_front();

    // delete old tunnel
    if (oldtid >= MPLS_TUNNEL_ID_START) {
      mplsgui->removeTunnel(oldtid);
      throwPortStatusEvent( tunnel_db[oldtid].troute[0].dpid, oldtid, false );
      teardownLsp( oldtid, ETHTYPE_LLDP );
      teardownLsp( oldtid, ETH_TYPE_IP );
      tunnel_flowstats_db.erase( tunnel_db[oldtid].tstats.hashval );
      tunnel_db.erase( oldtid );
    }
    debugAllDatabases();
  }

  tunnid
  Mpls::registerTunnelInRib( tunnid tid, datapathid srcBr, datapathid dstBr ) {
    tunninfo ti;
    ti.tid = tid;
    ti.outport = tunnel_db[tid].troute[0].outport;
    ti.outlabel = tunnel_db[tid].troute[0].outlabel;
    int lastindex = tunnel_db[tid].troute.size()-1;
    ti.dstBrInport = tunnel_db[tid].troute[lastindex].inport;
    tunnid oldtid = Rib[srcBr][dstBr].ti.tid;
    Rib[srcBr][dstBr].ti = ti;
    return oldtid;
  }


  // rerouteEjectedTunnels is called whenever a call to Cspf::get_route returns
  // tunnel ids of LSPs ejected due to CSPF routing with priorities. Tunnels may also
  // be ejected as a result of auto-bandwidth. This function performs the following
  // sequence of steps:
  // 1) It asks Cspf::get_route for a new route for the ejected tunnel
  // 2) It creates a new LSP over the new route and gives it a new tunnel-id and
  // updates the Rib and tunnel_db with characteristics of the old ejected tunnel
  // 3) moves flows from the ejceted-LSP to the newly created one
  // 4) removes (un-installs) the ejected LSP from the data-plane
  // Note: pts 3 and 4 and part of pt.2 are actually carried out by processThisTunnel
  //
  // XXX does not currently consider more ejections from step 1
  void
  Mpls::rerouteEjectedTunnels( tunnid etid ) {
    Cspf::RoutePtr route;
    Cspf::RouteId routeid;
    std::vector<uint16_t> ejected;

    tunnid ntid = tunnel_port_number++; // new tunnel_id
    VLOG_DBG(log, "**** Rerouting TE tunnel id 0x%"PRIx16" => 0x%"PRIx16"",
             etid, ntid);
    routeid.src = datapathid::from_host( tunnel_db[etid].telem.hdpid );
    routeid.dst = datapathid::from_host( tunnel_db[etid].telem.tdpid );
    uint32_t currResBw = ( tunnel_db[etid].telem.autobw ) \
      ? tunnel_db[etid].tstats.curr_resbw : tunnel_db[etid].telem.resbw;
    if( cspfrouting->get_route( routeid, route, ntid,
                                currResBw,
                                tunnel_db[etid].telem.priority,
                                ejected ) ) {
      debugTunnelRoute( route );
      // create an entry in the tunnel database from elements of the ejected tunnel
      tunn_char tc;
      tc.telem = tunnel_db[etid].telem;
      tc.telem.tid = ntid;
      tc.troute.clear(); // will be updated by setupLsp
      tc.tstats.curr_resbw = currResBw;
      time(&tc.tstats.last_poll);
      tc.tstats.byte_count = 0;
      tunnel_db.insert( std::make_pair(ntid, tc) );
      // setup the LSPs
      if( !setupLsp( route, tunnel_db[ntid].telem, ETHTYPE_LLDP ) ||
          !setupLsp( route, tunnel_db[ntid].telem, ETH_TYPE_IP ) ) {
        VLOG_ERR(log, "Could NOT create new tunnel %"PRIx16"", ntid);
        // XXX should remove tunnel_db entry and clear route in cspf
      } else {
        //throw port status event for head-end switch
        throwPortStatusEvent( datapathid::from_host(tunnel_db[ntid].telem.hdpid),
                              ntid, true );
        timeval tv={3,0};
        post(boost::bind(&Mpls::debugTopology, this), tv);
        temp_tunnel_list.push_back(ntid);
        post(boost::bind(&Mpls::processThisTunnel,this), tv);
      }

    } else {
      VLOG_ERR(log, "Could not find NEW route that met all constraints for %s %d",
               "ejected tunnel", etid );
    }

  }



  //-------------------------------------------------------------------------//
  //                           Tunnel Stats  Module                          //
  //-------------------------------------------------------------------------//

  void
  Mpls::startTunnelStats(tunnid tid) {
    // Asks for flow stats from switch for the corresponding tunnel
    // Does not request from tunnel head-end as we do not know what is matching
    // and going into the tunnel. Thus it asks the switch that is the next-hop
    // from the tunnel head-end.
    showTunnelStats(tid, 0);
    lsp_elem& le = tunnel_db[tid].troute[1];
    set_flow_stats_req( le.inport, ETHTYPE_MPLS, le.inlabel);
    enterFlowMatchAsTunnel(le.dpid, (ofp_match*)&osr->body, tid);
    send_openflow_command(le.dpid, &osr->header, false);
  }

  void
  Mpls::enterFlowMatchAsTunnel(datapathid dp, ofp_match *ofm, tunnid tid) {
    uint32_t hashval = hash_flow_entry(dp, ofm);
    tunnflowstatsmsg tm;
    tm.tid = tid;
    tm.dpid = dp;
    tm.raw_ofs_msg = raw_of;
    if ( tunnel_flowstats_db.find(hashval) == tunnel_flowstats_db.end() ) {
      tunnel_flowstats_db[hashval] = tm;
    }
    tunnel_db[tid].tstats.hashval = hashval;
  }

  uint32_t
  Mpls::hash_flow_entry(datapathid dp, ofp_match *ofm) {
    uint32_t x;
    x = vigil::fnv_hash(&dp, sizeof(datapathid));
    //x = vigil::fnv_hash(ofm, sizeof(ofp_match), x);
    x = vigil::fnv_hash(&ofm->in_port, sizeof(uint16_t), x);
    x = vigil::fnv_hash(&ofm->mpls_label, sizeof(uint32_t), x);
    return x;
  }

  Disposition
  Mpls::handle_fstatsin_message(const Event& e) {
    Flow_stats_in_event& fsie = const_cast<Flow_stats_in_event&>\
      (dynamic_cast<const Flow_stats_in_event&>(e));
    datapathid dp = fsie.datapath_id;
    //VLOG_DBG(log, "FLOW_STATS_IN @ %012"PRIx64"\t", dp.as_host());

    for( int i=0; i<fsie.flows.size(); i++) {
      //VLOG_DBG(log, "inport %d", ntohs(fsie.flows[i].match.in_port));
      //VLOG_DBG(log, "dltype %"PRIx16"", ntohs(fsie.flows[i].match.dl_type));
      //VLOG_DBG(log, "inlabel %d", ntohl(fsie.flows[i].match.mpls_label));
      //VLOG_DBG(log, "bytes: %"PRIu64"", ntohll(fsie.flows[i].byte_count));
      int32_t change = 0;
      uint32_t hashval = hash_flow_entry(dp, &fsie.flows[i].match);
      time_t cur_time;
      time(&cur_time);
      if ( tunnel_flowstats_db.find(hashval) != tunnel_flowstats_db.end() ) {
        tunnid tid = tunnel_flowstats_db[hashval].tid;
        //VLOG_DBG(log, "corresponding tunnel: 0x%"PRIx16"", tid);
        uint32_t cur_byte_count = uint32_t(ntohll(fsie.flows[i].byte_count));

        tunnel_db[tid].tstats.usage =
            uint32_t(8*(cur_byte_count - tunnel_db[tid].tstats.byte_count) /
                                difftime(cur_time, tunnel_db[tid].tstats.last_poll)/1000);

        //VLOG_DBG(log, "byte diff: %"PRIu32"", cur_byte_count - tunnel_db[tid].tstats.byte_count);
        //VLOG_DBG(log, "time diff: %f",  difftime(cur_time, tunnel_db[tid].tstats.last_poll));

        tunnel_db[tid].tstats.byte_count = cur_byte_count;
        tunnel_db[tid].tstats.last_poll = cur_time;
        tunnel_db[tid].tstats.autobw_count++;
        tunnel_db[tid].tstats.autobw_count = tunnel_db[tid].tstats.autobw_count %
                                                                                            AUTOBW_STEPS;
        if(tunnel_db[tid].telem.autobw && tunnel_db[tid].tstats.autobw_count == 0) {
            std::vector<uint16_t> eject;
            Cspf::RoutePtr route;
            bool newroute = false;
            route_from_tunn_route(route, tunnel_db[tid].troute);

            //can increase the bw
            if(cspfrouting->check_existing_route(route, tunnel_db[tid].tstats.curr_resbw,
                               tunnel_db[tid].telem.priority, tid,
                              tunnel_db[tid].tstats.usage, newroute,
                              eject)) {

                Cspf::RoutePtr old_route;
                route_from_tunn_route(old_route, tunnel_db[tid].troute);
                cspfrouting->set_existing_route(tid, tunnel_db[tid].telem.priority,
                           tunnel_db[tid].tstats.curr_resbw, tunnel_db[tid].tstats.usage,
                          old_route, newroute, route, eject);
                VLOG_DBG(log, "adjusted bw of %"PRIx16" from %"PRIu32" to %"PRIu32"", tid, tunnel_db[tid].tstats.curr_resbw, tunnel_db[tid].tstats.usage);
                change = tunnel_db[tid].tstats.usage - tunnel_db[tid].tstats.curr_resbw;
                VLOG_DBG(log, "~~~~change bw %"PRIx32", newroute = %"PRIx8"", change, newroute);
                tunnel_db[tid].tstats.curr_resbw = tunnel_db[tid].tstats.usage;
                // handle ejected tunnels if any
               for (int i=0; i<eject.size(); i++ ) {
                 rerouteEjectedTunnels(eject[i]);
               }
            } else {
                VLOG_ERR(log, "cannot increase the bw of %"PRIx16"", tid);
            }
        }

        showTunnelStats( tid, change );
        temp_hashval_list.push_back(hashval);
        timeval tv={TUNNEL_STATS_POLL_INTERVAL,0};
        post(boost::bind(&Mpls::sendTunnelStatsReq, this), tv);
      }
    }
    return STOP;
  }

  void
  Mpls::route_from_tunn_route(Cspf::RoutePtr& route, tunn_route& troute) {
    route.reset(new Cspf::Route());
    struct Cspf::Link link;
    link.outport = troute.begin()->outport;
    route->id.src = troute.begin()->dpid;
    for(tunn_route::iterator iter = troute.begin()+1; iter != troute.end(); iter++) {
         link.inport = iter->inport;
         link.dst = iter->dpid;
         route->path.push_back(link);
         link.outport = iter->outport;
    }
    route->id.dst = link.dst;
  }

  void
  Mpls::sendTunnelStatsReq( void ) {
    uint32_t hashval = temp_hashval_list.front();
    temp_hashval_list.pop_front();
    if ( tunnel_flowstats_db.find(hashval) != tunnel_flowstats_db.end() ) {
      tunnflowstatsmsg tm = tunnel_flowstats_db[hashval];
      osr = (ofp_stats_request*)tm.raw_ofs_msg.get();
      send_openflow_command(tm.dpid, &osr->header, false);
    }
  }

  void
  Mpls::set_flow_stats_req( uint16_t inport, uint16_t dltype, uint32_t inlabel ) {
    int size = sizeof(ofp_stats_request) + sizeof(ofp_flow_stats_request);
    raw_of.reset(new uint8_t[size]);

    osr = (ofp_stats_request*) raw_of.get();
    osr->header.version = OFP_VERSION;
    osr->header.type = OFPT_STATS_REQUEST;
    osr->header.xid = ++xidcounter;
    osr->header.length = htons(size);
    osr->type = htons(OFPST_FLOW);
    osr->flags = 0;

    struct ofp_flow_stats_request* ofsr = (ofp_flow_stats_request*)osr->body;
    ofp_match& match = ofsr->match;
    prepare_label_match(match, 0, inport, dltype, inlabel);
    ofsr->table_id = 0xff; //all tables
    memset(&ofsr->pad, 0, sizeof(uint8_t));
    ofsr->out_port = htons(OFPP_NONE);
  }

  //-------------------------------------------------------------------------//
  //                         Flow Routing Module                             //
  //-------------------------------------------------------------------------//

  Disposition
  Mpls::handle_packet_in(const Event& e) {
    if (!initialized) return CONTINUE;
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    uint16_t inport = pi.in_port;
    Nonowning_buffer b(*pi.get_buffer());
    Flow flow(htons(inport), b); // flow is in n.b.o
    if ( flow.dl_type != htons(ETHTYPE_LLDP) &&
         flow.dl_type != htons(ETHTYPE_IPv6) ) {
      std::ostringstream os;
      os << flow;
      VLOG_DBG(log, "Incoming: %s", os.str().c_str());
      VLOG_DBG(log, "hashvalue %"PRIx64" %"PRIu64"", flow.hash_code(), flow.hash_code());
      routeFlow( flow, pi.datapath_id );
    }

    return CONTINUE;
  }

  void
  Mpls::routeFlow( Flow& flow, datapathid dpid ) {
    Routing_module::RoutePtr route;
    Routing_module::RouteId routeid;
    Routing_module::Route newroute;
    bool usenewroute = false;

    uint32_t dst_prefix = ntohl(flow.nw_dst) & 0xffffff00; //24
    if ( bgpTable.find(dst_prefix) != bgpTable.end() ) {
      ASBR dstrouter = bgpTable[dst_prefix].router;
      uint16_t dstoutport = bgpTable[dst_prefix].outport;
      routeid.src = dpid;
      routeid.dst = datapathid::from_host( dstrouter );
      bool found = routing->get_route( routeid, route );

      if (found) {
        // check route for tunnel ports
        bool tunnroute = checkFixRouteTunnelFlow(flow, *route, ntohs(flow.in_port),
                                                 dstoutport, usenewroute, newroute);
        if (!tunnroute) {
          if (usenewroute) {
            setupFlowInIPRoute(flow, newroute, ntohs(flow.in_port),
                               dstoutport, FLOW_IDLE_TIMEOUT);
            registerFlow(flow, newroute, ntohs(flow.in_port), dstoutport);
            showFlowRoute(flow, newroute, ntohs(flow.in_port), dstoutport);
          } else {
            setupFlowInIPRoute(flow, *route, ntohs(flow.in_port),
                               dstoutport, FLOW_IDLE_TIMEOUT);
            registerFlow(flow, *route, ntohs(flow.in_port), dstoutport);
            showFlowRoute(flow, *route, ntohs(flow.in_port), dstoutport);
          }
          //XXX send packet out
        }
      } else {
        VLOG_DBG(log, "Cannot find route for incoming flow");
      }
    } else {
      VLOG_DBG(log, "Cannot determine destination router incoming flow");
    }
  }

  bool
  Mpls::checkFixRouteTunnelFlow( Flow& flow, Routing_module::Route& route,
                                 uint16_t nw_inport, uint16_t nw_outport,
                                 bool& usenewroute,
                                 Routing_module::Route& newroute ) {
    // CHECK: quick check for tunnel ports
    bool needsfixing = false;
    tunnid tid = 0;
    for(std::list<Routing_module::Link>::iterator iter = route.path.begin();
        iter != route.path.end(); ++iter ) {
      if ( iter->outport >= MPLS_TUNNEL_ID_START ) {
        needsfixing = true;
        tid = iter->outport;
        break;
      }
    }
    VLOG_DBG(log, "tid:%"PRIx16" needs fixing:%s", tid,
             (needsfixing)?"true":"false" );
    if (!needsfixing) return false;

    // FIX: If traffic type does not match tunnel traffic-type
    // in that case, fix the route to go over normal IP links instead.
    // We do this by creating 'newroute' from the cspf_routing module,
    // as cspf routes over phy links (we ask for lsp route with zero resBw)
    uint8_t flowtype;
    switch (ntohs(flow.tp_dst)) {
    case HTTPPORT: flowtype = FLOWTYPE_HTTP; break;
    case SIPPORT : flowtype = FLOWTYPE_VOIP; break;
    case VLCPORT : flowtype = FLOWTYPE_VIDEO; break;
    default: flowtype = FLOWTYPE_OTHER; break;
    }
    uint8_t traffictype = tunnel_db[tid].telem.traffictype;
    VLOG_DBG(log, "incoming flowtype:%x tunnel-traffictype:%x", flowtype >> 4,
             traffictype );
    if( !(traffictype & (flowtype >> 4)) ) {
      VLOG_DBG(log, "Incoming flow does not match traffictype of tunnel along the");
      VLOG_DBG(log, "shortest path. Changing flow route to go over IP links instead");
      Cspf::RoutePtr croute;
      Cspf::RouteId crouteid;
      std::vector<uint16_t> ejected;
      crouteid.src = route.id.src;
      crouteid.dst = route.id.dst;

      if( cspfrouting->get_route( crouteid, croute, tid, 0, 0, ejected ) ) {
        Cspf::Route cr = *croute;
        void* v = &cr;
        newroute = *((Routing_module::Route *) v);
      } else {
        VLOG_ERR(log,"**** Can't route incoming flow via normal IP links -- why??");
      }
      usenewroute = true;
      return false;
    }

    // ROUTE: If traffic type of flow does match allowed traffictype of tunnel
    // then we need to replace tunnel virtual outport at SrcBr and tunnel virtual
    // inport at DstBr with physical ports and in and out labels.
    flowinfo fi;
    fi.flow = flow; fi.route = route;
    bool found = findSrcAndDstBR( route, nw_inport, nw_outport,
                                  fi.srcBr, fi.dstBr, fi.srcOutport, fi.srcInport,
                                  fi.dstOutport, fi.dstInport);
    if (found) {
      VLOG_DBG( log, "SrcBr:: %d:%"PRIx64":%d DstBr:: %d:%"PRIx64":%d",
                fi.srcInport, fi.srcBr.as_host(), fi.srcOutport,
                fi.dstInport, fi.dstBr.as_host(), fi.dstOutport );
      // get tunnel actual phy ports and labels from Rib or tunnel_db
      uint16_t op = Rib[fi.srcBr][fi.dstBr].ti.outport;
      uint32_t ol = Rib[fi.srcBr][fi.dstBr].ti.outlabel;
      uint16_t ip = Rib[fi.srcBr][fi.dstBr].ti.dstBrInport;
      VLOG_DBG( log, "Installing in SrcBr -> changed to %d:%"PRIx64":%d:<%d>",
                fi.srcInport, fi.srcBr.as_host(), op, ol );
      VLOG_DBG( log, "Installing in DstBr -> changed to %d:<0>:%"PRIx64":%d",
                ip, fi.dstBr.as_host(), fi.dstOutport );
      setupFlowInTunnelRoute(flow, route, nw_inport,
                             nw_outport, FLOW_IDLE_TIMEOUT,
                             fi.srcBr, op, ol,
                             fi.dstBr, ip);
      registerFlow(flow, route, nw_inport, nw_outport);
      showFlowRoute(flow, route, nw_inport, nw_outport);
      // XXX send packet out
    } else {
      VLOG_ERR( log, "Problem detected which will likely result in crash" );
      VLOG_ERR( log, "Route shows tunnel ports, but SrcBr or DstBr not found" );
    }
    return true;
  }

  void
  Mpls::rerouteFlows( tunnid tid, datapathid srcBr, datapathid dstBr, tunnid oldtid ) {
    tunnflow& tf = Rib[srcBr][dstBr];
    std::list<flowid>& lfs = tf.linkflows;
    std::list<flowid>& tfs = tf.tunnflows;

    // rerouting flows from IP links to Tunnel 'tid'
    // flowtype must match tunnel traffic type
    std::list<flowid>::iterator iter = lfs.begin();
    while ( iter != lfs.end() ) {
      uint8_t traffictype = tunnel_db[tid].telem.traffictype;
      VLOG_DBG(log, "tid:%"PRIx16" traffictype:%x", tid, traffictype);
      uint8_t flowtype;
      switch (ntohs(flow_db[*iter].flow.tp_dst)) {
        case HTTPPORT: flowtype = FLOWTYPE_HTTP; break;
        case SIPPORT : flowtype = FLOWTYPE_VOIP; break;
        case VLCPORT : flowtype = FLOWTYPE_VIDEO; break;
        default: flowtype = FLOWTYPE_OTHER; break;
      }
      VLOG_DBG(log, "fid:%"PRIx64" flowtype:%x", *iter, flowtype >> 4 );
      if( traffictype & (flowtype >> 4) ) {
        rerouteFlow(flow_db[*iter], tf.ti);
        //reaccount for rerouted flows in Rib
        tf.tunnflows.push_back(*iter);
        iter = tf.linkflows.erase(iter);
      } else {
        ++iter;
      }
    }

    // rerouting flows from Tunnel 'oldtid' to Tunnel 'tid'
    // no need to check for traffictype as both tunnels have same type
    // no need to reaccount for rerouted flow as it is still a tunnel flow,
    // the difference being that it is a different tunnel now
    if (oldtid >= MPLS_TUNNEL_ID_START) {
      std::list<flowid>::iterator iter = tfs.begin();
      while ( iter != tfs.end() ) {
        rerouteFlow(flow_db[*iter], tf.ti);
        ++iter;
      }
    }

  }


  // To re-route flow over tunnel, sends a flow_mod message
  // to head-end and possibly tail-end routers
  bool
  Mpls::rerouteFlow( flowinfo& fi, tunninfo& ti ) {
    VLOG_DBG(log, "Auto-routing this flow %"PRIx64"", fi.flow.hash_code() );
    // check for in port at dstBr first
    if( fi.dstInport != ti.dstBrInport ) {
      VLOG_DBG(log, "Adding flow to DsrBr:%"PRIx64" to change inport %d ->%d",
               fi.dstBr.as_host(), fi.dstInport, ti.dstBrInport );
      set_flow_mod_msg(fi.flow, ti.dstBrInport, fi.dstOutport, UINT32_MAX,
                       FLOW_IDLE_TIMEOUT, false, OFPML_NONE);
      int err = send_openflow_command(fi.dstBr, &ofm->header, false);
      CHECK_OFM_ERR(err, fi.dstBr);
    }
    // next send modify message to head-end of tunnel
    // which is also the srcBr for the flow
    VLOG_DBG(log, "Modifying flow to SrcBr:%"PRIx64" to change outport %d ->%d:%d",
             fi.srcBr.as_host(), fi.srcOutport, ti.outport, ti.outlabel );
    set_flow_mod_msg(fi.flow, fi.srcInport, ti.outport, UINT32_MAX,
                     FLOW_IDLE_TIMEOUT, true, ti.outlabel);
    int err = send_openflow_command(fi.srcBr, &ofm->header, false);
    CHECK_OFM_ERR(err, fi.srcBr);

    //reaccount for re-routed flows in flowdb
    fixRoute( fi, ti.tid );
    fi.srcOutport = ti.tid; //change from phyport to tunnel virtual port
    fi.dstInport = ti.tid;

    // send flow change info to GUI
    showModifiedFlowRoute(fi.flow, fi.route, ntohs(fi.flow.in_port), fi.nw_outport);
    return true;
  }

  // replaces the 'route' in flowinfo with a route that goes through the tunnel
  // i.e the outport in srcBr and inport in dstBr are replaced with the tunnel-id
  // 'tid', which also serves as the virtual port number for the tunnel interface
  void
  Mpls::fixRoute( flowinfo& fi, tunnid tid ) {
    Routing_module::Route newroute;
    newroute.id = fi.route.id;
    newroute.path.clear();

    bool thisIsSrcBr = false;
    // first get path upto and including srcBr
    if( fi.route.id.src == fi.srcBr ) thisIsSrcBr = true;
    for(std::list<Routing_module::Link>::iterator iter = fi.route.path.begin();
        iter != fi.route.path.end(); ++iter ) {
      if (thisIsSrcBr) {
        Routing_module::Link pl;
        pl.dst = fi.dstBr;
        pl.inport = tid;
        pl.outport = tid;
        newroute.path.push_back( pl );
        break;
      } else {
        newroute.path.push_back( *iter );
        if( iter->dst == fi.srcBr ) thisIsSrcBr = true;
      }
    }
    //then get path beyond dstBr
    bool foundDstBr = false;
    for(std::list<Routing_module::Link>::iterator iter = fi.route.path.begin();
        iter != fi.route.path.end(); ++iter ) {
      if( iter->dst == fi.dstBr ) {
        foundDstBr = true;
        continue;
      }
      if (!foundDstBr) continue;
      newroute.path.push_back( *iter );
    }
    // finally replace the flow_path with new path
    fi.route = newroute;
  }

  void
  Mpls::registerFlow( Flow& flow, Routing_module::Route& route,
                      uint16_t nw_inport, uint16_t nw_outport ) {
    datapathid srcBr, dstBr;
    uint16_t srcOutport=0, srcInport=0, dstOutport=0, dstInport=0;
    bool found = findSrcAndDstBR( route, nw_inport, nw_outport,
                                  srcBr, dstBr, srcOutport, srcInport,
                                  dstOutport, dstInport);

    if (found) {
      VLOG_DBG( log, "Registering SrcBr:: %d:%"PRIx64":%d DstBr:: %d:%"PRIx64":%d",
                srcInport, srcBr.as_host(), srcOutport,
                dstInport, dstBr.as_host(), dstOutport );
      //enter into flow database
      uint64_t flowid = flow.hash_code();
      Flow thisflow = flow;
      Routing_module::Route thisroute = route;
      flowinfo fi = { thisflow, thisroute, srcBr, srcInport, srcOutport,
                      dstBr, dstInport, dstOutport, nw_outport };
      if ( flow_db.find(flowid) == flow_db.end() ) {
        flow_db[flowid] = fi;
      }
      //enter into routing information base
      if ( srcOutport >= MPLS_TUNNEL_ID_START )
        Rib[srcBr][dstBr].tunnflows.push_back(flowid);
      else
        Rib[srcBr][dstBr].linkflows.push_back(flowid);

    } else {
      VLOG_DBG( log, "Could not find src or dst backbone router..NOT REGISTERING" );
    }

  }


  bool
  Mpls::findSrcAndDstBR( Routing_module::Route& route, uint16_t nw_inport,
                         uint16_t nw_outport, datapathid& srcBr,
                         datapathid& dstBr, uint16_t& srcOutport, uint16_t& srcInport,
                         uint16_t& dstOutport, uint16_t& dstInport) {
    bool foundSrcBr = false;
    bool foundDstBr = false;
    // we distinguish Backbone Routers from ASBRs by configuration of their
    // datapathid. ASBR's have ids 0x20 and up
    if ( route.id.src.as_host() < ASBR_DPID_START ) {
      srcBr = route.id.src;
      srcInport = nw_inport;
      srcOutport = route.path.begin()->outport;
      foundSrcBr = true;
    }
    if ( route.id.dst.as_host() < ASBR_DPID_START ) {
      dstBr = route.id.dst;
      dstOutport = nw_outport;
      dstInport = route.path.back().inport;
      foundDstBr = true;
    }
    if ( foundDstBr && foundSrcBr ) return true;
    if ( !foundSrcBr ) {
      for( std::list<Routing_module::Link>::const_iterator iter = route.path.begin();
           iter != route.path.end(); ++iter ) {
        if ( iter->dst.as_host() < ASBR_DPID_START ) {
          foundSrcBr = true;
          srcBr = iter->dst;
          srcInport = iter->inport;
          ++iter;
          srcOutport = iter->outport;
          break;
        }
      }
      if ( !foundSrcBr ) return false;
    }
    if ( !foundDstBr ) {
      bool thisIsBR = false;
      datapathid thisrouter;
      if ( route.id.src == srcBr ) {
        thisIsBR = true;
        thisrouter = srcBr;
      }
      for( std::list<Routing_module::Link>::const_iterator iter = route.path.begin();
           iter != route.path.end(); ++iter ) {
        if ( iter->dst.as_host() >= ASBR_DPID_START && thisIsBR == true ) {
          foundDstBr = true;
          dstBr = thisrouter;
          dstOutport = iter->outport;
          --iter;
          dstInport = iter->inport;
          if (srcBr == dstBr) return false;
          return true;
        } else {
          //set for next iteration
          thisrouter = iter->dst;
          if ( iter->dst.as_host() < ASBR_DPID_START ) thisIsBR = true;
        }
      }
      return false;
    } else {
      return true;
    }
  }

  void
  Mpls::init_rib(void) {
    tunnflow tf;
    tf.linkflows.clear(); tf.tunnflows.clear();
    tf.ti.tid = tf.ti.outport = tf.ti.outlabel = tf.ti.dstBrInport = 0;
    dstmap dm;
    for ( std::list<datapathid>::const_iterator iter = mswSet.begin();
          iter != mswSet.end(); ++iter ) {
      datapathid src = *iter;
      dm.clear();
      for ( std::list<datapathid>::const_iterator iter1 = mswSet.begin();
            iter1 != mswSet.end(); ++iter1 ) {
        datapathid dst = *iter1;
        if ( dst != src ) {
          dm.insert( std::make_pair(dst, tf) );
        }
      }
      Rib.insert( std::make_pair(src, dm) );
    }
  }


  //-------------------------------------------------------------------------//
  //                       Packet Flow Setup API                             //
  //-------------------------------------------------------------------------//

  // Used to setup a 'flow' along a non-tunnel 'route' - thus the definition
  // of a flow is the same at each switch along the route. The only action
  // applied is OFPAT_OUTPUT.
  // Everything in Flow should be in network byte order.
  // nw_inport and nw_outport refer to the ports where packet enters and exits the
  // network, and should be specified in host byte order
  bool
  Mpls::setupFlowInIPRoute(const Flow& flow, const Routing_module::Route& route,
                           uint16_t nw_inport, uint16_t nw_outport,
                           uint16_t flow_timeout ) {
    if (route.path.empty()) return false;
    std::list<Routing_module::Link>::const_iterator link = route.path.begin();

    datapathid dp = route.id.src;
    uint16_t outport, inport = nw_inport;
    //setup packet route per switch
    while (true) {
      if (link == route.path.end()) {
        outport = nw_outport;
      } else {
        outport = link->outport;
      }
      set_flow_mod_msg(flow, inport, outport, UINT32_MAX, flow_timeout,
                       false, OFPML_NONE);
      int err = send_openflow_command(dp, &ofm->header, false);
      CHECK_OFM_ERR(err, dp);

      if (link == route.path.end()) {
        break;
      }

      dp = link->dst;
      inport = link->inport;
      ++link;
    }
    return true;
  }


  // Used to setup a 'flow' along a 'route' which includes a tunnel.
  // Instead of the information passed in @'route' (which includes virtual ports)
  //   @srcBr (tunnel-head) label information is pushed and physical outport is used
  //   @dstBr (tunnel-tail) the flow definition changes to the physical inport
  // Everything in Flow should be in network byte order.
  // nw_inport and nw_outport refer to the ports where packet enters and exits the
  // network, and should be specified in host byte order
  bool
  Mpls::setupFlowInTunnelRoute(const Flow& flow, const Routing_module::Route& route,
                               uint16_t nw_inport, uint16_t nw_outport,
                               uint16_t flow_timeout, datapathid srcBr,
                               uint16_t srcOp, uint32_t srcOl,
                               datapathid dstBr, uint16_t dstIp) {
    if (route.path.empty()) return false;
    std::list<Routing_module::Link>::const_iterator link = route.path.begin();

    datapathid dp = route.id.src;
    uint16_t outport, inport = nw_inport;
    //setup packet route per switch
    while (true) {
      if (link == route.path.end()) {
        outport = nw_outport;
      } else {
        outport = link->outport;
      }

      if (dp == srcBr) {
        set_flow_mod_msg(flow, inport, srcOp, UINT32_MAX, flow_timeout,
                         true, srcOl);
      } else if (dp == dstBr) {
        set_flow_mod_msg(flow, dstIp, outport, UINT32_MAX, flow_timeout,
                         false, OFPML_NONE);
      } else {
        set_flow_mod_msg(flow, inport, outport, UINT32_MAX, flow_timeout,
                         false, OFPML_NONE);
      }

      int err = send_openflow_command(dp, &ofm->header, false);
      CHECK_OFM_ERR(err, dp);

      if (link == route.path.end()) {
        break;
      }

      dp = link->dst;
      inport = link->inport;
      ++link;
    }
    return true;
  }



  void
  Mpls::set_flow_mod_msg(const Flow& flow, uint16_t inport, uint16_t outport,
                         uint32_t buffer_id, uint16_t timeout, bool modify,
                         uint32_t outlabel)
  {

    size_t size = sizeof(*ofm) + sizeof(ofp_action_output);
    if (modify) size += sizeof(ofp_action_push) + sizeof(ofp_action_mpls_label);
    raw_of.reset(new uint8_t[size]);
    ofm = (ofp_flow_mod*) raw_of.get();

    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.xid = ++xidcounter;
    ofm->header.length = htons(size);
    ofp_match& match = ofm->match;
    ofm->cookie = htonll(flow.hash_code());
    if (modify) ofm->command = htons(OFPFC_MODIFY);
    else ofm->command = htons(OFPFC_ADD);
    ofm->idle_timeout = htons(timeout);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->priority = htons(OFP_DEFAULT_PRIORITY);
    ofm->buffer_id = htonl(buffer_id);
    ofm->out_port = htons(OFPP_NONE);
    ofm->flags = htons(ofd_flow_mod_flags());

    match.wildcards = 0;
    match.in_port = htons(inport);
    memcpy(match.dl_src, flow.dl_src.octet, ethernetaddr::LEN);
    memcpy(match.dl_dst, flow.dl_dst.octet, ethernetaddr::LEN);
    match.dl_vlan = flow.dl_vlan;
    match.dl_vlan_pcp = flow.dl_vlan_pcp;
    memset(&ofm->match.pad1, 0, sizeof(uint8_t));
    match.dl_type = flow.dl_type;
    match.nw_tos = flow.nw_tos;
    match.nw_proto = flow.nw_proto;
    memset(&ofm->match.pad2, 0, 2*sizeof(uint8_t));
    match.nw_src = flow.nw_src;
    match.nw_dst = flow.nw_dst;
    match.tp_src = flow.tp_src;
    match.tp_dst = flow.tp_dst;
    match.mpls_label = htonl(OFPML_NONE);
    match.mpls_tc = 0;
    memset(&ofm->match.pad3, 0, 3*sizeof(uint8_t));

    ofp_action_header *action = (ofp_action_header*)(ofm->actions);
    if (modify) {
      ofp_action_push *pushmpls = (ofp_action_push*)action;
      pushmpls->type = htons(OFPAT_PUSH_MPLS);
      pushmpls->len  = htons(sizeof(ofp_action_push));
      pushmpls->ethertype = htons(ETHTYPE_MPLS);
      action = (ofp_action_header*)((char*)pushmpls + sizeof(ofp_action_push));

      ofp_action_mpls_label *mlabel = (ofp_action_mpls_label*)action;
      mlabel->type = htons(OFPAT_SET_MPLS_LABEL);
      mlabel->len  = htons(sizeof(ofp_action_mpls_label));
      mlabel->mpls_label = htonl(outlabel);
      action = (ofp_action_header*)((char*)action + sizeof(ofp_action_mpls_label));
    }
    ofp_action_output& output = *((ofp_action_output*)action);
    memset(&output, 0, sizeof(ofp_action_output));
    output.type = htons(OFPAT_OUTPUT);
    output.len = htons(sizeof(output));
    output.max_len = 0;
    output.port = htons(outport);
  }

  //-------------------------------------------------------------------------//
  //                Label Switched Path Setup API                            //
  //-------------------------------------------------------------------------//

  // We do not support LSP paths with size < 2 - ie LSP must traverse at least 3
  // nodes including headend and tailend switches.
  // We always do Penultimate Hop Popping due to lack of multiple tables in switch.
  bool
  Mpls::setupLsp( Cspf::RoutePtr& route, tunn_elem& te,
                  uint16_t payload_ethtype ) {
    if ( route->path.size()  <  2 ) {
      VLOG_ERR(log, "Invalid length LSP route, ... aborting setup");
      return false;
    }
    bool ok = (payload_ethtype != ETHTYPE_LLDP)? true: false;
    lsp_elem le;
    uint32_t nextlabel = OFPML_NONE;
    datapathid nextdp;
    uint16_t nextinport = OFPP_NONE;
    for( std::list<Cspf::Link>::const_iterator iter = route->path.begin();
         iter != route->path.end(); ++iter ) {
      // For ingress switch in static LSP we do not install a flow.
      // We only allocate a label for the outgoing port
      if ( iter == route->path.begin() ) {
        le.dpid = route->id.src;
        le.inport = OFPP_NONE;
        le.inlabel = OFPML_NONE;
        le.outport = iter->outport;
        le.outlabel = nextlabel = get_inlabel( iter->dst );
        if (ok) tunnel_db[te.tid].troute.push_back( le );
        nextinport = iter->inport; nextdp = iter->dst;
        continue;
      }

      // intermediate switch
      le.dpid = nextdp; le.inport = nextinport; le.inlabel = nextlabel;
      le.outport = iter->outport;
      uint32_t wc = OFPFW_ALL & ~OFPFW_IN_PORT & ~OFPFW_DL_TYPE & ~OFPFW_MPLS_LABEL;
      // determine if the intermediate sw happens to be the penultimate sw
      if ( iter->dst != route->id.dst ) {
        le.outlabel = nextlabel = get_inlabel( iter->dst );
        if (ok) tunnel_db[te.tid].troute.push_back( le );
        nextinport = iter->inport; nextdp = iter->dst;
        // Send flow messages with label_set (XXX optional dec_ttl)
        set_flow_mod_msg(wc, le.inlabel, le.inport, le.outport, le.outlabel,
                            ETHTYPE_MPLS, ETHTYPE_NULL,
                            false, false, true, false, false);
        int err = send_openflow_command(le.dpid, &ofm->header, false);
        CHECK_OFM_ERR(err, le.dpid);
        continue;
      } else {
        le.outlabel = IMPLICIT_NULL;
        if (ok) tunnel_db[te.tid].troute.push_back( le );
        // Send flow messgage with pop (XXX optional dec, copy_in and then pop)
        set_flow_mod_msg(wc, le.inlabel, le.inport, le.outport, le.outlabel,
                            ETHTYPE_MPLS, payload_ethtype,
                            false, true, false, false, false);
        int err1 = send_openflow_command(le.dpid, &ofm->header, false);
        CHECK_OFM_ERR(err1, le.dpid);
        // For egress switch in static LSP we do not install a flow
        le.dpid = route->id.dst;
        le.inport = iter->inport;
        le.inlabel = IMPLICIT_NULL;
        le.outlabel = OFPML_NONE;
        le.outport = OFPP_NONE;
        if (ok) tunnel_db[te.tid].troute.push_back( le );
        continue;
      }
    }
    return true;
  }

  bool
  Mpls::teardownLsp( tunnid tid, uint16_t payload_ethtype ) {
    tunn_route& tr = tunnel_db[tid].troute;
    uint32_t wc = OFPFW_ALL & ~OFPFW_IN_PORT & ~OFPFW_DL_TYPE & ~OFPFW_MPLS_LABEL;

    // lsp flow entries are removed in switches between the head and tail ends.
    // flow entries in the head and tail ends will idle-timeout when the
    // lsp is no longer used - we assume this is true when this function is called
    for( int i=1; i<tr.size()-1; i++ ) {
      uint32_t inlabel = ( payload_ethtype == ETHTYPE_LLDP ) ? tr[i].inlabel-1
        : tr[i].inlabel;
      set_flow_mod_msg(wc, inlabel, tr[i].inport, tr[i].outport, OFPML_NONE,
                       ETHTYPE_MPLS, ETHTYPE_NULL,
                       false, false, false, false, false);
      ofm->command = htons(OFPFC_DELETE);
      int err = send_openflow_command(tr[i].dpid, &ofm->header, false);
      CHECK_OFM_ERR(err, tr[i].dpid);
    }
    return true;
  }

  uint32_t
  Mpls::get_inlabel( datapathid dpid ) {
    uint32_t next = label_alloc_db[dpid].next_available_label++;
    return next;
  }

  void
  Mpls::init_label_alloc_db(void) {
    label_alloc la = {0,0};
    for ( std::list<datapathid>::const_iterator iter = mswSet.begin();
          iter != mswSet.end(); ++iter ) {
      label_alloc_db.insert( std::make_pair(*iter, la) );
    }
  }

  void
  Mpls::init_start_labels(void) {
    // could be random but using ordered labels to aid debugging
    uint32_t start = 20;
    for( std::map<datapathid, label_alloc>::iterator iter = label_alloc_db.begin();
         iter != label_alloc_db.end(); ++iter ) {
      iter->second.label_start = iter->second.next_available_label = start;
      VLOG_DBG( log, "Switch:%d start_label:%d", (int)iter->first.as_host(),
                iter->second.next_available_label );
      start += 111;
    }
  }

  void
  Mpls::set_flow_mod_msg( uint32_t wc, uint32_t inlabel, uint16_t inport,
                          uint16_t outport, uint32_t outlabel,
                          uint16_t dltype, uint16_t ethertype,
                          bool push, bool pop, bool setlabel, bool decttl,
                          bool copyin ) {

    int len_flow_actions = sizeof(ofp_action_output);
    if (push) len_flow_actions += sizeof(ofp_action_push);
    if (pop)  len_flow_actions += sizeof(ofp_action_pop_mpls);
    if (setlabel) len_flow_actions += sizeof(ofp_action_mpls_label);
    if (decttl) len_flow_actions += sizeof(ofp_action_header);
    if (copyin) len_flow_actions += sizeof(ofp_action_header);
    size_t size = sizeof(*ofm) + len_flow_actions;

    raw_of.reset(new uint8_t[size]);
    ofm = (ofp_flow_mod*) raw_of.get();

    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.xid = ++xidcounter;
    ofm->header.length = htons(size);
    ofp_match& match = ofm->match;
    ofm->cookie = htonll(0);
    ofm->command = htons(OFPFC_ADD);
    ofm->idle_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->priority = htons(OFP_LSP_DEFAULT_PRIORITY);
    ofm->buffer_id = htonl(UINT32_MAX);
    ofm->out_port = htons(OFPP_NONE);
    ofm->flags = htons(ofd_flow_mod_flags());

    prepare_label_match(match, wc, inport, dltype, inlabel);

    // follow ordering of actions?
    ofp_action_header *action = (ofp_action_header*)(ofm->actions);
    if (copyin) {
      action->type = htons(OFPAT_COPY_TTL_IN);
      action->len  = htons(sizeof(ofp_action_header));
      action = (ofp_action_header*)((char*)action + sizeof(ofp_action_header));
    }
    if (pop) {
      ofp_action_pop_mpls *popmpls = (ofp_action_pop_mpls*)action;
      popmpls->type = htons(OFPAT_POP_MPLS);
      popmpls->len  = htons(sizeof(ofp_action_pop_mpls));
      popmpls->ethertype = htons(ethertype);
      action = (ofp_action_header*)((char*)popmpls + sizeof(ofp_action_pop_mpls));
    }
    if (push) {
      ofp_action_push *pushmpls = (ofp_action_push*)action;
      pushmpls->type = htons(OFPAT_PUSH_MPLS);
      pushmpls->len  = htons(sizeof(ofp_action_push));
      pushmpls->ethertype = htons(ethertype);
      action = (ofp_action_header*)((char*)pushmpls + sizeof(ofp_action_push));
    }
    if (decttl) {
      action->type = htons(OFPAT_DEC_MPLS_TTL);
      action->len  = htons(sizeof(ofp_action_header));
      action = (ofp_action_header*)((char*)action + sizeof(ofp_action_header));
    }
    if (setlabel) {
      ofp_action_mpls_label *mlabel = (ofp_action_mpls_label*)action;
      mlabel->type = htons(OFPAT_SET_MPLS_LABEL);
      mlabel->len  = htons(sizeof(ofp_action_mpls_label));
      mlabel->mpls_label = htonl(outlabel);
      action = (ofp_action_header*)((char*)action + sizeof(ofp_action_mpls_label));
    }
    ofp_action_output *op = (ofp_action_output*)action;
    op->type = htons(OFPAT_OUTPUT);
    op->len  = htons(sizeof(ofp_action_output));
    op->port = htons(outport);

  }

  void
  Mpls::prepare_label_match( struct ofp_match& match, uint32_t wc,
                             uint16_t inport, uint16_t dltype, uint32_t inlabel ) {
    match.wildcards = htonl(wc | 0xbfffee);
    match.in_port = htons(inport);
    match.dl_type = htons(dltype);
    match.mpls_label = htonl(inlabel);
    //VLOG_DBG(log, "set match to %d", inlabel);
    // zero out everything else
    memset(match.dl_src, 0, ethernetaddr::LEN);
    memset(match.dl_dst, 0, ethernetaddr::LEN);
    match.dl_vlan = OFP_VLAN_NONE;
    match.dl_vlan_pcp = 0;
    memset(&match.pad1, 0, sizeof(uint8_t));
    match.nw_tos = 0;
    match.nw_proto = 0;
    memset(&match.pad2, 0, 2*sizeof(uint8_t));
    match.nw_src = 0;
    match.nw_dst = 0;
    match.tp_src = 0;
    match.tp_dst = 0;
    match.mpls_tc = 0;
    memset(&match.pad3, 0, 3*sizeof(uint8_t));
  }




  //-------------------------------------------------------------------------//
  //                           GUI / Debug  Module                           //
  //-------------------------------------------------------------------------//

  void
  Mpls::debugTunnelRoute( Cspf::RoutePtr& route ) {
    VLOG_DBG(log, "** Tunnel route from %"PRIx64" ==> %"PRIx64"",
             route->id.src.as_host(), route->id.dst.as_host());
    for( std::list<Cspf::Link>::const_iterator iter = route->path.begin();
         iter != route->path.end(); ++iter )
      VLOG_DBG(log, "** PATH: next_hop:0x%"PRIx64":%"PRIx16" via out_intf:%"PRIx16"",
               iter->dst.as_host(), iter->inport, iter->outport );
  }


  void
  Mpls::debugFlowRoute( Routing_module::Route& route ) {
    VLOG_DBG(log, "** Flow route from %"PRIx64" ==> %"PRIx64"",
             route.id.src.as_host(), route.id.dst.as_host());
    for( std::list<Routing_module::Link>::const_iterator iter = route.path.begin();
         iter != route.path.end(); ++iter )
      VLOG_DBG(log, "** PATH: next_hop:0x%"PRIx64":%"PRIx16" via out_intf:%"PRIx16"",
               iter->dst.as_host(), iter->inport, iter->outport );
  }

  void
  Mpls::debugTopology(void) {
    topo->get_switches();
    mswSet = topo->swSet;
    VLOG_DBG(log, "*** Current Topology ***");

    for ( std::list<datapathid>::const_iterator iter = mswSet.begin();
          iter != mswSet.end(); ++iter ) {
      const Topology::DatapathLinkMap& dlmap = topo->get_outlinks(*iter);
      VLOG_DBG(log, "** Src Node: 0x%"PRIx64"", (*iter).as_host());
      for ( Topology::DatapathLinkMap::const_iterator iter1 = dlmap.begin();
            iter1 != dlmap.end(); ++iter1 )
        for( Topology::LinkSet::const_iterator iter2 = iter1->second.begin();
             iter2 != iter1->second.end(); ++iter2 )
          VLOG_DBG(log, "* Linkto: %"PRIx64":%d via outintf %d",
                   iter1->first.as_host(),
                   iter2->dst, iter2->src);
    }
  }


  void
  Mpls::showTunnel(tunnid tid) {
    tunn_char& tc = tunnel_db[tid];
    uint8_t color = tc.tstats.color = lmarie->get_tunnel_color(tid);
    uint8_t prio  = tc.telem.priority;
    uint32_t res  = tc.telem.resbw;
    bool autobw   = tc.telem.autobw;
    uint8_t trtype = tc.telem.traffictype;

    //deliver hop list in network byte order
    dplist.clear();
    for( int i=0; i<tc.troute.size(); i++ )
      dplist.push_back(tc.troute[i].dpid.as_net());
    mplsgui->addTunnel( tid, color, prio, res, autobw, trtype, dplist );
  }


  void
  Mpls::showTunnelStats(tunnid tid, int32_t change) {
    mplsgui->sendTunnelStats( tid, tunnel_db[tid].tstats.curr_resbw,
                              tunnel_db[tid].tstats.usage, change );
  }

  void
  Mpls::showFlowRoute(Flow& flow, const Routing_module::Route& route,
                      uint16_t inport, uint16_t outport) {
    uint32_t flowid = (uint32_t)(flow.hash_code());
    uint16_t flowtype;
    switch(ntohs(flow.tp_dst))
      {
      case HTTPPORT  : flowtype = FLOWTYPE_HTTP; break;
      case SIPPORT   : flowtype = FLOWTYPE_VOIP; break;
      case VLCPORT   : flowtype = FLOWTYPE_VIDEO; break;
      default: flowtype = BOOKF_UNKNOWN;
      }
    mplsgui->addFlow( flowid, route, inport, outport, flowtype );
  }

  void
  Mpls::showModifiedFlowRoute(Flow& flow, const Routing_module::Route& route,
                              uint16_t inport, uint16_t outport) {
    uint32_t flowid = (uint32_t)(flow.hash_code());
    mplsgui->delFlow( flowid );
    showFlowRoute(flow, route, inport, outport);
  }

  void
  Mpls::debugRib(void) {
    VLOG_DBG(log, "*** ******** ***");
    VLOG_DBG(log, "***    Rib   ***");
    VLOG_DBG(log, "*** ******** ***");
    for ( std::map<datapathid, dstmap>::iterator srciter = Rib.begin();
          srciter != Rib.end(); ++srciter ) {
      VLOG_DBG(log, " From Src: %"PRIx64"", srciter->first.as_host());
      for ( std::map<datapathid, tunnflow>::iterator dstiter =
              srciter->second.begin(); dstiter != srciter->second.end();
            ++dstiter ) {
        if ( dstiter->second.linkflows.size() || dstiter->second.tunnflows.size() ||
             dstiter->second.ti.tid ) {
          VLOG_DBG(log, "   To Dst: %"PRIx64"", dstiter->first.as_host());
          VLOG_DBG(log, "   there are %d flows on IP links",
                   dstiter->second.linkflows.size());
          VLOG_DBG(log, "   there are %d flows on Tunnel links",
                   dstiter->second.tunnflows.size());
          VLOG_DBG(log, "   tunninfo: tid=%"PRIx16" outport=%x, outlabel=%d, %s%x",
                   dstiter->second.ti.tid, dstiter->second.ti.outport,
                   dstiter->second.ti.outlabel, "dstBrInport=",
                   dstiter->second.ti.dstBrInport);
        }
      }
    }
  }

  void
  Mpls::debugFlowDb(void) {
    VLOG_DBG(log, "*** *********** ***");
    VLOG_DBG(log, "***   flow_db   ***");
    VLOG_DBG(log, "*** *********** ***");
    for ( std::map<flowid, flowinfo>::iterator iter = flow_db.begin();
          iter != flow_db.end(); ++iter ) {
      VLOG_DBG(log, " flowid:%"PRIx64"", iter->first);
      std::ostringstream os;
      os << iter->second.flow;
      VLOG_DBG(log, "   flow: %s", os.str().c_str());
      debugFlowRoute( iter->second.route );
      VLOG_DBG(log, "   Br:: %x:%"PRIx64":%x -> %x:%"PRIx64":%x nw_out:%x",
               iter->second.srcInport, iter->second.srcBr.as_host(),
               iter->second.srcOutport, iter->second.dstInport,
               iter->second.dstBr.as_host(), iter->second.dstOutport,
               iter->second.nw_outport);
    }

  }

  void
  Mpls::debugTunnelDb(void) {
    VLOG_DBG(log, "*** *********** ***");
    VLOG_DBG(log, "***  tunnel_db  ***");
    VLOG_DBG(log, "*** *********** ***");
    for ( std::map<tunnid,tunn_char>::iterator iter = tunnel_db.begin();
          iter != tunnel_db.end(); ++iter ) {
      VLOG_DBG(log, " tunnid:%"PRIx16"", iter->first);
      VLOG_DBG(log, "  tunn config:: tid:%"PRIx16", head:%"PRIx64", tail:%"PRIx64"",
               iter->second.telem.tid, iter->second.telem.hdpid,
               iter->second.telem.tdpid);
      VLOG_DBG(log, "  tunn config:: resbw:%d, prio:%d, autobw:%d traffictype:%d",
               iter->second.telem.resbw, iter->second.telem.priority,
               iter->second.telem.autobw, iter->second.telem.traffictype);
      VLOG_DBG(log, "  tunn route::");
      for( int i=0; i<iter->second.troute.size(); i++ ) {
        VLOG_DBG(log, "   HOP: <%x:%d>::%"PRIx64"::<%x:%d>",
                 iter->second.troute[i].inport, iter->second.troute[i].inlabel,
                 iter->second.troute[i].dpid.as_host(),
                 iter->second.troute[i].outport, iter->second.troute[i].outlabel);
      }
      VLOG_DBG(log, "  tunn stats:: color:%d, autobw_count:%d, curr_resbw:%d",
               iter->second.tstats.color, iter->second.tstats.autobw_count,
               iter->second.tstats.curr_resbw);
      VLOG_DBG(log, "  tunn stats:: usage:%d, byte_count:%d, last_poll:%d",
               iter->second.tstats.usage, iter->second.tstats.byte_count,
               (int)iter->second.tstats.last_poll);
    }

  }


  void
  Mpls::debugAllDatabases(void) {
    debugRib();
    debugFlowDb();
    debugTunnelDb();
  }



  REGISTER_COMPONENT(container::Simple_component_factory<Mpls>, Mpls);

} // unnamed namespace
