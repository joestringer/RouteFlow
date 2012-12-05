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

/*******************************************************************
 * Application: MPLT-TE with an OPEN control plane
 * Author: Saurav Das
 * Date: 11-24-10
 * Version: 1.0
 * Change: first attempt at creating LSPs
 *
 *******************************************************************
 */

#ifndef mpls_HH
#define mpls_HH 1

#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <boost/shared_array.hpp>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <stdint.h>
#include <map>
#include <time.h>

#include "assert.hh"
#include "component.hh"
#include "flow.hh"
#include "fnv_hash.hh"
#include "hash_set.hh"
#include "hash_map.hh"
#include "packet-in.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "vlog.hh"
#include "port-stats-in.hh"
#include "port-status.hh"

#include "netinet++/ethernetaddr.hh"
#include "netinet++/ethernet.hh"

#include "mpls_gui.hh"
#include "cspf.hh"
#include "lavi/bookman.hh"
#include "routing/routing.hh"
#include "topology/topology.hh"
#include "lavi/marie.hh"

namespace vigil {

  using namespace vigil::container;


  ///////////////////////////////////////////////////////////
  ////////////         Tunnel definitions        ////////////
  ///////////////////////////////////////////////////////////

  typedef struct reoptimization_timers {
    uint32_t periodic;
    bool     event_link_up;
  } tetimers;

  typedef struct tunnel_path_options {
    uint8_t preference;
    std::vector<uint64_t> dpids;
  }tepath;

  typedef std::list<tepath> tepaths;

  enum tunnel_traffic_type {
    HTTP   = 1 << 0,
    VOIP   = 1 << 1,
    VIDEO  = 1 << 2,
    OTHER  = 1 << 3,
    ALL    = ((1 << 4) - 1)
  };

  /* Main element describing traffic-engineered tunnel configuration.
     Tunnel is unidirectional and defined from head-end to tail-end.
     If path-options is NULL then tunnel route is dynamiclly selected.
     If re_opt is NULL then tunnel is locked down.

     Currently tunnel affinity & mask, re-optimization timers and
     path-options are un-implemented in the CSPF algorithm
  */
  typedef struct TE_tunnel_elem {
    uint16_t tid;            //tunnel id - must be 0x7e00 and above
    uint64_t hdpid;          //tunnel head-end dpid
    uint64_t tdpid;          //tunnel tail-end dpid
    uint32_t resbw;          //tunnel reserved bandwidth in kbps
    uint8_t  priority;       //tunnel priority
    uint32_t affinity;       //tunnel affinity
    uint32_t affmask;        //tunnel affinity mask
    tetimers* re_opt;        //tunnel re-optimization timers
    bool     autobw;         //tunnel auto-bandwidth enabled
    tepaths* path_options;   //tunnel path-options
    uint8_t  traffictype;    //tunnel traffic type
  } tunn_elem;

  /* Main element describing TE tunnel route */
  typedef struct TE_LSP_elem {
    datapathid dpid;
    uint16_t inport;    //not valid for head-end
    uint32_t inlabel;   //not valid for head-end, IMPLICIT_NULL for tail-end
    uint16_t outport;   //not valid for tail-end
    uint32_t outlabel;  //not valid for tail-end
  } lsp_elem;

  typedef std::vector<lsp_elem> tunn_route;

  typedef struct TE_tunnel_statistics {
    uint8_t color; // for GUI
    uint8_t autobw_count;
    uint32_t curr_resbw;
    uint32_t usage;
    uint32_t byte_count;
    time_t last_poll;
    uint32_t hashval; // index into tunnel_flowstats_db
  } tunn_stats;

  typedef struct TE_tunnel_characteristics {
    tunn_elem telem;
    tunn_route troute;
    tunn_stats tstats;
  } tunn_char;

  typedef uint16_t tunnid;


  ///////////////////////////////////////////////////////////
  ///////////  Label/LSP  related definitions   /////////////
  ///////////////////////////////////////////////////////////

  #define OFP_MAX_PRIORITY 0xffff
  #define OFP_LSP_DEFAULT_PRIORITY 0xff00
  #define IMPLICIT_NULL 0x3
  #define ETHTYPE_MPLS 0x8847
  #define ETHTYPE_LLDP 0x88cc
  #define ETHTYPE_NULL 0xffff
  #define ETHTYPE_IPv6 0x86dd

  typedef struct label_allocator {
    uint32_t label_start;
    uint32_t next_available_label;
  } label_alloc;



  ///////////////////////////////////////////////////////////
  ///////////         Flow definitions          /////////////
  ///////////////////////////////////////////////////////////

  // for identifying destination IP domains
  typedef uint32_t ip_prefix;
  typedef uint64_t ASBR;

  struct prefix_entry {
    ip_prefix ip;
    ASBR router;
    uint16_t outport;
  };

  typedef struct destination_AS_border_router {
    ASBR router;
    uint16_t outport;
  } destASBR;

  // same as flow cookie used in flow mod
  // lower 32 bits represent flowid in GUI
  // flowid is a hash of flow fields which are in n.b.o
  typedef uint64_t flowid;

  // for storage in flow_db. Note that the full route may well be
  // ASBR -> edgeR -> srcBR -> otherBRs -> dstBR -> edgeR ->ASBR
  // But the ports below refer to the Backbone Routers not the
  // edge ones. They may be physical ports or tunnel virtual ports
  // This info is cached here separately to ease the
  // autoroute into tunnels when they come up between the BRs
  typedef struct flow_information {
    Flow flow;
    Routing_module::Route route;
    datapathid srcBr; // flow may originate or pass thru this BR
    uint16_t srcInport;
    uint16_t srcOutport;
    datapathid dstBr; // flow may terminate or pass thru this BR
    uint16_t dstInport;
    uint16_t dstOutport;
    uint16_t nw_outport;
  } flowinfo;

  // for storage in Rib. With tid we could get all the information
  // but we cache the outlabel and outport for the srcBr
  // and the inport for the dstBr for efficieny.
  // We do not need the inlabel for the dstBr as it is always
  // IMPLICIT_NULL (i.e no incoming label)
  typedef struct tunnel_info_for_BRs{
    tunnid tid;           // tunnel id == tunnel virtual port no.
    uint16_t outport;     // phy port
    uint32_t outlabel;
    uint16_t dstBrInport; // phy port
  } tunninfo;

  // for storage in Rib
  // linkflows are the flows traversing IP links between the BRs
  // tunnflows are the flows going down a tunnel between the BRs
  // XXX only a single tunnel between any two BRs in this version
  typedef struct tunnel_and_flow_information {
    std::list<flowid> linkflows;
    std::list<flowid> tunnflows;
    tunninfo ti;
  } tunnflow;



  ///////////////////////////////////////////////////////////
  ///////            Stats definitions           ////////////
  ///////////////////////////////////////////////////////////

  typedef struct TE_tunnel_flow_stats {
    tunnid tid;
    datapathid dpid;
    boost::shared_array<uint8_t> raw_ofs_msg;
  } tunnflowstatsmsg;


  ///////////////////////////////////////////////////////////
  ////////////    GUI related definitions        ////////////
  ///////////////////////////////////////////////////////////

  #define HTTPPORT   80
  #define SIPPORT    5060
  #define VLCPORT    1234

  enum flow_type {
    FLOWTYPE_HTTP  = 0x0010,
    FLOWTYPE_VOIP  = 0x0020,
    FLOWTYPE_VIDEO = 0x0040,
    FLOWTYPE_OTHER = 0x0080
  };



  ///////////////////////////////////////////////////////////
  ////////////          Class definition         ////////////
  ///////////////////////////////////////////////////////////

  class Mpls
    : public Component
  {
  public:
    Mpls(const Context* c,
         const xercesc::DOMNode*)
      : Component(c) { }

    void configure(const Configuration*);

    void install();

    Disposition handle_bme_message(const Event& e);
    Disposition handle_fstatsin_message(const Event& e);
    Disposition handle_packet_in(const Event& e);


    typedef std::list<Nonowning_buffer> ActionLists;
    typedef std::list<Flow> FlowList;
    typedef std::list<uint32_t> WildcardList;

    bool setupFlowInIPRoute(const Flow& flow, const Routing_module::Route& route,
                            uint16_t nw_inport, uint16_t nw_outport,
                            uint16_t flow_timeout );

    bool
    setupFlowInTunnelRoute(const Flow& flow, const Routing_module::Route& route,
                           uint16_t nw_inport, uint16_t nw_outport,
                           uint16_t flow_timeout, datapathid srcBr,
                           uint16_t srcOp, uint32_t srcOl,
                           datapathid dstBr, uint16_t dstIp);

    bool setupLsp( Cspf::RoutePtr& route, tunn_elem& te,
                   uint16_t payload_ethtype );
    bool teardownLsp( tunnid tid, uint16_t payload_ethtype );

    void debugTopology(void);
    void debugTunnelRoute(Cspf::RoutePtr& route);
    void debugFlowRoute(Routing_module::Route& route);

    void enableAutoBw(uint16_t tid);
    void disableAutoBw(uint16_t tid);

    /** Get instance
     * @param ctxt context
     * @param component reference to Mpls
     */
    static void getInstance(const container::Context* ctxt, Mpls*& component);


  private:

    Mpls_gui* mplsgui;
    Routing_module *routing;
    Cspf *cspfrouting;
    Topology *topo;
    marie *lmarie;


    /*********************  Databases ********************/

    // main database for all tunnel information
    std::map<tunnid, tunn_char> tunnel_db;

    // maintains a per switch database of (port-independent) labels
    std::map<datapathid, label_alloc> label_alloc_db;

    // stores openflow message for requesting tunnel stats
    // indexed by hash over <datapathid, in_port, in_label>
    hash_map<uint32_t, tunnflowstatsmsg> tunnel_flowstats_db;

    // stores mappings of prefixes learnt from corresponding AS border routers
    std::map<ip_prefix, destASBR> bgpTable;

    // flow database store Flow and Route info
    std::map<flowid, flowinfo> flow_db;

    // Routing information base (Rib)
    // maintained for every src BR with a dstmap to every other BR
    // and the flow and tunnel info between the BRs
    typedef std::map<datapathid, tunnflow> dstmap;
    std::map<datapathid, dstmap> Rib;

    /***************************************************/

    uint32_t xidcounter;
    bool initialized;
    ofp_flow_mod *ofm;
    ofp_stats_request *osr;
    boost::shared_array<uint8_t> raw_of;
    uint16_t tunnel_port_number;
    std::list<uint64_t> dplist;
    std::list<tunnid> temp_tunnel_list;
    std::list<uint32_t> temp_hashval_list;
    Topology::SwitchSet mswSet;
    int demostepper;
    int conf_tunnel_index;

    void set_flow_mod_msg(const Flow& flow, uint16_t inport, uint16_t outport,
                          uint32_t buffer_id, uint16_t timeout, bool modify,
                          uint32_t outlabel);


    void set_flow_mod_msg( uint32_t wc, uint32_t inlabel, uint16_t inport,
                           uint16_t outport, uint32_t outlabel,
                           uint16_t dltype, uint16_t ethertype,
                           bool push, bool pop, bool setlabel, bool decttl,
                           bool copyin );

    void init_label_alloc_db(void);
    void init_start_labels(void);
    uint32_t get_inlabel( datapathid dpid );
    void init_rib();
    void runSwitchInit( void );

    void applyConfTunnels(void);
    void throwPortStatusEvent( datapathid head, tunnid tid, bool add );

    void processThisTunnel(void);

    void startTunnelStats(tunnid id);

    void showTunnel(tunnid tid);

    void showTunnelStats(tunnid tid, int32_t change);

    void set_flow_stats_req( uint16_t inport, uint16_t dltype, uint32_t inlabel );

    void prepare_label_match( struct ofp_match& match, uint32_t wc,
                              uint16_t inport, uint16_t dltype, uint32_t inlabel );

    uint32_t hash_flow_entry(datapathid dp, ofp_match *ofm);

    void enterFlowMatchAsTunnel(datapathid dp, ofp_match *ofm, tunnid tid);

    void sendTunnelStatsReq( void );

    void routeFlow( Flow& flow, datapathid dpid );

    void showFlowRoute(Flow& flow, const Routing_module::Route& route,
                       uint16_t inport, uint16_t outport);

    void showModifiedFlowRoute(Flow& flow, const Routing_module::Route& route,
                               uint16_t inport, uint16_t outport);


    void registerFlow( Flow& flow, Routing_module::Route& route,
                       uint16_t nw_inport, uint16_t nw_outport );

    bool findSrcAndDstBR( Routing_module::Route& route, uint16_t nw_inport,
                          uint16_t nw_outport, datapathid& srcBr,
                          datapathid& dstBr, uint16_t& srcOutport, uint16_t& srcInport,
                          uint16_t& dstOutport, uint16_t& dstInport);

    tunnid registerTunnelInRib( tunnid tid, datapathid srcBr, datapathid dstBr );

    void rerouteFlows( tunnid tid, datapathid srcBr, datapathid dstBr, tunnid oldtid);
    bool rerouteFlow( flowinfo& fi, tunninfo& ti );
    void fixRoute( flowinfo& fi, tunnid tid );
    void route_from_tunn_route(Cspf::RoutePtr& route, tunn_route& troute);
    bool checkFixRouteTunnelFlow( Flow& flow, Routing_module::Route& route,
                                  uint16_t nw_inport, uint16_t nw_outport,
                                  bool& usenewroute,
                                  Routing_module::Route& newroute );
    void rerouteEjectedTunnels( tunnid etid );

    void debugRib(void);
    void debugFlowDb(void);
    void debugTunnelDb(void);
    void debugAllDatabases(void);

  };

}// namespace vigil


#endif
