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
 * Application: Aggregation & Differentiated services on a pac.c nw
 * Author: Saurav Das
 * Date: 08-09-10
 * Version: 1.0
 * Change: follow-up to GEC8 demo, use of multiple paths within a vlink
 *         addition of network recovery
 *******************************************************************
 */

#ifndef circsw_HH
#define circsw_HH 1

#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <boost/shared_array.hpp>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <stdint.h>
#include <map>

#include "assert.hh"
#include "component.hh"
#include "flow.hh"
#include "fnv_hash.hh"
#include "hash_set.hh"
#include "packet-in.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "vlog.hh"
#include "port-stats-in.hh"
#include "port-status.hh"

//#include "flowdb/flowroutecache.hh"
#include "netinet++/ethernetaddr.hh"
#include "netinet++/ethernet.hh"

#include "circsw_gui.hh"
#include "lavi/bookman.hh"

#define DIRECT 0
#define INDIRECT 1

namespace vigil {

  using namespace vigil::container;

  ///////////////////////////////////////////////////////////
  ////////////         Discovery definitions     ////////////
  ///////////////////////////////////////////////////////////

  typedef struct lldp_holder {
    uint8_t type1;
    uint8_t len1;
    uint8_t value1[7];
    uint8_t type2;
    uint8_t len2;
    uint8_t value2[3];
    uint8_t type3;
    uint8_t len3;
    uint8_t value3[2];
    uint8_t type4;
    uint8_t len4;
    uint8_t pad[26];
  } lldpin;

  ///////////////////////////////////////////////////////////
  ////////////         Bundle definitions        ////////////
  ///////////////////////////////////////////////////////////


  typedef struct bundle_req_holder {
    uint32_t criteria;
    uint32_t vlanid;
    uint32_t ipsrc;
    uint32_t ipsrcmask;
    uint32_t ipdest;
    uint32_t ipdestmask;
    uint32_t tcpsrc;
    uint32_t tcpdest;
    uint32_t pathlen;
    uint64_t path[0];
  } bundlereq;

  typedef struct bundle_del_holder {
    uint32_t vlanid;
  } bundledel;

  typedef struct bundle_mod_holder {
    uint32_t vlanid;
    uint32_t pathlen;
    uint64_t path[0];
  } bundlemod;

  enum bundle_type {
    ALL,
    HTTP,
    VOIP,
    VIDEO,
  };

  struct bundle_elem {
    uint32_t bundletype;
    std::vector<uint64_t> pktpath;
  };


  ///////////////////////////////////////////////////////////
  ///////////         Link definitions          /////////////
  ///////////////////////////////////////////////////////////

  // The same linkid is used for a link on both near and far end switches
  // as well as in the respective link databases.
  // Valid linkid's are as follows:
  // a) 0x1000 - 0x1fff for circuit (SONET) links -- link1ids
  // b) 0x2000 - 0x2fff for ethernet links        -- link2ids
  // c) 0x3000 - 0x3fff for virtual packet links  -- link3ids

  // Virtual packet links ( or vlinks ) are identified with link3ids.
  // They can be statically pre-configured ( in circsw_config.hh )
  // or dynamically created on demand.  A vlink can comprise
  // of several paths (or vlpaths). Each vlpath corresponds to a
  // single virtual port, and one or more cflows and pflows
  // that map into the virtual port.

  struct regvlink {
    uint16_t link3id;
    uint16_t vlpathid;
    uint16_t cflowid;
    uint16_t vlpathtype;
  };

  enum node_type {
    PKT_PATH_END1,
    CKT_PATH_END1,
    CKT_PATH_INTERMEDIATE,
    CKT_PATH_END2,
    PKT_PATH_END2,
  };

  struct node {
    uint64_t dpid;
    uint16_t nodetype;
    uint16_t ethport;
    uint16_t vcgport;  // only used for CKT_PATH_END
    uint16_t tdmport1;
    uint16_t tdmport2; // only used for CKT_PATH_INTERMEDIATE
  };

  enum vlink_path_type {
    STATIC,
    DYNAMIC_VOIP,
    DYNAMIC_VIDEO,
  };

  struct vlinkpath {
    uint16_t vlpathid;
    uint16_t vlpathtype;
    std::vector<uint32_t> vlpathvlans;
    std::map<uint16_t, std::vector<node> > vlpathroutes;
    // vlpathroutes are indexed by cflowids
  };

  // for virtual links between edge packet-switches in vlink_db
  struct vlink_elem {
    uint64_t ethdpid1;
    uint16_t ethport1;
    uint64_t ethdpid2;
    uint16_t ethport2;
    std::vector<uint16_t> link1ids;
    std::map<uint16_t, vlinkpath> vlpaths;
    // vlpaths are indexed with vlpathids
  };

  // for Ethernet links in link2_db
  struct link2_elem {
    uint64_t thissw;
    uint64_t thatsw;
    uint16_t thisport;
    uint16_t thatport;
    uint32_t linkspeed;
    uint16_t linkid;
  };

  // for SONET links in link1_db
  struct link1_elem {
    uint64_t thissw;  // datapathid of near end (only when part of switch_elem)
    uint64_t thatsw;  // datapathid of far  end (only when part of switch_elem)
    uint16_t thisport;
    uint16_t thatport;
    uint32_t linkspeed;
    uint16_t linkid;
    std::map<uint16_t, regvlink> regvlinks;
    // regvlink is the registration of all virtual-links with cflows
    // routed over this layer1 link. It is indexed by the cflowid
  };


  ///////////////////////////////////////////////////////////
  ///////////         Flow definitions          /////////////
  ///////////////////////////////////////////////////////////

  typedef struct packet_flow {
    uint16_t ethport;
    uint16_t vlanid;
    bool matchtag;
    //uint32_t flowid; // for L2 flow dragging
  } pflow;

  typedef struct circuit_flow {
    ofp_tdm_port tport1; // either mapper or sonet switchport
    ofp_tdm_port tport2; // always sonet switchport
    uint32_t flowid;     // for L1 flow dragging
  } cflow;



  ///////////////////////////////////////////////////////////
  ///////   Virtual Port and Switch definitions  ////////////
  ///////////////////////////////////////////////////////////

  typedef struct vcgPort {
    uint16_t vcgnum;
    uint16_t num_components;// number of component tdm signals
    uint16_t internal_port; // as vcg does not map across muiltiple internal ports
    uint16_t m_tstart; // keeps track of starting mapper ts with which vcg is created
    uint16_t num_pflows_in; // number of packet flows multiplexed into vcg
    uint16_t num_pflows_out; // number of packet flows demultiplexed out of vcg
    std::vector<cflow> component_cflows; // mapper to sonet xconn
    std::vector<pflow> component_pflows_in; // EthToVcg pflows
    std::vector<pflow> component_pflows_out; // VcgToEth pflows
  } vcgPort;

  // for Hybrid switches in switch_db
  struct switch_elem {
    switch_elem(const Datapath_join_event&);

    datapathid datapath_id;
    uint32_t n_buffers;
    uint8_t  n_tables;
    uint32_t capabilities;
    uint32_t actions;
    uint8_t n_cports;
    bool suppLcas, suppVcat, suppGfp;
    uint16_t nextvcgnum;

    std::map<uint16_t,Port> ethports;
    std::map<uint16_t,CPort> tdmports;
    std::map<uint16_t,CPort> internalports;
    std::map<uint16_t,vcgPort> vcgports;

    std::vector<cflow> xconns; //used when not going through vcgs

    std::map<uint16_t, link1_elem> L1links;
    std::map<uint16_t, link2_elem> L2links;

  };



  ///////////////////////////////////////////////////////////
  ///////            Other definitions           ////////////
  ///////////////////////////////////////////////////////////

  enum delete_state {
    START_DELETE,
    DEL_COMPONENT,
    FINISH,
  };

  struct delete_elem {
    uint64_t dpid;
    uint16_t vcgnum;
    uint16_t num_components;
    uint16_t curr_component;
    uint16_t next_state;
  };

  struct vlandelete_elem {
    uint32_t vlanid;
    uint16_t vlink_;
    uint16_t vlpath_;
  };

  struct broken_elem {
    uint64_t confirmedsw;
    uint16_t confirmedport;
    uint64_t farendsw;
    uint16_t farendport;
    bool confirmeddown;
    bool onesideup;
  };

  struct vcgcompdelete_elem {
    uint64_t dpid;
    uint16_t vcgnum;
    ofp_tdm_port t1;
  };

  ///////////////////////////////////////////////////////////
  ////////////    GUI related definitions        ////////////
  ///////////////////////////////////////////////////////////

  enum switch_type {
    HYBRID_SWITCH,
    PACKET_SWITCH
  };

  enum flow_type {
    STATIC_CFLOW = 1,
    VOIP_CFLOW = 2,
    VIDEO_CFLOW = 3,
    PFLOW = 4
  };



  ///////////////////////////////////////////////////////////
  ////////////          Class definition         ////////////
  ///////////////////////////////////////////////////////////

  class Circsw
    : public Component
  {
  public:
    Circsw(const Context* c,
         const xercesc::DOMNode*)
      : Component(c) { }

    void configure(const Configuration*);

    void install();

    Disposition handle_datapath_join(const Event&);
    Disposition handle_datapath_leave(const Event&);
    Disposition handle_packet_in(const Event&);
    Disposition handle_port_stats_in(const Event&);
    Disposition handle_L1flow_drag(const Event&);
    Disposition handle_cport_status(const Event&);
    Disposition handle_port_status(const Event&);
    Disposition handle_Agg_msg_py(const Event&);
    void repost_book_msg( void );


    const std::vector<uint64_t>& getDpids(void);

    /** Get instance
     * @param ctxt context
     * @param component reference to Circsw
     */
    static void getInstance(const container::Context* ctxt, Circsw*& component);


  protected:
    bool vcgEmpty( uint64_t switchid, uint16_t ethport, uint16_t& vcgnum );
    uint16_t createEmptyVcg(uint64_t switchid, uint16_t internalport);
    void sendEmptyVcg(uint64_t dpid, uint16_t htimeout, uint16_t vcgnum);
    bool addVcgComponent( uint64_t dpid, uint16_t vcgnum, uint16_t tport,
                          uint32_t tsig, uint16_t t_tstart, bool firsttime,
                          uint32_t flowid_ );
    void deleteVcgComponent( uint64_t dpid, uint16_t vcgnum, uint32_t dragflowid );

    bool findStartTslot(struct switch_elem& sw, uint16_t port, uint32_t tsig, \
                        uint16_t& tstart);
    bool sendVcgComponent( uint64_t dpid, uint16_t vcgnum, uint16_t htimeout, \
                           struct ofp_tdm_port& mpt, bool addormodify );
    bool sendXconn( uint64_t dpid, struct ofp_tdm_port& mpt,    \
                    struct ofp_tdm_port& tpt, bool addormodify );
    void updateTslots( uint64_t dpid, ofp_tdm_port& tpt, bool turnon);
    void updateVcgWithCflow( uint64_t dpid, uint16_t vcgnum, struct ofp_tdm_port& mpt, \
                             struct ofp_tdm_port& tpt, bool insert, uint32_t flowid_ );
    void updateVcgWithPflow( uint64_t dpid, uint16_t vcgnum, uint16_t ethport, \
                             uint16_t vlanid, bool insert, bool incoming,
                             bool matchtag );
    bool sendPflowOutToEth( uint64_t dpid, uint16_t vcgnum, uint16_t vlanid,
                            uint16_t ethport, bool addormodify,
                            bool matchtag, bool striptag );
    bool sendPflowOutToVcg( uint64_t dpid, uint16_t ethport, uint16_t vlanid,
                            uint16_t vcgnum , uint32_t bufferid, bool addormodify,
                            bool matchtag, bool inserttag );
    uint16_t getEgressEthPort( uint64_t idpid, uint64_t edpid, uint16_t iethport );
    void sendPortStatsReq( uint64_t dpid, uint16_t vcgnum );

    //void decreaseBandwidth( uint32_t dragflowid, uint32_t pathchoice );
    void addXconn( uint64_t dpid, uint16_t in_tport, uint16_t m_tstart,
                   uint16_t out_tport, uint16_t t_tstart, uint32_t tsignal,
                   uint32_t flowid_ );
    void deleteXconn( uint64_t dpid, uint32_t dragflowid );
    void updateXconnsWithCflow( uint64_t dpid, struct ofp_tdm_port& mpt, \
                                struct ofp_tdm_port& tpt, bool insert,  \
                                uint32_t flowid_ );
    void removeAllState(void);

    void discoverCktTopo(void);
    uint16_t findInternalPort( uint64_t dpid, uint16_t ethintf );
    bool findMatchingTimeSlots( uint64_t loccktsw, uint16_t loccktport,
                                uint64_t remcktsw, uint16_t remcktport,
                                uint32_t tsig, uint16_t& startts);
    bool usedTimeSlot( struct switch_elem& sw, uint16_t port,
                       uint32_t tsig, uint16_t tstart );

    uint16_t createDynamicVirtualLink( uint64_t psdpid1, uint64_t psdpid2,
                                       uint32_t vid, bool videolink );

    uint16_t createDynamicVirtualLinkPath( uint16_t link3idfound, uint32_t vid,
                                           bool videolink );

    bool findFreeEthPort( uint64_t psdpid, std::vector<uint16_t>& ethports,
                          uint16_t& freeethport );

    bool getRegisteredPorts( uint64_t pktswdpid, std::vector<uint16_t>& ethports);


    bool registerAndActOnBundle( uint32_t criteria, uint32_t vlanid,
                                 std::vector<uint64_t> pathvec );

    bool modifyBundle( uint32_t vlanid, std::vector<uint64_t> pathvec );


    bool deleteBundle( uint32_t vlanid );

    bool actOnBundle( uint32_t vlanid, bool deletebundle );

    void increaseBandwidth( uint16_t link3id_, uint16_t vlpathid_, int num_cflows );

    void confirmLinkDown( uint64_t dpint, const Port_status_event& pse );
    void confirmLinkUp( uint64_t dpint, const Port_status_event& pse );
    bool checkIfBroken( uint64_t dpid, uint16_t port, uint16_t linkid_ );
    bool checkIfFixed( uint64_t dpid, uint16_t port, uint16_t linkid_ );
    void reRouteVlinks( uint16_t linkid_ );
    void reRouteCflow( struct regvlink& rv );

  private:
    hash_map<uint64_t, std::vector<switch_elem> > switch_db;
    std::map<uint16_t, link1_elem> link1_db;
    std::map<uint16_t, link2_elem> link2_db;
    std::vector<uint64_t> dpids;
    std::map<uint16_t, vlink_elem> vlink_db;
    std::map<uint32_t, bundle_elem> bundle_db;
    std::map<uint32_t, bool> bme_xid_db;
    std::map<uint64_t, delete_elem> vcgdelete_db;
    std::vector<vlandelete_elem> vlandelete_db;
    std::map<uint16_t, broken_elem> broken_db;
    std::vector<vcgcompdelete_elem> vcgcompdelete_db;

    void configTopology(void);
    void verifyTopology(void);
    void debugDpJoin( const Datapath_join_event& dj, uint64_t dpint );
    void unitTest( uint64_t switchid );
    void updateCktTopo( uint64_t thissw, uint16_t thisport, uint64_t thatsw,
                        uint16_t thatport, uint32_t linkspeed );
    void processPacketLink( uint64_t loccktsw, uint16_t locethport,
                            uint64_t psdpid, uint16_t psportid );

    uint16_t registerPacketLink( uint64_t ingressdpid, uint16_t ingressport,
                             uint64_t sendingdpid, uint16_t sendingport );

    uint16_t checkForVirtualLink( uint64_t psdpid, uint16_t psportid,
                                  uint64_t& remotedpid, uint16_t& remoteportid );

    uint16_t checkPacketSwRegistry( uint64_t pktswdpid, uint16_t pktswport,
                                    uint64_t& cktswdpid, uint16_t& cktswethport );

    uint16_t getCktLink( uint64_t loccktsw, uint64_t remcktsw, uint16_t& loccktport,
                         uint16_t& remcktport );

    bool createDirectVLink( uint64_t loccktsw, uint16_t locethport, uint16_t loccktport,
                           uint64_t remcktsw, uint16_t remethport, uint16_t remcktport,
                           bool adduntaggedrules, uint32_t vlanid, uint16_t& vcgnum1,
                           uint16_t& vcgnum2 );

    void registerVirtualLinkOnL1Link( uint16_t link1id, uint16_t link3id_,
                                      uint16_t vlpathid_, uint16_t cflowid_,
                                      uint16_t vlpathtype_ );

    void deRegisterVirtualLinkOnL1Link( std::vector<uint16_t>& cflowids );

    void addNodesToPath( uint16_t link3id_, uint16_t vlpathid_, int64_t dpid,
                         uint16_t nodetype, uint16_t ethport, uint16_t vcgport,
                         uint16_t tdmport1, uint16_t tdmport2, uint16_t cflowid_ );


    void addOrRemoveVlanRules( uint64_t dpid, uint16_t ethport, uint16_t vlanid,
                               uint16_t vcgport, bool add, bool matchtag,
                               bool striptag );

    bool deleteDynamicVirtualLinkPath( uint16_t link3idtodel, uint16_t vlpathtodel );



    bool createIndirectVLink( uint64_t loccktsw, uint16_t locethport, uint16_t loccktport,
                              uint64_t midcktsw, uint16_t midtdmport1, uint16_t midtdmport2,
                              uint64_t remcktsw, uint16_t remethport, uint16_t remcktport,
                              bool adduntaggedrules, uint32_t vlanid, uint16_t& vcgnum1,
                              uint16_t& vcgnum2 );


    bool createVoipCkt( uint64_t cktsw1, uint16_t cktsweth1, uint64_t cktsw2,
                        uint16_t cktsweth2, bool adduntaggedrules,
                        uint32_t vid, uint64_t psdpid1, uint16_t freeeth1,
                        uint64_t psdpid2, uint16_t freeeth2,
                        uint16_t link3id_, uint16_t vlpathid_, bool newvlink );

    bool createVideoCkt( uint64_t loccktsw, uint16_t locethport, uint64_t remcktsw,
                         uint16_t remethport, bool adduntaggedrules,
                         uint32_t vlanid, uint64_t locpktsw, uint16_t locpkteth,
                         uint64_t rempktsw, uint16_t rempkteth,
                         uint16_t link3id_, uint16_t vlpathid_, bool newvlink );

    bool removeVcgPort( uint64_t dpid,  uint16_t vcgnum );


    void reRouteIndirectCflow( uint64_t loccktsw, uint64_t midcktsw, uint64_t remcktsw,
                               uint16_t loccktport, uint16_t midtdmport1, uint16_t midtdmport2,
                               uint16_t remcktport, uint16_t locvcg, uint16_t remvcg,
                               uint16_t link3id_, uint16_t vlpathid_, uint16_t vlpathtype_,
                               uint16_t locethport, uint16_t remethport, uint16_t cflowid_ );

    void reRouteDirectCflow( uint64_t loccktsw, uint64_t remcktsw, uint16_t loccktport,
                             uint16_t remcktport, uint16_t locvcg, uint16_t remvcg,
                             uint16_t link3id_, uint16_t vlpathid_, uint16_t vlpathtype_,
                             uint16_t locethport, uint16_t remethport, uint16_t cflowid_ );


    void deleteVcgMember( void );
    void removeVcgComponents( void );
    void delete_vlan_rule( void );
    void clear_dynamic_vlinks( void );
	boost::shared_ptr<Buffer>bme_msg_holder;

    uint32_t tsig;
    uint32_t tsignal_incr;

    bool increased_bandwidth;
    int num_bw_incr;

    int wait_to_start_polling;
    int stat_polling_interval;
    bool continue_monitoring;
    uint16_t monitorlink3id;
    uint16_t monitorvlpathid;
    uint64_t monitordp1;
    uint64_t monitordp2;
    uint16_t monitorvcg1;
    uint16_t monitorvcg2;
    bool sendStatReq1;
    bool sendStatReq2;
    uint64_t tx_bytes1;
    uint64_t tx_bytes2;
    uint64_t last_tx_bytes;
    int bw_incr_threshold;
    uint32_t above_tx_threshold_counter1;
    uint32_t above_tx_threshold_counter2;
    int num_above_tx_threshold;
    void stat_req_poll( void );
    void stat_req_start( void );

    int wait_for_xconn_delete;
    int wait_for_vcomp_delete;
    int wait_for_vmem_delete;

    uint32_t pause;

    Circsw_gui* cswgui;
    void showDpJoin( uint16_t bnt, uint64_t dpid );
    void showCflow( uint64_t dpid1, uint16_t tdmport1, uint64_t dpid2,
                    uint16_t tdmport2, uint16_t flowtype );

    void showIndirectCflow( uint64_t dpid1, uint16_t tdmport1, uint64_t mdpid,
                            uint16_t mtport1, uint16_t mtport2, uint64_t dpid2,
                            uint16_t tdmport2, uint16_t flowtype );

    void showPflow( uint64_t dpid1, uint16_t ethport1, uint64_t dpid2, uint16_t ethport2,
                    uint64_t dpid3, uint16_t ethport3, uint64_t dpid4, uint16_t ethport4,
                    uint16_t flowtype );

    void showCktTopo( void );
    void showPacketLink( uint64_t cs, uint16_t cp, uint64_t ps, uint16_t pp,
                         uint16_t lid );


    void showNoCflow( uint16_t flowid_ );
    void showNoPflow( uint16_t flowid_ );
    std::vector<uint16_t> pflow_db;

    uint32_t flowid;
    uint32_t flow2id;
    uint16_t linkid;
    uint16_t link2id;
    uint16_t link3id;
    uint16_t vlpathid;
  };

}// namespace vigil


#endif
