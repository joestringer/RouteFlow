#ifndef mpls_config_HH
#define mpls_config_HH 1

#include "mpls.hh"

namespace vigil {

  ///////////////////////////////////////////
  //////// Configurable Parameters //////////
  ///////////////////////////////////////////

  #define MPLS_TUNNEL_ID_START 0x7e00  // virtual port no.
  #define FLOW_IDLE_TIMEOUT    15      // secs
  #define ASBR_DPID_START      0x20
  #define TUNNEL_STATS_POLL_INTERVAL 5 // secs

  ///////////////////////////////////////////
  ///////// Hard-coded Parameters ///////////
  ///////////////////////////////////////////

  // for ease of entering tunnel configuration below
  //   BR == Backbone Router
  // ASBR == Autonomous System Border Router
  #define SFO_BR UINT64_C(0x0000000000000002)
  #define KAN_BR UINT64_C(0x0000000000000003)
  #define NYC_BR UINT64_C(0x0000000000000004)
  #define HOU_BR UINT64_C(0x0000000000000005)
  #define DEN_BR UINT64_C(0x000000000000000a)
  #define SJC_ER UINT64_C(0x0000000000000021)
  #define NJY_ER UINT64_C(0x0000000000000041)
  #define PHX_BR UINT64_C(0x0000000000000009)

  uint32_t num_prefixes = 6;

  prefix_entry pe[] = {
    {
      UINT32_C(0xc0a80a00), // 192.168.10.0
      SJC_ER,
      1,
    },
    {
      UINT32_C(0xc0a80100), // 192.168.1.0
      NJY_ER,
      2,
    },
    {
      UINT32_C(0xc0a81e00), // 192.168.30.0
      KAN_BR,
      4,
    },
    {
      UINT32_C(0xc0a81900), // 192.168.25.0
      HOU_BR,
      4,
    },
    {
      UINT32_C(0xc0a80f00), // 192.168.15.0
      SFO_BR,
      4,
    },
    {
      UINT32_C(0xc0a84600), // 192.168.70.0
      PHX_BR,
      3,
    },
  };

  ///////////////////////////////////////////
  //     Pre-configured  TE tunnels        //
  ///////////////////////////////////////////

  uint32_t num_tunnels = 5;

  tunn_elem conf_tunn[] = {
    {
      MPLS_TUNNEL_ID_START,         //tunnel id - must be 0x7ge00 and above
      SFO_BR,                       //tunnel head-end dpid
      NYC_BR,                       //tunnel tail-end dpid
      123,                          //tunnel reserved bandwidth in Mbps
      0,                            //tunnel priority
      0,                            //tunnel affinity
      0,                            //tunnel affinity mask
      NULL,                         //tunnel re-optimization timers
      false,                         //tunnel auto-bandwidth enabled
      NULL,                         //tunnel path-options
      VOIP | VIDEO,                 //tunnel traffic type
    },

    {
      MPLS_TUNNEL_ID_START+1,       //tunnel id - must be 0x7e00 and above
      SFO_BR,                       //tunnel head-end dpid
      HOU_BR,                       //tunnel tail-end dpid
      700,                          //tunnel reserved bandwidth in Mbps
      0,                            //tunnel priority
      0,                            //tunnel affinity
      0,                            //tunnel affinity mask
      NULL,                         //tunnel re-optimization timers
      false,                         //tunnel auto-bandwidth enabled
      NULL,                         //tunnel path-options
      ALL,                          //tunnel traffic type
    },

    {
      MPLS_TUNNEL_ID_START+2,       //tunnel id - must be 0x7e00 and above
      SFO_BR,                       //tunnel head-end dpid
      KAN_BR,                       //tunnel tail-end dpid
      235,                          //tunnel reserved bandwidth in Mbps
      0,                            //tunnel priority
      0,                            //tunnel affinity
      0,                            //tunnel affinity mask
      NULL,                         //tunnel re-optimization timers
      false,                         //tunnel auto-bandwidth enabled
      NULL,                         //tunnel path-options
      VIDEO,                          //tunnel traffic type
    },

    {
      MPLS_TUNNEL_ID_START+3,       //tunnel id - must be 0x7e00 and above
      NYC_BR,                       //tunnel head-end dpid
      HOU_BR,                       //tunnel tail-end dpid
      10,                          //tunnel reserved bandwidth in Mbps
      0,                            //tunnel priority
      0,                            //tunnel affinity
      0,                            //tunnel affinity mask
      NULL,                         //tunnel re-optimization timers
      true,                         //tunnel auto-bandwidth enabled
      NULL,                         //tunnel path-options
      ALL,                          //tunnel traffic type
    },

    {
      MPLS_TUNNEL_ID_START+4,       //tunnel id - must be 0x7e00 and above
      NYC_BR,                       //tunnel head-end dpid
      PHX_BR,                       //tunnel tail-end dpid
      180,                          //tunnel reserved bandwidth in Mbps
      1,                            //tunnel priority
      0,                            //tunnel affinity
      0,                            //tunnel affinity mask
      NULL,                         //tunnel re-optimization timers
      false,                         //tunnel auto-bandwidth enabled
      NULL,                         //tunnel path-options
      ALL,                          //tunnel traffic type
    },

    // add more TE tunnels here and increment num_tunnels
    // note that tunnels are uni-directional
  };


}


#endif
