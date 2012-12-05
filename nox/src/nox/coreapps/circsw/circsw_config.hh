#ifndef circsw_config_HH
#define circsw_config_HH 1

#include "circsw.hh"

namespace vigil {

  ///////////////////////////////////////////
  //////// Configurable Parameters //////////
  ///////////////////////////////////////////

  uint32_t tsig_ = OFPTSG_STS_1;
  uint32_t tsig_incr_  = OFPTSG_STS_1;
  int num_bw_incr_ = 3;    // no. of tsig_incr
  int wait_to_start_polling_ = 5;
  int stat_polling_interval_ = 2;
  uint32_t pause_ = 1; // secs
  int bw_incr_threshold_ = 40; // Mbps
  int num_above_tx_threshold_ = 3;
  int wait_for_xconn_delete_ = 3; //sec
  int wait_for_vcomp_delete_ = 1; //sec
  int wait_for_vmem_delete_ = 5; //sec

  ///////////////////////////////////////////
  ///////// Hard-coded Parameters ///////////
  ///////////////////////////////////////////

  bool forcenewvlinkcreation = false;
  bool usereservedports = true;
  uint16_t reserved_port1 = 0x0011; //17
  uint16_t reserved_port2 = 0x001d; //29;


  /////////////////////////////////////////////
  // Statically Defined Virtual Packet Links //
  /////////////////////////////////////////////

  uint32_t num_vplinks = 2;

  struct link2_elem vplinks[] = {
    {
      UINT64_C(0x00000023208d1306), //packet-switch 1 dpid
      UINT64_C(0x00000023208d1307), //packet-switch 2 dpid
      0x0010,  //16                 //packet-switch 1 portid
      0x0013,  //19                 //packet-switch 2 portid
      OFPTSG_STS_1,                 //desired bandwidth - currently only 50Mbps
      0x3000,                       //linkid - must be 0x3000 and above
    },
    {
      UINT64_C(0x00000023208d1307),
      UINT64_C(0x00000023208d1308),
      0x0014, //20
      0x001c, //28
      OFPTSG_STS_1,
      0x3001,
    },

    // add more virtual links here and increment num_vplinks
    // note that links are bidirectional
  };


}


#endif
