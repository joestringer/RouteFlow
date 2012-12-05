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
#ifndef PORT_HH
#define PORT_HH 1

#include <iostream>
#include "openflow/openflow.h"
#include "netinet++/ethernetaddr.hh"

namespace vigil {

struct Port
{
    Port(const ofp_phy_port *opp);
    Port() : port_no(0), speed(0), config(0), state(0), 
             curr(0), advertised(0), supported(0), peer(0) {};

    uint16_t port_no;
    std::string name;
    uint32_t speed;
    uint32_t config;
    uint32_t state;

    /*  Bitmaps of OFPPF_* that describe features.  All bits disabled if
     * unsupported or unavailable. */
    uint32_t curr;
    uint32_t advertised;
    uint32_t supported;
    uint32_t peer;

    ethernetaddr hw_addr;
};

inline
Port::Port(const ofp_phy_port *opp) : name((char *)opp->name)
{
    port_no    = ntohs(opp->port_no);
    config     = ntohl(opp->config);
    state      = ntohl(opp->state);
    curr       = ntohl(opp->curr);
    advertised = ntohl(opp->advertised);
    supported  = ntohl(opp->supported);
    peer       = ntohl(opp->peer);
    hw_addr.set_octet(opp->hw_addr);

    if (curr & (OFPPF_10MB_HD | OFPPF_10MB_FD)) {
        speed = 10;
    } else if (curr & (OFPPF_100MB_HD | OFPPF_100MB_FD)) {
        speed = 100;
    } else if (curr & (OFPPF_1GB_HD | OFPPF_1GB_FD)) {
        speed = 1000;
    } else if (curr & OFPPF_10GB_FD) {
        speed = 10000;
    } else {
        speed = 0;
    }
}

inline
std::ostream& operator<< (std::ostream& stream, const Port& p)
{
    stream << p.port_no << "(" << p.name << "): " << p.hw_addr 
                << " speed: " << p.speed
                << " config: " << std::hex << p.config 
                << " state: " << std::hex << p.state 
                << " curr: " << std::hex << p.curr
                << " advertised: " << std::hex << p.advertised
                << " supported: " << std::hex << p.supported
                << " peer: " << std::hex << p.peer;
    return stream;
}

/*

struct CPort
{
    CPort(const ofp_phy_cport *opcp);
    CPort() : port_no(0), speed(0), config(0), state(0),
              curr(0), advertised(0), supported(0), peer(0),
              supp_sw_tdm_gran(0), supp_swtype(0),
              peer_port_no(0), peer_datapath_id(0),
              num_bandwidth(0),
              bwbmp1(0), bwbmp2(0), bwbmp3(0), linkid(0) {};

    uint16_t port_no;
    std::string name;
    uint32_t speed;
    uint32_t config;
    uint32_t state;

    //  Bitmaps of OFPPF_* that describe features.  All bits disabled if
    //  unsupported or unavailable.
    uint32_t curr;
    uint32_t advertised;
    uint32_t supported;
    uint32_t peer;

    uint32_t supp_sw_tdm_gran; // TDM switching granularity OFPTSG_* flags
    uint16_t supp_swtype;      // Bitmap of switching type OFPST_* flags
    uint16_t peer_port_no;     // Discovered peer's switchport number
    uint64_t peer_datapath_id; // Discovered peer's datapath id
    uint16_t num_bandwidth;    // Identifies number of bandwidth array elems

    uint64_t bwbmp1;        // Bitmaps to keep track of bandwidth
    uint64_t bwbmp2;        // valid for STS-1 timeslots for up to
    uint64_t bwbmp3;        // OC-192

    uint16_t linkid;        // Discovered link id. If zero then not-connected
                               or not-discovered yet

    void bwparser(void);
};

inline
CPort::CPort(const ofp_phy_cport *opcp) : name((char *)opcp->name)
  {
    port_no    = ntohs(opcp->port_no);
    config     = ntohl(opcp->config);
    state      = ntohl(opcp->state);
    curr       = ntohl(opcp->curr);
    advertised = ntohl(opcp->advertised);
    supported  = ntohl(opcp->supported);
    peer       = ntohl(opcp->peer);

    if (curr & (OFPPF_10MB_HD | OFPPF_10MB_FD)) {
      speed = 10;
    } else if (curr & (OFPPF_100MB_HD | OFPPF_100MB_FD)) {
      speed = 100;
    } else if (curr & (OFPPF_1GB_HD | OFPPF_1GB_FD)) {
      speed = 1000;
    } else if (curr & (OFPPF_10GB_FD | OFPPF_OC192)) {
      speed = 10000;
    } else if (curr & (OFPPF_OC48 )) {
      speed = 2500;
    } else {
      speed = 0;
    }
    supp_swtype = ntohs(opcp->supp_swtype);
    supp_sw_tdm_gran = ntohl(opcp->supp_sw_tdm_gran);
    peer_port_no = ntohs(opcp->peer_port_no);
    peer_datapath_id = ntohll(opcp->peer_datapath_id);
    num_bandwidth = ntohs(opcp->num_bandwidth);
    bwbmp1 = bwbmp2 = bwbmp3 = 0;
    linkid = 0;

    if(supp_swtype & OFPST_T_SONET) {
      for (int i=0; i<num_bandwidth; ++i) {
        if (i==0) bwbmp1 = ntohll(opcp->bandwidth[i]);
        if (i==1) bwbmp2 = ntohll(opcp->bandwidth[i]);
        if (i==2) bwbmp3 = ntohll(opcp->bandwidth[i]);
      }
    }

  }

*/


} // namespace vigil

#endif /* PORT_HH */
