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

#include "hoolock.hh"
#include "assert.hh"
#include "packets.h"
#include "netinet++/ethernet.hh"
#include "vlog.hh"
#include "fnv_hash.hh"
#include <unistd.h>
#include <boost/bind.hpp>
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <sstream>

using namespace std;
using namespace vigil;
using namespace vigil::container;

namespace vigil {
namespace applications {

Hoolock::Hoolock(const Context* c, const xercesc::DOMNode* x)
        :Component(c), flowdb(0), mobiledb(0), rinstaller(0)
{ }

void
Hoolock::getInstance(const container::Context * ctxt, Hoolock*& s)
{
        s = dynamic_cast<Hoolock*>
                (ctxt->get_by_interface(container::Interface_description(typeid(Hoolock).name())));
}

void
Hoolock::configure(const Configuration* conf)
{
        resolve(flowdb);
        resolve(mobiledb);
        resolve(rinstaller);
        mobiledb->set_max_map_size(2);
        register_handler<Flow_in_event>(boost::bind(&Hoolock::handle_flow_in, this, _1));
        register_handler<SNMP_host_event>(boost::bind(&Hoolock::handle_snmp_host_event, this, _1));
}

Disposition
Hoolock::handle_flow_in(const Event& e)
{
	const Flow_in_event& fie = assert_cast<const Flow_in_event&>(e);

    ethernetaddr dst = fie.flow.dl_dst;
    lg.dbg("got flow-in event from %s to %s", fie.flow.dl_src.string().c_str(),
                    fie.flow.dl_dst.string().c_str());

    BindPointPtrList assocAP = mobiledb->BindPoints_of_host(dst);
    list<network::termination> hostAP;
    BindPointPtrList::iterator bppit = assocAP.begin();
    // Use the latest interface to route the flow to
    // Assumption: mobiledb holds the APs in the reverse order of their joining
    if(bppit != assocAP.end()) {
            BindPointPtr bp = *bppit;
            lg.dbg("Flow to %"PRIx64" port:%"PRIu16" ", bp->dp.as_host(), bp->port);
            hostAP.push_back(network::termination(bp->dp, bp->port));
    }

    network::route sroute(fie.datapath_id, ntohs(fie.flow.in_port));
    lg.dbg("Setting up Flow from %"PRIx64" port:%"PRIu16" ",fie.datapath_id.as_host(),
                    ntohs(fie.flow.in_port));
    if(rinstaller->get_shortest_path(hostAP, sroute)) {
            //successfully got a route
            hash_map<datapathid,ofp_action_list> act;
            rinstaller->install_route(fie.flow, sroute, fie.buffer_id, act);
            lg.dbg("New flow installed!");
    }

    return STOP;
}

Disposition
Hoolock::handle_snmp_host_event(const Event& e)
{
        const SNMP_host_event& snmphe = const_cast<SNMP_host_event&>(dynamic_cast<const SNMP_host_event&>(e));
        ethernetaddr hostMac = snmphe.hostMac;
        FlowEntryList assocFlow = flowdb->flowWithDst(hostMac);
        BindPointPtrList assocAP = mobiledb->BindPoints_of_host(hostMac);
        list<network::termination> hostAP;
        hostAP.push_back(network::termination(snmphe.dpid, snmphe.port));
        if(snmphe.join) {//join event
                lg.dbg("host(%"PRIx64") join AP:%012"PRIx64, hostMac.hb_long(), snmphe.dpid.as_host());
        }
        else {
                lg.dbg("host(%"PRIx64") leave AP:%012"PRIx64, hostMac.hb_long(), snmphe.dpid.as_host());
        }

        FlowEntryList::iterator feit = assocFlow.begin();
        if(feit == assocFlow.end()){
                lg.dbg("No flow associated to the host %"PRIx64, hostMac.hb_long());
                return CONTINUE;
        }

        for( ; feit != assocFlow.end(); feit++) {
                //if(!belongs((*feit)->dp, assocAP)) {
                if(!((*feit)->exit)) {
                        FlowEntryPtr fe = *feit;
                        flowdb->print_flowEntry(fe.get(), new string("Switching Flow:"));
                        //ofp_flow_mod *ofp = (ofp_flow_mod*)fe->flow_mod_cmd.get();
                        //ofp_match ofm = ofp->match;
                        Flow flow = flowdb->create_flow_instance(fe);
                        //sroute's inport is in host order or network order?
                        //network::route sroute(fe->dp, ntohs(ofm.in_port));
                        network::route sroute(fe->dp, flow.in_port);
                        //lg.dbg("Switching flow from @%"PRIx64"port:%"PRIu16, fe->dp.as_host(), ntohs(ofm.in_port));
                        lg.dbg("Switching flow from @%"PRIx64"port:%"PRIu16, fe->dp.as_host(), flow.in_port);
                        if(rinstaller->get_shortest_path(hostAP, sroute)) {
                                //successfully got a route
                                hash_map<datapathid,ofp_action_list> act;
                                rinstaller->install_route(flow, sroute,  htonl(-1), act);
                                lg.dbg("Route switched!");
                        }
                        else {
                                lg.dbg("Couldn't get a route from %"PRIx64" to Host(%"PRIx64")",
                                                fe->dp.as_host(), hostMac.hb_long());
                        }
                }
        }
        return CONTINUE;
}

bool
Hoolock::belongs(datapathid& dpid, BindPointPtrList assocAP){
        BindPointPtrList::iterator bppit = assocAP.begin();
        for( ; bppit!= assocAP.end(); bppit++){
                if(dpid == (*bppit)->dp) return true;
        }
        return false;
}

REGISTER_COMPONENT(container::Simple_component_factory<Hoolock>, Hoolock);

} // applications
} // vigil
