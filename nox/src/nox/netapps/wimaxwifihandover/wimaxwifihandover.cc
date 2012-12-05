#include "wimaxwifihandover.hh"
#include "authenticator/flow_in.hh"
#include "authenticator/authenticator.hh"
#include "messenger/message.hh"
#include "messenger/messenger.hh"
#include <boost/bind.hpp>
#include "assert.hh"

#define DP_FROM_AP(loc) ((loc) & 0xffffffffffffULL)

namespace vigil
{
  using namespace vigil::applications;

  static Vlog_module lg("wimaxwifihandover");

  void wimaxwifihandover::configure(const Configuration* config)
  {
    resolve(fdb);
    resolve(ri);
    resolve(mdb);

    mdb->set_max_map_size(1);
    inWiMAX = false;

    register_handler<Msg_event>
      (boost::bind(&wimaxwifihandover::handle_wimax_msg, this, _1));
    register_handler<Flow_in_event>
      (boost::bind(&wimaxwifihandover::handle_flow_in, this, _1));
    register_handler<SNMP_host_event>
      (boost::bind(&wimaxwifihandover::handle_wifi, this, _1));
  }

  Disposition wimaxwifihandover::handle_flow_in(const Event& e)
  {
    const Flow_in_event& fi = assert_cast<const Flow_in_event&>(e);

    if (!inWiMAX)
      return CONTINUE;

    VLOG_DBG(lg, "Traffic from %"PRIx16" with WiMAX@%"PRIx16" and Network@%"PRIx16"",
	     fi.flow.in_port, WIMAX_PORT, NETWORK_PORT);

    if (ntohl(fi.flow.nw_src) == WIMAX_IP)
    {
      VLOG_DBG(lg, "Host's WiMAX reply");
      /*      hash_map<datapathid,ofp_action_list> act;
      changeMacAction(WIMAX_MAC, act, false);

      network::route rte(datapathid::from_host(WIMAXWIFI_DPID), WIMAX_PORT);
      const Flow_in_event::DestinationInfo& dst = fi.dst_locations[0];
      uint64_t location = dst.authed_location.location->dpport;
      if (ri->get_shortest_path(network::termination(datapathid::from_host(DP_FROM_AP(location)),
						     (uint16_t)(location >> 48)), rte))
						     ri->install_route(fi.flow, rte, -1, act);*/
    }

    return CONTINUE;
    //return STOP;
  }

  Disposition wimaxwifihandover::handle_wifi(const Event& e)
  {
    const SNMP_host_event& she = assert_cast<const SNMP_host_event&>(e);

    //Ignore leave event
    if (!she.join)
      return CONTINUE;

    VLOG_DBG(lg, "Host %"PRIx64" join at %"PRIx64" port %"PRIx16"",
	     she.hostMac.hb_long(), she.dpid.as_host(), she.port);

    if (she.hostMac.hb_long() == WIFI_MAC)
    {
	BindPointPtrList loc = mdb->BindPoints_of_host(ethernetaddr(WIFI_MAC));
	if (loc.size() == 0)
	  return CONTINUE;

	//Get flows destined to host and reroute.
	std::list<FlowEntryPtr> flows(fdb->flowWithDst(ethernetaddr(WIFI_MAC)));
	for (std::list<FlowEntryPtr>::iterator i = flows.begin(); i != flows.end(); i++)
	{
	  VLOG_DBG(lg, "Rerouting");
	  Flow f = fdb->create_flow_instance(*i);
	  network::route rte((*i)->dp,f.in_port);
	  if (ri->get_shortest_path((*loc.begin())->network_point(), rte))
	    ri->install_route(f, rte, -1);
	}
    }

    return CONTINUE;
  }

  Disposition wimaxwifihandover::handle_wimax_msg(const Event& e)
  {
    const Msg_event& me = assert_cast<const Msg_event&>(e);
    VLOG_DBG(lg, "WiMAX message received");

    if (me.msg->type == MSG_WIMAX)
    {
      wimax_msg* wmsg = (wimax_msg*) me.msg->body;

      if (wmsg->subtype == WIMAX_JOIN)
      {
	inWiMAX=true;

	VLOG_DBG(lg, "WiMAX joins with host mac %"PRIx64" and bs mac %"PRIx64"",
		 wmsg->host_mac, wmsg->bs_mac);

	//Get flows destined to host and reroute.
	std::list<FlowEntryPtr> flows(fdb->flowWithDst(ethernetaddr(WIFI_MAC)));
	for (std::list<FlowEntryPtr>::iterator i = flows.begin(); i != flows.end(); i++)
	{
	  VLOG_DBG(lg, "Rerouting");
	  hash_map<datapathid,ofp_action_list> act;
	  changeMacAction(WIMAX_MAC, act, false);
	  Flow f = fdb->create_flow_instance(*i);
	  network::route rte((*i)->dp,f.in_port);
	  if (ri->get_shortest_path(network::termination(datapathid::from_host(WIMAXWIFI_DPID),
							 WIMAX_PORT), rte))
	    ri->install_route(f, rte, -1, act);
	}
      }
      else
      {
	inWiMAX=false;

	wimax_msg* wmsg = (wimax_msg*) me.msg->body;
	VLOG_DBG(lg, "WiMAX leaves with host mac %"PRIx64" and bs mac %"PRIx64"",
		 wmsg->host_mac, wmsg->bs_mac);

      }
    }

    return CONTINUE;
  }

  void wimaxwifihandover::changeMacIPAction(uint64_t mac, uint32_t ip,
					    hash_map<datapathid,ofp_action_list>& act, bool source)
  {
    ofp_action_list oal;

    ofp_action* ofpa = new ofp_action();
    if (source)
      ofpa->set_action_dl_addr(OFPAT_SET_DL_SRC, ethernetaddr(mac));
    else
      ofpa->set_action_dl_addr(OFPAT_SET_DL_DST, ethernetaddr(mac));
    oal.action_list.push_back(*ofpa);

    ofpa = new ofp_action();
    if (source)
      ofpa->set_action_nw_addr(OFPAT_SET_NW_SRC, ip);
    else
      ofpa->set_action_nw_addr(OFPAT_SET_NW_DST, ip);
    oal.action_list.push_back(*ofpa);

    act.insert(std::make_pair(datapathid::from_host(WIMAXWIFI_DPID), oal));
  }

  void wimaxwifihandover::changeMacAction(uint64_t mac,
					  hash_map<datapathid,ofp_action_list>& act, bool source)
  {
    ofp_action_list oal;

    ofp_action* ofpa = new ofp_action();
    if (source)
      ofpa->set_action_dl_addr(OFPAT_SET_DL_SRC, ethernetaddr(mac));
    else
      ofpa->set_action_dl_addr(OFPAT_SET_DL_DST, ethernetaddr(mac));
    oal.action_list.push_back(*ofpa);

    act.insert(std::make_pair(datapathid::from_host(WIMAXWIFI_DPID), oal));
  }

  void wimaxwifihandover::getInstance(const container::Context* ctxt,
				      wimaxwifihandover*& ofp)
  {
    ofp = dynamic_cast<wimaxwifihandover*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(wimaxwifihandover).name())));
  }
}


REGISTER_COMPONENT(vigil::container::Simple_component_factory
		   <vigil::wimaxwifihandover>,
		   vigil::wimaxwifihandover);
