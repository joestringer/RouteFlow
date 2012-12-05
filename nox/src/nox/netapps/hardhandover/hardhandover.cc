#include "hardhandover.hh"

namespace vigil
{
  static Vlog_module lg("hardhandover");

  void hardhandover::configure(const Configuration* config)
  {
    resolve(fdb);
    resolve(mdb);
    resolve(ri);

    mdb->set_max_map_size(2);

    register_handler<SNMP_host_event>
      (boost::bind(&hardhandover::handle_wireless_join, this, _1));
    //register_handler<Flow_in_event>
    //  (boost::bind(&hardhandover::handle_flow_in, this, _1));
  }

  Disposition hardhandover::handle_flow_in(const Event& e)
  {
    //Received flow in for host
    const Flow_in_event& fie = assert_cast<const Flow_in_event&>(e);
    if (fie.flow.dl_dst.is_broadcast())
      return CONTINUE;

    VLOG_DBG(lg, "Flow from %"PRIx64" port %"PRIx16" going to %"PRIx64"",
	     fie.datapath_id.as_host(), ntohs(fie.flow.in_port), fie.flow.dl_dst.hb_long());

    BindPointPtrList loc = mdb->BindPoints_of_host(fie.flow.dl_dst);
    if (loc.size() == 0)
      return CONTINUE;

    network::route rte(fie.datapath_id,ntohs(fie.flow.in_port));
    if (ri->get_shortest_path((*loc.begin())->network_point(), rte))
    {
      ri->install_route(fie.flow, rte, fie.buffer_id);
      return STOP;
    }

    return CONTINUE;
  }

  Disposition hardhandover::handle_wireless_join(const Event& e)
  {
    //Received wireless host join
    const SNMP_host_event& she = assert_cast<const SNMP_host_event&>(e);

    //Ignore leave event
    if (!she.join)
      return CONTINUE;

    VLOG_DBG(lg, "Host %"PRIx64" join at %"PRIx64" port %"PRIx16"",
	     she.hostMac.hb_long(), she.dpid.as_host(), she.port);

    //Get flows destined to host and reroute.
    std::list<FlowEntryPtr> flows(fdb->flowWithDst(she.hostMac));
    for (std::list<FlowEntryPtr>::iterator i = flows.begin(); i != flows.end(); i++)
    {
      Flow f = fdb->create_flow_instance(*i);
      if (!((*i)->exit))
      {
	VLOG_DBG(lg, "Rerouting");
	network::route rte((*i)->dp,f.in_port);
	if (ri->get_shortest_path(network::termination(she.dpid, she.port), rte))
	  ri->install_route(f, rte, -1);
      }
    }

    return CONTINUE;
  }

  void hardhandover::getInstance(const container::Context* ctxt,
				   hardhandover*& ofp)
  {
    ofp = dynamic_cast<hardhandover*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(hardhandover).name())));
  }
}


REGISTER_COMPONENT(vigil::container::Simple_component_factory
		   <vigil::hardhandover>,
		   vigil::hardhandover);
