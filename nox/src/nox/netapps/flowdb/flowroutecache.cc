#include "flowroutecache.hh"

namespace vigil
{
  static Vlog_module lg("flowroutecache");

  Route_hop::Route_hop(uint16_t inport, datapathid dpid, uint16_t output):
    in_port(inport), out_port(output)
  {
    sw = dpid;
  }

  Host_route_event::~Host_route_event()
  {
    installed_route.clear();
  }

  Host_route_event::Host_route_event(uint32_t flowid_, bool add_):
    Event(static_get_name())
  {
    flowid = flowid_;
    add = add_;
  }

  void Host_route_event::add_route(network::route* rte)
  {
    single_route sr;
    while (!rte->in_switch_port.dpid.empty())
    {
      sr.push_back(*(new Route_hop(rte->in_switch_port.port,
				   rte->in_switch_port.dpid,
				   rte->next_hops.begin()->first)));
      rte = rte->next_hops.begin()->second;
    }
    installed_route.push_front(sr);
  }

  flowroutecache::flowrecord::flowrecord(ethernetaddr srcmac, ethernetaddr dstmac,
					 datapathid srcdpid, uint32_t flowid)
  {
    src_mac = srcmac;
    dst_mac = dstmac;
    src_dpid = srcdpid;
    flow_id  = flowid;
  }

  flowroutecache::flowrecord::flowrecord(ethernetaddr srcmac, ethernetaddr dstmac,
					 uint32_t flowid)
  {
    src_mac = srcmac;
    dst_mac = dstmac;
    src_dpid = datapathid();
    flow_id  = flowid;
  }

  void flowroutecache::configure(const Configuration* config)
  {
    resolve(ri);

    register_event(Host_route_event::static_get_name());

    flowid = 0;

    register_handler<Flowdb_event>
      (boost::bind(&flowroutecache::handle_flowdb_event, this, _1));
  }

  void flowroutecache::getInstance(const container::Context* ctxt,
				   flowroutecache*& component)
  {
    component = dynamic_cast<flowroutecache*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(flowroutecache).name())));
  }

  Disposition flowroutecache::handle_flowdb_event(const Event& e)
  {
    const Flowdb_event& fde = assert_cast<const Flowdb_event&>(e);
    VLOG_DBG(lg,"Received flow db notification (%s) (%s) from %"\
	     PRIx64" between %"PRIx64" and %"PRIx64"",
	     (fde.type == ADD)?"adding":"deleting",
	     (fde.exit)?"source":"destination",
	     fde.dp.as_host(),
	     fde.srcmac.hb_long(), fde.dstmac.hb_long());

    //Find flow record
    std::list<flowroutecache::flowrecord>::iterator i =
      find_flowrecord(fde.srcmac, fde.dstmac);
    if (i == flowrecords.end())
    {
      //Cannot find exiting flow => deleted
      if (fde.type == DELETE)
	return CONTINUE;
      flowrecord* fr = new flowrecord(fde.srcmac, fde.dstmac, fde.dp, ++flowid);
      flowrecords.push_front(*fr);
      i = flowrecords.begin();
    }
    else
      post_flow_event(*i, false);

    //Update flow record
    switch (fde.type)
    {
    case ADD:
      if (fde.exit)
      {
	hash_map<uint64_t, uint8_t>::iterator j = i->dst_dpid.find(fde.dp.as_host());
	if (j == i->dst_dpid.end())
	{
	  i->dst_dpid.insert(std::make_pair(fde.dp.as_host(), 0));
	  j = i->dst_dpid.find(fde.dp.as_host());
	}
	j->second++;
      }
      else
	i->src_dpid=fde.dp;
      break;

    case DELETE:
      if (fde.exit)
      {
	hash_map<uint64_t, uint8_t>::iterator j = i->dst_dpid.find(fde.dp.as_host());
	if (j != i->dst_dpid.end())
	{
	  j->second--;
	  if (j->second == 0)
	    i->dst_dpid.erase(j);
	}
      }
      else
	i->src_dpid=datapathid();
      break;
    }

    //Post adding of required host route event
    VLOG_DBG(lg,"Flow record from %"PRIx64" to %"PRIx64"",
	     fde.srcmac.hb_long(), fde.dstmac.hb_long());

    if ((!i->src_dpid.empty()) &&
	(i->dst_dpid.size() != 0))
      post_flow_event(*i,true);

    if ((i->src_dpid.empty()) &&
	(i->dst_dpid.size() == 0))
      flowrecords.erase(i);

    return CONTINUE;
  }

  void flowroutecache::post_flow_event(flowrecord fr, bool add)
  {
    network::route rte(fr.src_dpid,0xffff);

    Host_route_event* hre = new Host_route_event(fr.flow_id, add);
    //Loop over all destinations
    for (hash_map<uint64_t, uint8_t>::iterator i = fr.dst_dpid.begin();
	 i != fr.dst_dpid.end(); i++)
    {
      if (ri->get_shortest_path(network::termination(datapathid::from_host(i->first),
						     0xffff),
				rte))
	hre->add_route(&rte);
    }
    post(hre);
  }

  std::list<flowroutecache::flowrecord>::iterator flowroutecache::find_flowrecord(ethernetaddr srcmac, ethernetaddr dstmac)
  {
    for (std::list<flowrecord>::iterator i = flowrecords.begin();
	 i != flowrecords.end(); i++)
      if ((i->src_mac.hb_long() == srcmac.hb_long()) &&
	  (i->dst_mac.hb_long() == dstmac.hb_long()))
	return i;

    return flowrecords.end();
  }
}


REGISTER_COMPONENT(vigil::container::Simple_component_factory
		   <vigil::flowroutecache>,
		   vigil::flowroutecache);
