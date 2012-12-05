#include "dhcp.hh"
#include "assert.hh"
#include "packets.h"
#include <boost/bind.hpp>
#include <iostream>
#include <sys/time.h>
#include "flow.hh"

namespace vigil
{
  using namespace vigil::container;
  using namespace vigil::applications;
  using namespace vigil::xml;

  static Vlog_module lg("dhcp");

  void dhcp::getInstance(const container::Context* ctxt,
			 dhcp*& obj)
  {
    obj = dynamic_cast<dhcp*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(dhcp).name())));
  }

  void dhcp::configure(const Configuration* config)
  {
    resolve(ofp);
    resolve(sqllog);

    dhcp_sw_okay = false;

    //Log Database
    if (DHCP_LOG)
    {
      std::string TABLE(DHCP_LOGNAME);
      storage::Column_definition_map columns;
      columns["TimeSec"] = (int64_t) 0;
      columns["TimeUSec"] = (int64_t) 0;
      columns["Host"] = (int64_t) 0;
      columns["Status"] = (int64_t) 0;
      sqllog->create_table(TABLE, columns);
      VLOG_DBG(lg, "Switch activity database table created.");
    }

    register_handler<Datapath_join_event>
      (boost::bind(&dhcp::handle_switch_join, this, _1));
    register_handler<Packet_in_event>
      (boost::bind(&dhcp::handle_packet_in, this, _1));

    //Post periodic clear of stale requests
    timeval tim;
    tim.tv_sec = DHCP_CHECK_INTERVAL;
    tim.tv_usec = 0;
    post(boost::bind(&dhcp::clear_stale_request, this), tim);

    string err;
    const string schema;
    const string filename = "dhcp_config.xml";
    xercesc::DOMDocument* doc = load_document(schema, filename, err);
    domNode = (xercesc::DOMNode*) doc->getDocumentElement();
  }

  void dhcp::clear_stale_request()
  {
    timeval tim;
    gettimeofday(&tim, NULL);
    hash_map<uint64_t,dhcp_req>::iterator i = dhcpRequest.begin();
    while (i != dhcpRequest.end())
    {
      if ((tim.tv_sec - i->second.tim.tv_sec) > DHCP_STALE_TIMEOUT)
	i = dhcpRequest.erase(i);
      else
	i++;
    }

    //Post periodic clear of stale requests
    tim.tv_sec = DHCP_CHECK_INTERVAL;
    tim.tv_usec = 0;
    post(boost::bind(&dhcp::clear_stale_request, this), tim);
  }

  Disposition dhcp::handle_packet_in(const Event& e)
  {
    const Packet_in_event& pie = assert_cast<const Packet_in_event&>(e);
    Flow flow(pie.in_port, *pie.get_buffer());

    //Traffic from DHCP switch
    if (pie.datapath_id.as_host() == ((uint64_t) DHCP_DPID))
    {
      hash_map<uint64_t, dhcp_req>::iterator i = dhcpRequest.find(flow.dl_dst.hb_long());
      if (i == dhcpRequest.end())
      {
	VLOG_WARN(lg, "Unknown DHCP for %"PRIx64" send to all recent ports",
		  flow.dl_dst.hb_long());
	hash_map<uint64_t, dhcp_req>::iterator j = dhcpRequest.begin();
	while (j != dhcpRequest.end())
        {
	  send_openflow_packet(j->second.dpid, *pie.get_buffer(),
			       j->second.port, OFPP_NONE, true);
	  j++;
	}
	log_request(flow.dl_dst.hb_long(), repliedBroadcast);
      }
      else
      {
	send_openflow_packet(i->second.dpid, *pie.get_buffer(),
			     i->second.port, OFPP_NONE, true);
	log_request(flow.dl_dst.hb_long(), repliedUnicast);
	VLOG_DBG(lg, "DHCP reply for %"PRIx64" sent", flow.dl_dst.hb_long());
      }
      return STOP;
    }

    //DHCP request
    if ((flow.dl_type == htons(ETH_TYPE_IP)) &&
        (flow.nw_proto == IP_TYPE_UDP) &&
	(flow.tp_src == htons(68)) && (flow.tp_dst == htons(67)))
    {

      if (ignore_dhcp(pie))
	return CONTINUE;

      if (drop_dhcp(pie))
      {
	log_request(flow.dl_src.hb_long(), rejectedOutside);
	return STOP;
      }

      if (dhcp_sw_okay)
      {
	//Logged with host_auth function if authorized
        if (!host_auth(flow))
	{
	  VLOG_DBG(lg, "Unauthorized host DHCP request from %"PRIx64"",
		   flow.dl_src.hb_long());
	  log_request(flow.dl_src.hb_long(), rejected);
	  return STOP;
	}

	//Send DHCP request
	VLOG_DBG(lg, "DHCP request sent for %"PRIx64" from %"PRIx64"",
		 flow.dl_src.hb_long(), pie.datapath_id.as_host());
	send_openflow_packet(datapathid::from_host(DHCP_DPID), *pie.get_buffer(),
			     DHCP_PORT, OFPP_NONE, true);

	hash_map<uint64_t, dhcp_req>::iterator i = dhcpRequest.find(flow.dl_src.hb_long());
	if (i != dhcpRequest.end())
	  dhcpRequest.erase(i);
	dhcpRequest.insert(std::make_pair(flow.dl_src.hb_long(),
					  dhcp_req(pie.datapath_id, pie.in_port)));
      }
      else
	log_request(flow.dl_src.hb_long(), noDHCPNow);

      return STOP;
    }

    return CONTINUE;
  }

  bool dhcp::ignore_dhcp(const Packet_in_event& pie)
  {
    if (((pie.datapath_id.as_host() >= 0x000db9000000ULL) &&
	 (pie.datapath_id.as_host() <= 0x000db9FFFFFFULL)) ||
	((pie.datapath_id.as_host() >= 0x020db9000000ULL) &&
	 (pie.datapath_id.as_host() <= 0x020db9FFFFFFULL)))
      return false;
    else
      return true;
  }

  /** Check if DHCP should be dropped, e.g.,  broadcast from connecting network.
   * @param pie packet in event
   * @return if DHCP packet should be dropped
   */
  bool dhcp::drop_dhcp(const Packet_in_event& pie)
  {
    if (((pie.datapath_id.as_host() >= 0x000db9000000ULL) &&
	 (pie.datapath_id.as_host() <= 0x000db9FFFFFFULL)) ||
	((pie.datapath_id.as_host() >= 0x020db9000000ULL) &&
	 (pie.datapath_id.as_host() <= 0x020db9FFFFFFULL)))
    {
      if (ntohs(pie.in_port) == 0)
	return false;
      else
	return true;
    }

    return true;
  }

  bool dhcp::host_auth(const Flow& flow)
  {
    //Check a whois server
    if (host_auth_whois(flow))
    {
      log_request(flow.dl_src.hb_long(), whoisAuthenticated);
      return true;
    }

    //Check file
    if (host_auth_file(flow))
    {
      log_request(flow.dl_src.hb_long(), fileAuthenticated);
      return true;
    }

    VLOG_DBG(lg, "Unable to authorize %"PRIx64"",
	     flow.dl_src.hb_long());
    return false;
  }

  bool dhcp::host_auth_file(const Flow& flow)
  {
    std::ifstream ifs(ALLOW_HOST_FILE);
    char hostString[100];

    while (ifs)
    {
      ifs.getline(hostString, 100);
      if (flow.dl_src.hb_long() ==  strtoull(hostString,NULL,16))
      {
	VLOG_DBG(lg, "Authorized %"PRIx64" via file", flow.dl_src.hb_long());
	return true;
      }
    }

    VLOG_DBG(lg, "Unable to authorize %"PRIx64" via file",
	     flow.dl_src.hb_long());

    ifs.close();
    return false;
  }

  bool dhcp::host_auth_whois(const Flow& flow)
  {
    // Compose the whois command to verify source authenticity
    char whois_command[100];
    FILE *whois;
    sprintf(whois_command, "/usr/bin/whois -h %s "EA_FMT,
	    WHOIS_SERVER, EA_ARGS(&flow.dl_src));
    whois = popen(whois_command, "r");

    char buf[1000];
    bool no_match = false;

    while (!feof(whois))
    {
      fgets(buf, 100, whois);
      if (!strcmp(buf, "NO MATCH"))
      {
	no_match = true;
	break;
      }
    }
    pclose(whois);

    return !no_match;
  }

  Disposition dhcp::handle_switch_join(const Event& e)
  {
    const Datapath_join_event& dje = assert_cast<const Datapath_join_event&>(e);

    //Create action to send entire packet to NOX controller
    ofp_action act;
    act.set_action_output(OFPP_CONTROLLER, 0);
    ofp_action_list actlist;
    actlist.action_list.push_front(act);

    //Send command to switch
    ofp->init_flow_mod(of_raw, actlist);
    ofp_flow_mod* ofm = (ofp_flow_mod*) of_raw.get();
    ofm->command = htons(OFPFC_ADD);
    ofm->priority = htons(DHCP_PRIORITY);
    ofm->flags = 0;
    ofm->cookie = 0;
    ofm->out_port = htons(OFPP_NONE);
    ofm->buffer_id = htonl(-1);
    ofm->idle_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);

    ofp_match& match = ofm->match;
    memset(&match.pad1, 0, sizeof match.pad1);
    memset(&match.pad2, 0, sizeof match.pad2);

    if (dje.datapath_id.as_host() == ((uint64_t) DHCP_DPID))
    {
      VLOG_DBG(lg, "DHCP switch joined.");
      dhcp_sw_okay = true;
      match.wildcards = htonl(OFPFW_ALL);
    }
    else
    {
      VLOG_DBG(lg, "Normal switch joined");
      match.wildcards = htonl(OFPFW_ALL-
			      OFPFW_TP_SRC-OFPFW_TP_DST-
			      OFPFW_DL_TYPE-OFPFW_NW_PROTO);
      match.dl_type=htons(ETH_TYPE_IP);
      match.nw_proto=htons(IP_TYPE_UDP);
      match.tp_src=htons(68);
      match.tp_dst=htons(67);
    }
    ofp->set_flow_mod_actions(of_raw, actlist);
    if (DHCP_INSERT_FLOW)
      ofp->send_command(of_raw, dje.datapath_id, false);
    return CONTINUE;
  }


  void dhcp::log_request(uint64_t mac, uint64_t status)
  {
    if (!(DHCP_LOG))
      return;

    timeval tim;
    gettimeofday(&tim, NULL);

    //Get connection
    string TABLE(DHCP_LOGNAME);
    storage::Row row = *(new storage::Row());
    row["TimeSec"] = (int64_t) tim.tv_sec;
    row["TimeUSec"] = (int64_t) tim.tv_usec;
    row["Host"]= (int64_t) mac;
    row["Status"]=  (int64_t) status;
    sqllog->rowStore.push_back(std::make_pair(TABLE, row));
  }

}


REGISTER_COMPONENT(vigil::container::Simple_component_factory
		   <vigil::dhcp>,
		   vigil::dhcp);
