#include "openflowpacket.hh"

namespace vigil
{
  static Vlog_module lg("openflowpacket");

  void ofp_action::set_action_nw_addr(uint16_t type, uint32_t ip)
  {
    action_raw.reset(new uint8_t[sizeof(ofp_action_nw_addr)]);
    header = (ofp_action_header*) action_raw.get();
    ofp_action_nw_addr* oana = (ofp_action_nw_addr*) header;

    oana->type = htons(type);
    oana->len = htons(sizeof(ofp_action_nw_addr));
    oana->nw_addr = htonl(ip);
  }

  void ofp_action::set_action_dl_addr(uint16_t type, ethernetaddr mac)
  {
    action_raw.reset(new uint8_t[sizeof(ofp_action_dl_addr)]);
    header = (ofp_action_header*) action_raw.get();
    ofp_action_dl_addr* oada = (ofp_action_dl_addr*) header;

    oada->type = htons(type);
    oada->len = htons(sizeof(ofp_action_dl_addr));
    memcpy(oada->dl_addr, mac.octet, ethernetaddr::LEN);
  }

  void ofp_action::set_action_output(uint16_t port, uint16_t max_len)
  {
    action_raw.reset(new uint8_t[sizeof(ofp_action_output)]);
    header = (ofp_action_header*) action_raw.get();
    ofp_action_output* oao = (ofp_action_output*) header;

    oao->type = htons(OFPAT_OUTPUT);
    oao->len = htons(sizeof(ofp_action_output));
    oao->port = htons(port);
    oao->max_len = htons(max_len);
  }

  uint16_t ofp_action_list::mem_size()
  {
    uint16_t size = 0;
    std::list<ofp_action>::iterator i = action_list.begin();
    while (i != action_list.end())
    {
      size += ntohs(i->header->len);
      i++;
    }

    return size;
  }

  void openflowpacket::getInstance(const container::Context* ctxt,
				   openflowpacket*& ofp)
  {
    ofp = dynamic_cast<openflowpacket*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(openflowpacket).name())));
  }

  void openflowpacket::init(boost::shared_array<uint8_t>& of_raw, ssize_t size, uint8_t type)
  {
    init(of_raw, size, type, next_xid());
  }

  void openflowpacket::init(boost::shared_array<uint8_t>& of_raw, ssize_t size, uint8_t type, uint32_t xid)
  {
    VLOG_DBG(lg, "Initialize command with size %zu of type %"PRIx8"",
	     size, type);
    of_raw.reset(new uint8_t[size]);
    ofp_header* ofh = (ofp_header*) of_raw.get();
    ofh->version = OFP_VERSION;
    ofh->type = type;
    ofh->length = htons(size);
    ofh->xid = htonl(xid);
  }

  int openflowpacket::send_command(boost::shared_array<uint8_t>& of_raw,
		   const datapathid& dpid, bool block)
  {
    uint16_t val = ((ofp_header*) of_raw.get())->length;
    VLOG_DBG(lg, "Sending command of length %"PRIx16"", ntohs(val));
    return send_openflow_command(dpid, (ofp_header*) of_raw.get(), block);
  }

  bool openflowpacket::set_flow_mod_exact(boost::shared_array<uint8_t>& of_raw, const Flow& flow,
					  uint32_t buffer_id,  uint16_t in_port, uint16_t command)
  {
    return set_flow_mod_exact(of_raw, flow, buffer_id, in_port, command,
			      FLOW_TIMEOUT, OFP_FLOW_PERMANENT, OFP_DEFAULT_PRIORITY);
  }

  bool openflowpacket::set_flow_mod_exact(boost::shared_array<uint8_t>& of_raw,
					  const Flow& flow, uint32_t buffer_id, uint16_t in_port,
					  uint16_t command, uint16_t idle_timeout,
					  uint16_t hard_timeout, uint16_t priority)
  {
    ofp_header* ofh = (ofp_header*) of_raw.get();
    if (ofh->type != OFPT_FLOW_MOD)
      return false;

    ofp_flow_mod* ofm = (ofp_flow_mod*) ofh;
    ofm->command = htons(command);
    ofm->priority = htons(priority);
    ofm->cookie = 0;
    ofm->flags = 0;
    ofm->out_port = htons(OFPP_NONE);
    ofm->buffer_id = htonl(buffer_id);
    ofm->idle_timeout = htons(idle_timeout);
    ofm->hard_timeout = htons(hard_timeout);

    ofp_match& match = ofm->match;
    match.wildcards = 0;
    memset(match.pad1, 0, sizeof(match.pad1));
    memset(match.pad2, 0, sizeof(match.pad2));
    match.in_port = in_port;
    memcpy(match.dl_src, flow.dl_src.octet, ethernetaddr::LEN);
    memcpy(match.dl_dst, flow.dl_dst.octet, ethernetaddr::LEN);
    match.dl_vlan = flow.dl_vlan;
    match.dl_vlan_pcp = flow.dl_vlan_pcp;
    match.dl_type = flow.dl_type;
    match.nw_src = flow.nw_src;
    match.nw_dst = flow.nw_dst;
    match.nw_tos = flow.nw_tos;
    match.nw_proto = flow.nw_proto;
    match.tp_src = flow.tp_src;
    match.tp_dst = flow.tp_dst;

    return true;
  }

  void openflowpacket::set_flow_mod_actions(boost::shared_array<uint8_t>& of_raw,
					    ofp_action_list list)
  {
    ofp_flow_mod* ofm = (ofp_flow_mod*) of_raw.get();
    uint8_t* actions = (uint8_t*) ofm->actions;

    std::list<ofp_action>::iterator i = list.action_list.begin();
    while (i != list.action_list.end())
    {
      memcpy(actions, i->header, ntohs(i->header->len));
      actions += ntohs(i->header->len);
      i++;
    }
  }
}


REGISTER_COMPONENT(vigil::container::Simple_component_factory
		   <vigil::openflowpacket>,
		   vigil::openflowpacket);
