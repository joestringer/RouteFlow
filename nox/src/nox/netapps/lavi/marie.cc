#include "marie.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "discovery/link-event.hh"
#include "vlog.hh"
#include "assert.hh"
#include <boost/bind.hpp>

namespace vigil
{
  using namespace vigil::container;
  using namespace vigil::applications;


  static Vlog_module lg("marie");

  marie::marie(const Context* c, const xercesc::DOMNode* node)
    : Component(c)
  {}

  void marie::configure(const Configuration* config)
  {
    resolve(book);
    resolve(topology);
    tunncolor = 0;
    mpls_tunnelid_start = 0x7e00;

    register_handler<Datapath_join_event>
      (boost::bind(&marie::handle_switch_add, this, _1));
    register_handler<Datapath_leave_event>
      (boost::bind(&marie::handle_switch_del, this, _1));
    register_handler<Link_event>
      (boost::bind(&marie::handle_link_event, this, _1));
  }

  void marie::getInstance(const container::Context* ctxt,
			  marie*& component)
  {
    component = dynamic_cast<marie*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(marie).name())));
  }

  void marie::handle_nodes_req(const Book_msg_event& bm)
  {
    book_node_req_message* value = (book_node_req_message*) bm.msg->body;
    VLOG_DBG(lg, "Node request of requesttype %"PRIx8"",value->type);
    switch(value->type)
    {
    case BOOKR_ONETIME:
      node_req(bm);
      break;
    case BOOKR_SUBSCRIBE:
      node_subscribe(bm);
      break;
    case BOOKR_UNSUBSCRIBE:
      node_unsubscribe(bm);
      break;
    default:
      VLOG_WARN(lg,"Unknown request type %"PRIx16"",
		value->type);
    }
  }

  uint64_t marie::link_capacity(uint64_t dpid1, uint64_t dpid2)
  {
    if ((node_type(dpid1) == BOOKN_WIRELESS_OPENFLOW) ||
	(node_type(dpid2) == BOOKN_WIRELESS_OPENFLOW))
      return 1e8;

    return 1e9;
  }

  uint16_t marie::link_type(uint64_t dpid1, uint64_t dpid2)
  {
    return BOOKL_SW2SW;
  }

  uint16_t marie::link_type2(uint16_t port1, uint16_t port2)
  {
    if ( port1 >= mpls_tunnelid_start ||
         port2 >= mpls_tunnelid_start )
      return BOOKL_TUNNEL;
    else
      return BOOKL_SW2SW;
  }

  uint16_t marie::node_type(uint64_t dpid)
  {
    if (((dpid >= 0x000db9000000ULL) &&
	 (dpid <= 0x000db9FFFFFFULL)) ||
	((dpid >= 0x020db9000000ULL) &&
	 (dpid <= 0x020db9FFFFFFULL)))
      return BOOKN_WIRELESS_OPENFLOW;

    return BOOKN_OPENFLOW;
  }

  void marie::node_req(const Book_msg_event& bm)
  {
    book_node_req_message* value = (book_node_req_message*) bm.msg->body;

    //Return all switches
    topology->get_switches();
    booknodelist.clear();
    for (Topology::SwitchSet::iterator i = topology->swSet.begin();
	 i != topology->swSet.end(); i++)
      booknodelist.push_front(*(new booknode(datapathid::from_host(i->as_host()),
					     node_type(i->as_host()))));

    if ((ntohs(value->nodeType) != BOOKN_UNKNOWN) &&
	(ntohs(value->nodeType) != BOOKN_OPENFLOW))
      booknodelist.clear();

    book->send_node_list(booknodelist, bm.sock, true, ntohl(bm.msg->header.xid));
  }

  void marie::node_subscribe(const Book_msg_event& bm)
  {
    book_node_req_message* value = (book_node_req_message*) bm.msg->body;
    std::multimap<uint16_t, Msg_stream*>::iterator i;
    std::pair<std::multimap<uint16_t, Msg_stream*>::iterator,
      std::multimap<uint16_t, Msg_stream*>::iterator> ret;
    ret = nodeSub.equal_range(ntohs(value->nodeType));
    for (i=ret.first; i!=ret.second; ++i)
      if (i->second == bm.sock)
	return;

    nodeSub.insert(std::make_pair(ntohs(value->nodeType), new Msg_stream(*bm.sock)));
    VLOG_DBG(lg, "Subscribe to node of type %"PRIx16"",ntohs(value->nodeType));
  }

  void marie::node_unsubscribe(const Book_msg_event& bm)
  {
    book_node_req_message* value = (book_node_req_message*) bm.msg->body;
    if (ntohs(value->nodeType) == BOOKN_UNKNOWN)
    {
      std::multimap<uint16_t, Msg_stream*>::iterator i =nodeSub.begin();
      while(i != nodeSub.end())
      {
	if (i->second == bm.sock)
	  nodeSub.erase(i);
	else
	  i++;
      }
    }
    else
      nodeSub.erase(ntohs(value->nodeType));
  }

  Disposition marie::handle_switch_add(const Event& e)
  {
    const Datapath_join_event& dje = assert_cast<const Datapath_join_event&>(e);
    booknodelist.clear();
    booknodelist.push_front(*(new booknode(dje.datapath_id,
					   node_type(dje.datapath_id.as_host()))));

    std::multimap<uint16_t, Msg_stream*>::iterator i;
    std::pair<std::multimap<uint16_t, Msg_stream*>::iterator,
      std::multimap<uint16_t, Msg_stream*>::iterator> ret;

    ret = nodeSub.equal_range(BOOKN_UNKNOWN);
    for (i=ret.first; i!=ret.second; ++i)
	book->send_node_list(booknodelist, i->second, true);

    ret = nodeSub.equal_range(BOOKN_OPENFLOW);
    for (i=ret.first; i!=ret.second; ++i)
      book->send_node_list(booknodelist, i->second, true);

    return CONTINUE;
  }

  Disposition marie::handle_switch_del(const Event& e)
  {
    const Datapath_leave_event& dle = assert_cast<const Datapath_leave_event&>(e);
    booknodelist.clear();
    booknodelist.push_front(*(new booknode(dle.datapath_id,
					   node_type(dle.datapath_id.as_host()))));

    std::multimap<uint16_t, Msg_stream*>::iterator i;
    std::pair<std::multimap<uint16_t, Msg_stream*>::iterator,
      std::multimap<uint16_t, Msg_stream*>::iterator> ret;

    ret = nodeSub.equal_range(BOOKN_UNKNOWN);
    for (i=ret.first; i!=ret.second; ++i)
      book->send_node_list(booknodelist, i->second, false);

    ret = nodeSub.equal_range(BOOKN_OPENFLOW);
    for (i=ret.first; i!=ret.second; ++i)
      book->send_node_list(booknodelist, i->second, false);

    return CONTINUE;
  }

  void marie::handle_links_req(const Book_msg_event& bm)
  {
    book_link_req_message* blm = (book_link_req_message*) bm.msg->body;
    VLOG_DBG(lg,"Link request of request type %"PRIx8" datapathid %"PRIx64"",
	     blm->type, ntohll(blm->nodeTypeId.id));
    switch(blm->type)
    {
    case BOOKR_ONETIME:
      link_request(bm);
      break;
    case BOOKR_SUBSCRIBE:
      link_subscribe(bm);
      break;
    case BOOKR_UNSUBSCRIBE:
      link_unsubscribe(bm);
      break;
    }
  }

  void marie::link_request(const Book_msg_event& bm)
  {
    book_link_req_message* blm = (book_link_req_message*) bm.msg->body;
    booklinklist.clear();
    std::list<datapathid> dpids;
    uint8_t color;

    switch (ntohs(blm->linkType))
      {
      case BOOKL_UNKNOWN:
      case BOOKL_SW2SW:
        if (!blm->nodeTypeId.id) {
          topology->get_switches();
          dpids = topology->swSet;
        } else {
          dpids.push_back(datapathid::from_net(blm->nodeTypeId.id));
        }

        for (Topology::SwitchSet::const_iterator k = dpids.begin();
             k != dpids.end(); k++ ) {
          const Topology::DatapathLinkMap& ols = topology->get_outlinks(*k);
          for (Topology::DatapathLinkMap::const_iterator i = ols.begin();
               i != ols.end(); i++) {
            for (std::list<Topology::LinkPorts>::const_iterator j = i->second.begin();
                 j != i->second.end(); j++) {
              VLOG_DBG(lg,"To send link from datapathid %"PRIx64" to datapathid %"PRIx64"",
                       k->as_host(), i->first.as_host());
              if ( tunnelcolormap.find(j->src) == tunnelcolormap.end() )
                color = get_tunnel_color(j->src, j->dst);
              else
                color = tunnelcolormap[j->src];
              booklinklist.push_back(booklinkspec(link_type2(j->src, j->dst),
                                                  booknode(BOOKN_OPENFLOW, k->as_host()),
                                                  j->src,
                                                  booknode(BOOKN_OPENFLOW, i->first.as_host()),
                                                  j->dst,
                                                  link_capacity(k->as_host(), i->first.as_host()),
                                                  color));
            }
          }
        }
        break;
      }
    book->send_link_list(booklinklist, bm.sock, true, ntohl(bm.msg->header.xid));
  }

  void marie::link_subscribe(const Book_msg_event& bm)
  {
    book_link_req_message* value = (book_link_req_message*) bm.msg->body;
    std::multimap<uint16_t, Msg_stream*>::iterator i;
    std::pair<std::multimap<uint16_t, Msg_stream*>::iterator,
      std::multimap<uint16_t, Msg_stream*>::iterator> ret;
    ret = linkSub.equal_range(ntohs(value->linkType));
    for (i=ret.first; i!=ret.second; ++i)
      if (i->second == bm.sock)
	return;
    linkSub.insert(std::make_pair(ntohs(value->linkType), new Msg_stream(*bm.sock)));
    VLOG_DBG(lg, "Subscribe to link of linktype %"PRIx16"",ntohs(value->linkType));
  }

  void marie::link_unsubscribe(const Book_msg_event& bm)
  {
    book_link_req_message* value = (book_link_req_message*) bm.msg->body;
    if (ntohs(value->linkType) == BOOKL_UNKNOWN)
    {
      std::multimap<uint16_t, Msg_stream*>::iterator i = linkSub.begin();
      while (i != linkSub.end())
      {
	if (i->second == bm.sock)
	  linkSub.erase(i);
	else
	  i++;
      }
    }
    else
      linkSub.erase(ntohs(value->linkType));
  }


  uint8_t marie::get_tunnel_color(uint16_t srcport, uint16_t dstport) {
    if (srcport >= mpls_tunnelid_start && dstport == srcport) {
      uint8_t color = (tunncolor < 9)? tunncolor++ : 9;
      tunnelcolormap.insert(std::make_pair(srcport,color));
      return color;
    } else {
      return 0;
    }
  }

  uint8_t marie::get_tunnel_color(uint16_t tid) {
    if ( tunnelcolormap.find(tid) != tunnelcolormap.end() )
      return tunnelcolormap[tid];
    else
      return 0;
  }

  Disposition marie::handle_link_event(const Event& e)
  {
    const Link_event& le = assert_cast<const Link_event&>(e);
    booklinklist.clear();
    booklinklist.push_back(booklinkspec(link_type2(le.sport, le.dport),
                                        booknode(BOOKN_OPENFLOW,
                                                 le.dpsrc.as_host()),le.sport,
                                        booknode(BOOKN_OPENFLOW,
                                                 le.dpdst.as_host()),le.dport,
                                        link_capacity(le.dpsrc.as_host(),
                                                      le.dpdst.as_host()),
                                        get_tunnel_color(le.sport, le.dport)));

    std::multimap<uint16_t, Msg_stream*>::iterator i;
    std::pair<std::multimap<uint16_t, Msg_stream*>::iterator,
      std::multimap<uint16_t, Msg_stream*>::iterator> ret;

    ret = linkSub.equal_range(BOOKL_UNKNOWN);
    for (i=ret.first; i!=ret.second; ++i)
	book->send_link_list(booklinklist, i->second, le.action==le.ADD);

    ret = linkSub.equal_range(link_type2(le.sport, le.dport));
    for (i=ret.first; i!=ret.second; ++i)
	book->send_link_list(booklinklist, i->second, le.action==le.ADD);

    return CONTINUE;
  }

  void marie::clearConnection(const Book_msg_event& bm)
  {
    VLOG_DBG(lg, "Clearing connections");
    //Remove topo update list
    std::multimap<uint16_t,Msg_stream*>::iterator g = nodeSub.begin();
    while (g != nodeSub.end())
      if (&(*(((Async_stream*) ((g->second)->stream)))) == &(*(bm.sock->stream)))
      {
	nodeSub.erase(g);
	g = nodeSub.begin();
	VLOG_DBG(lg, "Removed switch subscription due to connection close ");
      }
      else
	g++;

    //Remove link update list
    std::multimap<uint16_t,Msg_stream*>::iterator h = linkSub.begin();
    while (h != linkSub.end())
      if (&(*(((Async_stream*) ((h->second)->stream)))) == &(*(bm.sock->stream)))
      {
	linkSub.erase(h);
	h = linkSub.begin();
	VLOG_DBG(lg, "Removed link subscription due to connection close ");
      }
      else
	h++;

  }
}


REGISTER_COMPONENT(vigil::container::Simple_component_factory<vigil::marie>,
		   vigil::marie);
