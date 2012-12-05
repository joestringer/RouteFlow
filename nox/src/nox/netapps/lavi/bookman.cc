#include "bookman.hh"
#include "component.hh"
#include "buffer.hh"
#include "async_io.hh"
#include "assert.hh"
#include <errno.h>
#include "errno_exception.hh"
#include <xercesc/dom/DOM.hpp>
#include "vlog.hh"

namespace vigil
{
  using namespace vigil::container;

  static Vlog_module lg("bookman");
  static const std::string app_name("bookman");

  booknode::booknode(uint16_t type_, uint64_t id_):
    book_node(type_,id_)
  {  }

  booknode::booknode(datapathid dpid):
    book_node(BOOKN_UNKNOWN, dpid.as_host())
  { }

  booknode::booknode(datapathid dpid, uint16_t type_):
    book_node(type_, dpid.as_host())
  { }

  void booknode::insert(book_node* bknode)
  {
    bknode->type = htons(type);
    bknode->id = htonll(id);
  }

  booklinkspec::booklinkspec(uint16_t type_, booknode src, uint16_t srcport,
			     booknode dst, uint16_t dstport):
    src_node(src.type, src.id), dst_node(dst.type, dst.id)
  {
    type = type_;
    src_port = srcport;
    dst_port = dstport;
  }

  booklinkspec::booklinkspec(uint16_t type_, booknode src, uint16_t srcport,
			     booknode dst, uint16_t dstport, uint64_t rate_):
    src_node(src.type, src.id), dst_node(dst.type, dst.id)
  {
    type = type_;
    src_port = srcport;
    dst_port = dstport;
    rate = rate_;
  }


  booklinkspec::booklinkspec(uint16_t type_, booknode src, uint16_t srcport,
                             booknode dst, uint16_t dstport, uint64_t rate_,
                             uint8_t color):
    src_node(src.type, src.id), dst_node(dst.type, dst.id)
  {
    type = type_;
    src_port = srcport;
    dst_port = dstport;
    rate = rate_;
    tunn_color = color;
  }


  void booklinkspec::insert(book_link_spec* bklink)
  {
    bklink->type = htons(type);
    src_node.insert(&bklink->src_node);
    bklink->src_port = htons(src_port);
    dst_node.insert(&bklink->dst_node);
    bklink->dst_port = htons(dst_port);
  }

  void booklinkspec::insert(book_link_rate_spec* bklink)
  {
    insert(&bklink->bls);
    bklink->rate = htonll(rate);
    bklink->tunncolor = tunn_color;
  }

  void bookman::configure(const Configuration* config)
  {
    resolve(golem);

    register_handler<Book_msg_event>
      (boost::bind(&bookman::handle_book_msg, this, _1));
  }

  void bookman::install()
  {
  }

  void bookman::getInstance(const container::Context* ctxt,
			    vigil::bookman*& scpa)
  {
    scpa = dynamic_cast<bookman*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(bookman).name())));
  }

  Disposition bookman::handle_book_msg(const Event& e)
  {
    const Book_msg_event& bm = assert_cast<const Book_msg_event&>(e);
    VLOG_DBG(lg,"Received message of type 0x%"PRIx16"",
	     bm.msg->header.type);

    switch(bm.msg->header.type)
    {
    case BOOKT_ECHO:
      VLOG_DBG(lg, "Echo request");
      reply_echo(bm);
      return STOP;
      break;
    case BOOKT_ECHO_RESPONSE:
      //VLOG_DBG(lg, "Echo reply received");
      return STOP;
      break;
    }

    return CONTINUE;
  }


  void bookman::reply_echo(const Book_msg_event& echoreq)
  {
    golem->init(raw_book, sizeof(book_message), BOOKT_ECHO_RESPONSE,
		ntohl(echoreq.msg->header.xid));
    golem->send(raw_book, echoreq.sock->stream);
  }

  void bookman::send_node_list(std::list<booknode> nodeSet,
			       Msg_stream* sock, bool add)
  {
    send_node_list(nodeSet, sock, add, golem->nextxid());
  }

  void bookman::send_node_list(std::list<booknode> nodeSet,
			       Msg_stream* sock, bool add, uint32_t xid)
  {
    golem->init(raw_book, sizeof(book_header)+sizeof(book_node)*nodeSet.size(),
		(add)? BOOKT_NODES_ADD: BOOKT_NODES_DEL, xid);
    book_node* node = (book_node*) ((book_message*) raw_book.get())->body;
    for (std::list<booknode>::iterator i = nodeSet.begin();
	 i != nodeSet.end(); i++)
    {
      i->insert(node);
      node++;
    }

    VLOG_DBG(lg, "Sending list of node of size %zu with message buffer %p over socket %p",
	     nodeSet.size(), raw_book.get(), sock->stream);
    golem->send(raw_book, sock->stream);
  }

  void bookman::send_link_list(std::list<booklinkspec> linkSet,
			       Msg_stream* sock, bool add)
  {
    send_link_list(linkSet, sock,  add, golem->nextxid());
  }

  void bookman::send_link_list(std::list<booklinkspec> linkSet,
			       Msg_stream* sock, bool add, uint32_t xid)
  {
    if (add)
    {
      //Send adding message
      golem->init(raw_book, sizeof(book_header)+sizeof(book_link_rate_spec)*linkSet.size(),
                  (add)? BOOKT_LINKS_ADD: BOOKT_LINKS_DEL, xid);
      book_link_rate_spec* link = (book_link_rate_spec*) ((book_message*) raw_book.get())->body;
      for (std::list<booklinkspec>::iterator i = linkSet.begin();
           i != linkSet.end(); i++)
        {
          i->insert(link);
          link++;
          VLOG_DBG(lg, "Link %s %"PRIx64":%"PRIx16"->%"PRIx64":%"PRIx16" rate:%d type:%d color:%d",
                   (add)? "added":"deleted",
                   i->src_node.id, i->src_port,
                   i->dst_node.id, i->dst_port, (int)i->rate, i->type, i->tunn_color);
        }
    }
    else
      {
        //Send deleting message
      golem->init(raw_book, sizeof(book_header)+sizeof(book_link_spec)*linkSet.size(),
                  (add)? BOOKT_LINKS_ADD: BOOKT_LINKS_DEL, xid);
      book_link_spec* link = (book_link_spec*) ((book_message*) raw_book.get())->body;
      for (std::list<booklinkspec>::iterator i = linkSet.begin();
           i != linkSet.end(); i++)
        {
          VLOG_DBG(lg, "Link %s %"PRIx64":%"PRIx16"->%"PRIx64":%"PRIx16"",
                   (add)? "added":"deleted",
                   i->src_node.id, i->src_port,
                   i->dst_node.id, i->dst_port);

          i->insert(link);
          link++;
        }
      }

    golem->send(raw_book, sock->stream);
  }

  void bookman::send_flow_list(std::list<single_route> routes,
                               Msg_stream* sock, bool add, uint32_t flowid,
                               uint16_t flowtype)
  {
    send_flow_list(routes, sock, add, flowid, flowtype, golem->nextxid());
  }

  void bookman::send_flow_list(std::list<single_route> routes,
			       Msg_stream* sock, bool add, uint32_t flowid,
                               uint16_t flowtype, uint32_t xid)
  {
    VLOG_DBG(lg, "Sending lists of %zu routes",routes.size());

    ssize_t size = sizeof(book_header)+sizeof(book_flow_message);
    for (std::list<single_route>::iterator i = routes.begin();
	 i != routes.end(); i++)
      size += sizeof(book_flow_spec)+
	sizeof(book_flow_hop)*(i->size()-2);
    golem->init(raw_book, size,
		(add)? BOOKT_FLOWS_ADD: BOOKT_FLOWS_DEL, xid);

    //Header of book_flow_message
    book_flow_message* bfm = (book_flow_message*) \
      ((book_message*) raw_book.get())->body;
    bfm->num_flows = htonl(routes.size());

    //Adding each flow
    book_flow_spec* bfs = (book_flow_spec*) bfm->body;
    for (std::list<single_route>::iterator i = routes.begin();
	 i != routes.end(); i++)
    {
      book_flow_hop* k = (book_flow_hop*) bfs->path;
      bfs->num_hops = htons(i->size()-2);
      bfs->flow_id = htonl(flowid);
      bfs->type = htons(flowtype);
      //bfs->type = htons(BOOKF_UNKNOWN);
      VLOG_DBG(lg, "Adding flow id %"PRIx32" with %"PRIx32" hops, type %"PRIx16" ",
               ntohl(bfs->flow_id), ntohs(bfs->num_hops)+2, ntohs(bfs->type));
      //VLOG_DBG(lg, "Adding flow id %"PRIx32" with %"PRIx32" hops",
	  //     ntohl(bfs->flow_id), ntohl(bfs->num_hops));

      //Each hop
      for (single_route::iterator j = i->begin();
	   j != i->end(); j++)
      {
	single_route::iterator next = j;
	next++;
	if (j == i->begin())
	{
	  bfs->src.id.type = htons(BOOKN_OPENFLOW);
	  bfs->src.id.id = j->sw.as_net();
	  bfs->src.port = htons(j->out_port);
	}
	else if (next == i->end())
	{
	  bfs->dst.id.type = htons(BOOKN_OPENFLOW);
	  bfs->dst.id.id = j->sw.as_net();
	  bfs->dst.port = htons(j->in_port);
	}
	else
	{
	  k->src_port = htons(j->in_port);
	  k->node_out.port = htons(j->out_port);
	  k->node_out.id.type = htons(BOOKN_OPENFLOW);
	  k->node_out.id.id = j->sw.as_net();
	  k++;
	}
      }
      bfs =  (book_flow_spec*) k;
    }

    //Send flow list
    golem->send(raw_book, sock->stream);
  }

  void bookman::stat_reply(const Openflow_msg_event& ome, Msg_stream* sock)
  {
    ofp_stats_reply* osr = (ofp_stats_reply*)ome.get_ofp_msg();
    ssize_t size = sizeof(book_message)+sizeof(book_stat_message)+
      ntohs(osr->header.length)-sizeof(ofp_stats_reply);
    golem->init(raw_book, size, BOOKT_STAT, ntohl(osr->header.xid));

    book_message* bookmsg = (book_message*) raw_book.get();
    book_stat_message* bsm = (book_stat_message*)bookmsg->body;
    bsm->datapath_id = ome.datapath_id.as_net();
    bsm->type = osr->type;
    bsm->flags = osr->flags;
    memcpy(bsm->osr_body, osr->body, ntohs(osr->header.length)-sizeof(ofp_stats_reply));

    golem->send(raw_book, sock->stream);
  }





} // namespace vigil

namespace noxsup
{
  REGISTER_COMPONENT(vigil::container::
		     Simple_component_factory<vigil::bookman>,
		     vigil::bookman);
}
