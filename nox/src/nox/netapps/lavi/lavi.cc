#include "lavi.hh"
#include <xercesc/dom/DOM.hpp>
#include "vlog.hh"
#include "assert.hh"
#include <boost/bind.hpp>

namespace vigil
{
  using namespace vigil::container;
  using namespace std;

  static Vlog_module lg("lavi");
  
  void lavi::configure(const Configuration*)
  {
    resolve(book);
    resolve(topo);
    resolve(poll);
    resolve(flowinfo);
    resolve(ofproxy);

    register_handler<Book_msg_event>
      (boost::bind(&lavi::handle_book_msg, this, _1));
  }
  
  void lavi::install()
  { }

  void lavi::getInstance(const container::Context* ctxt, vigil::lavi*& scpa)
  {
    scpa = dynamic_cast<lavi*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(lavi).name())));
  }

  inline void lavi::check_len(const Book_msg_event& bm, ssize_t size)
  {
    if (ntohs(bm.msg->header.length) != size)
      VLOG_WARN(lg, "Message expected to be of size %u has size %zu",
	       size, ntohs(bm.msg->header.length));
  }

  inline void lavi::wrong_msg(book_message* msg)
  {
    VLOG_WARN(lg, "Received packet of length %"PRIx16" of type %"PRIx8
	      " that is for reply!",
	      ntohs(msg->header.length), msg->header.type);
  }

  Disposition lavi::handle_book_msg(const Event& e)
  {
    const Book_msg_event& bm = assert_cast<const Book_msg_event&>(e);
    VLOG_DBG(lg,"Received message of type %"PRIx16"",
	     bm.msg->header.type);

    switch(bm.msg->header.type)
    {
    case BOOKT_DISCONNECT:
      VLOG_DBG(lg, "Clearing state of disconnected socket");
      topo->clearConnection(bm);
      poll->clearConnection(bm);
      ofproxy->clearConnection(bm);
      return CONTINUE;
      break;

    case BOOKT_POLL:
      poll->handle_poll(bm);
      break;
    case BOOKT_POLL_STOP:
      poll->handle_poll_stop(bm);
      break;

    //Marie related messages
    case BOOKT_NODES_REQ:
      check_len(bm,sizeof(book_message)+sizeof(book_node_req_message));
      topo->handle_nodes_req(bm);
      break;
    case BOOKT_NODES_ADD:
    case BOOKT_NODES_DEL:
      wrong_msg(bm.msg);
      break;

    case BOOKT_LINKS_REQ:
      check_len(bm,sizeof(book_message)+sizeof(book_link_req_message));
      topo->handle_links_req(bm);
      break;
    case BOOKT_LINKS_ADD:
    case BOOKT_LINKS_DEL:
      wrong_msg(bm.msg);
      break;

    //Timcanpy related messages
    case BOOKT_STAT_REQ:
      ofproxy->handle_stat_req(bm);
      break;
    case BOOKT_STAT:
      wrong_msg(bm.msg);
      break;

    //Lenalee related messages
    case BOOKT_FLOWS_REQ:
      flowinfo->handle_flow_req(bm);
      break;

    default:
      if (LAVI_WARN_UNKNOWN_MSG)
      {
	  VLOG_DBG(lg, "Received packet of length %"PRIx16" of unknown type %"PRIx8"",
		   ntohs(bm.msg->header.length), bm.msg->header.type);
      }
      return CONTINUE;
    }

	/* this is supposed to indicate ENVI connection, since these are the first messages to be sent */
	/* return CONTINUE so that modules can initialize their socket references early enough.. */
	if((bm.msg->header.type == BOOKT_NODES_REQ) || (bm.msg->header.type ==  BOOKT_LINKS_REQ)
	   || (bm.msg->header.type == BOOKT_FLOWS_REQ)){
	  return CONTINUE;
	}

    return STOP;
  }

} // namespace vigil

namespace {
  REGISTER_COMPONENT(vigil::container::Simple_component_factory<vigil::lavi>,
		     vigil::lavi);
} // unnamed namespace
