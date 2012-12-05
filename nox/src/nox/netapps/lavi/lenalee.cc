#include "lenalee.hh"
#include "vlog.hh"
#include "assert.hh"
#include <boost/bind.hpp>
#include <boost/shared_array.hpp>

namespace vigil
{
  static Vlog_module lg("lenalee");

  void lenalee::configure(const Configuration* config)
  {
    resolve(book);

    register_handler<Host_route_event>
      (boost::bind(&lenalee::handle_host_route_event, this, _1));
  }

  void lenalee::getInstance(const container::Context* ctxt,
				   lenalee*& component)
  {
    component = dynamic_cast<lenalee*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(lenalee).name())));
  }

  Disposition lenalee::handle_host_route_event(const Event& e)
  {
	return CONTINUE;
    const Host_route_event& hr = assert_cast<const Host_route_event&>(e);
    VLOG_DBG(lg,"Received host route notification (%s) id=%"PRIx32" with %zu destinations.",
	     (hr.add)?"new flow":"expired flow",
	     hr.flowid, hr.installed_route.size());

    std::multimap<uint16_t, Msg_stream*>::iterator i;
    std::pair<std::multimap<uint16_t, Msg_stream*>::iterator,
      std::multimap<uint16_t, Msg_stream*>::iterator> ret;
    ret = flowSub.equal_range(BOOKF_UNKNOWN);
    for (i=ret.first; i!=ret.second; ++i)
      book->send_flow_list(hr.installed_route, i->second, hr.add, hr.flowid);
    return CONTINUE;
  }

  void lenalee::handle_flow_req(const Book_msg_event& bm)
  {
    book_flow_req_message* bfr = (book_flow_req_message*) bm.msg->body;
    switch(bfr->type)
    {
    case BOOKR_ONETIME:
      VLOG_DBG(lg, "One time request does not work for flows");
      break;
    case BOOKR_SUBSCRIBE:
      flow_subscribe(bm);
      break;
    case BOOKR_UNSUBSCRIBE:
      flow_unsubscribe(bm);
      break;
    }
  }

  void lenalee::flow_subscribe(const Book_msg_event& bm)
  {
    book_flow_req_message* value = (book_flow_req_message*) bm.msg->body;
    std::multimap<uint16_t, Msg_stream*>::iterator i;
    std::pair<std::multimap<uint16_t, Msg_stream*>::iterator,
      std::multimap<uint16_t, Msg_stream*>::iterator> ret;
    ret = flowSub.equal_range(ntohs(value->flowType));
    for (i=ret.first; i!=ret.second; ++i)
      if (i->second == bm.sock)
	return;
    flowSub.insert(std::make_pair(ntohs(value->flowType), new Msg_stream(*bm.sock)));
    VLOG_DBG(lg, "Subscribe to node of type %"PRIx16"",ntohs(value->flowType));
  }

  void lenalee::flow_unsubscribe(const Book_msg_event& bm)
  {
    book_flow_req_message* value = (book_flow_req_message*) bm.msg->body;
    std::multimap<uint16_t, Msg_stream*>::iterator i;
    std::pair<std::multimap<uint16_t, Msg_stream*>::iterator,
      std::multimap<uint16_t, Msg_stream*>::iterator> ret;

    if (ntohs(value->flowType) == BOOKF_UNKNOWN)
    {
      //Iterate over all
      i = flowSub.begin();
      while (i != flowSub.end())
      {
	if (i->second == bm.sock)
	{
	  flowSub.erase(i);
	  i = flowSub.begin();
	}
	else
	  i++;
      }
    }
    else
    {
      //Loop on flow type
      ret = flowSub.equal_range(ntohs(value->flowType));
      for (i=ret.first; i!=ret.second; ++i)
	if (i->second == bm.sock)
	  flowSub.erase(i);
    }
  }

}


REGISTER_COMPONENT(vigil::container::Simple_component_factory
		   <vigil::lenalee>,
		   vigil::lenalee);
