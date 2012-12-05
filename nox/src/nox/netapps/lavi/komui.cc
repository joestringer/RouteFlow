#include "komui.hh"

namespace vigil
{
  using namespace vigil::container;
  using namespace std;

  static Vlog_module lg("komui");

  komui::Poll_msg::Poll_msg(time_t next_post_sec_, long next_post_usec_ , uint16_t postInterval_,
			    book_message* bm, Msg_stream* sock):
    next_post_sec(next_post_sec_), next_post_usec(next_post_usec_)
  {
    postInterval = postInterval_;
    bme.sock = new Msg_stream(*sock);
    bme.set_message(bm);
  }

  void komui::configure(const Configuration* config)
  {
    pollTimerCount = 0;
  }

  void komui::handle_poll(const Book_msg_event& bm)
  {
    book_poll_message* pm = (book_poll_message*) bm.msg->body;
    book_message* inner_bm = (book_message*) pm->body;
    inner_bm->header.length = htons(ntohs(bm.msg->header.length)-
				    sizeof(book_header)-sizeof(book_poll_message));

    //Can't poll a poll -- thanks to David
    if ((inner_bm->header.type == BOOKT_POLL) ||
	(ntohs(pm->pollInterval) == 0))
      return;

    timeval tim;
    gettimeofday(&tim, NULL);
    VLOG_DBG(lg, "Adding poll of type %"PRIx8" of length %"PRIx16
	     " for polling at interval %"PRIx16"",
	     inner_bm->header.type, inner_bm->header.length,
	     ntohs(pm->pollInterval));
    addPollMsg(time(NULL), tim.tv_usec, ntohs(pm->pollInterval),
	       inner_bm, bm.sock);
    tim.tv_sec=tim.tv_usec=0;
    pollTimerCount++;
    post(boost::bind(&komui::handle_poll_timer, this), tim);
  }

  void komui::handle_poll_timer()
  {
    if (pollMsgs.size() == 0)
    {
      pollTimerCount--;
      return;
    }

    std::list<Poll_msg>::iterator i = pollMsgs.begin();
    timeval tim;
    gettimeofday(&tim, NULL);
    time_t timeNow = time(NULL);

    while (findTimeDiff(i->next_post_sec,i->next_post_usec,
			timeNow, tim.tv_usec) <= 0)
    {
      post(new Book_msg_event(i->bme.msg, i->bme.sock->stream, i->bme.sock->isSSL));
      VLOG_DBG(lg,"Posted event of type %"PRIx8" of length %"PRIx16
	       " for polling at interval %"PRIx16"",
	       i->bme.msg->header.type, ntohs(i->bme.msg->header.length),
	       i->postInterval);

      long nextPostUSec = tim.tv_usec+(i->postInterval)%10*100000;
      time_t nextPostSec = timeNow+time_t(double(i->postInterval)/10.0)+
	((nextPostUSec>=1000000)?1:0);
      if (nextPostUSec > 1000000)
	nextPostUSec-=1000000;

      addPollMsg(nextPostSec, nextPostUSec, i->postInterval,
		 i->bme.msg, i->bme.sock);
      pollMsgs.pop_front();
      i = pollMsgs.begin();
    }

    //Post timer
    pollTimerCount--;
    if ((pollTimerCount == 0) && (pollMsgs.size() != 0))
    {
      gettimeofday(&tim,NULL);
      timeNow = time(NULL);
      timeval nextTime;

      i=pollMsgs.begin();
      if ((i->next_post_usec - tim.tv_usec) >= 0)
      {
	nextTime.tv_usec = i->next_post_usec-tim.tv_usec;
	nextTime.tv_sec = i->next_post_sec-timeNow;
      }
      else
      {
	nextTime.tv_usec = (1000000-tim.tv_usec+i->next_post_usec);
	nextTime.tv_sec = i->next_post_sec-timeNow-1;
      }
      pollTimerCount++;
      post(boost::bind(&komui::handle_poll_timer, this), nextTime);
    }
  }

  void komui::addPollMsg(time_t nextPostSec, long nextPostUSec,
			uint16_t postInterval, book_message* bm,
			Msg_stream* sock)
  {
    std::list<Poll_msg>::iterator i = pollMsgs.begin();
    while((i != pollMsgs.end()) &&
	  (findTimeDiff(i->next_post_sec, i->next_post_usec,
			nextPostSec, nextPostUSec) <= 0))
      i++;

    i = pollMsgs.insert(i, *(new Poll_msg(nextPostSec, nextPostUSec, postInterval, bm,
				    sock)));
  }

  void komui::handle_poll_stop(const Book_msg_event& bm)
  {
    book_poll_stop_message* psm = (book_poll_stop_message*) bm.msg->body;
    removePollMsg(psm->xid);
  }

  void komui::removePollMsg(uint32_t xid)
  {
    std::list<Poll_msg>::iterator i = pollMsgs.begin();
    while(i != pollMsgs.end())
    {
      if (i->bme.msg->header.xid == xid)
      {
	VLOG_DBG(lg, "Removing poll with xid %"PRIx32"", ntohl(xid));
	i = pollMsgs.erase(i);
      }
      else
	i++;
    }
  }

  void komui::clearConnection(const Book_msg_event& bm)
  {
    VLOG_DBG(lg, "Clearing connections");

    //Remove polling requests
    std::list<Poll_msg>::iterator j  = pollMsgs.begin();
    while( j != pollMsgs.end())
      if (&(*(j->bme.sock->stream)) == &(*bm.sock->stream))
      {
	j = pollMsgs.erase(j);
	VLOG_DBG(lg, "Removed poll due to connection close");
      }
      else
	j++;
  }

  void komui::getInstance(const container::Context* ctxt,
			  komui*& component)
  {
    component = dynamic_cast<komui*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid(komui).name())));
  }
}


REGISTER_COMPONENT(vigil::container::Simple_component_factory
		   <vigil::komui>,
		   vigil::komui);
