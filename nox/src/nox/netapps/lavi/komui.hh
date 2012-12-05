#ifndef komui_HH
#define komui_HH 1

#include "component.hh"
#include "bookman-msg-event.hh"
#include "config.h"
#include <xercesc/dom/DOM.hpp>

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

namespace vigil
{
  using namespace vigil::container;

  /** \brief Class to manage polling in lavi.
   *
   * Copyright Stanford University, 20009
   * @author ykk
   * @date May 2009
   */
  class komui
    : public container::Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    komui(const Context* c, const xercesc::DOMNode* node)
        : Component(c)
    {}

    /** Configure component
     * Register events.
     * @param config configuration
     */
    void configure(const Configuration* config);

    /** Start component.
     */
    void install()
    {}

    /** Get instance.
     * @param ctxt context
     * @param component reference to komui
     */
    static void getInstance(const container::Context*, komui*& component);

    void handle_poll(const Book_msg_event& bm);
    /** Function to check polling.
     */
    void handle_poll_timer();
    /** Function to remove message from periodic posting.
     * @param bm message event removing from periodic posting.
     */
    void handle_poll_stop(const Book_msg_event& bm);
    /** Function to delete poll without connection
     * @param bm message event from disconnection
     */
    void clearConnection(const Book_msg_event& bm);

  private:
    /** Add poll message to queue.
     * @param nextPostSec time of next post in seconds
     * @param nextPostUSec time of next post in microseconds
     * @param postInterval interval to post message in 100 milliseconds
     * @param bm message to post
     */
    void addPollMsg(time_t nextPostSec, long nextPostUSec, uint16_t postInterval,
		    book_message* bm, Msg_stream* sock);
    /** Remove poll message from queue.
     * @param xid transaction id in network order
     */
    void removePollMsg(uint32_t xid);
    /** Function to find difference between time.
     * @param time1_sec time1 up to second accuracy
     * @param time1_usec time1 sub-second accuracy
     * @param time2_sec time2 up to second accuracy
     * @param time2_usec time2 sub-second accuracy
     * @return time1-time2 in seconds
     */
    inline double findTimeDiff(time_t time1_sec, long time1_usec,
			time_t time2_sec, long time2_usec)
    {
      return (time1_sec-time2_sec)+((time1_usec-time2_usec)/1000000.0);
    }
    /** Function express time in milliseconds.
     * @param time time value
     * @return value in millisecond
     */
    inline double time_in_ms(timeval time)
    {
      return (time.tv_sec*1000.0)+(time.tv_usec/1000.0);
    };

    /** Messages to periodically post.
     */
    struct Poll_msg
    {
      /** Constructor.
       */
      Poll_msg(time_t next_post_sec_, long next_post_usec_ , uint16_t postInterval_,
	       book_message* bm, Msg_stream* sock);

      /** Time of last post in seconds.
       */
      time_t next_post_sec;
      /** Time of last post in microseconds.
       */
      long next_post_usec;
      /** Interval to post message.
       */
      uint16_t postInterval;
      /** Message to post.
       */
      Book_msg_event bme;
    };
    /** List of message to be polled periodically.
     */
    std::list<Poll_msg> pollMsgs;
    /** Counter for number of poll timers.
     */
    int pollTimerCount;
  };
}
#endif
