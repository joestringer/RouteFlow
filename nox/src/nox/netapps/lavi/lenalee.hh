#ifndef lenalee_HH
#define lenalee_HH 1

#include "component.hh"
#include "config.h"
#include <xercesc/dom/DOM.hpp>
#include "flowdb/flowroutecache.hh"
#include <map>
#include "bookman.hh"
#include "bookman-message.hh"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

namespace vigil
{
  using namespace vigil::container;

  /** \brief Component to deliver flow and routes to GUI.
   *
   * Copyright (C) Stanford University, 2009.
   * @author ykk
   * @date May 2009
   */
  class lenalee
    : public container::Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    lenalee(const Context* c, const xercesc::DOMNode* node)
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
     * @param component reference to lenalee
     */
    static void getInstance(const container::Context*, lenalee*& component);

    /** Handles route installation.
     * @param e host route event
     */
    Disposition handle_host_route_event(const Event& e);

    /** Function to provide subscribe to changes in flow.
     * @param bm message event requesting for link list of node.
     */
    void handle_flow_req(const Book_msg_event& bm);

  private:
    /** Reference to bookman.
     */
    bookman* book;
    /** List to store route.
     */
    //std::list<booknode> booknodelist;
    /** List to store node interest.
     */
    std::multimap<uint16_t, Msg_stream*> flowSub;
    /** Subscribe to flow update
     * @param bm request message
     */
    void flow_subscribe(const Book_msg_event& bm);
    /** Unsubscribe from flow update
     * @param bm request message
     */
    void flow_unsubscribe(const Book_msg_event& bm);


  };
}
#endif
