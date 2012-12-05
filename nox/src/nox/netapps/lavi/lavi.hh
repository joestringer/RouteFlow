#ifndef LAVI_HH__
#define LAVI_HH__

#include <sys/time.h>
#include "component.hh"
#include "hash_map.hh"
#include "tcp-socket.hh"
#include "bookman.hh"
#include "marie.hh"
#include "komui.hh"
#include "lenalee.hh"
#include "timcanpy.hh"
#include "netinet++/datapathid.hh"
#include "topology/topology.hh"


/** Indicate if unknown messages is indicated via WARN.
 */
#define LAVI_WARN_UNKNOWN_MSG false

namespace vigil {
using namespace vigil::applications;
using namespace vigil::container;
  /** \brief Class for network monitor information.
   *
   * This network monitor is designed with work with simultaneous
   * NOX controllers within a network.  This prevents the hijacking
   * of messages from the controllers to determine network status,
   * leaving controlled query as the means of monitoring.
   *
   * TCP and SSL port can be changed at commandline using
   * tcpport and sslport arguments for golems respectively.
   * port 0 is interpreted as disabling the server socket.
   * E.g.,
   * ./nox_core -i ptcp:6633 lavi golems=tcport=11222,sslport=0
   * will run TCP server on port 11222 and SSL server will be disabled.
   *
   * Copyright (C) Stanford University, 2008.
   * @author ykk
   * @date November 2008
   * @see bookman
   * @see marie
   * @see komui
   * @see lenalee
   * @see timcanpy
   */
  class lavi
    : public Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    lavi(const Context* c,const xercesc::DOMNode* node)
      : Component(c)
    {}
    
    /** Destructor.
     */
    virtual ~lavi()
    { ; }

    /** Configure component
     * @param config configuration
     */
    void configure(const Configuration* config);

    /** Start component.
     */
    void install();

    /** Get instance (for python)
     * @param ctxt context
     * @param scpa reference to return instance with
    */
    static void getInstance(const container::Context* ctxt, vigil::lavi*& scpa);

    /** Function to handle \ref vigil::Book_msg_event.
     * @param e event to handle
     * @return CONTINUE if unknown message type, else STOP
     */
    Disposition handle_book_msg(const Event& e);

  private:
    /** Function to warn about errorneous messages.
     * @param msg message to warn of
     */
    inline void wrong_msg(book_message* msg);
    /** Check length of message.
     * @param bm message event
     * @param size expected size
     */
    inline void check_len(const Book_msg_event& bm, ssize_t size);
    /** Reference to bookman for messaging.
     */
    bookman* book;
    /** Reference to marie for topology monitoring.
     */
    marie* topo;
    /** Reference to komui for polling management.
     */
    komui* poll;
    /** Reference to lenalee for flows.
     */
    lenalee* flowinfo;
    /** Reference to timcanpy as OpenFlow proxy
     */
    timcanpy* ofproxy;
  };
} // namespace vigil

#endif
