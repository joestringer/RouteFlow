#ifndef BOOKMAN_HH__
#define BOOKMAN_HH__

#include "component.hh"
#include "bookman-msg-event.hh"
#include "openflow-msg-in.hh"
#include "golems.hh"
#include "ssl-socket.hh"
#include "tcp-socket.hh"
#include <sys/time.h>
#include <boost/bind.hpp>
#include <boost/shared_array.hpp>
#include "flowdb/flowroutecache.hh"

namespace vigil
{
  using namespace vigil::container;

  /** \brief Bookman node class.
   *
   * Stores the id and type in host order.
   *
   * Copyright (C) Stanford University, 2009.
   * @author ykk
   * @date May 2009
   */
  struct booknode:
    book_node
  {
  public:
    /** Constructor.
     * @param type_ book_node_type
     * @param id_ identifier for node
     */
    booknode(uint16_t type_, uint64_t id_);

    /** Constructor for switch of unknown type.
     * @param dpid identifier for switch
     */
    booknode(datapathid dpid);

    /** Constructor for switch of unknown type.
     * @param dpid identifier for switch
     * @param type_ book_node_type
     */
    booknode(datapathid dpid, uint16_t type_);

    /** Fill book_node structure with value in this structure.
     * @param bknode reference to structure.
     */
    void insert(book_node* bknode);
  };

  /** \brief Bookman link class.
   *
   * Stores members in host order.
   *
   * Copyright (C) Stanford University, 2009.
   * @author ykk
   * @date May 2009
   */
  struct booklinkspec
  {
    /** Constructor.
     * @param type_ type of link
     * @param src source node
     * @param srcport source port number
     * @param dst destination node
     * @param dstport destination port number
     */
    booklinkspec(uint16_t type_, booknode src, uint16_t srcport,
		 booknode dst, uint16_t dstport);

    /** Constructor.
     * @param type_ type of link
     * @param src source node
     * @param srcport source port number
     * @param dst destination node
     * @param dstport destination port number
     * @param rate rate of link
     */
    booklinkspec(uint16_t type_, booknode src, uint16_t srcport,
		 booknode dst, uint16_t dstport, uint64_t rate);


    booklinkspec(uint16_t type_, booknode src, uint16_t srcport,
                 booknode dst, uint16_t dstport, uint64_t rate,
                 uint8_t color);


    /** Fill book_link_spec structure with value in this structure.
     * @param bklink reference to structure.
     */
    void insert(book_link_spec* bklink);

    /** Fill book_link_rate_spec structure with value in this structure.
     * @param bklink reference to structure.
     */
    void insert(book_link_rate_spec* bklink);

    /** Link type, member of book_link_type
     */
    uint16_t type;
    /** Source node.
     */
    booknode src_node;
    /** Port number on source.
     */
    uint16_t src_port;
    /** Destination node.
     */
    booknode dst_node;
    /** Port number on destination.
     */
    uint16_t dst_port;
    /** Rate in Mbps.
     */
    uint64_t rate;
    /** Tunnel Color - only used for tunnel linktypes.
     */
    uint8_t tunn_color;

  };

  /** \brief Class through which to interact with lavi.
   *
   * Copyright (C) Stanford University, 2008.
   * @author ykk
   * @date December 2008
   * @see golems
   */
  class bookman : public Component
  {
  public:
    /** Constructor.
     * Start server socket.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    bookman(const Context* c, const xercesc::DOMNode* node): Component(c)
    { };

    /** Destructor.
     * Close server socket.
     */
    virtual ~bookman()
    { };

    /** Configure component.
     * Register events.
     * @param config configuration
     */
    void configure(const Configuration* config);

    /** Start component.
     */
    void install();

    /** Get instance of bookman (for python)
     * @param ctxt context
     * @param scpa reference to return instance with
     */
    static void getInstance(const container::Context* ctxt,
			    vigil::bookman*& scpa);

    /** Reply to echo request.
     * @param echoreq echo request
     */
    void reply_echo(const Book_msg_event& echoreq);

    /** Function to handle \ref vigil::Book_msg_event.
     * @param e event to handle
     * @return CONTINUE if unknown message type, else STOP
     */
    Disposition handle_book_msg(const Event& e);

    /** Send list of nodes to connection.
     * @param nodeSet list of nodes to send in message
     * @param sock socket to send over
     * @param add add message or delete
     * @param xid xid of message
     */
    void send_node_list(std::list<booknode> nodeSet,
			Msg_stream* sock, bool add, uint32_t xid);
    /** Send list of nodes to connection.
     * Allocate new xid
     * @param nodeSet list of nodes to send in message
     * @param sock socket to send over
     * @param add add message or delete
     */
    void send_node_list(std::list<booknode> nodeSet,
			Msg_stream* sock, bool add);

    /** Send list of links to connection.
     * @param linkSet list of links to send in message
     * @param sock socket to send over
     * @param add add message or delete
     * @param xid xid of message
     */
    void send_link_list(std::list<booklinkspec> linkSet,
			Msg_stream* sock, bool add, uint32_t xid);
    /** Send list of links to connection.
     * Allocate new xid.
     * @param linkSet list of links to send in message
     * @param sock socket to send over
     * @param add add message or delete
     */
    void send_link_list(std::list<booklinkspec> linkSet,
			Msg_stream* sock, bool add);

    /** Send flow list.
     */
    void send_flow_list(std::list<single_route> routes,
			Msg_stream* sock, bool add, uint32_t flowid);

    /** Send flow list.
     */
    void send_flow_list(std::list<single_route> routes,
			Msg_stream* sock, bool add, uint32_t flowid, uint32_t xid);

    void send_flow_list(std::list<single_route> routes,
                        Msg_stream* sock, bool add, uint32_t flowid,
                        uint16_t flowtype);

    void send_flow_list(std::list<single_route> routes,
                        Msg_stream* sock, bool add, uint32_t flowid,
                        uint16_t flowtype, uint32_t xid);




    /** Send reply for statistic request.
     * @param ome OpenFlow stat reply
     * @param sock socket to send message to
     */
    void stat_reply(const Openflow_msg_event& ome, Msg_stream* sock);

  private:
    /** Memory allocated for \ref vigil::bookman messages.
     */
    boost::shared_array<uint8_t> raw_book;
    /** Reference to golems server.
     */
    golems* golem;
  };

} // namespace vigil

#endif
