#ifndef GOLEMS_HH
#define GOLEMS_HH

/** Server port number for TCP connection in \ref vigil::golems.
 */
#define GOLEMS_PORT 2503
/** Server port number for SSL connection in \ref vigil::golems.
 */
#define GOLEMS_SSL_PORT 1305
/** Enable/Disable TCP connection.
 */
#define ENABLE_TCP_GOLEMS true
/** Enable/Disable SSL connection.
 */
#define ENABLE_SSL_GOLEMS false

#include "messenger/messenger_core.hh"
#include "messenger/msgpacket.hh"

namespace vigil
{
  using namespace vigil::container;

  /** \brief Class through which to interact with lavi.
   *
   * Copyright (C) Stanford University, 2009.
   * @author ykk
   * @date May 2009
   * @see messenger
   */
  class golems : public message_processor
  {
  public:
    /** Constructor.
     * Start server socket.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    golems(const Context* c, const xercesc::DOMNode* node);

    /** Destructor.
     * Close server socket.
     */
    virtual ~golems()
    { };

    /** Configure component
     * Register events..
     * @param config configuration
     */
    void configure(const Configuration* config);

    /** Start component.
     */
    void install();

    /** Function to do processing for messages received.
     * @param msg message event for message received
     */
    void process(const Msg_event* msg);

    /** Send echo request.
     * @param sock socket to send echo request over
     */
    void send_echo(Async_stream* sock);

    /** Return next bookman xid.
     */
    uint32_t nextxid()
    {
      return ++lastxid;
    }

    /** Initialize packet with size and type.
     * Also allocate xid for the message.
     * @param msg_raw message buffer reference
     * @param size size of buffer to allocate
     * @param type type of packet
     */
    void init(boost::shared_array<uint8_t>& msg_raw, ssize_t size, uint8_t type);

    /** Initialize packet with size and type.
     * @param msg_raw message buffer reference
     * @param size size of buffer to allocate
     * @param type type of packet
     * @param xid xid to use
     */
    void init(boost::shared_array<uint8_t>& msg_raw, ssize_t size, uint8_t type, uint32_t xid);

    /** Send packet on given socket.
     * @param msg message buffer reference
     * @param sock Async_stream socket
     */
    void send(boost::shared_array<uint8_t>& msg, Async_stream* sock);

    /** Get instance of bookman (for python)
     * @param ctxt context
     * @param scpa reference to return instance with
     */
    static void getInstance(const container::Context* ctxt,
			    vigil::golems*& scpa);

  private:
    /** Last transaction id given.
     */
    uint32_t lastxid;
    /** Memory allocated for \ref vigil::bookman messages.
     */
    boost::shared_array<uint8_t> raw_book;
    /** Reference to msgpacket
     */
    msgpacket* msger;
    /** Reference to messenger_core.
     */
    messenger_core* msg_core;
    /** TCP port number.
     */
    uint16_t tcpport;
    /** SSL port number.
     */
    uint16_t sslport;
  };
}

#endif
