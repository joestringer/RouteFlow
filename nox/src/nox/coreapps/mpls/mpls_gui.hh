#ifndef mpls_gui_HH
#define mpls_gui_HH 1

#include "async_io.hh"
#include "component.hh"
#include "config.h"
#include <xercesc/dom/DOM.hpp>
#include "messenger/msgpacket.hh"
#include "lavi/bookman-msg-event.hh"
#include <boost/shared_array.hpp>
#include "lavi/golems.hh"
#include "lavi/bookman.hh"
#include "lavi/bookman-message.hh"
#include <boost/shared_ptr.hpp>
#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif
#include "flowdb/flowroutecache.hh"

#define BOOKT_DRAG_REQ 0xAA

namespace vigil
{
  using namespace vigil::container;
  using namespace std;

  /////////////////////////////////////////////////
  /////////   Internal MPLS-GUI storage   /////////
  /////////////////////////////////////////////////

  // convienience struct for storage in tunneldb
  // NOTE: everything is stored in network byte order
  typedef struct tunnel_db_entry {
    uint16_t tid;
    uint8_t color;
    uint8_t priority;
    uint32_t current_resbw;
    uint32_t usage;
    uint16_t autobw;
    uint8_t trtype;
    std::list<uint64_t> hoplist;
  } tunnel_entry;

  // convienience struct for storage in flowdb
  typedef struct flow_db_entry {
    uint16_t flowtype;
    std::list<single_route> routelist;
  } flow_entry;


  /////////////////////////////////////////////////
  //    Messages for communication with GUI    ////
  /////////////////////////////////////////////////

  struct mpls_tunnel_hop {
    uint64_t hopdpid;
  } __attribute__ ((packed));

  struct mpls_tunnel_reply_message {
    uint8_t del;
    uint16_t tid;
    uint8_t color;
    uint8_t priority;
    uint32_t resbw;
    uint32_t usage;
    uint16_t autobw;
    uint8_t trtype;
    uint16_t num_hops;
    mpls_tunnel_hop path[0];
  } __attribute__ ((packed));


  struct mpls_tunnel_stats_message {
    uint16_t tid;
    uint32_t curr_resbw;
    uint32_t usage;
    int32_t change;
    uint16_t num_hops;
    mpls_tunnel_hop path[0];
  } __attribute__ ((packed));


  /////////////////////////////////////////////////
  //             Main GUI Class                ////
  /////////////////////////////////////////////////


  /** \brief Messaging component
   *
   * This is the messenger component for the mpls module
   * It co-ordinates the communication with ENVI
   *
   * @author Saurav Das
   * @date November 2010
   * @see lavi
   */
  class Mpls_gui : public container::Component {
  public:
    /** Constructor
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    Mpls_gui(const Context* c, const xercesc::DOMNode* node)
      : Component(c)
    {}

    /** Configure component - register events.
     *@param config configuration
     */
    void configure(const Configuration* config);

    /** start component
     */
    void install()
    {}

    /** Process an aggregation-related message.
     * @param e event to be handled
     */
    Disposition handle_message(const Event& e);



    void addFlow( uint32_t flow_id, const Routing_module::Route& route,
                  uint16_t inport, uint16_t outport, uint16_t flowtype );

    /*
    void removeAllFlows( void );
    */

    void delFlow( uint32_t flow_id );

    void addTunnel( uint16_t tid, uint8_t color, uint8_t prio,
                    uint32_t resbw, bool autobw, uint8_t trtype,
                    std::list<uint64_t>& dplist );

    void removeTunnel( uint16_t tid );


    void sendTunnelStats( uint16_t tid, uint32_t bw, uint32_t usage, int32_t change);

    /** Get instance
     * @param ctxt context
     * @param component reference to aggregationmsg
     */
    static void getInstance(const container::Context* ctxt, Mpls_gui*& component);

  private:
    /** Buffer for packet.*/
    //boost::shared_array<uint8_t> msg_raw;

    /** reference to messenger packet.*/
    //msgpacket* msgpacker;

	/** reference to golems server */
	golems* golem;

	/** reference to bookman */
	bookman* book;

	/** clients subscribed to gui updates */
	std::list<Msg_stream*> guiClients;

	/* handle messages related to flow subscription */
    void handle_flow_subscribe(const Book_msg_event& bm);

    /** Subscribe to flow update
     * @param bm request message
     */
    void flow_subscribe(const Book_msg_event& bm);
    /** Unsubscribe from flow update
     * @param bm request message
     */
    void flow_unsubscribe(const Book_msg_event& bm);


    // These databases store GUI specific information
    // for flows and tunnels
    std::map<uint32_t, flow_entry> flowdb;
    std::map<uint16_t, tunnel_entry> tunneldb;

    boost::shared_array<uint8_t> rawmsg;

    void send_tunnel( uint16_t tid, Msg_stream* sock, uint8_t del = 0 );

    void sendAllTunnels( void );
    void sendAllFlows( void );
  };
}


#endif
