#ifndef circsw_gui_HH
#define circsw_gui_HH 1

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


#define BOOKT_DRAG_REQ 0xAA

namespace vigil
{
  using namespace vigil::container;
  using namespace std;

  /** Packet for flow dragging.
   */
  struct flow_drag_req
  {
    /** Header field
     */
    book_header header;
    /** Flow id.  Note we are hacking, so no flow type.
     */
    uint32_t flow_id;
    /** List of waypoints.  Again, no node type.
     * Number of dpid in the field is deduced for the
     * length field in the header.
     */
    uint64_t waypoint_dpid[0];
  };

  /** \brief Structure for triggering L1 Flow dragging (aka VCG regrooming).
   */
  struct L1_flow_drag_event : public Event
  {
    /** Constructor.
     * Allocate memory for event.
     * @param flowid_ flowid of flow being dragged
     * @param dpids_ way points
     */
    L1_flow_drag_event( uint32_t flowid_, std::vector<uint64_t> dpids_);

    /** Destructor.
     */

    ~L1_flow_drag_event()
    { ; }


    /** Static name required in NOX.
     */
    static const Event_name static_get_name()
    {
      return "L1_flow_drag_event";
    }

    /** Flow id of flow being dragged.
     */
    uint32_t flowid;
    /** Waypoint datapathids.
     */
    std::vector<uint64_t> dpids;
  };

  // convienience struct for storage in flowdb
  typedef struct flow_db_entry {
    uint16_t flowtype;
    std::list<single_routed> routelist;
  } flow_entry;


  /** \brief Messaging component
   *
   * This is the messenger component for the circsw module
   * It co-ordinates the communication with ENVI
   *
   * @author Saurav Das
   * @date July 2010
   * @see lavi
   */
  class Circsw_gui : public container::Component{
  public:
    /** Constructor
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    Circsw_gui(const Context* c, const xercesc::DOMNode* node)
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

    void addAFlow( std::list<single_routed> routes, uint32_t flow_id, \
                   uint16_t flowtype );
    void registerNodes( uint16_t nodetype, uint64_t datapathid );
    void registerLinks( uint16_t linktype, uint64_t dpid1, uint16_t port1,
                        uint64_t dpid2, uint16_t port2, uint16_t linkid );

    void registerLinks( void );
    void removeAllFlows( void );
    void removeAFlow( uint32_t flow_id, bool sendtempflow );
    void showCongestion( void );
    void showNoCongestion( void );

    /** Get instance
     * @param ctxt context
     * @param component reference to aggregationmsg
     */
    static void getInstance(const container::Context* ctxt, Circsw_gui*& component);

  private:
    /** Buffer for packet.*/
    boost::shared_array<uint8_t> msg_raw;

    /** reference to messenger packet.*/
    msgpacket* msgpacker;

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

    std::list<booklinkspec> links;
    std::list<booknode> nodes;

    std::map<uint64_t, booknode*> searchnodes;
    std::map<uint16_t, booklinkspec*> searchlinks;

    booknode* client1; booknode* client2; booknode* client3;
    booknode* server1; booknode* server2; booknode* server3;
    booknode* ciena1;  booknode* ciena2;  booknode* ciena3;

    std::map<uint32_t, flow_entry> flowdb;

    std::list<booknode> tempnode;
    booknode* alarm;
    uint32_t congestion_count;
    bool flash_on;

  };
}


#endif
