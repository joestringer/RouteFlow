#ifndef marie_HH
#define marie_HH 1

#include "component.hh"
#include "config.h"
#include <xercesc/dom/DOM.hpp>
#include <map>
#include "bookman-msg-event.hh"
#include "bookman.hh"
#include "topology/topology.hh"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

namespace vigil
{
  using namespace vigil::container;
  using namespace vigil::applications;

  /** \brief Component that tracks topology changes
   * for lavi.
   *
   * Copyright (C) Stanford University, 2009.
   * @author ykk
   * @date May 2009
   */
  class marie
    : public container::Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    marie(const Context* c, const xercesc::DOMNode* node);

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
     * @param component reference to marie
     */
    static void getInstance(const container::Context*, marie*& component);

    /** Function to provide node list or subscribe to changes.
     * @param bm message event requesting for node list.
     */
    void handle_nodes_req(const Book_msg_event& bm);
    /** Function to track switch add.
     * @param e switch join event
     * @return CONTINUE always
     */
    Disposition handle_switch_add(const Event& e);
    /** Function to track switch deletion.
     * @param e switch leave event
     * @return CONTINUE always
     */
    Disposition handle_switch_del(const Event& e);

    /** Function to provide link list or subscribe to changes.
     * @param bm message event requesting for link list of node.
     */
    void handle_links_req(const Book_msg_event& bm);
    /** Function to link events.
     * @param e link event
     * @return CONTINUE always
     */
    Disposition handle_link_event(const Event& e);

    /** Function to delete subscription.
     * @param bm message event from disconnection
     */
    void clearConnection(const Book_msg_event& bm);

    uint8_t get_tunnel_color(uint16_t tid);

  private:
    /** Reference to bookman.
     */
    bookman* book;
    /** Reference to topology.
     */
    Topology* topology;

    /** List to store nodes.
     */
    std::list<booknode> booknodelist;
    /** List to store node interest.
     */
    std::multimap<uint16_t, Msg_stream*> nodeSub;
    /** Request list of nodes
     * @param bm request message
     */
    void node_req(const Book_msg_event& bm);
    /** Subscribe to node update
     * @param bm request message
     */
    void node_subscribe(const Book_msg_event& bm);
    /** Unsubscribe from node update
     * @param bm request message
     */
    void node_unsubscribe(const Book_msg_event& bm);

    /** List to store links.
     */
    std::list<booklinkspec> booklinklist;
    /** List to store link interest.
     */
    std::multimap<uint16_t, Msg_stream*> linkSub;
    /** Function to handle one time link request.
     */
    void link_request(const Book_msg_event& bm);
    /** Subscribe to link update
     * @param bm request message
     */
    void link_subscribe(const Book_msg_event& bm);
    /** Unsubscribe from link update
     * @param bm request message
     */
    void link_unsubscribe(const Book_msg_event& bm);

    /** Return type of node.
     * @param dpid datapath id in host order
     * @return type of node
     */
    uint16_t node_type(uint64_t dpid);

    /** Return type of link.
     * @param dpid1 datapath id of one switch in host order
     * @param dpid2 datapath id of other switch in host order
     * @return type of node
     */
    uint16_t link_type(uint64_t dpid1, uint64_t dpid2);

    /** Return type of link - SW2SW or Tunnel.
     * @param port1
     * @param port2
     * @return type of link
     */
    uint16_t link_type2(uint16_t port1, uint16_t port2);


    /** Return capacity of link.
     * @param dpid1 datapath id of one switch in host order
     * @param dpid2 datapath id of other switch in host order
     * @return capacity of link
     */
    uint64_t link_capacity(uint64_t dpid1, uint64_t dpid2);


    /** For TE-tunnels only.
     */
    uint8_t tunncolor;
    std::map<uint16_t, uint8_t> tunnelcolormap;
    uint8_t get_tunnel_color(uint16_t srcport, uint16_t dstport);
    uint16_t mpls_tunnelid_start;

  };
}
#endif
