#ifndef OPENFLOWPACKET_HH
#define OPENFLOWPACKET_HH 1

#include "component.hh"
#include "config.h"
#include "netinet++/ethernetaddr.hh"
#include "flow.hh"
#include <xercesc/dom/DOM.hpp>
#include <boost/shared_array.hpp>
#include "openflow/openflow.h"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

/** Default idle timeout for flows.
 */
#define FLOW_TIMEOUT 5

namespace vigil
{
  using namespace vigil::container;

  /** \brief Structure to hold OpenFlow action.
   *
   * Copyright (C) Stanford University, 2009.
   * @author ykk
   * @date February 2009
   */
  struct ofp_action
  {
    /** Header of action
     */
    ofp_action_header* header;

      /** Pointer to memory for OpenFlow messages.
       */
    boost::shared_array<uint8_t> action_raw;

    /** Initialize action.
     */
    ofp_action()
    {}

    /** Set output action, i.e., ofp_action_output.
     * @param port port number of send to
     * @param max_len maximum length to send to controller
     */
    void set_action_output(uint16_t port, uint16_t max_len);

    /** Set source/destination mac address.
     * @param type OFPAT_SET_DL_SRC or OFPAT_SET_DL_DST
     * @param mac mac address to set to
     */
    void set_action_dl_addr(uint16_t type, ethernetaddr mac);

    /** Set source/destination IP address.
     * @param type OFPAT_SET_NW_SRC or OFPAT_SET_NW_DST
     * @param ip ip address to set to
     */
    void set_action_nw_addr(uint16_t type, uint32_t ip);
  };

  /** \brief List of actions for switches.
   *
   * Copyright (C) Stanford University, 2009.
   * @author ykk
   * @date February 2009
   */
  struct ofp_action_list
  {
    /** List of actions.
     */
    std::list<ofp_action> action_list;

    /** Give total length of action list, i.e.,
     * memory needed.
     * @return memory length needed for list
     */
    uint16_t mem_size();

    /** Destructor.
     * Clear list of actions.
     */
    ~ofp_action_list()
    {
      action_list.clear();
    }
  };

  /** \brief Class through which to pack and
   * send command to OpenFlow switches.
   *
   * To use this, the component sending OpenFlow packet
   * must have a boost::shared_array<uint8_t> to hold the
   * content of the packet.  The functions here merely aid
   * in writing to that buffer and sending it.
   *
   * Copyright (C) Stanford University, 2009.
   * @author ykk
   * @date February 2009
   */
  class openflowpacket
    : public container::Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    openflowpacket(const Context* c, const xercesc::DOMNode* node)
        : Component(c)
    {}

    /** Configure component
     * Register events.
     * @param config configuration
     */
    void configure(const Configuration* config)
    {
      lastXid = 0;
    }

    /** Start component.
     */
    void install()
    {}


    /** Get instance.
     * @param ctxt context
     * @param ofp reference to openflowpacket
     */
    static void getInstance(const container::Context*, openflowpacket*& ofp);

    /** Get next xid.
     * Increment xid by one at each call.
     * @return next xid
     */
    uint32_t next_xid()
    {
      return ++lastXid;
    }

    /** Initialize message with size.
     * Also initialize header with version.
     * @param of_raw buffer/memory for message
     * @param size size of message
     * @param type type of OpenFlow message
     */
    void init(boost::shared_array<uint8_t>& of_raw, ssize_t size, uint8_t type);

    /** Initialize message with size and xid.
     * Also initialize header with version.
     * @param of_raw buffer/memory for message
     * @param size size of message
     * @param type type of OpenFlow message
     * @param xid transaction id
     */
    void init(boost::shared_array<uint8_t>& of_raw, ssize_t size, uint8_t type, uint32_t xid);

    /** Send openflow packet.
     * @param of_raw buffer/memory for message
     * @param dpid datapathid of switch to send packet to
     * @param block indicate if blocking call or not
     * @return result of command call
     */
    int send_command(boost::shared_array<uint8_t>& of_raw,
		     const datapathid& dpid, bool block);

    /** Initialize message as flow_mod.
     * @param of_raw buffer/memory for message
     * Also initialize header with version.
     * @param list list of actions
     */
    inline void init_flow_mod(boost::shared_array<uint8_t>& of_raw,
			      ofp_action_list list)
    {
      init(of_raw, list.mem_size()+sizeof(ofp_flow_mod), OFPT_FLOW_MOD);
    };

    /** Set ofp_flow_mod message, with default timeouts and priority.
     * @param of_raw buffer/memory for message
     * @param flow reference to flow to match to
     * @param buffer_id buffer id of flow
     * @param in_port input port
     * @param command command in flow_mod
     * @return true if flow mod is set (check that type is flow_mod)
     */
    bool set_flow_mod_exact(boost::shared_array<uint8_t>& of_raw,
			    const Flow& flow, uint32_t buffer_id, uint16_t in_port, uint16_t command);

    /** Set flow_mod message.
     * @param of_raw buffer/memory for message
     * @param flow reference to flow to match to
     * @param buffer_id buffer id of flow
     * @param in_port input port
     * @param command command in flow_mod
     * @param idle_timeout idle timeout
     * @param hard_timeout hard timeout
     * @param priority priority of entry
     * @return true if flow mod is set (check that type is flow_mod)
     */
    bool set_flow_mod_exact(boost::shared_array<uint8_t>& of_raw,
			    const Flow& flow, uint32_t buffer_id, uint16_t in_port, uint16_t command,
			    uint16_t idle_timeout, uint16_t hard_timeout, uint16_t priority);

    /** Set action for flow_mod message.
     * @param of_raw buffer/memory for message
     * @param list list of actions
     */
    void set_flow_mod_actions(boost::shared_array<uint8_t>& of_raw,
			      ofp_action_list list);

  private:
    /** Size of last xid given.
     */
    uint32_t lastXid;
  };
}

#endif
