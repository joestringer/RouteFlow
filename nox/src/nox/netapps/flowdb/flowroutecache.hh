#ifndef flowroutecache_HH
#define flowroutecache_HH 1

#include "component.hh"
#include "config.h"
#include "flowdb.hh"
#include "routeinstaller/routeinstaller.hh"
#include "routeinstaller/network_graph.hh"
#include <xercesc/dom/DOM.hpp>
#include "assert.hh"
#include "hash_map.hh"
#include <boost/bind.hpp>
#include <time.h>

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

namespace vigil
{
  using namespace vigil::container;

  /** \brief Structure to hold hop in route.
   *
   * Copyright (C) Stanford University, 2009.
   * @author ykk
   * @date May 2009
   */
  struct Route_hop
  {
    /** Constructor.
     * @param inport input port
     * @param dpid datapath id
     * @param output output port
     */
    Route_hop(uint16_t inport, datapathid dpid, uint16_t output);

    /** In_port
     */
    uint16_t in_port;
    /** Switch
     */
    datapathid sw;
    /** In_port.
     */
    uint16_t out_port;
  };

  /**Single route implementation.
   */
  typedef std::list<Route_hop> single_route;

  /** \brief Event to throw on route of host changes.
   *
   * Copyright (C) Stanford University, 2009.
   * @author ykk
   * @date May 2009
   */
  struct Host_route_event : public Event
  {
  public:
    /** Constructor.
     * Does not allow multicast tree for now.
     * @param route_ route installed
     */
    Host_route_event(uint32_t flowid_, bool add_);

    /** Destructor.
     */
    ~Host_route_event();

    /** Empty constructor.
     * For use within python.
     */
    Host_route_event() : Event(static_get_name())
    { }

    /** Static name required in NOX.
     */
    static const Event_name static_get_name()
    {
      return "Host_route_event";
    }

    /** Add route to list
     * @param rte reference to route
     * @see #installed_route
     */
    void add_route(network::route* rte);

    /** Indicate if adding or deleting.
     */
    bool add;
    /** Flow id.
     */
    uint32_t flowid;
    /** Route installed.
     */
    std::list<single_route> installed_route;

  };

  /** \brief Component that manages routes of flows.
   *
   * Copyright (C) Stanford University
   * @author ykk
   * @date May 2009
   */
  class flowroutecache
    : public container::Component
  {
  public:
    /** \brief Record of a flow.
     *
     * @author ykk
     * @date May 2009
     */
    struct flowrecord
    {
      /** Constructor.
       * @param srcmac
       * @param dstmac
       * @param srcdpid
       * @param flowid
       */
      flowrecord(ethernetaddr srcmac, ethernetaddr dstmac,
		 datapathid srcdpid, uint32_t flowid);

      /** Constructor.
       * @param srcmac
       * @param dstmac
       * @param flowid
       */
      flowrecord(ethernetaddr srcmac, ethernetaddr dstmac,
		 uint32_t flowid);

      /** Destructor.
       */
      ~flowrecord()
      {
	dst_dpid.clear();
      }

      /** Source mac.
       */
      ethernetaddr src_mac;
      /** Destination mac.
       */
      ethernetaddr dst_mac;
      /** Source datapath id.
       */
      datapathid src_dpid;
      /** Destination datapath ids and counter for number of flows.
       */
      hash_map<uint64_t, uint8_t> dst_dpid;
      /** Flow identifier.
       */
      uint32_t flow_id;
    };

    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    flowroutecache(const Context* c, const xercesc::DOMNode* node)
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

    /** Handles route installation.
     * @param e flowdb event to handle
     */
    Disposition handle_flowdb_event(const Event& e);

    /** Post host route event for lenalee.
     * @param fr flow record for change
     * @param add indicate if flow is added or deleted
     */
    void post_flow_event(flowrecord fr,bool add);

    /** Get instance.
     * @param ctxt context
     * @param component reference to flowroutecache
     */
    static void getInstance(const container::Context*, flowroutecache*& component);

  private:
    /** Reference to routeinstaller.
     */
    routeinstaller* ri;
    /** Flow id.
     */
    uint32_t flowid;
    /** List of flow records.
     */
    std::list<flowrecord> flowrecords;

    /** Find flow record.
     */
    std::list<flowrecord>::iterator find_flowrecord(ethernetaddr srcmac, ethernetaddr dstmac);
  };
}
#endif
