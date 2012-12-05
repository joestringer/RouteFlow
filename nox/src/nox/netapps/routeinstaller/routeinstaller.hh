#ifndef ROUTEINSTALLER_HH__
#define ROUTEINSTALLER_HH__

#include "component.hh"
#include "network_graph.hh"
#include "openflow/openflow.h"
#include "openflowpacket/openflowpacket.hh"
#include "hash_map.hh"
#include "routing/routing.hh"

namespace vigil
{
  using namespace vigil;
  using namespace vigil::container;
  using namespace vigil::applications;

  /** \brief Class to install route.
   *
   * Routes are installed in the reverse order, so as to prevent
   * multiple packet in per flow.  This is not bullet-proof but
   * is better than installing it the forward manner at least.
   *
   * Copyright (C) Stanford University, 2009.
   * @author ykk
   * @date February 2009
   */
  class routeinstaller
    : public Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    routeinstaller(const Context* c,const xercesc::DOMNode* node)
      : Component(c)
    {}

    /** Destructor.
     */
    virtual ~routeinstaller()
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
    static void getInstance(const container::Context*,
			    vigil::routeinstaller*& scpa);

    /** Get shortest path route.
     * Note that a route for a list of destination is a tree.
     * @param dst list of network terminations for destinations
     * @param route route to populate with source network termination
     * @return if route is found
     */
    bool get_shortest_path(std::list<network::termination> dst, network::route& route);

    /** Get shortest path route.
     * Note that a route for a list of destination is a tree.
     * @param dst destinations
     * @param route route to populate with source network termination
     * @return if route is found
     */
    bool get_shortest_path(network::termination dst, network::route& route);

    /** Install route, i.e., sending the route setup to a set of switches.
     * Throws Route_install_event if desired.
     * @param flow reference to flow to route
     * @param route network route to be installed
     * @param buffer_id id of buffer
     * @param actions list of datapath id and action list pairs
     */
    void install_route(const Flow& flow, network::route route, uint32_t buffer_id,
		       hash_map<datapathid,ofp_action_list>& actions);

    /** Install route, i.e., sending the route setup to a set of switches.
     * @param flow reference to flow to route
     * @param route network route to be installed
     * @param buffer_id id of buffer
     */
    void install_route(const Flow& flow, network::route route, uint32_t buffer_id);

    /** Install flow entry to switch.
     * @param dpid datapathid of switch to send flow entry to
     * @param flow reference to flow to route
     * @param buffer_id id of buffer
     * @param in_port input port
     * @param act_list list of action to install on top of forwarding
     */
    void install_flow_entry(const datapathid& dpid,
			    const Flow& flow, uint32_t buffer_id, uint16_t in_port,
			    ofp_action_list act_list);

  private:
    /** Install route, i.e., sending the route setup to a set of switches.
     * @param flow reference to flow to route
     * @param route network route to be installed
     * @param buffer_id id of buffer
     */
    void real_install_route(const Flow& flow, network::route route, uint32_t buffer_id,
			    hash_map<datapathid,ofp_action_list>& actions);

    /** Reference to routing module.
     */
    Routing_module* routing;
    /** Reference to OpenFlow packet.
     */
    openflowpacket* ofp;
    /** Buffer for openflow message.
     */
    boost::shared_array<uint8_t> of_raw;

    /** Function to merge tree and route.
     * @param tree tree to merge route into
     * @param route route to merge into tree
     */
    void merge_route(network::route* tree, network::route* route);

    void route2tree(network::termination dst, Routing_module::RoutePtr sroute,
		    network::route& route);
  };

} // namespace vigil

#endif
