#ifndef NETWORKGRAPH_HH_
#define NETWORKGRAPH_HH_

#include "netinet++/datapathid.hh"

namespace vigil
{

  /** \brief Class to contain abstraction of network graph.
   *
   * @author ykk
   * @date February 2009
   */
  class network
  {
  public:

    /** \brief Switch/port pair.
     *
     * @author ykk
     * @date February 2009
     */
    struct switch_port
    {
      /** Switch datapath id.
       */
      datapathid dpid;
      /** Port number.
       */
      uint16_t port;

      /** Constructor.
       * @param dpid_ datapath id of switch
       * @param port_ port number
       */
      switch_port(datapathid dpid_, uint16_t port_):
	dpid(dpid_), port(port_)
      {}

      /** Set value of switch_port.
       * @param val value to set to.
       */
      void set(switch_port val)
      {
	dpid=val.dpid;
	port=val.port;
      }
    };

    /** Network termination, classified by switch port pair.
     *
     * @author ykk
     * @date February 2009
     */
    typedef switch_port termination;

    /** \brief Hop in route.
     *
     * @author ykk
     * @date February 2009
     */
    struct hop
    {
      /** Switch/port pair, i.e., in port to switch.
       */
      switch_port in_switch_port;
      /** List of next hop.
       */
      std::list<std::pair<uint16_t, hop*> > next_hops;

      /** Constructor.
       * @param dpid_ switch datapathid
       * @param port_ port number
       */
      hop(datapathid dpid_, uint16_t port_):
	in_switch_port(dpid_, port_)
      { }

      /** Destructor.
       * Delete std::list of pointers.
       */
      ~hop()
      {
	if (!in_switch_port.dpid.empty())
	  next_hops.clear();
      }
    };

    /** List of next hops.
     *
     * @author ykk
     * @date February 2009
     */
    typedef std::list<std::pair<uint16_t, hop*> > nextHops;

    /** Route in network, i.e., a tree.
     * Reoute terminate when next_hop has empty datapathid, i.e., 0.
     *
     * @author ykk
     * @date February 2009
     */
    typedef hop route;
  };
}

#endif
