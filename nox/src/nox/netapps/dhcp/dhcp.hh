#ifndef dhcp_HH
#define dhcp_HH 1

#include "component.hh"
#include "config.h"
#include "openflowpacket/openflowpacket.hh"
#include "netinet++/datapathid.hh"
#include "netinet++/ethernetaddr.hh"
#include "datapath-join.hh"
#include "packet-in.hh"
#include "sqlitelog/sqlitelog.hh"
#include <xercesc/dom/DOM.hpp>
#include <fstream>
#include <string>
#include "hash_map.hh"
#include "xml-util.hh"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

/** Define whois server to verify host with.
 */
#define WHOIS_SERVER "whois.stanford.edu"
/** Declare if flow entry is to be inserted.
 */
#define DHCP_INSERT_FLOW false
/** Checking interval for stale requests.
 */
#define DHCP_CHECK_INTERVAL 180
/** Stale request defined as more than this time.
 */
#define DHCP_STALE_TIMEOUT 180
/** Priority of DHCP packet hijack
 */
#define DHCP_PRIORITY 0xF000
/** Datapathid of DHCP switch.
 */
#define DHCP_DPID 0xaaaaaaaaaaLL
/** Port number of DHCP on its switch.
 */
#define DHCP_PORT 0
/** Allowed hosts file
 */
#define ALLOW_HOST_FILE "/home/basenox/Apr11-2009/noxcore/src/nox/netapps/dhcp/allowHost"
/** DHCP SQL LOG NAME
 */
#define DHCP_LOGNAME "DhcpLog"
/** SQL LOG SWITCH
 */
#define DHCP_LOG true

namespace vigil
{
  using namespace vigil::container;
  using namespace vigil::xml;

  /** \brief DHCP via NOX controller.
   *
   * Here, we use a local OpenFlow switch to connect to a DHCP server running
   * locally.  The DHCP server listens to a tap device which is connected to another
   * tap device via VDE.  The reason being that OpenFlow kernel module does not
   * work with bridge utility.  Any DHCP request is proxied to the DHCP server and
   * replied and directed back to the input switch/port.  A maps of request and switch/port
   * is maintained for a certain amount of time (DHCP_STALE_TIMEOUT).  If the reply is
   * directed a broadcast, all recent ports are sent the reply.
   *
   * In this component, we assume the entire packet will be sent to this
   * NOX controller.  This can be achieved by changing openflow.cc.
   *
   * Hosts can be authenticated for IP address via the DHCP settings, a whois
   * server, and/or a local file.
   *
   * @author ykk
   * @author srini
   * @author masa
   * @date February 2009
   */
  class dhcp
    : public container::Component
  {
  public:
    /** Status of DHCP request.
     */
    enum dhcp_status
    {
      /** No DHCP server.
       */
      noDHCPNow,
      /** Authenticated okay with whois.
       */
      whoisAuthenticated,
      /** Authenticated okay with file.
       */
      fileAuthenticated,
      /** Rejected, deemed as outside network.
       */
      rejectedOutside,
      /** Rejected simply.
       */
      rejected,
      /** DHCP request replied to with unicast
       */
      repliedUnicast,
      /** DHCP request replied to with unicast
       */
      repliedBroadcast,
    };

    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    dhcp(const Context* c, const xercesc::DOMNode* node)
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

    /** Handle switch join event.
     * @param e event to handle
     * @return CONTINUE always
     */
    Disposition handle_switch_join(const Event& e);

    /** Handle authentication of host.
     * @return if host should be given IP address
     */
    bool host_auth(const Flow& flow);

    /** Handle authentication of host using whois server.
     * @return if host should be given IP address
     */
    bool host_auth_whois(const Flow& flow);

    /** Handle authentication of host using a file.
     * @return if host should be given IP address
     */
    bool host_auth_file(const Flow& flow);

    bool ignore_dhcp(const Packet_in_event& pie);

    /** Check if DHCP should be dropped, e.g.,  broadcast from connecting network.
     * @param pie packet in event
     * @return if DHCP packet should be dropped
     */
    bool drop_dhcp(const Packet_in_event& pie);

    /** Log DHCP request.
     * @param mac mac address of requestor
     * @param status status of request (from dhcp_status)
     */
    void log_request(uint64_t mac, uint64_t status);

    /** Handle packet in event.
     * @param e event to handle
     * @return CONTINUE if not DHCP packet
     */
    Disposition handle_packet_in(const Event& e);

    /** Function to time out requests without reply.
     */
    void clear_stale_request();

    /** Get instance.
     * @param ctxt context
     * @param component reference to dhcp
     */
    static void getInstance(const container::Context*, dhcp*& component);

    /** Structure to hold DHCP request.
     */
    struct dhcp_req
    {
      /** Incoming switch.
       */
      datapathid dpid;
      /** Incoming port.
       */
      uint16_t port;
      /** Time stamp.
       */
      timeval tim;

      /** Constructor.
       * @param dpid_ datapath id of incoming switch
       * @param port_ number of incoming port
       */
      dhcp_req(datapathid dpid_, uint16_t port_):
	port(port_)
      {
	dpid = dpid_;
	gettimeofday(&tim, NULL);
      }
    };

  private:
    /** Pending DHCP request.
     */
    hash_map<uint64_t,dhcp_req> dhcpRequest;
    /** Reference to SQLite Log.
     */
    sqlitelog* sqllog;
    /** Reference to openflowpacket.
     */
    openflowpacket* ofp;
    /** Buffer of openflow message.
     */
    boost::shared_array<uint8_t> of_raw;
    /** Indicate if DHCP switch joined.
     */
    bool dhcp_sw_okay;
    /**
     */
    xercesc::DOMNode* domNode;
  };
}
#endif
