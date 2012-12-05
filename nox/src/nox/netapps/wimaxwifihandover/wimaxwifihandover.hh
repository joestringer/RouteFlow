#ifndef wimaxwifihandover_HH
#define wimaxwifihandover_HH 1

/** Datapathid to WiMAX.
 */
#define WIMAXWIFI_DPID 0xcafecafeULL
/** Port to WiMAX.
 */
#define WIMAX_PORT 0x0U
/** Port to Network
 */
#define NETWORK_PORT 0x1U

/** Mac address for WiMAX.
 */
#define WIMAX_MAC 0xc420263dfULL
/** WiMAX IP address
 */
#define WIMAX_IP 0xc0a802e1UL

/** Mac address for WiFi.
 */
#define WIFI_MAC 0x50C274D108ULL
/** WiFi IP address
 */
#define WIFI_IP 0xc0a802e1UL

#include "component.hh"
#include "config.h"
#include "wimaxmsg.hh"
#include "flowdb/flowdb.hh"
#include <xercesc/dom/DOM.hpp>
#include "flowdb/flowdb.hh"
#include "routeinstaller/routeinstaller.hh"
#include "authenticator/flow_in.hh"
#include "mobiledb/mobiledb.hh"

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

  /** WiMAX message subtype.
   */
  enum
  {
    /** Host join event.
     */
    WIMAX_JOIN = 0x01,
    /** Host leave event.
     */
    WIMAX_LEAVE = 0x02,
  };

  /** Message for WiMAX client association/disassociation.
   */
  struct wimax_msg
  {
    /** WiMAX subtype.
     */
    uint8_t subtype;
    /** Host mac address.
     */
    uint64_t host_mac;
    /** Base station mac address.
     */
    uint64_t bs_mac;
    /** Wireless port number.
     */
    uint16_t port;
  };

  /** \brief Class to handle hard handover between WiMAX and WiFi.
   *
   * @author ykk
   * @date March 2009
   */
  class wimaxwifihandover
    : public container::Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    wimaxwifihandover(const Context* c, const xercesc::DOMNode*)
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

    /** Handles flow in.
     * @param e event to be handled
     * @return CONTINUE always
     */
    Disposition handle_flow_in(const Event& e);

    /** Handles message event, for WiMAX host join/leave.
     * @param e event to be handled
     * @return CONTINUE always
     */
    Disposition handle_wimax_msg(const Event& e);

    Disposition handle_wifi(const Event& e);

    void changeMacAction(uint64_t mac,
			 hash_map<datapathid,ofp_action_list>& act, bool source);

    void changeMacIPAction(uint64_t mac, uint32_t ip,
			   hash_map<datapathid,ofp_action_list>& act, bool source);

    /** Get instance.
     * @param ctxt context
     * @param component reference to wimaxwifihandover
     */
    static void getInstance(const container::Context*, wimaxwifihandover*& component);

  private:
    /** Indicator of Host with WiMAX or not.
     */
    bool inWiMAX;
    /** Reference to flow database.
     */
    FlowDB* fdb;
    /** Reference to mobile database.
     */
    MobileDB* mdb;
    /** Reference to routeinstaller.
     */
    routeinstaller* ri;
  };
}
#endif
