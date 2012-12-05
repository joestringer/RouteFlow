#ifndef timcanpy_HH
#define timcanpy_HH 1

#include "component.hh"
#include "config.h"
#include <xercesc/dom/DOM.hpp>
#include <boost/shared_array.hpp>
#include "bookman-msg-event.hh"
#include "bookman.hh"
#include "bookman-message.hh"
#include "openflowpacket/openflowpacket.hh"
#include "openflow/openflow/openflow.h"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

/** File for dpid hostname mapping
 */
#define DPID_HOSTNAME_FILE "/home/basenox/Apr11-2009/noxcore/src/nox/netapps/lavi/dpidhostname"

namespace vigil
{
  using namespace vigil::container;

  /** \brief Class to proxy command between lavi
   * and OpenFlow switches.
   *
   * @author ykk
   * @date February 2009
   */
  class timcanpy
    : public container::Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    timcanpy(const Context* c, const xercesc::DOMNode* node)
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

    /** Function to set a message for periodic posting.
     * @param bm message event requesting for periodic posting.
     */
    /** Function to provide statistics request.
     * @param bm message event requesting for statistics.
     */
    void handle_stat_req(const Book_msg_event& bm);

    /** Function to handle Openflow_msg_event.
     * @param e event to handle
     * @return CONTINUE if unknown message type, else STOP
     */
    Disposition handle_of_msg_in(const Event& e);
    /** Function to delete poll without connection
     * @param bm message event from disconnection
     */
    void clearConnection(const Book_msg_event& bm);

    /** Get instance.
     * @param ctxt context
     * @param component reference to packet
     */
    static void getInstance(const container::Context* ctxt, timcanpy*& component);

  private:
    /** Reference to bookman.
     */
    bookman* book;
    /** Reference to openflowpacket
     */
    openflowpacket* ofp;
    /** Memory allocated for openflowpacket messages.
     */
    boost::shared_array<uint8_t> of_raw;
    /** List of pending stat request.
     */
    hash_map<uint32_t, Msg_stream*> requestMap;
    /** List of dpid and hostname.
     */
    hash_map<uint64_t,std::string> dpidhostlist;
  };
}
#endif
