#ifndef hardhandover_HH
#define hardhandover_HH 1

#include "component.hh"
#include "config.h"
#include <xercesc/dom/DOM.hpp>
#include "snmp/snmptrap.hh"
#include "flowdb/flowdb.hh"
#include "mobiledb/mobiledb.hh"
#include "routeinstaller/routeinstaller.hh"

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

  /** \brief Hard Handover
   *
   * @author ykk
   * @date February 2009
   */
  class hardhandover
    : public container::Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    hardhandover(const Context* c, const xercesc::DOMNode*)
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

    Disposition handle_flow_in(const Event& e);

    /** Handles wireless host join event.
     * @param e event to be handled
     * @return CONTINUE always
     */
    Disposition handle_wireless_join(const Event& e);

    /** Get instance.
     * @param ctxt context
     * @param component reference to hardhandover
     */
    static void getInstance(const container::Context*, hardhandover*& component);

  private:
    /** Reference to mobile db.
     */
    MobileDB* mdb;
    /** Reference to flowdb.
     */
    FlowDB* fdb;
    /** Reference to routeinstaller.
     */
    routeinstaller* ri;
  };
}
#endif
