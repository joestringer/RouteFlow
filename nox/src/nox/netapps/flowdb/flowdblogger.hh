#ifndef flowdblogger_HH
#define flowdblogger_HH 1

#include "component.hh"
#include "config.h"
#include <xercesc/dom/DOM.hpp>
#include "storage/transactional-storage.hh"
#include "flowdb/flowdb.hh"
#include "sqlitelog/sqlitelog.hh"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

/** Name of flow database count table.
 */
#define FLOWCOUNT_TABLENAME "FlowCount"
/** FlowDB check interval.
 */
#define FLOWCOUNT_CHECK_INTERVAL 60

namespace vigil
{
  using namespace vigil::container;
  using namespace vigil::applications;

  /** \brief Logger for FlowDB counts.
   *
   * @author ykk
   * @date April 2009
   */
  class flowdblogger
    : public container::Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    flowdblogger(const Context* c, const xercesc::DOMNode* node)
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

    /** Get instance.
     * @param ctxt context
     * @param component reference to flowdblogger
     */
    static void getInstance(const container::Context*, flowdblogger*& component);

    /** Periodic FlowDB check.
     */
    void periodic_check();

  private:
    /** Reference to sqlite logging.
     */
    sqlitelog* sqllog;
    /** Reference to Flow database.
     */
    FlowDB* fdb;
  };
}
#endif
