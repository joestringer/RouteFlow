#ifndef sqlitelog_HH
#define sqlitelog_HH 1

#include "component.hh"
#include "config.h"
#include <xercesc/dom/DOM.hpp>
#include "threads/cooperative.hh"
#include "storage/transactional-storage.hh"
#include "storage/transactional-storage-blocking.hh"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

/** Interval between checks in seconds.
 */
#define SQLITELOG_CHECK_INTERVAL 5
/** Threshold to trigger flushing list.
 */
#define SQLITELOG_THRESHOLD 20

namespace vigil
{
  using namespace std;
  using namespace vigil::container;
  using namespace vigil::applications;

  /** \brief SQL logging.
   *
   * Cooperative thread that logs data into SQLite database.
   * Performs record into file in batches.
   *
   * @author ykk
   * @date February 2009
   */
  class sqlitelog
    : public container::Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    sqlitelog(const Context* c, const xercesc::DOMNode* node)
        : Component(c)
    {}

    /** Configure component
     * Register events.
     * @param config configuration
     */
    void configure(const Configuration* config);

    /** Start component.
     */
    void install();

    /** Get instance.
     * @param ctxt context
     * @param component reference to sqlitelog
     */
    static void getInstance(const container::Context*, sqlitelog*& component);

    /** Function to handle periodic check.
     */
    void handle_check();

    /** Function to create table.
     * @param TABLE name of table
     * @param columns column definition
     * @return result of create table query
     */
    storage::Result create_table(string TABLE, storage::Column_definition_map columns);

    /** Store for pair of table name and rows to insert.
     */
    list<pair<string,storage::Row> > rowStore;
    /** Reference to storage.
     */
    storage::Async_transactional_storage* storage;
    /** Value to indicate if a thread running.
     */
    bool running;
  private:
  };

  /** \brief SQL logging thread.
   *
   * @author ykk
   * @date February 2009
   */
  class sqlitelog_thread
    : Co_thread
  {
  public:
    /** Constructor.
     */
    sqlitelog_thread(sqlitelog* log);

    /** Destructor.
     */
    ~sqlitelog_thread();

    /** Main function to run logging thread.
     */
    void run();

  private:
    /** SQLite log component.
     */
    sqlitelog* sqllog;
  };
}
#endif
