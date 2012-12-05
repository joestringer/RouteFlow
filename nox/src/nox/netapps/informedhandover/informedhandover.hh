#ifndef informedhandover_HH
#define informedhandover_HH 1

#include "component.hh"
#include "config.h"
#include <xercesc/dom/DOM.hpp>

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

namespace vigil
{
  using namespace vigil::container;

  /** \brief
   *
   * @author
   * @date
   */
  class informedhandover
    : public container::Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    informedhandover(const Context* c, const xercesc::DOMNode*)
        : Component(c)
    {}

    /** Configure component
     * Register events.
     * @param config configuration
     */
    void configure(const Configuration* config)
    { }

    /** Start component.
     */
    void install()
    {}

    /** Get instance.
     * @param ctxt context
     * @param component reference to informedhandover
     */
    static void getInstance(const container::Context*, informedhandover*& component);

  private:
  };
}
#endif
