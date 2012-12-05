#ifndef ROUTEINSTALLER_PROXY_HH__
#define ROUTEINSTALLER_PROXY_HH__

#include <Python.h>
#include "routeinstaller.hh"
#include "pyrt/pyglue.hh"

namespace vigil
{
  namespace applications
  {

    /** Class to proxy command between C/C++ and Python
     * for vigil::routeinstaller.
     *
     * @author ykk
     * @date January 2009
     */
    class routeinstaller_proxy
    {
    public:
      /** Get a pointer to the runtime context so we can resolve
       * routeinstaller at configure time.
       * @param ctxt context
       */
      routeinstaller_proxy(PyObject* ctxt);
      /** Configure component.
       * Get a handle to the routeinstaller container on the C++ side.
       * Component saved in component
       * @param ctxt context
       */
      void configure(PyObject* ctxt);
      /** Start component in wrapper.
       * @param obj component
       */
      void install(PyObject* obj);

      // --
      // Proxy public interface methods here!!
      // --

    protected:
      /** routeinstaller component.
       */
      routeinstaller* scpa;
      /** Component container.
       */
      container::Component* c;
    }; // class routeinstaller_proxy

  } // namespace applications
} // namespace vigil

#endif
