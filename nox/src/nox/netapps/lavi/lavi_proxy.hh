#ifndef LAVI_PROXY_HH__
#define LAVI_PROXY_HH__

#include <Python.h>
#include "lavi.hh"
#include "pyrt/pyglue.hh"

namespace vigil
{
  namespace applications
  {

    /** Class to proxy command between C/C++ and Python
     * for vigil::lavi.
     *
     * @author ykk
     * @date November 2008
     */
    class lavi_proxy
    {
    public:
      /** Get a pointer to the runtime context so we can resolve
       * lavi at configure time.
       * @param ctxt context
       */
      lavi_proxy(PyObject* ctxt);
      /** Configure component.
       * Get a handle to the lavi container on the C++ side.
       * Component saved in \ref component
       * @param ctxt context
       */
      void configure(PyObject* ctxt);
      /** Start component in wrapper.
       * @param ctxt context
       */
      void install(PyObject* ctxt);

      // --
      // Proxy public interface methods here!!
      // --

    protected:
      /** lavi component.
       */
      lavi* scpa;
      /** Component container.
       */
      container::Component* component;
    }; // class lavi_proxy

  } // namespace applications
} // namespace vigil

#endif
