#include "routeinstaller_proxy.hh"
#include "pyrt/pycontext.hh"
#include "swigpyrun.h"
#include "vlog.hh"

using namespace std;
using namespace vigil;
using namespace vigil::applications;

namespace
{
  Vlog_module lg("routeinstaller-proxy");
}

namespace vigil
{
  namespace applications
  {

    routeinstaller_proxy::routeinstaller_proxy(PyObject* ctxt)
    {
      SwigPyObject* swigo = SWIG_Python_GetSwigThis(ctxt);
      if (!swigo || !swigo->ptr)
        throw runtime_error("Unable to access Python context.");

      c = ((PyContext*)swigo->ptr)->c;
    }

    void routeinstaller_proxy::configure(PyObject* configuration)
    {
      c->resolve(scpa);
    }

    void routeinstaller_proxy::install(PyObject*)
    {
    }

  } // namespace applications
} // namespace vigil
