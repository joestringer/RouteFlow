#include "lavi_proxy.hh"
#include "pyrt/pycontext.hh"
#include "swigpyrun.h"
#include "vlog.hh"

using namespace std;
using namespace vigil;
using namespace vigil::applications;

namespace
{
  Vlog_module lg("lavi-proxy");
}

namespace vigil
{
  namespace applications
  {

    lavi_proxy::lavi_proxy(PyObject* ctxt)
    {
      SwigPyObject* swigo = SWIG_Python_GetSwigThis(ctxt);
      if (!swigo || !swigo->ptr)
        throw runtime_error("Unable to access Python context.");

      component = ((PyContext*)swigo->ptr)->c;
    }

    void lavi_proxy::configure(PyObject* configuration)
    {
      component->resolve(scpa);
    }

    void lavi_proxy::install(PyObject* ctxt)
    {
    }

  } // namespace applications
} // namespace vigil
