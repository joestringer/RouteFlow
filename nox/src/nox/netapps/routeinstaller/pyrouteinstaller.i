%module "nox.apps.pyrouteinstaller_app"

%{
#include "routeinstaller_proxy.hh"
#include "pyrt/pycontext.hh"
using namespace vigil;
using namespace vigil::applications;
%}

%include "routeinstaller_proxy.hh"

%pythoncode
%{
  from nox.lib.core import Component

    class pyrouteinstaller_app(Component):
      """
        An adaptor over the C++ based Python bindings to
        simplify their implementation.
      """
      def __init__(self, ctxt):
        self.pscpa = routeinstaller_proxy(ctxt)

      def configure(self, configuration):
        self.pscpa.configure(configuration)

      def install(self):
        pass

      def getInterface(self):
        return str(pyrouteinstaller_app)

      # --
      # Expose additional methods here!
      # --


  def getFactory():
        class Factory():
            def instance(self, context):

                return pyrouteinstaller_app(context)

        return Factory()
%}
