%module "nox.apps.pylavi_app"

%{
#include "lavi_proxy.hh"
#include "pyrt/pycontext.hh"
using namespace vigil;
using namespace vigil::applications;
%}

%include "lavi_proxy.hh"

%pythoncode
%{
  from nox.lib.core import Component

    class pylavi_app(Component):
      """
        An adaptor over the C++ based Python bindings to
        simplify their implementation.
      """
      def __init__(self, ctxt):
        self.pscpa = lavi_proxy(ctxt)

      def configure(self, configuration):
        self.pscpa.configure(configuration)

      def install(self):
        pass

      def getInterface(self):
        return str(pylavi_app)

      # --
      # Expose additional methods here!
      # --


  def getFactory():
        class Factory():
            def instance(self, context):

                return pylavi_app(context)

        return Factory()
%}
