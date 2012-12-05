#Check number of arguments
if [ $# -ne 1 ]
then
    echo "Usage: `basename $0` <component name>"
    exit 65
fi

mkdir $1
cd $1

#meta.xml
cat > meta.xml <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<components:components xmlns:components="http://www.noxrepo.org/components.xsd">
  <component>
    <name>$1</name>
    <library>$1</library>
  </component>
</components:components>
EOF

#Makefile.am
cat > Makefile.am <<EOF
include ../../../Make.vars

EXTRA_DIST =\\
	meta.xml

if PY_ENABLED
AM_CPPFLAGS += \$(PYTHON_CPPFLAGS)
endif # PY_ENABLED

pkglib_LTLIBRARIES =  \\
	$1.la

$1_la_CPPFLAGS = \$(AM_CPPFLAGS) -I \$(top_srcdir)/src/nox -I \$(top_srcdir)/src/nox/coreapps/
$1_la_SOURCES = $1.cc $1.hh
$1_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.xml

all-local: nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local
EOF

#Component header file
cat > $1.hh <<EOF
#ifndef $1_HH
#define $1_HH 1

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
  class $1
    : public container::Component
  {
  public:
    /** Constructor.
     * @param c context as required by Component
     * @param node Xercesc DOMNode
     */
    $1(const Context* c, const xercesc::DOMNode* node)
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
     * @param component reference to $1
     */
    static void getInstance(const container::Context*, $1*& component);

  private:
  };
}
#endif
EOF

#Component C file
cat > $1.cc <<EOF
#include "$1.hh"

namespace vigil
{
  static Vlog_module lg("$1");

  void $1::getInstance(const container::Context* ctxt,
				   $1*& component)
  {
    component = dynamic_cast<$1*>
      (ctxt->get_by_interface(container::Interface_description
			      (typeid($1).name())));
  }
}


REGISTER_COMPONENT(vigil::container::Simple_component_factory
		   <vigil::$1>,
		   vigil::$1);
EOF

echo "Add $1 to configure.ac.in"
