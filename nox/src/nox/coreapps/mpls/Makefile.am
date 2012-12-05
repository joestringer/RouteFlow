include ../../../Make.vars

EXTRA_DIST =\
	meta.xml

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
endif # PY_ENABLED

pkglib_LTLIBRARIES =		\
        mpls_gui.la		\
        cspf.la		    \
	    mpls.la

mpls_gui_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/coreapps/ -I $(top_srcdir)/src/nox/netapps/
mpls_gui_la_SOURCES = mpls_gui.cc mpls_gui.hh
mpls_gui_la_LDFLAGS = -module -export-dynamic

cspf_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/coreapps/ -I $(top_srcdir)/src/nox/netapps/
cspf_la_SOURCES = cspf.cc cspf.hh
cspf_la_LDFLAGS = -module -export-dynamic

mpls_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/coreapps/ -I $(top_srcdir)/src/nox/netapps/
mpls_la_SOURCES = mpls.cc mpls.hh mpls_config.hh
mpls_la_LDFLAGS = -module -export-dynamic


NOX_RUNTIMEFILES = meta.xml

all-local: nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local
