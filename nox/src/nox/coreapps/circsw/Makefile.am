include ../../../Make.vars

EXTRA_DIST =\
	meta.xml

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
endif # PY_ENABLED

pkglib_LTLIBRARIES =		\
        circsw_gui.la		\
	    circsw.la

circsw_gui_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/coreapps/ -I $(top_srcdir)/src/nox/netapps/
circsw_gui_la_SOURCES = circsw_gui.cc circsw_gui.hh
circsw_gui_la_LDFLAGS = -module -export-dynamic


circsw_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/coreapps/ -I $(top_srcdir)/src/nox/netapps/
circsw_la_SOURCES = circsw.cc circsw.hh circsw_config.hh
circsw_la_LDFLAGS = -module -export-dynamic


NOX_RUNTIMEFILES = meta.xml

all-local: nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local
