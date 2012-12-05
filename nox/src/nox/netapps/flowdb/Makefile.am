include ../../../Make.vars

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)

pkglib_LTLIBRARIES =		\
	flowdb.la		\
	flowdblogger.la		\
	flowroutecache.la

flowdb_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/nox -I$(top_srcdir)/src/nox/netapps
flowdb_la_SOURCES = flowdb.cc flowdb.hh
flowdb_la_LDFLAGS = -module -export-dynamic

flowroutecache_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/netapps/ -I $(top_srcdir)/src/nox/coreapps/
flowroutecache_la_SOURCES = flowroutecache.cc flowroutecache.hh
flowroutecache_la_LDFLAGS = -module -export-dynamic

flowdblogger_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/netapps/
flowdblogger_la_SOURCES = flowdblogger.cc flowdblogger.hh
flowdblogger_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.xml
endif # PY_ENABLED

EXTRA_DIST = meta.xml

all-local: nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local
