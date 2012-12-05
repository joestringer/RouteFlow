include ../../../Make.vars

EXTRA_DIST = meta.xml

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)

pkglib_LTLIBRARIES =		\
	bicast.la

bicast_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/nox -I$(top_srcdir)/src/nox/netapps -I$(top_srcdir)/src/include \
		     -I $(top_srcdir)/src/nox/coreapps/                                              \
	             -I $(top_srcdir)/src/nox/netapps/
bicast_la_SOURCES = bicast.cc
bicast_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.xml

endif # PY_ENABLED

all-local: nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local
