include ../../../Make.vars

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)

pkglib_LTLIBRARIES =		\
	routeinstaller.la

routeinstaller_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/netapps -I $(top_srcdir)/src/nox/coreapps
routeinstaller_la_SOURCES = routeinstaller.cc routeinstaller.hh network_graph.hh
routeinstaller_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.xml

NOX_RUNTIMEFILES += __init__.py

pyrouteinstaller_wrap.cc pyrouteinstaller.py: pyrouteinstaller.i
	$(SWIG) $(SWIG_PYTHON_OPT) -I$(top_srcdir)/src/nox/lib/ -outdir $(builddir)/. -o pyrouteinstaller_wrap.cc  -module pyrouteinstaller $(srcdir)/pyrouteinstaller.i

pkglib_LTLIBRARIES += _pyrouteinstaller.la
_pyrouteinstaller_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/nox -I$(top_srcdir)/src/nox/coreapps -I$(srcdir)/../ -I$(top_builddir)/src/nox/
_pyrouteinstaller_la_SOURCES = routeinstaller_proxy.cc routeinstaller_proxy.hh
nodist__pyrouteinstaller_la_SOURCES = pyrouteinstaller_wrap.cc
_pyrouteinstaller_la_LDFLAGS = -module

NOX_PYLIBFILES = _pyrouteinstaller.so
endif # PY_ENABLED


EXTRA_DIST = \
	__init__.py \
	pyrouteinstaller.i \
	meta.xml

all-local:  nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local
