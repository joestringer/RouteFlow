include ../../../Make.vars 

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)

pkglib_LTLIBRARIES =		\
	golems.la \
	bookman.la \
	komui.la \
	marie.la \
	lenalee.la \
	lavi.la \
	timcanpy.la
#golem.la timcanpy.la

golems_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/netapps/ -I $(top_srcdir)/src/nox/coreapps/
golems_la_SOURCES = golems.cc golems.hh bookman-msg-event.hh bookman-msg-event.cc bookman-message.hh
golems_la_LDFLAGS = -module -export-dynamic

bookman_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/netapps/ -I $(top_srcdir)/src/nox/coreapps/
bookman_la_SOURCES = bookman.cc bookman.hh
bookman_la_LDFLAGS = -module -export-dynamic

komui_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/netapps/ -I $(top_srcdir)/src/nox/coreapps/
komui_la_SOURCES = komui.cc komui.hh
komui_la_LDFLAGS = -module -export-dynamic

marie_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/netapps/ -I $(top_srcdir)/src/nox/coreapps/
marie_la_SOURCES = marie.cc marie.hh
marie_la_LDFLAGS = -module -export-dynamic

lenalee_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/netapps/ -I $(top_srcdir)/src/nox/coreapps/
lenalee_la_SOURCES = lenalee.cc lenalee.hh
lenalee_la_LDFLAGS = -module -export-dynamic

lavi_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/netapps/ -I $(top_srcdir)/src/nox/coreapps/
lavi_la_SOURCES = lavi.cc lavi.hh
lavi_la_LDFLAGS = -module -export-dynamic

timcanpy_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/netapps/ -I $(top_srcdir)/src/nox/coreapps/
timcanpy_la_SOURCES = timcanpy.cc timcanpy.hh
timcanpy_la_LDFLAGS = -module -export-dynamic

#golem_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/netapps/
#golem_la_SOURCES = golem.cc golem.hh
#golem_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.xml

NOX_RUNTIMEFILES += __init__.py

pylavi_wrap.cc pylavi.py: pylavi.i
	$(SWIG) $(SWIG_PYTHON_OPT) -I$(top_srcdir)/src/nox/lib/ -outdir $(builddir)/. -o pylavi_wrap.cc  -module pylavi $(srcdir)/pylavi.i

pkglib_LTLIBRARIES += _pylavi.la
_pylavi_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/nox -I$(srcdir)/../ -I$(top_builddir)/src/nox/ -I$(top_srcdir)/src/nox/coreapps/
_pylavi_la_SOURCES = lavi_proxy.cc lavi_proxy.hh
nodist__pylavi_la_SOURCES = pylavi_wrap.cc
_pylavi_la_LDFLAGS = -module

NOX_PYLIBFILES = _pylavi.so
endif # PY_ENABLED


EXTRA_DIST = \
	__init__.py \
	pylavi.i \
	meta.xml

all-local:  nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local
