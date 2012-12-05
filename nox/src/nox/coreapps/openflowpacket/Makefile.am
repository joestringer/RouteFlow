include ../../../Make.vars

EXTRA_DIST =\
	meta.xml

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
endif # PY_ENABLED

pkglib_LTLIBRARIES =		\
	openflowpacket.la

openflowpacket_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox -I $(top_srcdir)/src/nox/coreapps/
openflowpacket_la_SOURCES = openflowpacket.cc openflowpacket.hh
openflowpacket_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.xml

all-local: nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local
