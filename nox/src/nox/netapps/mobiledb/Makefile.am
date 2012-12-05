include ../../../Make.vars

EXTRA_DIST = meta.xml

pkglib_LTLIBRARIES =		\
	mobiledb.la

mobiledb_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/nox -I$(top_srcdir)/src/nox/netapps -I$(top_srcdir)/src/nox/coreapps
mobiledb_la_SOURCES = mobiledb.cc
mobiledb_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.xml

all-local: nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local
