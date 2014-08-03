noinst_LIBRARIES = librouteflow.a
librouteflow_a_CXXFLAGS = -I$(top_srcdir)/rflib @AM_CXXFLAGS@
librouteflow_a_SOURCES = defs.h converter.h

SUBDIRS = types ipc
if LOCAL_BSON
SUBDIRS += bson
endif
