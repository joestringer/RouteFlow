bin_PROGRAMS = rfclient

rfclient_CXXFLAGS = -I$(top_srcdir)/rflib @AM_CXXFLAGS@
AM_LDFLAGS = -lrt -lnetlink -lutil @AM_LDFLAGS@
if USE_MONGO
AM_LDFLAGS += -lmongoclient
endif
if USE_ZEROMQ
AM_LDFLAGS += -lzmq
endif

rfclient_SOURCES = libnetlink.hh Interface.hh HostEntry.hh RouteEntry.hh \
	SyncQueue.hh PendingRoute.hh PortMapper.hh PortMapper.cc fpm.h \
	fpm_lsp.h FPMServer.hh FPMServer.cc FlowTable.cc FlowTable.hh \
	RFClient.hh RFClient.cc

# For now, fpm.h and fpm_lsp.h are included in the rfclient/ directory, however
# when these headers are standardised in Quagga upstream, we should include
# them directly from the Quagga source path.

RFLIB_DIR=$(top_builddir)/rflib
# the additional libraries needed to link rfclient
rfclient_LDADD =  $(RFLIB_DIR)/librouteflow.a $(RFLIB_DIR)/ipc/librouteflow-ipc.a \
		  $(RFLIB_DIR)/types/librouteflow-types.a $(AM_LDFLAGS)
if LOCAL_BSON
rfclient_LDADD += $(RFLIB_DIR)/bson/libbson.a
endif
