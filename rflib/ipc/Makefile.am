noinst_LIBRARIES = librouteflow-ipc.a
librouteflow_ipc_a_CXXFLAGS = -I$(top_srcdir)/rflib -I$(with_bson) @AM_CXXFLAGS@

librouteflow_ipc_a_SOURCES = IPC.cc RFProtocol.cc \
	RFProtocolFactory.cc
if USE_MONGO
librouteflow_ipc_a_SOURCES += MongoIPC.cc
librouteflow_ipc_a_CXXFLAGS += -I/usr/include/mongo
endif
if USE_ZEROMQ
librouteflow_ipc_a_SOURCES += ZeroMQIPC.cc
endif

