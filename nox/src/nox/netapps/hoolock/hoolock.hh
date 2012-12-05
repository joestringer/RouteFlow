/* Copyright 2008 (C) Nicira, Inc.
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef HOOLOCK_HH
#define HOOLOCK_HH 1

#include <iostream>

#include "component.hh"
#include "config.h"
#include "netinet++/ethernet.hh"
#include "netinet++/datapathid.hh"
#include "flow-mod-event.hh"
#include "authenticator/flow_in.hh"
#include <string.h>
#include <pthread.h>
#include <map>
#include "hash_map.hh"
#include "topology/topology.hh"
#include "flow.hh"
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <xercesc/dom/DOM.hpp>
#include "openflow/openflow.h"
#include "flowdb/flowdb.hh"
#include "mobiledb/mobiledb.hh"
#include "routing/routing.hh"
#include "routeinstaller/routeinstaller.hh"
#include "routeinstaller/network_graph.hh"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

#include "assert.hh"
#include "datapath-leave.hh"
#include "error-event.hh"
#include "flow-stats-in.hh"
#include "nox.hh"
#include "storage/storage.hh"
#include "bindings_storage/bindings_storage.hh"

using namespace std;
using namespace vigil;
using namespace vigil::container;
using namespace vigil::applications;

namespace vigil {
namespace applications {


#ifdef LOG4CXX_ENABLED
static log4cxx::LoggerPtr lg(log4cxx::Logger::getLogger("nox.netapps.hoolock"));
#else
static Vlog_module lg("hoolock");
#endif


class Hoolock
    : public Component {
            public:
                    Hoolock(const Context*, const xercesc::DOMNode*);
                    ~Hoolock() { }
                    static void getInstance(const container::Context*, Hoolock*&);
                    void configure(const Configuration*);
                    void install() { }

            private:
                    FlowDB *flowdb;
                    MobileDB *mobiledb;
                    routeinstaller *rinstaller;
                    Disposition handle_flow_in(const Event&);
                    Disposition handle_snmp_host_event(const Event&);
                    bool belongs(datapathid& dpid, BindPointPtrList assocAP);
};

}
}

#endif // HOOLOCK_HH
