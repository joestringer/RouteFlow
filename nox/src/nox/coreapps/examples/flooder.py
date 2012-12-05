# Flooder - a very simple app designed to stress the network with stat requests
# David Underhill

from nox.lib.core import Component
from nox.lib.packet.packet_utils import longlong_to_octstr
from time import time

# the number of times to query for stats **per switch** per second
QPS = 10.0

# time from start of component until it will start querying switches
WARMUP_DELAY_SEC = 120.0

# minimum callback interval in sec (reduce callback frequency by batching queries when QPS high)
MIN_CALLBACK_INTERVAL = 0.05

class Flooder(Component):
    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.switches = {}              # maps DPIDs to switch description (or None if not present)
        self.numSwitches = 0            # current number of switches in the network
        self.requestLineup = []         # list of DPIDs to query (first = next)
        self.nextRequestLineupIndex = 0 # index in self.requestLineup which will be queried next
        self.nextXID = 10000            # next transaction ID to use
        self.intervalPerQueryCallback=1 # interval between queries to each switch
        self.queriesPerInterval = 1     # number of queries per interval

        # start the query loop once NOX has had time to warmup (e.g., tell us about switches)
        self.post_callback(WARMUP_DELAY_SEC, lambda : self.query_timer())

    def getInterface(self):
        return str(Flooder)

    def install(self):
        # have nox tell us which switches are in our network
        self.register_for_datapath_join( lambda dpid, stats : self.datapath_join_callback(dpid,stats))
        self.register_for_datapath_leave(lambda dpid :        self.datapath_leave_callback(dpid))

        # tell nox we want to handle stats replies
        self.register_for_desc_stats_in( lambda dpid, desc :  self.desc_stats_in_handler(dpid,desc))
        self.register_for_port_stats_in( lambda dpid, ports:  self.port_stats_in_handler(dpid,ports))

    # set the interval per query per switch
    def setNumSwitches(self, n):
        self.numSwitches = n
        if self.numSwitches > 0:
            qpsps = self.numSwitches * QPS
            self.intervalPerQueryCallback = 1.0 / qpsps

            # batch queries, if needed, to keep the interval per callback reasonable
            if self.intervalPerQueryCallback < MIN_CALLBACK_INTERVAL:
                self.queriesPerInterval = int(MIN_CALLBACK_INTERVAL / self.intervalPerQueryCallback) + 1
                self.intervalPerQueryCallback =  self.queriesPerInterval / qpsps
            else:
                self.queriesPerInterval = 1
        else:
            self.intervalPerQueryCallback = 1  # sleep in 1sec intervals while waiting for a switch

    # handle the addition of a switch to the network
    def datapath_join_callback(self, dpid, stats):
        print '##SWITCH_JOIN %s' % longlong_to_octstr(dpid)[6:]
        self.ctxt.send_desc_stats_request(dpid)  # figure out info about this switch

    # handle the removal of a switch from the network
    def datapath_leave_callback(self, dpid):
        print '##SWITCH_LEAVE %s' % longlong_to_octstr(dpid)[6:]
        if self.switches.has_key(dpid):
            del self.switches[dpid]
            self.setNumSwitches(self.numSwitches - 1)
            self.requestLineup.remove(dpid)
            if self.nextRequestLineupIndex >= self.numSwitches:
                self.nextRequestLineupIndex = 0

    # handle switch description reply
    def desc_stats_in_handler(self, dpid, desc):
        print '##SWITCH_DESC %s %s' % (longlong_to_octstr(dpid)[6:], desc_to_str(desc))
        self.switches[dpid] = desc
        self.setNumSwitches(self.numSwitches + 1)
        self.requestLineup.append(dpid)

    # sends the next interval's worth of queries, as appropriate
    def query_timer(self):
        # query the next switch if there are any to query
        if self.numSwitches > 0:
            for _ in range(0, self.queriesPerInterval):
                self.send_query()

        # ask for another callback
        self.post_callback(self.intervalPerQueryCallback, lambda : self.query_timer())

    # send a single query
    def send_query(self):
        dpid = self.requestLineup[self.nextRequestLineupIndex]
        self.nextRequestLineupIndex = (self.nextRequestLineupIndex + 1) % self.numSwitches
        xid = self.nextXID
        self.nextXID += 1
        now = time()
        self.ctxt.send_port_stats_request_with_xid(dpid, xid)
        print '##QUERY_START %u %s %f' % (xid, longlong_to_octstr(dpid)[6:], now)


    # handle port stats reply
    def port_stats_in_handler(self, dpid, ports):
        now = time()
        p = ports[0]
        xid = p['rx_crc_err'] # hacked nox to put xid in this magic field
        print '##QUERY_DONE %u %f' % (xid, now)

def desc_to_str(desc):
    return '%s %s %s %s' % (desc['hw_desc'].replace(' ', '_'),
                            desc['sw_desc'].replace(' ', '_'),
                            desc['serial_num'].replace(' ', '_'),
                            desc['mfr_desc'].replace(' ', '_'))

def getFactory():
    class Factory:
        def instance(self, ctxt):
            return Flooder(ctxt)

    return Factory()
