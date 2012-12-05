# FSLatency - a very simple app designed to measure flow setup latency as experienced by a client
# David Underhill

from nox.lib.core                import Component, openflow
from nox.lib.netinet             import netinet
from nox.lib.packet.ethernet     import ethernet
from nox.netapps.routing         import pyrouting
from time                        import time

# a switch-port pair
class SwitchPort:
    def __init__(self, dpid, port):
        self.dpid = dpid
        self.port = port

# populate the list of switch-port pairs available from a config file
def loadSwitchPortInfo():
    fh = open('./nox/coreapps/examples/switches_info.txt', mode='r')
    lines = fh.readlines()
    for line in lines:
        s = line.split(' ')
        varName = s[0]
        dpid = long(s[1].replace(':',''), 16)
        port = int(s[0].split('_')[1])
        globals()[varName] = SwitchPort(dpid, port)
(lambda : loadSwitchPortInfo())()

# number of switches to wait for before starting the experiment
SWITCH_WAIT_COUNT = 15

# Ethernet type of our magic packet
MAGIC_DL_TYPE = 0x7777
MAGIC_DL_SRC = "\x00\x77\x77\x77\x77\x77"
MAGIC_DL_DST = "\x00\x77\x77\x77\x77\x77"
MAGIC_DL_SRC_VAL = 0x777777777777
MAGIC_DL_DST_VAL = 0x777777777777

# lifetime of the flow in seconds
FLOW_LIFETIME = 5

# number of magic packets for measurement
NUM_PACKETS_TO_MEASURE_TRIP_TIME = 100

# input for running a trial
class FSTrial():
    def __init__(self, sender, intermediate_hops, sink):
        self.sender  = sender                   # switch which will source the magic packets
        self.src     = intermediate_hops[0]     # first hop on the path (e.g. right after the sender)
        self.ihops   = intermediate_hops        # intermediate hops on the path
        self.dst     = intermediate_hops[-1]    # last hop on the path (e.g. right before the sink)
        self.sink    = sink                     # switch which will "receive" the magic packet
        self.numHops = len(intermediate_hops)   # number of hops in the path
        self.route   = None                     # used for computing routing info for flows

        # trial stats
        self.start = -1                         # when the most recent magic packet was sent
        self.numPacketsMeasuredForTripTime = 0  # number of extra packets sent to measure trip time
        self.avgTripTime = -1                   # average trip time from sourcing to receipt
        self.timeForFirstPacket = -1            # time for the first magic packet to reach its dst

    def initRoute(self, routing):
        # create the route object which we'll use to install the flow later
        route = pyrouting.Route()
        route.id.src  = netinet.datapathid.from_host(self.src.dpid)
        route.id.dst  = netinet.datapathid.from_host(self.dst.dpid)
        route.inport  = self.src.port
        route.outport = self.dst.port
        outport = None
        for hop in self.ihops:
            if outport != None:
                link = pyrouting.Link()
                link.outport = outport
                link.dst = netinet.datapathid.from_host(hop.dpid)
                link.inport = hop.port
                route.path.append(link)

            outport = hop.port
        if not routing.get_route(route):
            raise Exception('failed to compute route')
        else:
            self.route = route

# input: list of paths to try
TRIALS = [ FSTrial(CISCO_0, [NEC1_0, NEC2_0, HP1_2], NF2_1) ]

# input: number of runs per path
RUNS_PER_TRIAL = 1

# manages and runs flow setup trials
class FSLatency(Component):
    def getInterface(self):
        return str(FSLatency)

    def install(self):
        self.register_for_datapath_join( lambda dpid, stats : self.datapath_join_callback(dpid,stats))
        self.register_for_packet_in(self.handle_packet_in)
        self.routing = self.resolve(pyrouting.PyRouting)

    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.trial_on = -1
        self.run_on = 0
        self.trial = None
        self.num_connected_switches = 0

        # build a flow for the routes
        self.flow = netinet.Flow()
        self.flow.dl_vlan  = 0xFFFF
        self.flow.dl_src   = netinet.ethernetaddr(MAGIC_DL_SRC_VAL)
        self.flow.dl_dst   = netinet.ethernetaddr(MAGIC_DL_DST_VAL)
        self.flow.dl_type  = MAGIC_DL_TYPE
        self.flow.nw_src   = 0
        self.flow.nw_dst   = 0
        self.flow.nw_proto = 0
        self.flow.tp_src   = 0
        self.flow.tp_dst   = 0

        self.actions = None

    # starts the next trial
    def start_next_trial(self):
        if self.trial_on >= len(TRIALS):
            print '## Done running all trials'
            return

        self.start_trial(TRIALS[self.trial_on])
        self.run_on += 1
        if self.run_on >= RUNS_PER_TRIAL:
            self.trial_on += 1
            self.run_on = 0

        print '## Started trial %u of %u' % (self.trial_on, len(TRIALS))

    # starts the specified trial (e.g. one flow path setup)
    def start_trial(self, trial):
        self.trial = trial
        self.trial.initRoute()
        self.flow.in_port = self.trial.src.port

        # no-op actions along the paths (just forward it)
        self.actions = []
        rlen = self.trial.route.path.size()
        for _ in xrange(rlen + 1):
            action = self.make_action_array([])
            self.actions.append(action)

        self.send_magic_packet()

    # called when a trial is over; outputs stats and then starts the next trial
    def trial_over(self):
        t = self.trial
        print 'RESULT %u %.3f %.3f' % (t.numHops, t.timeForFirstPacket - t.avgTripTime, t.avgTripTime)

        # start the next trial after we've waited long enough for this one's flows to expire
        self.post_callback(FLOW_LIFETIME + 3, self.start_next_trial)

    # handle magic packets (ignore others)
    def handle_packet_in(self, dpid, inport, reason, len, bufid, packet):
        if packet.type == MAGIC_DL_TYPE:
            if (dpid == self.trial.sink.dpid) and (inport == self.trial.sink.port):
                self.magic_packet_recv(time())
            else:
                self.setup_flow(dpid, inport, bufid, packet)

    # setup the flow for the received packet
    def setup_flow(self, dpid, inport, bufid, packet):
        t = self.trial
        self.routing.setup_route(self.flow, t.route, t.src.port, t.dst.port, FLOW_LIFETIME, self.actions, False)

        if bufid == 0xFFFFFFFF: # sent if whole packet sent to us
            self.send_openflow_packet(dpid, packet.arr, openflow.OFPP_TABLE, inport)
        else:
            self.send_openflow_buffer(dpid, bufid, openflow.OFPP_TABLE, inport)

    # handle receipt of magic packet
    def magic_packet_recv(self, when):
        t = self.trial
        diff = when - t.start
        if(t.timeForFirstPacket < 0):
            t.timeForFirstPacket = diff
        else:
            # update our trip time estimate
            t.numPacketsMeasuredForTripTime += 1
            n = t.numPacketsMeasuredForTripTime
            if n == 1:
                t.avgTripTime = float(diff)
            else:
                t.avgTripTime = ((n-1)*t.avgTripTime + diff) / float(n)

        # determine the trip time
        if self.trial.numPacketsMeasuredForTripTime < NUM_PACKETS_TO_MEASURE_TRIP_TIME:
            self.send_magic_packet()
        else:
            self.trial_over()

    # sends a magic packet
    def send_magic_packet(self):
        eth = ethernet()
        eth.dst = MAGIC_DL_DST
        eth.src = MAGIC_DL_SRC
        eth.type = MAGIC_DL_TYPE
        self.trial.start = time()
        self.send_openflow(self.trial.sender.dpid, None, eth.tostring(), self.trial.sender.port)

    # used to track the number of switches which have connected
    def datapath_join_callback(self, dpid, stats):
        self.num_connected_switches += 1
        if (self.num_connected_switches == SWITCH_WAIT_COUNT) and (self.trial_on < 0):
            self.trial_on = 0
            self.start_next_trial()

def getFactory():
    class Factory:
        def instance(self, ctxt):
            return FSLatency(ctxt)

    return Factory()
