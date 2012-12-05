#!/usr/bin/env python

import string
import sys

CDF_STEP = 0.001

def main(argv=None):
    index = 1
    if argv is None:
        argv = sys.argv
    else:
        index = 0

    if len(argv) < index + 1:
        print "usage: ./flooder_data_parser.py <FILENAME>"
        return -1

    # open the file
    fn = argv[index]
    try:
        fh = open(fn, mode='r')
    except IOError:
        print 'Unable to find', fn
        return -1

    lines = fh.readlines()
    for line in lines:
        if line.startswith('##'):
            processInfoLine(line[2:])

    finishStats()

def processInfoLine(line):
    l = line.split(' ')
    what = l[0]
    if what == 'SWITCH_JOIN':
        processSwitchJoin(l[1])
    elif what == 'SWITCH_LEAVE':
        processSwitchLeave(l[1])
    elif what == 'SWITCH_DESC':
        processSwitchDesc(l[1], l[2], l[3], l[4], l[5])
    elif what == 'QUERY_START':
        processQueryStart(int(l[1]), l[2], float(l[3]))
    elif what == 'QUERY_DONE':
        processQueryStop(int(l[1]), float(l[2]))
    else:
        print 'warning: unknown line type: %s' % what

class SimpleStats:
    def __init__(self):
        self.n = 0
        self.min =  1000000.0
        self.max = -1000000.0
        self.avg = 0.0

    def track(self, v):
        if v < self.min:
            self.min = v
        if v > self.max:
            self.max = v
        self.avg = ((self.avg * self.n) + v) / (self.n + 1)
        self.n = self.n + 1

class SwitchInfo:
    def __init__(self, strType):
        self.type = strType
        self.outstandingQueries = {}
        self.stats = SimpleStats()


class QueryInfo:
    def __init__(self, dpid, when):
        self.dpid = dpid
        self.start = when

switches = {}
outstandingQueries = {}
stats = SimpleStats()
latencies = []

def processSwitchJoin(dpid):
    pass

def processSwitchLeave(dpid):
    pass

def processSwitchDesc(dpid, hw, sw, num, mfr):
    switches[dpid] = SwitchInfo(getType(hw, sw, num, mfr))

def processQueryStart(xid, dpid, when):
    oq = switches[dpid].outstandingQueries
    oq[xid] = QueryInfo(dpid, when)
    outstandingQueries[xid] = dpid

def processQueryStop(xid, when):
    try:
        dpid = outstandingQueries.pop(xid)
        sw = switches[dpid]
        oq = sw.outstandingQueries
        qi = oq.pop(xid)
        latency = (when - qi.start) * 1000.0  # sec --> msec
        sw.stats.track(latency)
        stats.track(latency)
        latencies.append(latency)
    except KeyError:
        print 'warning: reply for missing request (xid=%u)' % xid

def getType(hw, sw, num, mfr):
    all = ('%s-%s-%s-%s' % (hw, sw, num, mfr)).strip()
    if all.find('NEC') != -1:
        return 'NEC'
    elif all.find('HP') != -1:
        return 'HP'
    elif all.find('Cisco') != -1:
        return 'Cisco'
    elif all.find('ap') != -1:
        return 'AP'
    elif (all.find('NY') != -1) or (all.find('losa') != -1):
        return 'I2'
    elif all.find('k101') != -1:
        return 'Japan'
    else:
        return '???-%s' % all

def finishStats():
    tOut = 0
    tComp = 0

    # print info about each switch
    for dpid in switches.keys():
        sw = switches.get(dpid)
        out = len(outstandingQueries)
        tOut += out
        comp = sw.stats.n - out
        tComp += comp
        fmt = '# %s: %s => outstanding=%u, completed=%u, min=%.1f avg=%.1f max=%.1f'
        print fmt % (dpid, sw.type, out, comp, sw.stats.min, sw.stats.avg, sw.stats.max)

    # print the CDF
    print 'CDF\tLatency(ms)'
    n = len(latencies)
    if n == 0:
        return

    latencies.sort()
    cdf = 0
    numSteps = 1.0 / CDF_STEP
    numPerStep = n / numSteps

    # first data point
    print '%.3f\t%.1f' % (0.0, latencies[0])

    # other data points
    for i in range(1, int(numSteps-1)):
        print '%.3f\t%.1f' % (i * CDF_STEP, latencies[int(i * numPerStep)])


    # last data point
    print '%.3f\t%.1f' % (100.0, latencies[n-1])

if __name__ == "__main__":
    sys.exit(main())
