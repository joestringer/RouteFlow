"""This module defines message channel for lavi.

Copyright (C) 2009 Stanford University
Created by ykk
"""
import struct
import random
import socket
import threading
import noxmsg

LENGTH_PER_NODE=10
LENGTH_PER_LINK=34

def parse_dpid(msg):
    """Parse dpid from message
    """
    r=struct.unpack(">Q",msg)
    return (0xffffffffffffffff & r[0])

def node_string(msg):
    """Return string about node
    """
    node = parse_node(msg)
    return "Datapath ID %x " % node[1] + "(type %x)" % node[0]

def parse_node(msg):
    """Parse node from message
    """
    r=struct.unpack(">HQ",msg)
    return ((0xffff & r[0]),
            (0xffffffffffffffff & r[1]))

def link_string(msg):
    """Return string about link
    """
    link=parse_link(msg)
    return "Link %x:" % link[2] + "%x" % link[3] + \
           "->%x:" % link[5] + "%x" % link[6]+\
           " of type %x" % link[0]+\
           " and rate "+str(link[7])

def parse_link(msg):
    """Parse link from message
    """
    r=struct.unpack(">HHQHHQHQ",msg)
    return ((0xffff & r[0]),
            (0xffff & r[1]),
            (0xffffffffffffffff & r[2]),
            (0xffff & r[3]),
            (0xffff & r[4]),
            (0xffffffffffffffff & r[5]),
            (0xffff & r[6]),
            (0xffffffffffffffff & r[7]))

def flow_string(msg):
    """Return flow of flow and residual data
    """
    (num_hops, flow_id,
     src_node_string, dst_node_string, hop_list,
     data) = parse_flow(msg)
    return ("Flow "+str(flow_id)+" with "+str(num_hops)+" hops",
            src_node_string, dst_node_string, hop_list,
            data)

def parse_flow(msg):
    """Parse flow information from message
    """
    (type, flow_id)=struct.unpack(">HL",msg[0:6])
    src_node_string=flow_node_port_string(msg[6:18])
    dst_node_string=flow_node_port_string(msg[18:30])
    num_hops=struct.unpack(">H",msg[30:32])[0]
    data = msg[32:]
    hop_list = []
    for i in range(0,num_hops):
        hop_list.append(flow_hop_string(data[0:14]))
        data = data[14:]
    return (0xffffffff & num_hops,
            0xffffffff & flow_id,
            src_node_string, dst_node_string, hop_list,
            data)

def flow_node_port_string(msg):
    """Return string flow node-port
    """
    (type, dpid, port) = parse_flow_node_port(msg)
    return "%x" % dpid +"("+str(type)+"):"+str(port)

def parse_flow_node_port(msg):
    """Parse book_flow_node_port
    """
    r=struct.unpack(">HQH",msg)
    return ((0xffff & r[0]),
            (0xffffffffffffffff & r[1]),
            (0xffff & r[2]))

def flow_hop_string(msg):
    """Return string flow node-port
    """
    (inport, type, dpid, outport) = parse_flow_hop(msg)
    return str(inport)+":%x" % dpid +"("+str(type)+"):"+str(outport)

def parse_flow_hop(msg):
    """Parse book_flow_hop
    """
    r=struct.unpack(">HHQH",msg)
    return ((0xffff & r[0]),
            (0xffff & r[1]),
            (0xffffffffffffffff & r[2]),
            (0xffff & r[3]))


class lavichannel:
    """Channel for lavi.
    """
    def __init__(self, noxchannel):
        """Initialize with NOXChannel
        """
        self.channel = noxchannel

    def send(self,type,cmd):
        """Send command with lavi header appended.
        Return xid of command sent.
        """
        xid = random.randrange(0,0xffffffff)
        self.channel.send(type,
                          struct.pack(">L",xid)+cmd)
        return xid

    def receive(self, recvLen=0,timeout=0):
        """Receive command
        If length == None, nonblocking receive (return None or message)
        With nonblocking receive, timeout is used for select statement

        If length is zero, receive single message.

        If reply is > 7 in length, parse lavi header,
        and return tuple (length,type,xid,msg)
        with the first three in host order.
        Else, return only raw message.
        """
        reply=self.channel.receive(recvLen, timeout)
        if (reply==None or len(reply) < 7):
            return reply
        else:
            r = struct.unpack(">HBL",reply[0:7]);
            return ((0xffff & r[0]), r[1],
                    (0xffffffff & r[2]),
                    reply[7:])

class lavilistener(threading.Thread):
    """Channel listener for lavi.
    """
    def __init__(self, lavichannel,laviheader):
        threading.Thread.__init__(self)
        ##Event to stop thread
        self.__stop_event = threading.Event()
        ##Channel to receive messages
        self.channel = lavichannel
        ##Reference to lavi header
        self.header = laviheader

    def run(self):
        """Loop in thread
        """
        while not self.__stop_event.isSet():
            reply = self.channel.receive(None)
            if (reply != None):
                print_lavimsg(reply, self.header)

    def stop(self):
        """Stop running listener
        """
        self.__stop_event.set()

def check_reply(reply,expected_type,expected_xid):
    """Check xid and reply type
    """
    if not (reply[1] == expected_type):
        print "Warning reply is of wrong type "+\
              str(reply[1])
    if (expected_xid != reply[2]):
        print "Warning xid wrong! Sending xid is %x" % expected_xid +\
              " while received xid %x" % reply[2]

def print_lavimsg(msg, laviheader):
    if (msg[1] == laviheader.get_variable("MSG_ECHO ")):
        print "Echo request"
    elif (msg[1] == laviheader.get_variable("BOOKT_STAT ")):
        #Stat type
        stattype = struct.unpack(">H",msg[3][9:11])[0]
        if (stattype == 0):
            #Description type
            print "Switch datapath id:\t\t%x" % parse_dpid(msg[3][0:8])
            print "Manufacturer's description:\t"+msg[3][12:268]
            print "Hardware description:\t\t"+msg[3][268:524]
            print "Software description:\t\t"+msg[3][524:780]
            print "Serial number:\t\t\t"+noxmsg.stringarray(msg[3][780:812])
        else:
            print "Unrecognized OpenFlow statistics type "+stattype
    elif (msg[1] == laviheader.get_variable("BOOKT_NODES_ADD")):
        #Node reply
        nodeNo = len(msg[3])/LENGTH_PER_NODE
        print "Reply of length "+str(msg[0])+\
              " received, i.e., "+str(nodeNo)+" nodes"
        for i in range(0,nodeNo):
            print "\t "+\
                  node_string(msg[3][i*LENGTH_PER_NODE:(i+1)*LENGTH_PER_NODE])
    elif (msg[1] == laviheader.get_variable("BOOKT_LINKS_ADD")):
        #Link reply
        linkNo = len(msg[3])/LENGTH_PER_LINK
        print "Reply of length "+\
              str(msg[0])+\
              " received, i.e., "+\
              str(linkNo)+\
              " links"
        for i in range(0,linkNo):
            print "\t "+\
                  link_string(msg[3][i*LENGTH_PER_LINK:(i+1)*LENGTH_PER_LINK])
    elif (msg[1] == laviheader.get_variable("BOOKT_FLOWS_ADD") or
          msg[1] == laviheader.get_variable("BOOKT_FLOWS_DEL")):
        #Flow reply
        if (msg[1] == laviheader.get_variable("BOOKT_FLOWS_ADD")):
            type="add"
        elif (msg[1] == laviheader.get_variable("BOOKT_FLOWS_DEL")):
            type="del"
        else:
            type="unknown"
        num_flows = struct.unpack(">L",msg[3][0:4])[0]
        print "Flow ("+type+") of length "+str(msg[0])+\
              " with "+str(num_flows)+" flow(s)"
        data = msg[3][4:]
        for i in range(0, num_flows):
            (flowstring,
             src_node_string,dst_node_string, hop_list,
             data) = flow_string(data)
            print "\t"+flowstring
            print "\t\t"+src_node_string
            for hop in hop_list:
                print "\t\t"+hop
            print "\t\t"+dst_node_string
        print "\t"+str(len(data))+" bytes of data left"
    else:
        print "Unrecognized lavi message of type"+msg[1]
