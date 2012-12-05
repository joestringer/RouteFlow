"""This module defines messages for proxying to OpenFlow in lavi.

Copyright (C) 2009 Stanford University
Created by ykk
"""
import struct
import lavitopo
import lavimsg
import sys

STATTYPE=["desc"]

def send_stat_query(laviheader, lavichannel, node, stattype):
    """Query for statistics associated with node
    """
    cmd = struct.pack(">QHH",node,stattype,0)
    sendxid = lavichannel.send(laviheader.get_variable("BOOKT_STAT_REQ"),
                               cmd)

    reply = lavichannel.receive()
    lavimsg.check_reply(reply, laviheader.get_variable("BOOKT_STAT "),sendxid)
    lavimsg.print_lavimsg(reply, laviheader)
