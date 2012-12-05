"""This module defines messages for topology query in lavi.

Copyright (C) 2009 Stanford University
Created by ykk
"""
import struct
import lavimsg

def send_link_query(laviheader,lavichannel, node, linktype):
    """Query for link associated with node.
    """
    cmd=struct.pack(">BHHQ",laviheader.get_variable("BOOKR_ONETIME"),linktype,
                    laviheader.get_variable("BOOKN_UNKNOWN"),node)
    sendxid=lavichannel.send(laviheader.get_variable("BOOKT_LINKS_REQ"),cmd)

    reply=lavichannel.receive()
    lavimsg.check_reply(reply, laviheader.get_variable("BOOKT_LINKS_ADD "),sendxid)
    lavimsg.print_lavimsg(reply, laviheader)

def send_node_query(laviheader,lavichannel, nodetype):
    """Query for nodes.
    """
    cmd=struct.pack(">BH",laviheader.get_variable("BOOKR_ONETIME"),nodetype)
    sendxid=lavichannel.send(laviheader.get_variable("BOOKT_NODES_REQ"),cmd)
    reply=lavichannel.receive()
    lavimsg.check_reply(reply, laviheader.get_variable("BOOKT_NODES_ADD "),sendxid)
    lavimsg.print_lavimsg(reply, laviheader)
