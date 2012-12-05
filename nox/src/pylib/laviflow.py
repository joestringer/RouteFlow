"""This module defines messages for communication with lavi about flows.

Copyright (C) 2009 Stanford University
Created by ykk
"""
import struct
import lavimsg

def send_flow_subscribe(laviheader, lavichannel):
    """Send flow subscribe to lavi and listen for flows
    """
    cmd = struct.pack(">BH",
                      laviheader.get_variable("BOOKR_SUBSCRIBE"),
                      laviheader.get_variable("BOOKF_UNKNOWN"))
    lavichannel.send(laviheader.get_variable("BOOKT_FLOWS_REQ"),
                     cmd)
    listener = lavimsg.lavilistener(lavichannel, laviheader)
    listener.start()
    raw_input("Press Enter to Continue\n")
    cmd = struct.pack(">BH",
                      laviheader.get_variable("BOOKR_UNSUBSCRIBE"),
                      laviheader.get_variable("BOOKF_UNKNOWN"))
    listener.stop()
