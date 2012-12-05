"""This module defines messages for bookman communication in lavi.

Copyright (C) 2009 Stanford University
Created by ykk
"""
import struct
import threading
import lavimsg

class keep_alive_thread(threading.Thread):
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
                if (reply[1] == self.header.get_variable("MSG_ECHO ")):
                    print "Received echo, replying..."
                    self.channel.send(self.header.get_variable("MSG_ECHO_RESPONSE"),"")

    def stop(self):
        """Stop running listener
        """
        self.__stop_event.set()

def send_echo_req(laviheader, lavichannel):
    """Send echo request to lavi
    """
    sendxid = lavichannel.send(laviheader.get_variable("MSG_ECHO "),"")
    reply = lavichannel.receive()
    print "Echo response received"
    lavimsg.check_reply(reply, laviheader.get_variable("MSG_ECHO_RESPONSE "),sendxid)

def idle(laviheader, lavichannel):
    """Set up idle connection and listen for echo requests
    """
    listener = lavimsg.lavilistener(lavichannel, laviheader)
    listener.start()
    raw_input("Press Enter to Continue\n")
    listener.stop()

def keep_alive(laviheader, lavichannel):
    kat = keep_alive_thread(lavichannel, laviheader)
    kat.start()
    raw_input("Press Enter to Continue\n")
    kat.stop()
