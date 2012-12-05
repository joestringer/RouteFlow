"""This module defines messages used by messaging to and from NOX.

Copyright (C) 2009 Stanford University
Created by ykk
See messenger
"""
import socket
import struct
import sys
import select

def stringarray(string):
    """Output array of binary values in string.
    """
    arrstr = ""
    if (len(string) != 0):
        for i in range(0,len(string)):
            arrstr += "%x " % struct.unpack("=B",string[i])[0]
    return arrstr

def printarray(string):
    """Print array of binary values
    """
    print "Array of length "+str(len(string))
    print stringarray(string)

def htonll(value):
    val = struct.unpack("=HHHH",struct.pack("=Q",value))
    return struct.unpack("=Q",struct.pack("=HHHH",socket.htons(val[3]),socket.htons(val[2]),socket.htons(val[1]),socket.htons(val[0])))[0]

def ntohll(value):
    val = struct.unpack("=HHHH",struct.pack("=Q",value))
    return struct.unpack("=Q",struct.pack("=HHHH",socket.ntohs(val[3]),socket.ntohs(val[2]),socket.ntohs(val[1]),socket.ntohs(val[0])))[0]

class NOXMsg:
    """Base class for messages to NOX.
    If not extended provides the disconnect message.
    """
    def __init__(self):
        """Initialization.
        """
        ##Type of message
        self.type = 0;

    def __repr__(self):
        """Provide message to send
        """
        return "";

class NOXChannel:
    """TCP channel to communicate to NOX with.
    """
    def __init__(self,ipAddr,portNo=2603,debug=False):
        """Initialize with socket
        """
        ##Socket reference for channel
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((ipAddr,portNo))
        self.debug = debug
        ##Internal buffer for receiving
        self.__buffer = ""

    def baresend(self,cmd):
        """Send bare message
        """
        msg =struct.pack(">H",len(str(cmd))+2)+str(cmd)
        self.sock.send(msg)
        if (self.debug):
            printarray(msg)

    def send(self,type,cmd):
        """Send message of certain type
        """
        self.baresend(struct.pack(">B",type)+str(cmd))

    def sendMsg(self,msg):
        """Send message that is NOXMsg
        """
        if isinstance(msg, NOXMsg):
            self.send(msg.type, msg)

    def receive(self, recvLen=0,timeout=0):
        """Receive command
        If length == None, nonblocking receive (return None or message)
        With nonblocking receive, timeout is used for select statement

        If length is zero, return single message
        """
        if (recvLen==0):
            #Receive full message
            msg=""
            length=3
            while (len(msg) < length):
                msg+=self.sock.recv(1)
                #Get length
                if (len(msg) == 2):
                    length=struct.unpack(">H",msg)[0]
            return msg
        elif (recvLen==None):
            #Non-blocking receive
            ready_to_read = select.select([self.sock],[],[],timeout)[0]
            if (ready_to_read):
                self.__buffer += self.sock.recv(1)
            if (len(self.__buffer) >= 2):
                length=struct.unpack(">H",self.__buffer[0:2])[0]
                if (length == len(self.__buffer)):
                    msg = self.__buffer
                    self.__buffer = ""
                    return msg
            return None
        else:
            #Fixed length blocking receive
            return self.sock.recv(recvLen)

    def __del__(self):
        """Terminate connection
        """
        self.sendMsg(NOXMsg())
        self.sock.shutdown(1)
        self.sock.close()

class NOXSSLChannel(NOXChannel):
    """SSL channel to communicate to NOX with.
    """
    def __init__(self, ipAddr, portNo=1304,debug=False):
        """Initialize with SSL sock
        """
        NOXChannel.__init__(self, ipAddr, portNo,debug)
        ##Reference to SSL socket for channel
        self.sslsock = socket.ssl(self.sock)

    def baresend(self,cmd):
        """Send bare message"""
        self.sslsock.write(struct.pack("=H",socket.htons(len(str(cmd))+2))\
                           +str(cmd))
