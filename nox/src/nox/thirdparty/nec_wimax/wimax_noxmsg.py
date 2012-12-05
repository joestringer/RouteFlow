#!/usr/bin/python
from socket import *
from struct import *

def htonll(value):
    val = unpack("LL",pack("Q",value))
    return unpack("Q",pack("LL",htonl(val[1]),htonl(val[0])))[0]

def printNoxMsg(msg):
    for i in range(0,len(msg)):
	print str(ord(msg[i])),
    print

dpid = int("0xdb913b274",16)
wimaxhost = "0.0.0.0"
wimaxport = int("0x791a",16)
noxhost = "172.24.74.117"
noxport = 2603
noxmsgtype = 17
noxwimaxjointype = 1
noxwimaxleavetype = 2
wirelessport=2
clientmac=int("0x1cf0ee5ad1",16)
#Note received[7] is client MAC on wimax
#Note received[8] is wimax basestation MAC

print "WiMAX Host : "+wimaxhost
print "WiMAX Port : "+str(wimaxport)
print "NOX Host : "+noxhost
print "NOX Port : "+str(noxport)

TCPSock = socket(AF_INET,SOCK_STREAM)
TCPSock.connect((noxhost,noxport))
UDPSock = socket(AF_INET,SOCK_DGRAM)
UDPSock.bind((wimaxhost,wimaxport))

while 1:
    (data,addr) = UDPSock.recvfrom(30)
    print "Got data, length = " + str(len(data))
    if (len(data) == 28):
        received = unpack('BBBBHHLQQ',data)
        print received

        if (received[0] == 1):
            print "Received Link Establishment Request"
            noxmsg = pack('HBBQQH',
                          htons(22),noxmsgtype,
                          noxwimaxjointype,
                          htonll(clientmac),htonll(dpid),htons(wirelessport))
            printNoxMsg(noxmsg)
            TCPSock.send(noxmsg)

        elif (received[0] == 3):
            print "Received Link Release Request"
            noxmsg = pack('HBBQQH',
                          htons(22),noxmsgtype,
                          noxwimaxleavetype,
                          htonll(clientmac),htonll(dpid),htons(wirelessport))
            printNoxMsg(noxmsg)
            TCPSock.send(noxmsg)
