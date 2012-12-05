#!/usr/bin/python
from socket import *
from struct import *

wimaxhost = "0.0.0.0"
wimaxport = int("0x791a",16)
noxhost = "172.27.74.153"
noxport = 2603
noxmsgtype = 17
noxwimaxjointype = 1
noxwimaxleavetype = 2
wirelessport=1

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
    if (len(data) == 28):
        received = unpack('BBBBHHLQQ',data)
        print received
        if (received[0] == 1):
            print "Received Link Establishment Request"
            noxmsg = pack('HBBQQH',
                          htons(20),
                          noxmsgtype,noxwimaxjointype,
                          received[7],received[8],htons(wirelessport))
            TCPSock.send(noxmsg)

        elif (received[0] == 3):
            print "Received Link Release Request"
            noxmsg = pack('HBBQQH',
                          htons(20),
                          noxmsgtype,noxwimaxleavetype,
                          received[7],received[8],htons(wirelessport))
            TCPSock.send(noxmsg)
