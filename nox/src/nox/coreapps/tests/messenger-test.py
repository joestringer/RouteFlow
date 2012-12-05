#!/usr/bin/python2.5
import noxmsg

print 'Testing messenger...'
noxchannel = noxmsg.NOXChannel('127.0.0.1');
noxchannel.send(10,"test")
print 'Sent message of length 7 via TCP'

noxsslchannel = noxmsg.NOXSSLChannel('127.0.0.1');
noxsslchannel.send(10,"testing")
print 'Sent message of length 10 via SSL'
