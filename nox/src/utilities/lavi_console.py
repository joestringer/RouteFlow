#!/usr/bin/env python2.5
"""This script allows you to query a LAVI instance
from the console.

Copyright(C) Stanford University 2009
Author ykk
Date May 2009
"""
import sys
import getopt
import noxmsg
import lavimsg
import laviheader
import lavitopo
import laviproxy
import lavibookman
import laviflow

def usage():
    """Display usage
    """
    print "Usage "+sys.argv[0]+" <options> server command [arguments]\n"+\
          "Commands:\n"+\
          "echo\n\tSend echo request\n"+\
          "alive\n\tLive connection (to test LAVI periodic echo)\n"+\
          "idle\n\tIdle connection (to test LAVI periodic echo)\n"+\
          "query_node [nodeType=0]\n\tQuery for all nodes (of specific type) in the graph\n"+\
          "query_link <node (in hex)> [linkType=0]\n\tQuery for all links (of specific type) associated with node\n"+\
          "query_stat <stat type> <node (in hex)>\n\tQuery statistics from node\n"+\
          "\t<stat type>\tdesc\tdescription of switch\n"+\
          "view_flows\n\tSend flow subscription and see flow events\n"
    print "Options:\n"+\
          "-b/--bookman-header\n\tSpecify header file of lavi (default: $NOXPATH/"+\
          laviheader.BOOKMAN_MSG_FILENAME+")\n"+\
          "-m/--messenger-header\n\tSpecify header file of messenger (default: $NOXPATH/"+\
          laviheader.MESSENGER_FILENAME+")\n"+\
          "-h/--help\n\tPrint this usage guide\n"+\
          "-p/--port\n\tSpecify port number of lavi (default:2503)\n"

#Parse options and arguments
#Port number to connect to
portNo=2503
#Filename of header file
headerfile=""
#Filename of messenger header file
msgheaderfile=""
try:
    opts, args = getopt.getopt(sys.argv[1:], "hp:b:m:",
                               ["help","port=","bookman-header=","messenger-header="])
except getopt.GetoptError:
    usage()
    sys.exit(2)

#Check there is only 1 input file
if (len(args) < 2):
    usage()
    sys.exit(2)

#Parse options
for opt,arg in opts:
    if (opt in ("-h","--help")):
        usage()
        sys.exit(0)
    elif (opt in ("-p","--port")):
        portNo = int(arg)
    elif (opt in ("-b","--bookman-header")):
        headerfile = arg
    elif (opt in ("-m","--messenger-header")):
        msgheaderfile = arg
    else:
        assert (False,"Unhandled option :"+opt)

#Process commands
cmd=args[1]
lavichannel = lavimsg.lavichannel(noxmsg.NOXChannel(args[0], portNo))
laviheader = laviheader.laviheader(headerfile, msgheaderfile)

if (cmd=="echo"):
    #Send echo request
    lavibookman.send_echo_req(laviheader,lavichannel)
elif (cmd=="idle"):
    #Idle connection
    lavibookman.idle(laviheader,lavichannel)
elif (cmd=="alive"):
    #Live connection
    lavibookman.keep_alive(laviheader,lavichannel)
elif (cmd=="query_node"):
    #Query node
    if (len(args) < 3):
        nodetype=0
    else:
        nodetype=int(args[2])
    lavitopo.send_node_query(laviheader,lavichannel, nodetype)
elif (cmd=="query_link"):
    #Query link
    if (len(args) < 3):
        print "query_link requires node id as argument!"
        raise SystemExit
    else:
        node = int("0x"+args[2],16)
    if (len(args) < 4):
        linktype=0
    else:
        linktype=int(args[3])
    lavitopo.send_link_query(laviheader,lavichannel, node, linktype)
elif (cmd=="query_stat"):
    #Query stat
    if (len(args) < 4):
        print "query_state requires stat type and node id as argument!"
        raise SystemExit
    else:
        stattype = laviproxy.STATTYPE.index(args[2])
        node = int("0x"+args[3],16)
    laviproxy.send_stat_query(laviheader,lavichannel, node, stattype)
elif (cmd=="view_flows"):
    #View flows events
    laviflow.send_flow_subscribe(laviheader, lavichannel)
else:
    print "Unknown command :"+cmd
