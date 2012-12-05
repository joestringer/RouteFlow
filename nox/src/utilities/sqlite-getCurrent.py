#!/usr/bin/env python2.5
"""This script gathers and prints current FlowCount statistics.
Displays TotalFlow,CtrlFlow,UserFlow=(TotalFlow-CtrlFlow),TotalUser

Run sqlite-getCurrent.py --help to see help for usage

Dependency: sqlite3

Copyright(C) Stanford University 2009
Author ykk
Date April 2009
"""
import mysqlite
import getopt
import sys

def usage():
    """Display usage
    """
    print "Usage "+sys.argv[0]+" [sqlite filename]\n"+\
          "Finds the latest SQLite file in current directory "+\
          "if no filename is supplied\n."

#Parse options and arguments
try:
    opts, args = getopt.getopt(sys.argv[1:], "", [])
except getopt.GetoptError:
    usage()
    sys.exit(2)

#Check there is only 1 input file
##Filename of SQLite DB
filename = ""
if not (len(args) == 1):
    filename =  mysqlite.get_latest_sqlite()
    if (filename == None):
        print "No SQLite file found"
        usage()
        sys.exit(2)
else:
    filename = args[0]

##Reference to database
sqlitedb = mysqlite.sqlitedb(filename)
if (not "FlowCount" in sqlitedb.getTables()):
    print "FlowCount not found in SQLite database "+str(filename)
    sys.exit(2)
print str(sqlitedb.select("TotalFlow,CtrlFlow,(TotalFlow-CtrlFlow),TotalUser",
                          "FlowCount",
                          "TimeSec=(select MAX(TimeSec) from FlowCount)")[0]).\
                          replace(", ","\t").replace("(","").replace(")","")
