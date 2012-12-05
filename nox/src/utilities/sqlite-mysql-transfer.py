#!/usr/bin/env python2.5
"""This script transfers data from SQLite to MySQL.

Run sqlite-mysql-transfer.py --help to see help for usage

Dependency: sqlite3

Copyright(C) Stanford University 2009
Author ykk
Date April 2009
"""
import time
import getopt
import sys
import mysqlite
import ezmysql
import os

def usage():
    """Display usage
    """
    print "Usage "+sys.argv[0]+" <options> [sqlite filename]\n"+\
          "Finds the latest SQLite file in current directory "+\
          "if no filename is supplied\n."+\
          "Options:\n"+\
          "-h/--help\n\tPrint this usage guide\n"+\
          "-b/--buffertime\n\tBuffer time for data to ensure non-empty tables\n"+\
          "-t/--table\n\tTable to dump (can have multiple instances\n"+\
          "-i/--ignore\n\tIgnore missing tables in SQLite\n"+\
          "-a/--database\n\tSpecify database to use\n"+\
          "-d/--delete\n\tDelete file if all tables are empty\n"

#Parse options and arguments
try:
    opts, args = getopt.getopt(sys.argv[1:], "hb:t:ida",
                               ["help","buffer=","table","ignore","delete",
                                "database"])
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

#Parse options
##Username
user="ofwifi"
##Password
password="ofwifi"
##Host
dbhost="openflow.stanford.edu"
##Database name
dbname="ofwifi"
##Time to limit dump to (in mins)
dumpBefore=int(time.time())-5
##Indicate if ignoring missing tables
ignore=False
##Delete empty (i.e., no content is specified tables"
deleteEmpty = False
##List of tables to dump
tables=["SwitchActivity","FlowCount","FlowDB","DhcpLog"]
##Indicate if table is default
__defaultTables=True
for opt,arg in opts:
    if (opt in ("-h","--help")):
        usage()
        sys.exit(0)
    elif (opt in ("-t","--table")):
        if (__defaultTables):
            __defaultTables=False
            tables=[]
        tables.append(arg)
    elif (opt in ("-b","--buffertime")):
        dumpBefore=int(time.time())-int(arg)
    elif (opt in ("-i","--ignore")):
        ignore=True
    elif (opt in ("-d","--delete")):
        deleteEmpty=True
    elif (opt in ("-a","--database")):
        dname=arg
    else:
        assert (False,"Unhandled option :"+opt)

if (not os.path.exists(filename)):
    print filename+" not found..."
    sys.exit(2)
##Reference to database
sqlitedb = mysqlite.sqlitedb(filename)

#Check tables available
##Table names in SQLite
sqlitetables = sqlitedb.getTables()
##Process each table
for tab in tables:
    if (not tab in sqlitetables):
        print "Table "+tab+" not in SQLite database "+str(filename)+\
              ", which has tables "+str(sqlitetables)
        if (not ignore):
            sys.exit(2)
    else:
        print "============================="
        print "Dumping table:"+str(tab)
        print "============================="
        sqlitetab = mysqlite.sqlitetable(tab, sqlitedb)
        mysqldb = ezmysql.mysqldb(dbname, user, password, dbhost)
        mysqldb.execute(sqlitetab.mysqlCreateStatement().\
                        replace(' PRIMARY KEY','').\
                        replace('CREATE TABLE', 'CREATE TABLE IF NOT EXISTS'))
        mysqldb.execute(sqlitetab.dump("TimeSec<="+str(dumpBefore)))
        if not (sqlitetab.size() == 0):
            deleteEmpty = False

#Delete SQLite file?
if (deleteEmpty):
    os.remove(filename)
    print filename+" deleted"
