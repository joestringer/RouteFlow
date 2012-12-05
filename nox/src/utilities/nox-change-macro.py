#!/usr/bin/env python2.5
"""This script seeks out macro definition in the source
(i.e., in the current directory and its subdirectories)
and changes some macro definition to specified value.

Run nox-change-macro.py --help to see help for usage

Copyright(C) Stanford University 2009
Author ykk
Date April 2009
"""
import commands
import getopt
import sys
import textfile

def usage():
    """Display usage
    """
    print "Usage "+sys.argv[0]+" <options> macro new_value\n"+\
          "Options:\n"+\
          "-r/--restrict <file extension allowed>\n\tRestrict macro to file with extension,"+\
          "maybe used multiple times\n"+\
          "-d/--directory <root directory of source>\n\tDirectory to consider as root directory"

#Parse options and arguments
try:
    opts, args = getopt.getopt(sys.argv[1:], "r:d:",
                               ["restrict=","directory="])
except getopt.GetoptError:
    usage()
    sys.exit(2)

#Check there is macro name and new value only
if not (len(args) == 2):
    usage()
    sys.exit(2)

#Parse option
##List of acceptable extensions
fileExten=[]
##Root directory
rootDir="."
for opt,arg in opts:
    if (opt in ("-r","--restrict")):
        fileExten.append(arg)
    elif (opt in ("-d","--directory")):
       rootDir = arg
    else:
        assert (False,"Unhandled option :"+opt)

print "Searching in "+rootDir+" ..."
##Result of grep
results = commands.getoutput("grep -r \""+args[0]+" \" "+rootDir+"/*")

print "Restrict to files with extension(s):"+str(fileExten)
##Accepted result after filtering
filteredresult=[]
for r in results.split("\n"):
    result = r.split(":")
    if (len(fileExten) == 0):
        if (len(result) >= 2 and
            not result[1].find("#define") == -1):
            filteredresult.append(result)
    else:
        for exten in fileExten:
            if (len(result[0]) >= len(exten) and
                len(result) >= 2 and
                result[0][-len(exten):] == exten and
                not result[1].find("#define") == -1):
                filteredresult.append(result)

#Process result
if (len(filteredresult) > 1):
    print "Multiple results for "+args[0]+" found:"
    for r in filteredresult:
        print "\t"+":".join(r)
    sys.exit(2)
elif (len(filteredresult) == 0):
    print "Macro definition "+args[0]+" not found"
    sys.exit(2)
else:
    print "Processing "+str(filteredresult[0][0])+" ..."
    srcFile = textfile.textfile(filteredresult[0][0])
    srcFile.read_file()
    linefound = srcFile.find_string(":".join(filteredresult[0][1:]))
    words = srcFile.content[linefound].split()
    if (not len(words) == 3):
        print "3 words expected with "+len(words)+" found in "+str(words)
        sys.exit(2)
    print "Changing "+srcFile.content[linefound].strip()+" to "+words[0]+" "+words[1]+" "+args[1]
    srcFile.content[linefound] = words[0]+" "+words[1]+" "+args[1]+"\n"
    srcFile.write_file("")
