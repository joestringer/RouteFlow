"""This module reads the bookman-message.hh for type and macro values.

Copyright (C) 2009 Stanford University
Created by ykk
"""
import os

BOOKMAN_MSG_FILENAME="noxcore/src/nox/netapps/lavi/bookman-message.hh"
MESSENGER_FILENAME="noxcore/src/nox/coreapps/messenger/message.hh"

class cheader:
    """Class to read and query C/C++ header.

    Copyright(C) Stanford University 2009
    Author ykk
    Date May 2009
    """
    def __init__(self, filename):
        """Initialize content wth file named
        """
        self.content=[]
        self.append(filename)

    def append(self, filename):
        """Append content of file named
        """
        fileRef = open(filename)
        for line in fileRef:
            self.content.append(line)
        fileRef.close()

    def __get_line_with_variable(self, string):
        """Get line with variable in it
        """
        for line in self.content:
            if string in line:
                return line

    def __get_val_from_line(self, line, string):
        """Get value from line
        """
        varstring = line.replace(',','').replace('}','').replace(';','')
        varstring = varstring.replace(string,'').replace('=','')
        return varstring.strip()

    def get_variable(self,string):
        """Get value of variable
        """
        varstring = self.__get_line_with_variable(string)
        varstring = self.__get_val_from_line(varstring,string)
        if ( varstring[0:2] == "0x" ):
            return int(varstring,16)
        else:
            return int(varstring)

class laviheader(cheader):
    """Class to read and query lavi header.

    Copyright(C) Stanford University 2009
    Author ykk
    Date May 2009
    """
    def __init__(self,filename="",msgfilename=""):
        """Initialize content with standard file
        """
        #Get LAVI header
        if (msgfilename==""):
            cheader.__init__(self,os.environ['NOXPATH']+"/"+MESSENGER_FILENAME)
        else:
            cheader.__init__(self,msgfilename)

        #Get messenger header
        if (filename==""):
            self.append(os.environ['NOXPATH']+"/"+BOOKMAN_MSG_FILENAME)
        else:
            self.append(filename)
