

class textfile:
    """Class to hold text file in Python.

    Copyright(C) Stanford University 2009
    Author ykk
    Date April 2009
    """
    def __init__(self,filename="tmpfile"):
        """Initialize textfile
        """
        ##Filename of graphviz file
        self.filename = filename
        ##File content, i.e., list of strings
        self.content = []
