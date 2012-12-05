"""MySQL module to make connections easier

Copyright(C) Stanford University 2009
Author ykk
Date April 2009
"""
import MySQLdb

class mysqldb:
    """Database in MySQL

    Copyright(C) Stanford University 2009
    Author ykk
    Date April 2009
    """
    def __init__(self, dbname, username, password, dbhost="localhost"):
        """Initialize database
        """
        ##Reference to connection
        self.connection = MySQLdb.connect(host = dbhost,
                                          user = username,
                                          passwd = password,
                                          db = dbname)

    def __del__(self):
        """ Destructor
        """
        self.connection.close()

    def execute(self,statement):
        """Execute SQL statement.
        Statement can be string or list of strings.
        """
        cursor = self.connection.cursor()
        result = None
        if (isinstance(statement, list)):
            if (len(statement) > 0):
                for s in statement:
                    cursor.execute(s)
                result = cursor.fetchall()
        else:
            cursor.execute(statement)
            result = cursor.fetchall()
        cursor.close()
        return result
