"""SQLite module to handle various operations

Copyright(C) Stanford University 2009
Author ykk
Date April 2009
"""
import sqlite3
import os

def get_latest_sqlite():
    """Get latest sqlite file, else return None
    """
    filelist = [(os.path.getmtime(x), x) for x in os.listdir(".")]
    filelist.sort()
    for f in reversed(filelist):
        if (len(f[1]) >= 7 and f[1][-7:] == '.sqlite'):
            return f[1]
    return None

class sqlitedb:
    """Database in SQLITE.

    Copyright(C) Stanford University 2009
    Author ykk
    Date April 2009
    """
    def __init__(self, filename):
        """Initialization
        """
        ##Filename of sqlite3 database
        self.filename = filename

    def connect(self):
        """Return connection.
        """
        return sqlite3.connect(self.filename)

    def getTables(self):
        """Return list of table name in database
        """
        tables = self.select("tbl_name","sqlite_master","type='table'")
        result = []
        for tab in tables:
            result.append(tab[0])
        return result

    def select(self, selectfor, tablename, condition=None):
        """Return result of select statement
        """
        c = self.connect()
        if (condition == None):
            result = c.execute("SELECT "+selectfor+\
                               " FROM "+tablename).fetchall()
        else:
            result = c.execute("SELECT "+selectfor+\
                               " FROM "+tablename+\
                               " WHERE "+condition).fetchall()
        c.close()
        return result

    def delete(self, tablename, condition=None):
        """Delete given table and condition
        """
        c = self.connect()
        if (condition == None):
            result = c.execute("DELETE FROM "+tablename).fetchall()
        else:
            result = c.execute("SELECT FROM "+tablename+\
                               " WHERE "+condition).fetchall()
        c.commit()
        c.close()
        return result

class sqlitetable:
    """Table in SQLite.

    Copyright(C) Stanford University 2009
    Author ykk
    Date April 2009
    """
    def __init__(self, name, db):
        """ Initialize
        """
        ##Table name
        self.name = name
        ##Reference to database
        self.db = db

    def createStatement(self):
        """Get creation statement.
        """
        return self.db.select("sql","sqlite_master","type='table' AND "+\
                              "name='"+self.name+"'")[0][0]

    def mysqlCreateStatement(self):
        """Get creation statement.
        """
        return self.createStatement().replace('INTEGER','BIGINT')

    def size(self):
        """Check size of table
        """
        r = self.db.select("COUNT(*)",self.name)
        return r[0][0]

    def dump(self, condition=None):
        """Dump all entries of table given condition, i.e.,
        select entries, then delete them.

        See private function __select2dump
        """
        result = []
        r = None
        c = self.db.connect()
        cur = c.cursor()
        if (condition == None):
            r = cur.execute("SELECT * FROM "+self.name).fetchall()
            cur.execute("DELETE FROM "+self.name)
        else:
            r = cur.execute("SELECT * FROM "+self.name+
                            " WHERE "+condition).fetchall()
            cur.execute("DELETE FROM "+self.name+" WHERE "+condition)
        cur.close()
        c.commit()
        c.close()

        #Process result
        for line in r:
            result.append(self.__select2dump(line))
        return result

    def __select2dump(self, data):
        """Convert table to insert statement from dump

        Incomplete, i.e., handling only integer and long integer
        """
        return "INSERT INTO "+self.name+\
               " VALUES"+str(data).replace('L','')
