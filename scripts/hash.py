"""
python hash create script
Potential functions
1)Initial call from first database creation
  init.sh creates initial database info
2)Newly created file scan

3)Target file scanning


Development environment
   Windows 10
   IDE Pycharm
   python3 version :3.7
   testing environment : raspberry pi 3 Model B V1.2

"""
import argparse
import os
import hashlib
import sqlite3

"""GLOBAL"""
DB_PATH = "'../database/init_hashmaster'"

def parser():
    """
    Option parser of python script
    :return:args.attributes
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('attributes', help='[i] initialize hash database ')
    args = parser.parse_args()
    return args.attributes


class hashscan():
    """
    Hash scanning
    path: target directory
    file: target file
    """

    def __init__(self, option):
        self.option = option
        self.path = ''
        self.filename = ''

    def initialDatabase(self):
        """
        scanning : /usr/bin /home /tmp /opt
        and import hash info via sql script
        :return:
        """
        pathArray = ["/usr/bin", "/home", "/tmp", "/opt"]
        for d in pathArray:
            files = os.listdir(d)
            for f in files:
                self.importHash(self.hash_string(f))

        """files = os.listdir(path)"""


    def hash_string(self,filename, block_size = 56636):
        """
        Check file hash in sha256
        :param filename:file name under its directory
        :param block_size: hashing block size
        :return:sha256.hexdigest()
        """
        sha256 = hashlib.sha256()
        with open(filename, 'rb') as f:
            for block in iter(lambda : f.read(block_size), b''):
                sha256.update(block)
        return sha256.hexdigest()


    def import_hash(self):
        """

        :return:
        """

        db = databaseInfo()
        db.insert_column(db.create_connection())


class databaseInfo():
    """
    Database path , executing SQL commands
    """
    def __init__(self):
        """
        initializing database path
        """
        self.db_path = DB_PATH

    def create_connection(self):
        """Establish sqlite connection
           If fails connection print erroe message and return None
           connection variable : db_path
        """
        con = sqlite3.connect(self.db_path)
        return con

    def insert_column(self, cur):
        sqlstring = ""
        cur.execute(sqlstring)
        cur.commit()
        cur.close()

    def initial_creation(self):

if __name__ == '__main__':
    hashScan = hashscan(parser())
    hashScan.initialDatabase()

