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
import datetime


"""GLOBAL"""
DB_PATH = "../database/init_hashmaster"


def parser():
    """
    Option parser of python script
    :return:args.attributes
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('attributes', help='[i] initialize hash database, [d] create hash under a directory, [f] scan a file')
    parser.add_argument('path', help='mandatory for directory or file hash creating')
    args = parser.parse_args()
    return args.attributes, args.path


class HashScan():
    """
    Hash scanning
    path: target directory
    file: target file
    """

    def __init__(self, option, path):
        self.option = option
        self.path = path
        self.db = DatabaseInfo()

    def create_info(self):
        """
        scanning : /usr/bin /home /tmp /opt
        and import hash info via sql script
        :return:
        """
        if self.option == "i":
            homedir = os.path.expanduser("~")
            pathArray = [homedir, "/tmp/", "/opt/"]
            for d in pathArray:
                files = os.listdir(d)
                for f in files:
                    if self.check_file(os.path.join(d, f)):
                        self.import_hash(self.hash_string(os.path.join(d, f)), os.path.join(d, f))
        elif self.option == "f" and self.path !="":
            if self.check_file(self.path):
                record_number=self.db.find_hash(self.db.create_connection(),self.path)
            if record_number ==1 :
                print ('Current hash record has found')
                record_info = self.db.select_hash(self.db.create_connection(),self.path)
            elif record_number == 0:
                print ('Check new file hash info')
                if self.check_file(self.path):
                    self.import_hash(self.hash_string(self.path), self.path)


    def check_file(self,filepath):
        if os.path.isfile(filepath) and os.path.getsize(filepath):
            return True
        else:
            return False


    def hash_string(self, filename, block_size=56636):
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

    def import_hash(self,hash, filename):
        """
        import hash (sha256) and file name
        :return:None
        """
        self.db.insert_column(self.db.create_connection(), hash, filename)


class DatabaseInfo():
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

    def insert_column(self, cur, hash, filename):
        sqlstring = 'insert into INIT_HASH  (FILE_NAME, HASH, SCANED_FLAG, INSERTED_DATE, UPDATED_DATE) values ("'+ filename +'", "' + hash +'",0, "' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +'","'+ datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") +'")'
        cur.execute(sqlstring)
        cur.commit()
        cur.close()

    def find_hash (self,cur,filename):
        sqlstring = 'select count() as record_number from INIT_HASH where FILE_NAME =' + '"' + filename + '"'
        cur.execute(sqlstring)
        record_number = cur.fetchall()

        return record_number

    def select_hash(self,cur,filename):
        sqlstring = 'select FILE_NAME, HASH, SCANED_FLAG, INSERTED_DATE, UPDATED_DATE from INIT_HASH where FILE_NAME =' + '"' + filename + '"'
        cur.execute(sqlstring)
        detail_hash = cur.fetchall()
        return detail_hash

if __name__ == '__main__':
    options = parser()
    scan = HashScan(options[0],options[1])
    if scan.option == 'i':
        scan.create_info()
    elif scan.option == 'd' or scan.option == 'f':
        if scan.path != "":
            scan.create_info()
        else:
            print('Lack of file path information \n')



