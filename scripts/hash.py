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

SAVAPI server-client ( query_hash and hash_string) sample script from Koichi Uchida

"""
import argparse
import os
import hashlib
import sqlite3
import datetime
import socket
import sys
from hmac import compare_digest


"""GLOBAL"""
DB_PATH = "../database/hashmaster"
SERVER_IP = "192.168.10.30"


def parser():
    """
    Option parser of python script
    :return:args.attributes as script options [i] initialize hash database, [d] create hash under a directory, [f] create a file hash
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('attributes', help='[i] initialize hash database, [d] create hash under a directory, [f] create a file hash')
    parser.add_argument('--path', help='mandatory for directory or file hash creating')
    args = parser.parse_args()
    return args.attributes, args.path


class HashScan():
    """
    Hash scanning
    path: target directory
    file: target file
    db : database connection
    file : hashed file in hex
    """

    def __init__(self, option, path):
        self.option = option
        self.path = path
        self.db = DatabaseInfo()
        self.file_hash =''
        """self.con = self.db.create_connection()"""

    def create_info(self):
        """
        scanning : /usr/bin /home/[current user] /tmp /opt
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
                        self.db.insert_column( self.hash_string(os.path.join(d, f)), os.path.join(d, f), self.option, 0)

        elif self.option == "f" and self.path != "":
            if self.check_file(self.path):
                record_number=self.db.find_hash(self.path)
            if record_number[0][0] == 1:
                print ('Current hash record has found')
                record_info = self.db.select_hash(self.path)
                for r in record_info[0]:
                    print (r)
                previous_hash = record_info[0][1]
                current_hash = self.hash_string(self.path)

                if (compare_digest(previous_hash, previous_hash)):
                    print("Get hash updated ? \npress[Enter] to send or [n] to abort")
                    str = input()
                    if (str == 'n' or str.lower() == 'n'):
                        print ('abort process')
                    elif (str == ''):
                        self.db.insert_column(self.hash_string(self.path), self.path, self.option, record_number[0][0])
                else:
                    print('Previous hash is ' + previous_hash + '\n')
                    print('Current  hash is ' + current_hash + '\n')
                    print()
                    print("Hash is different. Get hash updated and inquiry to SAVAPI or abort?  \npress[Enter] to send or [n] to abort")
                    str = input()
                    if (str == 'n' or str.lower() == 'n'):
                        print('abort process')
                    elif (str == ''):
                        self.db.insert_column(self.hash_string(self.path), self.path, self.option, record_number[0][0])

            elif record_number[0][0] == 0:
                print ('Check new file hash info : ' + self.path)
                if self.check_file(self.path):
                    self.db.insert_column(self.hash_string(self.path), self.path, self.option,record_number[0][0])
                print ('created hash information : ' + self.path + self.file_hash + '\n Get it sent to SAVAPI ? press[Enter] to send or [n] to abort')
                str = input()
                if (str == 'n' or str.lower() == 'n'):
                    print ('abort process')
                elif (str == ''):
                    self.query_hash()


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

        self.file_hash = sha256.hexdigest()
        return self.file_hash


    def query_hash(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((SERVER_IP, 5000))
        client.send(self.file_hash.encode('utf-8'))
        response = client.recv(4096)
        response = response.decode('utf-8').split(";")
        code = response[0].split()

        if code[0] == "200":
            result = "CLEAN"
            print ("File : " + self.path + " " + result)
        elif code[0] == "310":
            result = "MALICIOUS"
            print("File : " + self.path + " " + result)
            print("Name :" + response[1])
            print("Desc :" + response[2] + "\n")


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

    def insert_column(self, hash, filename, option, colum_number):
        if option == 'i':
            cur = self.create_connection()
            sqlstring = 'insert into HASH (FILE_NAME, HASH, SCANED_FLAG, INSERTED_DATE, UPDATED_DATE) values ("' + filename + '", "' + hash + '",0, "' + datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S") + '","' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '")'
        elif option == 'f' or option == 'd':
            cur = self.create_connection()
            if colum_number == 0:
                sqlstring = 'insert into HASH (FILE_NAME, HASH, SCANED_FLAG, INSERTED_DATE, UPDATED_DATE) values ("' + filename + '", "' + hash + '",0, "' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '","' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '")'
            elif colum_number >0:
                sqlstring = 'update HASH set HASH="' + hash + '", SCANED_FLAG=1, UPDATED_DATE="'+ datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '" where FILE_NAME="' + filename + '"'

        cur.execute(sqlstring)
        cur.commit()
        cur.close()

    def find_hash (self,filename):
        cur = self.create_connection()
        sqlstring = 'select count() as record_number from HASH where FILE_NAME =' + '"' + filename + '"'
        r = cur.execute(sqlstring)
        record = r.fetchall()
        cur.close()
        return record

    def select_hash(self, filename):
        cur = self.create_connection()
        sqlstring = 'select FILE_NAME, HASH, SCANED_FLAG, INSERTED_DATE, UPDATED_DATE from HASH where FILE_NAME =' + '"' + filename + '"'
        r = cur.cursor()
        r.execute(sqlstring)
        detail_hash = r.fetchall()
        r.close()
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



