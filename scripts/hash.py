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
import glob
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

    def create_info(self):
        """
        scanning : /usr/bin /home/[current user] /tmp /opt
        and import hash info via sql script
        NEED recrusive search function
        :return:
        """
        if self.option == "i":
            homedir = os.path.expanduser("~")
            pathArray = [homedir, "/tmp/", "/opt/"]

            for self.path in pathArray:
                for f in self.find_files():
                    if self.check_file(os.path.join(self.path, f)):
                        self.db.insert_column(self.hash_string(os.path.join(self.path, f)), os.path.join(self.path, f),
                                              self.option, 0)

        elif self.option == "f" and self.path != "":
            if self.check_file(self.path):
                record_number=self.db.find_hash(self.hash_string(self.path))
            if record_number[0][0] == 1:
                previous_hash = self.print_info(record_number)
                current_hash = self.hash_string(self.path)
                if (compare_digest(previous_hash, current_hash)):
                    print("Hash is same. Get hash updated ? \npress[Enter] to send or [n] to abort")
                    str = input()
                    if (str == 'n' or str.lower() == 'n'):
                        print ('abort process')
                    elif (str == ''):
                        self.db.insert_column(self.hash_string(self.path), self.path, self.option, record_number[0][0])
                else:
                    print('Previous hash is ' + previous_hash )
                    print('Current  hash is ' + current_hash + '\n')
                    print('Hash is different. Choose an action\n')
                    str = self.check_suspicious_file()
                    if(str=='q'):
                        self.query_hash(self)
                    elif(str=='u'):
                        self.db.insert_column(self.hash_string(self.path), self.path, self.option, record_number[0][0])
                    elif(str=='a'):
                        print ('finishing process...')

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

        elif self.option == "d" and self.path != "":
            checked_array = []
            new_array = []
            for f in self.find_files():
                if self.check_file(f):
                    hash = self.hash_string(f)
                    record_number = self.db.find_hash(hash)
                    if record_number[0][0] == 1:
                        record_info = [record_number[0][0],f,hash,record_number[0][1]]
                        checked_array.append(record_info)
                    elif record_number[0][0] == 0:
                        new_array.append(f)

            if len(checked_array) > 0:
                 self.check_dir(checked_array)

            if len(new_array) > 0:
                hash_array = []
                for files in new_array:
                    self.hash = self.hash_string(files)
                    hash_array.append(self.hash)
                    self.db.insert_column(self.hash, files, self.option, 0)
                print ('created hash information : ' + self.path + '\n Get them sent to SAVAPI ? press[Enter] to send or [a] to abort')
                str = input()
                if (str == 'a' or str.lower() == 'a'):
                    print ('abort process')
                elif (str == ''):
                    for self.hash in hash_array:
                        self.query_hash()
                else:
                    print ("Invalid option... end the process")


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

    def check_suspicious_file(self):
        str = ''
        while str =='':
            print ('-------------------------------------------')
            print('Press q to send data to SAVAPI')
            print('Press u to update hash data in previous column')
            print('Press a to abort this process')
            str = input().lower()
            if (str == 'q' ):
                print ('Send Hash to SAVAPI')
                return str
                break
            elif(str == 'u'):
                print('update hash to database')
                return str
                break
            elif(str == 'a'):
                print('abort checking hash')
                return str
                break
            else:
                print('Invalid option')
                str = ''

    def find_files(self):
        for root,dirs,files in os.walk(self.path):
            yield root
            for file in files:
                yield os.path.join(root,file)


    def print_info(self,record_info):
        print('Current hash record has found')
        record_info = self.db.select_hash(self.path)
        print('File Path   : ' + record_info[0][0])
        print('File Hash   : ' + record_info[0][1])
        print('Last Update : ' + record_info[0][4] + '\n')
        previous_hash = record_info[0][1]
        return previous_hash

    def check_dir(self,checked_array):
        str = ""
        while str == "":
            for arr in checked_array:
                    print("File Path   : " + arr[1]+ " | " + 'File Hash   : ' + arr[2] + " | " + 'Last Update : ' + arr[3])

            print("Choose action")
            print("Show all files and hash,  enter [p]")
            print("Compear all hash info  ,  enter [c]")
            print("Abort                  ,  enter [a]")
            str = input()

            if str.lower() == "p":
                for arr in checked_array:
                    print("File Path   : " + arr[0][0] + " | " + 'File Hash   : ' + arr[0][1] + " | " + 'Last Update : ' + arr[0][4])
            elif str.lower() == "c":
                diff_hash = []
                for arr in checked_array:
                    if (compare_digest(arr[0][1], current_hash)) == False:
                        hash_info = [arr[0][0],arr[0][1],current_hash]
                        diff_hash.append(hash_info)
                        print('Previous hash is ' + arr[0][1])
                        print('Current  hash is ' + current_hash + '\n')

                str = self.check_suspicious_file()

                if (str == 'q'):
                    for hash_info in diff_hash:
                        self.query_hash(self)
                elif (str == 'u'):
                    self.db.insert_column(self.hash_string(self.path), self.path, self.option, record_number[0][0])
                elif (str == 'a'):
                    print('finishing process...')
            elif str.lower() =="a":
                print('finishing process...')
                return None
            else:
                print("Invalid option")
                str = ""


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
                sqlstring = 'update HASH set HASH="' + hash + '", SCANED_FLAG=1, UPDATED_DATE="'+ datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + '" where HASH="' + hash + '"'

        cur.execute(sqlstring)
        cur.commit()
        cur.close()

    def find_hash (self,hash):
        cur = self.create_connection()
        sqlstring = 'select count(),UPDATED_DATE as record_number from HASH where HASH =' + '"' + hash + '"'
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



