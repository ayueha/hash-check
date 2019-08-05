"""
python hash create script
Potential functions
1)Initial call from first database creation
  init.sh creates initial database info
2)Newly created file scan

3)Target file scanning

"""
import argparse
import os
import hashlib


def parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('attributes', help='[i] initialize hash database ')
    args = parser.parse_args()
    return args.attributes


class hashScan():
    """
    Hash scanning
    """
    def __init__(self, execitionOption):
        self.option = execitionOption
        self.path = ''
        self.filename = ''

    def initialDatabase(self):
        """
        scanning : /usr/bin /home /tmp /opt
        :return:
        """
        pathArray = ["/usr/bin","/home", "/tmp", "/opt"]
        for d in pathArray:
            files = os.listdir(d)
            for f in files:
                hashString = createHash(f)
                importHash(hashString)

        """files = os.listdir(path)"""

    def hashString(self,fileName):
        hashlib.sha256


if __name__ == '__main__':
    result = parser()
    hashScan = hashScan(result)
    hashScan.initialDatabase()

