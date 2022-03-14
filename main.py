import argparse
import cowsay
from shodex_engine import *


def splashscreen():
    """"
    Displays the program's splashscreen.
    :param: 
    :return:
    """
    cowsay.tux("Project Shodex! IoT devices scanning simplified!")
    print("Desc: Project Shodex by Team Pizzaluvers")
    time.sleep(2)
    os.system("clear")


def init_arg_parser():
    """"
    Arg parser for the program.
    :param:
    :return: args.
    """
    parser = argparse.ArgumentParser(description="ICT2206 - Project Shodex", epilog="ICT2206 Assignment 1 Team Pizzaluvers")
    parser.add_argument("--api_key", help="Shodan API key.", required=False)
    parser.add_argument("--filter", help="Shodan search filter.", required=False)
    parser.add_argument("--ondemand", help="Shodan on-demand scan a target.", required=False)
    parser.add_argument("--target", help="Target (e.g. 192.168.1.2).", required=False)
    parser.add_argument("--speed", help="Speed of the offline scan (optional: fast).", required=False)
    parser.add_argument("--brute", help="Enable the brute force modules", required=False, action="store_true")
    parser.add_argument("--update", help="Update the local CVE database.", required=False, action="store_true")
    args = parser.parse_args()
    return args


def main():
    """"
    Program's main function.
    :param:
    :return:
    """
    # Display the splash screen.
    splashscreen()

    # Obtain the parameters from arg parser.
    args = init_arg_parser()
    target = args.target
    speed = args.speed
    api_key = args.api_key
    search_filter = args.filter
    ondemand = args.ondemand
    brute = args.brute
    update = args.update

    # Check arguments.
    if ondemand:
        if api_key is None:
            print(print_red("[!] Please enter the shodan API key!"))
            exit()

    # Check if folders exists
    parent_dir = os.getcwd()
    data_path = os.path.join(parent_dir, "data")
    if not os.path.exists(data_path):
        os.makedirs(data_path)
    exploit_path = os.path.join(parent_dir, "data", "local_exploits")
    if not os.path.exists(exploit_path):
        os.makedirs(exploit_path)
    wordlist_path = os.path.join(parent_dir, "data", "wordlists")
    if not os.path.exists(wordlist_path):
        os.makedirs(wordlist_path)
    downloads_path = os.path.join(parent_dir, "downloads")
    if not os.path.exists(downloads_path):
        os.makedirs(downloads_path)

    # Initiate update mode. 
    if update:
        cve_parser = LocalCveParser()
        cve_parser.check_last_update()
        exploit_db = ExploitDb()
        exploit_db.force_update()
        exit()

    # Initiate online Mode. 
    if api_key is not None:
        online_mode(api_key, ondemand, search_filter, speed, brute)

    # Initiate offline mode.
    else:
        offline_mode(speed, target, [], [], brute)
    print(print_yellow("\n[!] Exiting program!"))
    exit() 


if __name__ == '__main__':
    main()
