import argparse
import cowsay
from shodex_engine import *


def splashscreen():
    """"
    Displays the program's splashscreen.
    :param: None.
    :return: None.
    """
    cowsay.tux("Project Shodex! IoT devices scanning simplified!")
    print("Desc: <insert desc here")


def init_arg_parser():
    """"
    Arg parser for the program.
    :param: None.
    :return: None.
    """
    parser = argparse.ArgumentParser(description="ICT2206 - Project Shodex", epilog="ICT2206 Assignment 1 Team x")
    parser.add_argument("--api_key", help="Shodan API key.", required=False)
    parser.add_argument("--filter", help="Shodan search filter.", required=False)
    parser.add_argument("--ondemand", help="Shodan on-demand scan a target.", required=False)
    parser.add_argument("--target", help="Target (e.g. 192.168.1.2).", required=False)
    parser.add_argument("--speed", help="Speed of the offline scan (e.g. quick or through).", required=False)
    parser.add_argument("--update", help="Update the local CVE database.", required=False, action='store_true')
    args = parser.parse_args()
    return args


def main():
    """"
    Program's main function.
    :param: None.
    :return: None.
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
    update = args.update

    # Initiate update mode. 
    if update:
        cve_parser = LocalCveParser()
        cve_parser.check_last_update()
        exit()

    # Initiate online Mode. 
    if api_key is not None:
        online_mode(api_key, ondemand, search_filter, speed)

    # Initiate offline mode.
    else:
        offline_mode(speed, target, [], [])
    print("\n[!] Exiting program!")
    exit() 


if __name__ == '__main__':
    main()
