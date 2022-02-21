import argparse
import cowsay
from modules.shodan_api import *
from modules.nmap import *
from modules.local_cve_parser import *

# SHODAN_API_KEY = "OooeRjrCHdbDI98zZV8VQqhoTT6WCqoc"
# gSQ3nesmWGafxG3xX8U3mP6YE8dcaJeK

# Global Variables
API_KEY_POS = 0
FILTER_POS = 1


def splashscreen():
    cowsay.tux("Project Shodex! IoT devices scanning simplified!")
    print("Desc: <insert desc here")


def init_arg_parser():
    parser = argparse.ArgumentParser(description="ICT2206 - Project Shodex", epilog="ICT2206 Assignment 1 Team x")
    parser.add_argument("--target", help="Target IP (e.g. 192.168.1.2 / 192.168.1.1-8 / 192.168.1.0/24)", required=True)
    parser.add_argument("--speed", help="Speed of the offline scan (e.g. quick or through)", required=False)
    parser.add_argument("--api_key", help="Shodan API key", required=False)
    parser.add_argument("--filter", help="Search filter", required=False)
    args = parser.parse_args()
    return args


def main():
    # Display the splash screen.
    splashscreen()

    # Obtain the parameters from arg parser.
    args = init_arg_parser()
    target = args.target
    speed = args.speed
    api_key = args.api_key
    filter = args.filter

    # Initiate online mode.
    if api_key != None:
        pass
        # Initiate Shodan API and run its functions
    #    print("[!] Initiating an online scan!")
    #    shodan_app_obj = ShodanAPI(api_key, filter)
    #    shodan_app_obj.check_api_info()
    #    if shodan_app_obj.scan_filter():
    #        shodan_app_obj.scan_specified_ip()

    # Initiate offline mode
    else:
        print("[!] Initiating an offline scan!")
        nmap = Nmap()
        if speed is None:
            speed = "quick"
        cve_list = nmap.run(target, speed)

        # Check if there are any services found
        if cve_list == {}:
            print("[!] No services found!")

        # If there are no services found.
        else:
            cve_parser = LocalCveParser()
            cve_parser.run(cve_list)


if __name__ == '__main__':
    main()
