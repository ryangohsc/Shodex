<<<<<<< HEAD
import argparse
import cowsay
import modules.exploit_db
from modules.shodan_api import *
from modules.nmap import *
from modules.local_cve_parser import *

# SHODAN_API_KEY = "OooeRjrCHdbDI98zZV8VQqhoTT6WCqoc"
# backup key: gSQ3nesmWGafxG3xX8U3mP6YE8dcaJeK

# Global Variables
API_KEY_POS = 0
FILTER_POS = 1


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
    parser.add_argument("--target", help="Target (e.g. 192.168.1.2 / 192.168.1.1-8 / 192.168.1.0/24).", required=False)
    parser.add_argument("--speed", help="Speed of the offline scan (e.g. quick or through).", required=False)
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

    # Initiate online mode.
    if api_key is not None:
        online_mode(api_key, ondemand, search_filter)

    # Initiate offline mode
    else:
        offline_mode(speed, target, [])


def online_mode(api_key, ondemand, search_filter):
    # Initiate Shodan API and run its functions
    shodan_app_obj = ShodanAPI(api_key, search_filter)
    shodan_app_obj.check_api_info()

    # On-demand scan mode.
    if ondemand is not None:
        print("[!] Initiating an ondemand scan!")
        shodan_app_obj.on_demand_scan(ondemand)

    # Search mode.
    else:
        print("[!] Retrieving results from Shodan!")
        if shodan_app_obj.scan_filter():
            target, cve_list, port_list = shodan_app_obj.retrieve_info()
            speed = "quick"
            offline_mode(speed, target, port_list)


def offline_mode(speed, target, port_list):
    print("[!] Initiating an offline scan!")
    nmap = Nmap()
    if speed is None:
        speed = "quick"
    service_list = nmap.run(target, speed, port_list)

    # Check if there are any services and CVEs found for each IP
    ips = service_list.keys()
    cve_parser = LocalCveParser()
    cve_parser.check_last_update()

    for ip in ips:
        lst = []
        for item in service_list[ip]:
            # Parse the services found against a local CVE database.
            port_cve = cve_parser.run(item)

            # Append the cve to the list.
            if port_cve:
                for item2 in port_cve:
                    lst.append([item['port'], item2[0], item2[1]])

        # Store and clean the data.
        df = pd.DataFrame(np.array(lst, dtype=object), columns=['port', 'name', 'desc'])
        print("\nPotential Vulnerable CVEs")




        print(df.to_string())

        # Ask the user if they want to use the recommended or local exploit
        choice = input("\n[+] Do you wish to use a recommended CVE (y/n): ")
        if choice == "y":
            choice = input("Enter row no: ")
            search_list = df.iloc[[choice]].name.to_string().split(" ")[4]
            modules.exploit_db.run(search_list)
        elif choice == "n":
            print("[+] Enter a local exploit name: ")
            # Search the local db for data


if __name__ == '__main__':
    main()
=======
import argparse
import cowsay
from modules.shodan_api import *
from modules.nmap import *
from modules.local_cve_parser import *
import modules.exploit_db

# SHODAN_API_KEY = "OooeRjrCHdbDI98zZV8VQqhoTT6WCqoc"
# backup key: gSQ3nesmWGafxG3xX8U3mP6YE8dcaJeK

# Global Variables
API_KEY_POS = 0
FILTER_POS = 1


def splashscreen():
    cowsay.tux("Project Shodex! IoT devices scanning simplified!")
    print("Desc: <insert desc here")


def init_arg_parser():
    parser = argparse.ArgumentParser(description="ICT2206 - Project Shodex", epilog="ICT2206 Assignment 1 Team x")
    parser.add_argument("--target", help="Target IP (e.g. 192.168.1.2 / 192.168.1.1-8 / 192.168.1.0/24)",
                        required=False)
    parser.add_argument("--speed", help="Speed of the offline scan (e.g. quick or through)", required=False)
    parser.add_argument("--api_key", help="Shodan API key", required=False)
    parser.add_argument("--filter", help="Search filter", required=False)
    parser.add_argument("--ondemand", help="Shodan on-demand scan a target", required=False)
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
    ondemand = args.ondemand

    # Initiate online mode.
    if api_key is not None:
        # Initiate Shodan API and run its functions
        shodan_app_obj = ShodanAPI(api_key, filter)
        shodan_app_obj.check_api_info()

        # On-demand scan mode.
        if ondemand is not None:
            print("[!] Initiating an ondemand scan!")
            shodan_app_obj.on_demand_scan(ondemand)

        # Search mode.
        else:
            print("[!] Retrieving results from Shodan!")
            if shodan_app_obj.scan_filter():
                shodan_app_obj.scan_specified_ip()

    # Initiate offline mode
    else:
        print("[!] Initiating an offline scan!")
        nmap = Nmap()
        if speed is None:
            speed = "quick"
        service_list = nmap.run(target, speed)

        # Check if there are any services found
        if service_list == {}:
            print("[!] No services found!")
        else:
            cve_parser = LocalCveParser()
            cve_list = cve_parser.run(service_list)
            # Feed the cve_list to the exploit crawler here.
            modules.exploit_db.run(cve_list)


if __name__ == '__main__':
    main()
>>>>>>> 4aea341f408aeab2298509fddfbdab6d5b4fe054
