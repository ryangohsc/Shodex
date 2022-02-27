import argparse
import cowsay
import modules.exploit_db
from modules.shodan_api import *
from modules.nmap import *
from modules.local_cve_parser import *
from modules.exploit_loader import * 

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

    # Initiate online Mode. 
    if api_key is not None:
        online_mode(api_key, ondemand, search_filter, speed)

    # Initiate offline mode.
    else:
        offline_mode(speed, target, [])


def online_mode(api_key, ondemand, search_filter, speed):
    """"
    The online mode which leverages on Shodan to obtain a target or to on-demand scan a target. 
    :param: api_key, ondemand, search_filter.
    :return: None.
    """
    # Initiate Shodan API and run its functions
    shodan_app = ShodanAPI(api_key, search_filter)
    shodan_app.check_api_info()

    # On-demand scan mode.
    if ondemand is not None:
        print("[!] Initiating an ondemand scan!")
        shodan_app.on_demand_scan(ondemand)

    # Search mode.
    else:
        if shodan_app.search_filter():
            target, cve_list, port_list = shodan_app.retrieve_info()
            offline_mode(speed, target, port_list)


def offline_mode(speed, target, port_list):
    """"
    The offline mode which uses nmap to scan a target. 
    :param: speed, target, port_list.
    :return: None.
    """
    # Initiate a nmap scan. 
    print("[*] Initiating an offline nmap scan!")
    nmap = Nmap()
    if speed is None:
        speed = "quick"
    service_list, total_hosts, down_hosts = nmap.run(target, speed, port_list)

    # End the process if no hosts are up
    if down_hosts == total_hosts:
        print("[!] Error! No hosts are up!")
        return 

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
        try:
            df = pd.DataFrame(np.array(lst, dtype=object), columns=['port', 'name', 'desc'])
            print("\nPotential Vulnerable CVEs")
            print(df.to_string(justify="left", col_space=10))

            # Ask the user if they want to use the recommended exloit.
            recommended_cve = use_recommended_cve(df)

            # Ask the user if they want to use a local exploit.
            if not recommended_cve:
                use_local_exploit()

        except ValueError:
            print("[!] No recommended CVEs!")
            use_local_exploit()


def use_recommended_cve(df):
    print('hi')
    valid = False
    if recommended_empty is False:
        while valid is not True:
            if recommended_empty is False:
                choice = input("\n[+] Do you wish to use a recommended CVE (y/n): ")
                if choice.lower() == "y":
                    row_choice = input("\t[+] Enter row no: ")
                    if int(row_choice) not in range(len(df)):
                        print("[!] Error! Invalid input entered!")
                    else: 
                        search_list = df.iloc[[row_choice]].name.to_string().split(" ")[4]
                        found, exploit_file_path = modules.exploit_db.run([search_list])
                        print(found)
                        print(exploit_file_path)
                        if found is True:
                            return found
                elif choice.lower() == "n":
                    valid = True 
                    return False
                else:
                    print("[!] Error! Invalid input entered!")


def use_local_exploit():
    valid = False 
    while valid is not True:
        choice = input("\n[*] Do you wish to use a local exploit (y/n): ")
        if choice.lower() == "y":
            exploit_name = input("\t[+] Enter the exploit name: ")
            parent_dir = os.getcwd()
            exploit_path = os.path.join(parent_dir, "data", "local_exploits")
            # avail_exploits = [(i.split(".")[0] for i in os.listdir(exploit_path)]
            avail_exploits = [i for i in os.listdir(exploit_path)]

            # Check if the exploits exists within local exploits dir. 
            found = False
            for exploit in avail_exploits:
                if exploit_name == exploit.split(".")[0]:
                    found = True
                    exploit_name = exploit
                
            if found == False:
                print("[!] Error! Exploit not found!")
            else:
                valid = True 
                extension = exploit_name.split(".")[1]
                name = os.path.join(parent_dir, "data", "local_exploits", exploit_name)
                exploit_loader = ExploitLoader(name, extension)
                exploit_loader.run()

                
                # Arm the exploit here. 

        elif choice.lower() == "n":
            valid = True 
        else:
            print("[!] Error! Invalid input entered!")


if __name__ == '__main__':
    main()
