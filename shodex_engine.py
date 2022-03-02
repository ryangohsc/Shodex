import modules.exploit_db
from modules.shodan_api import *
from modules.nmap import *
from modules.local_cve_parser import *
from modules.exploit_loader import *


def use_recommended_cve(df):
    """"
    Locates the recommended exploit that the user wishes to use.
    :param: df.
    :return: True or None.
    """
    valid = False
    while valid is not True:
        # Prompt the user if they wish to use a recommended exploit.
        choice = input("\n[+] Do you wish to use a recommended CVE (y/n): ")

        # The user does not wish to use a recommended exploit.
        if choice.lower() == "y":
            row_choice = input("\t[+] Enter row no: ")
            if int(row_choice) not in range(len(df)):
                print("[!] Error! Invalid input entered!")
            else: 
                search_list = df.iloc[[row_choice]].name.to_string().split(" ")[4]
                found, exploit_file_path = modules.exploit_db.run([search_list])

                # If a recommended exploit is found.
                if found is True:
                    exploit_path = exploit_file_path.split("/")[-1]
                    exploit_ext = exploit_file_path.split(".")[1]

                    # Arm the exploit.
                    exploit_loader = ExploitLoader(exploit_path, exploit_ext)
                    exploit_loader.run()
                    return True

                # If a recommended exploit is not found.
                else:
                    return None

        # The user does not wish to use a recommended exploit.
        elif choice.lower() == "n":
            return None

        # The user supplies an invalid input.
        else:
            print("[!] Error! Invalid input entered!")


def use_local_exploit():
    """"
    Asks the user to provide a local exploit and attempts to load it.
    :param: None.
    :return: None.
    """
    valid = False
    while valid is not True:
        # Prompt the user if they want to use a local exploit.
        choice = input("\n[+] Do you wish to use a local exploit (y/n): ")

        # If the user wishes to use a local exploit.
        if choice.lower() == "y":
            exploit_name = input("\t[+] Enter the exploit name: ")
            parent_dir = os.getcwd()
            exploit_path = os.path.join(parent_dir, "data", "local_exploits")
            avail_exploits = [i for i in os.listdir(exploit_path)]

            # Check if the exploits exists within local exploits dir. 
            found = False
            for exploit in avail_exploits:
                if exploit_name == exploit.split(".")[0]:
                    found = True
                    exploit_name = exploit

            # Display error message if the exploit is not found.
            if not found:
                print("[!] Error! Exploit not found!")

            # Attempt to arm the local exploit that the user provided.
            else:
                valid = True 
                extension = exploit_name.split(".")[1]
                name = os.path.join(parent_dir, "data", "local_exploits", exploit_name)

                # Arm the exploit. 
                exploit_loader = ExploitLoader(name, extension)
                exploit_loader.run()

        # If the user do not wish to use a local exploit.
        elif choice.lower() == "n":
            valid = True

        # If the user supplies a invalid input.
        else:
            print("[!] Error! Invalid input entered!")


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
            offline_mode(speed, target, port_list, cve_list)


def offline_mode(speed, target, port_list, cve_list):
    """"
    The offline mode which uses nmap to scan a target.
    :param: speed, target, port_list.
    :return: None.
    """
    # If there are CVEs returned by Shodan.
    if cve_list:
        df = pd.DataFrame(np.array(cve_list, dtype=object), columns=['name'])
        print("[!] CVEs obtained from Shodan")
        print(df.to_string(justify="left", col_space=10))

        # If the user does not want to use a recommended exploit or no recommended exploits are found.
        if use_recommended_cve(df) is not True:
            # Ask the user if they want to run a local exploit instead if the recommended one failed.
            use_local_exploit()

        # Exit the program.
        exit()

    # Initiate a nmap scan if there are no CVEs returned by Shodan.
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
    for ip in ips:
        lst = []
        for item in service_list[ip]:
            # Parse the services found against a local CVE database.
            port_cve = cve_parser.run(item)

            # Append the cve to the list.
            if port_cve:
                for item2 in port_cve:
                    lst.append([item2[0].strip(" "), item2[1].strip(" ")])

                # Store and clean the data.
                try:
                    df = pd.DataFrame(np.array(lst, dtype=object), columns=['name', 'desc'])
                    print("\n[*] Potential Vulnerable CVEs")
                    print(df.to_string(justify="left", col_space=10))

                    # Ask the user if they want to use the recommended exloit.
                    recommended_cve = use_recommended_cve(df)

                    # Ask the user if they want to use a local exploit.
                    if not recommended_cve:
                        use_local_exploit()

                except ValueError:
                    print("[!] No recommended CVEs!")
                    use_local_exploit()
