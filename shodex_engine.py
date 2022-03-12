from modules.exploit_db import *
from modules.pktstorm import *
from modules.github import *
from modules.shodan_api import *
from modules.nmap import *
from modules.local_cve_parser import *
from modules.exploit_loader import *
from tabulate import tabulate
from modules.ftp_brute import FTPBrute
from modules.ssh_brute import SSHBrute
from modules.telnet_brute import TelnetBrute
from modules.http_brute import HTTPBrute


def use_recommended_cve(df):
    """"
    Locates the recommended exploit that the user wishes to use.
    :param: df.
    :return: True or None.
    """
    valid = False
    while valid is not True:
        # Prompt the user if they wish to use a recommended exploit.
        choice = input(print_yellow("\n[+] Do you wish to use a recommended CVE (y/n): "))

        # The user does not wish to use a recommended exploit.
        if choice.lower() == "y":
            row_choice = input(print_yellow("\t[+] Enter row no: "))
            if int(row_choice) not in range(len(df)):
                print(print_red("[!] Error! Invalid input entered!"))
            else:
                search_list = df.iloc[[row_choice]].name.to_string().split(" ")[4]
                exploit_db = ExploitDb()
                found, exploit_file_path = exploit_db.run([search_list])

                # If a recommended exploit is found.
                if found is True:
                    exploit_path = exploit_file_path
                    exploit_ext = exploit_file_path.split(".")[1]

                    # Arm the exploit.
                    exploit_loader = ExploitLoader(exploit_path, exploit_ext)
                    exploit_loader.run()
                    return True

                # If a recommended exploit is not found in exploit-db.
                else:
                    print(print_red("\n[!] Unable to find the CVE in exploit-db!"))
                    valid = False
                    while valid is not True:
                        choice = input(print_yellow("\n[+] Do you wish to use search for the CVE online? Searching "
                                       "online disables the autoloader feature. (y/n): "))
                        if choice.lower() == "y":
                            try:
                                print(print_yellow("\n[!] Searching PacketStormSecurity"))
                                pktstorm = Pkstorm()
                                pktstorm_link = pktstorm.run([search_list])
                                pktstorm_df = pd.DataFrame({"link": pktstorm_link})
                                print(print_yellow("\n[!] Searching GitHub"))
                                github = Github()
                                github_link = github.run([search_list])
                                github_df = pd.DataFrame({"link": github_link})
                                online_df = [pktstorm_df, github_df]
                                result_df = pd.concat(online_df)
                                print(print_green("\n[!] Available exploits!"))
                                print(print_green(tabulate(result_df, headers='keys', tablefmt='psql')))
                                row_choice = input(print_yellow("\t[+] Enter row no: "))
                                if int(row_choice) not in range(len(result_df)):
                                    print(print_red("[!] Error! Invalid input entered!"))
                                else:
                                    choice_link = result_df.iloc[[row_choice]].link[0]
                                    if "packetstormsecurity" in choice_link:
                                        print(print_yellow("[+] Downloading in progress"))
                                        pktstorm.download_files(choice_link)
                                        print(print_green("[!] Downloading completed, downloaded files are located in "
                                              " the downloads folder"))
                                        sys.exit(0)
                                    elif "github" in choice_link:
                                        print(print_yellow("[+] Downloading in progress"))
                                        github.download_files(choice_link)
                                        print(print_green("[!] Downloading completed, downloaded files are located in the downloads"
                                              " folder"))
                                        sys.exit(0)
                            except:
                                print(print_red("[!] Failed to search online!"))

                        # The user does not wish to search online.
                        elif choice.lower() == "n":
                            return None
                        # The user supplies an invalid input.
                        else:
                            print(print_red("[!] Error! Invalid input entered!"))

                    return None

        # The user does not wish to use a recommended exploit.
        elif choice.lower() == "n":
            return None

        # The user supplies an invalid input.
        else:
            print(print_red("[!] Error! Invalid input entered!"))


def use_local_exploit():
    """"
    Asks the user to provide a local exploit and attempts to load it.
    :param: None.
    :return: None.
    """
    valid = False
    while valid is not True:
        # Prompt the user if they want to use a local exploit.
        choice = input(print_yellow("\n[+] Do you wish to use a local exploit (y/n): "))

        # If the user wishes to use a local exploit.
        if choice.lower() == "y":
            exploit_name = input(print_yellow("\t[+] Enter the exploit name: "))
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
                print(print_red("[!] Error! Exploit not found!"))

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
            print(print_red("[!] Error! Invalid input entered!"))


def online_mode(api_key, ondemand, search_filter, speed, brute):
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
        print(print_yellow("[!] Initiating an ondemand scan!"))
        shodan_app.on_demand_scan(ondemand)

    # Search mode.
    else:
        if shodan_app.search_filter():
            target, cve_list, port_list = shodan_app.retrieve_info()
            offline_mode(speed, target, port_list, cve_list, brute)


def offline_mode(speed, target, port_list, cve_list, brute):
    """"
    The offline mode which uses nmap to scan a target.
    :param: speed, target, port_list.
    :return: None.
    """
    # If there are CVEs returned by Shodan.
    if cve_list:
        df = pd.DataFrame(np.array(cve_list, dtype=object), columns=['name'])
        print(print_green("[!] CVEs obtained from Shodan"))
        print(df.to_string(justify="left", col_space=10))

        # If the user does not want to use a recommended exploit or no recommended exploits are found.
        if use_recommended_cve(df) is not True:
            # Ask the user if they want to run a local exploit instead if the recommended one failed.
            use_local_exploit()

        # Exit the program.
        exit()

    # Initiate a nmap scan if there are no CVEs returned by Shodan.
    print(print_yellow("[*] Initiating an offline nmap scan!"))
    nmap = Nmap()
    if speed is None:
        speed = "quick"
    service_list = nmap.run(target, speed, port_list)

    # End the process if no hosts are up
    if service_list == {}:
        print(print_red("[!] Error! No hosts are up!"))
        return

    # Mapping Nmap results with brute force modules
    if brute:
        ftp_module = False
        ssh_module = False
        telnet_module = False
        http_module = False
        ip = list(service_list.keys())[0]
        for item in service_list[ip]:
            if str(item["port"]) == "21" and item["state"] == "open":
                print(print_yellow("\n[*] Executing FTP brute force module!"))
                ftp_module = True
                ftp_thread = FTPBrute(target)
                ftp_thread.start()
            if str(item["port"]) == "22" and item["state"] == "open":
                print(print_yellow("\n[*] Executing SSH brute force module!"))
                ssh_module = True
                ssh_thread = SSHBrute(target)
                ssh_thread.start()
            if str(item["port"]) == "23" and item["state"] == "open":
                print(print_yellow("\n[*] Executing Telnet brute force module!"))
                telnet_module = True
                telnet_thread = TelnetBrute(target)
                telnet_thread.start()
            if str(item["port"]) == "80" and item["state"] == "open":
                print(print_yellow("\n[*] Executing HTTP brute force module!"))
                http_module = True
                http_url = "http://" + target
                http_thread = HTTPBrute(http_url)
                http_thread.start()

    # Check if there are any services and CVEs found for each IP
    exist = False
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
                    cve_name = item2[0].strip(" ")
                    lst.append([cve_name])

                # Store and clean the data.
                try:
                    df = pd.DataFrame(np.array(lst, dtype=object), columns=['name'])
                    print(print_green("\n[!] Potential Vulnerable CVEs"))
                    print(print_red("Note: The description is unable to be displayed due to display limitations."))
                    print(print_green(tabulate(df, headers='keys', tablefmt='psql')))

                    # Ask the user if they want to use the recommended exploit.
                    recommended_cve = use_recommended_cve(df)
                    if recommended_cve:
                        exist = True

                    # Ask the user if they want to use a local exploit.
                    if not recommended_cve:
                        use_local_exploit()
                        exist = True

                except ValueError:
                    pass

    # Display error message if no recommended CVEs are found.
    if not exist:
        print(print_red("[!] No recommended CVEs!"))

    # Wait for the respective brute force threads.
    if brute:
        if ftp_module:
            if ftp_thread.is_alive():
                print(print_yellow("\n[*] FTP brute force module is still executing!"))
            ftp_thread.join()
        if ssh_module:
            if ssh_thread.is_alive():
                print(print_yellow("\n[*] SSH brute force module is still executing!"))
            ssh_thread.join()
        if telnet_module:
            if telnet_thread.is_alive():
                print(print_yellow("\n[*] TELNET brute force module is still executing!"))
            telnet_thread.join()
        if http_module:
            if http_thread.is_alive():
                print(print_yellow("\n[*] HTTP brute force module is still executing!"))
            http_thread.join()
