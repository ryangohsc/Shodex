import shodan
import numpy as np
import pandas as pd
import time
import os


class ShodanAPI:
    def __init__(self, api_key, filter):
        """"
        Default constructor. 
        :param: self, api_key, filter.
        :return: None.
        """        
        self.api = shodan.Shodan(api_key)
        self.api_key = api_key
        self.filter = filter
        self.target = pd.DataFrame()

    def check_api_info(self):
        """"
        Displays success and limitation messages. 
        :param: self.
        :return: None.
        """     
        print("[+] API Key Successfully Loaded!")
        print("[!] Only the first 100 results of the Shodan Cralwer will be displayed as this is an Edu Account!\n")
        time.sleep(5)

    def search_filter(self):
        """"
        Runs a search filter on Shodan's database. 
        :param: self.
        :return: None.
        """     
        # Obtain the results from Shodan and store them into a list. 
        print("[*] Retrieving results from Shodan!")
        try:
            results = self.api.search(self.filter)
            results_list = []
            for result in results['matches']:
                sub_results_list = []
                sub_results_list.append(result['hostnames'])
                sub_results_list.append(result['ip_str'])
                sub_results_list.append(result['domains'])
                sub_results_list.append(result['os'])
                sub_results_list.append(result['location']['city'])
                sub_results_list.append(result['location']['region_code'])
                sub_results_list.append(result['location']['area_code'])
                sub_results_list.append(result['location']['longitude'])
                sub_results_list.append(result['location']['postal_code'])
                sub_results_list.append(result['location']['country_code'])
                sub_results_list.append(result['location']['country_name'])
                results_list.append(sub_results_list)
        except shodan.exception.APIError:
            print("[!] Unexpected error with the Shodan API! Restart the program.")
            exit() 

        try:
            # Store, display & clean the data in a dataframe. 
            df = pd.DataFrame(np.array(results_list, dtype=object), columns=['hostnames', 'ip', 'domains', 'os', 'city', 'region_code', 'area_code', 'longitude', 'postal_code', 'country_code', 'country_name']).astype(str)
            df = df.drop_duplicates()
            df = df.reset_index(drop=True)
            os.system("clear")
            print(df.to_string(justify="left", col_space=10))

            # Get the user to select a target
            df_len = len(df)
            valid = False 
            while valid is not True:
                # Prompt the user for a target
                target = int(input("\n[+] Select a target (e.g. 5): "))

                # Check that the input entered is valid. 
                if target not in range(0, df_len):
                    print("[!] Error! Invalid input entered!")
                else:
                    valid = True
                    self.target = df.iloc[[target]]
                    print("Target %s selected!" % target)
            return True
        except ValueError:
            print("[!] No results found!")
            return False

    def retrieve_info(self):
        """"
        Retrieves the info on the target selected by the user.
        :param: self.
        :return: None.
        """     
        os.system("clear")
        print("[*] Retrieving info on the selected target!")
        cve_list = []

        # Store data into variables
        target = self.target['ip']
        try:
            host = self.api.host(target)
        except shodan.exception.APIError:
            print("[!] Unexpected error with the Shodan API! Restart the program.")
            exit()
        port_list = [str(item['port']) for item in host['data']]
        try:
            cve_list = host['vulns']
        except KeyError:
            pass

        # Print the information
        print("\n\tTarget Information")
        print("\tLast update: %s" % host['last_update'])
        print("\tIP: %s" % host['ip_str'])
        print("\tCity: %s" % host['city'])
        print("\tCountry: %s" % host['country_name'])
        print("\tOS: %s" % host['os'])
        print("\tDomains: %s" % " ".join(host['domains']))
        print("\tHostnames: %s" % " ".join(host['hostnames']))
        print("\tISP: %s" % host['isp'])
        print("\tOrg: %s" % host['org'])
        print("\tPorts: %s\n" % ', '.join(port_list))
        return host['ip_str'], cve_list, port_list

    def on_demand_scan(self, target):
        """"
        Performs a on-demand scan on the target. 
        :param: self, target.
        :return: None.
        """          
        command = "shodan scan submit %s" % target
        os.system(command)
