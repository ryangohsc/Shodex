import shodan
import numpy as np
import pandas as pd
import time
import os
from tabulate import tabulate
from .misc import *


class ShodanAPI:
    def __init__(self, api_key, filter):
        """"
        Default constructor.
        :param api_key:
        :param filter:
        :return:
        """        
        self.api = shodan.Shodan(api_key)
        self.api_key = api_key
        self.filter = filter
        self.target = pd.DataFrame()

    def check_api_info(self):
        """"
        Displays success and limitation messages. 
        :param:
        :return:
        """     
        print(print_green("[+] API Key Successfully Loaded!"))
        print(print_red("[!] Only the first 100 results of the Shodan Crawler will be displayed "
                        "as this is an Edu Account!\n"))
        time.sleep(5)

    def search_filter(self):
        """"
        Runs a search filter on Shodan's database. 
        :param:
        :return True:
        :return False:
        """     
        # Obtain the results from Shodan and store them into a list. 
        print(print_yellow("[*] Retrieving results from Shodan!"))
        try:
            results = self.api.search(self.filter)
            results_list = []
            for result in results['matches']:
                hostnames = ", ".join(result['hostnames'])
                if not hostnames:
                    hostnames = None
                domains = ", ".join(result['domains'])
                if not domains:
                    domains = None
                ip = result['ip_str']
                operating_system = result['os']
                city = result['location']['city']
                region_code = result['location']['region_code']
                area_code = result['location']['area_code']
                longtitude = result['location']['longitude']
                postal_code = result['location']['postal_code']
                country_code = result['location']['country_code']
                country_name = result['location']['country_name']
                sub_results_list = [hostnames, ip, domains, operating_system, city, region_code, area_code, longtitude,
                                    postal_code, country_code, country_name]
                results_list.append(sub_results_list)
        except shodan.exception.APIError:
            print(print_red("[!] Unexpected error with the Shodan API! Restart the program."))
            exit() 

        try:
            # Store, display & clean the data in a dataframe. 
            df = pd.DataFrame(np.array(results_list, dtype=object), columns=['hostnames', 'ip', 'domains', 'os', 'city', 'region_code', 'area_code', 'longitude', 'postal_code', 'country_code', 'country_name']).astype(str)
            df = df.drop_duplicates()
            df = df.reset_index(drop=True)
            os.system("clear")
            print(print_yellow(tabulate(df, headers='keys', tablefmt='psql')))

            # Get the user to select a target.
            df_len = len(df)
            valid = False 
            while valid is not True:
                # Prompt the user for a target.
                target = int(input(print_yellow("\n[+] Select a target (e.g. 5): ")))

                # Check that the input entered is valid. 
                if target not in range(0, df_len):
                    print(print_red("[!] Error! Invalid input entered!"))
                else:
                    valid = True
                    self.target = df.iloc[[target]]
                    print(print_yellow("Target %s selected!" % target))
            return True
        except ValueError:
            print(print_red("[!] No results found!"))
            return False

    def retrieve_info(self):
        """"
        Retrieves the info on the target selected by the user.
        :param:
        :return host['ip_str']:
        :return cve_list:
        :return port_list:
        """     
        os.system("clear")
        print(print_yellow("[*] Retrieving info on the selected target!"))
        cve_list = []

        # Store data into variables.
        target = self.target['ip']
        try:
            host = self.api.host(target)
        except shodan.exception.APIError:
            print(print_red("[!] Unexpected error with the Shodan API! Restart the program."))
            exit()
        port_list = [str(item['port']) for item in host['data']]
        try:
            cve_list = host['vulns']
        except KeyError:
            pass

        # Print the information.
        print(print_yellow("\n\tTarget Information"))
        print(print_yellow("\tLast update: %s" % host['last_update']))
        print(print_yellow("\tIP: %s" % host['ip_str']))
        print(print_yellow("\tCity: %s" % host['city']))
        print(print_yellow("\tCountry: %s" % host['country_name']))
        print(print_yellow("\tOS: %s" % host['os']))
        print(print_yellow("\tDomains: %s" % " ".join(host['domains'])))
        print(print_yellow("\tHostnames: %s" % " ".join(host['hostnames'])))
        print(print_yellow("\tISP: %s" % host['isp']))
        print(print_yellow("\tOrg: %s" % host['org']))
        print(print_yellow("\tPorts: %s\n" % ', '.join(port_list)))
        return host['ip_str'], cve_list, port_list

    def on_demand_scan(self, target):
        """"
        Performs a on-demand scan on the target. 
        :param: self, target.
        :return:
        """          
        command = "shodan scan submit %s" % target
        os.system(command)
