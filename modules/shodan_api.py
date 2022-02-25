import shodan
import numpy as np
import pandas as pd
import time
import os


class ShodanAPI:
    def __init__(self, api_key, filter):
        self.api = shodan.Shodan(api_key)
        self.api_key = api_key
        self.filter = filter
        self.target = pd.DataFrame()

    def check_api_info(self):
        print("[!] API Key Successfully Loaded!")
        print("[!] Only the first 100 results of the Shodan Cralwer will be displayed as this is an Edu Account!")
        # os.system("curl -X GET https://api.shodan.io/tools/myip?key=%s" % self.api_key)
        # print(" is Your Public IP Addreess!")
        time.sleep(5)

    def scan_filter(self):
        print("[!] Running search query!")
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
        try:
            data_frame = pd.DataFrame(np.array(results_list, dtype=object), columns=['hostnames', 'ip', 'domains', 'os', 'city', 'region_code', 'area_code', 'longitude', 'postal_code', 'country_code', 'country_name'],)
            os.system("clear")
            print(data_frame.to_string())
            target = input("[!] Select a target (e.g. 5): ")
            self.target = data_frame.iloc[[target]]
            print("Target %s selected!" % target)
            return True
        except ValueError:
            print("[!] No results found!")
            return False

    def retrieve_info(self):
        os.system("clear")
        print("[!] Retrieving info on the selected target!")
        cve_list = []

        # Store data into variables
        target = self.target['ip']
        host = self.api.host(target)
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
        print("\tDomains: %s" % host['domains'])
        print("\tHostnames: %s" % host['hostnames'])
        print("\tISP: %s" % host['isp'])
        print("\tOrg: %s" % host['org'])
        print("\tPorts: %s\n" % ', '.join(port_list))
        return host['ip_str'], cve_list, port_list

    def on_demand_scan(self, target):
        command = "shodan scan submit %s" % target
        os.system(command)
