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
        os.system("curl -X GET https://api.shodan.io/tools/myip?key=%s" % self.api_key)
        print(" is Your Public IP Addreess!")
        time.sleep(5)

    def scan_filter(self):
        os.system("cls")
        print("[!] Running search!")
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
            print(data_frame.to_string())
            target = input("[!] Select a target (e.g. 5): ")
            self.target = data_frame.iloc[[target]]
            print("Target %s selected!" % target)
            return True
        except ValueError:
            print("[!] No results found!")
            return False

    def scan_specified_ip(self):
        os.system("cls")
        print("[!] Running a scan on the selected target!")
        port_list = []
        cve_list = []

        # Store data into variables
        target = self.target['ip']
        host = self.api.host(target)
        port_list = [str(item['port']) for item in host['data']]
        cve_list = host['vulns']

        # Print the information
        print("Target Information")
        print("IP: %s\n" % host['ip_str'])
        print("Ports: %s\n" % ', '.join(port_list))
        print("Vulns: %s\n" % ', '.join(cve_list))
        print(cve_list)

        with open("test.txt", "w", encoding="utf-8") as a_file:
            a_file.write(str(host['data']))


