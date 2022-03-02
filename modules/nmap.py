import nmap
import numpy as np
import pandas as pd
from tabulate import tabulate


class Nmap:
    def __init__(self):
        """"
        Default constructor. 
        :param: self.
        :return: None.
        """
        self.results = {}

    def scan_target(self, ip, speed, port_list):
        """"
        Scans a particular target.
        :param: ip, speed.
        :return: cve_info.cve_List
        """
        # Define the port range to scan.
        scanner = nmap.PortScanner()
        lst = []
        cve_info_list = []
        cve_info = {}
        if not port_list:
            if speed == "fast":
                port_list = [i for i in range(0, 1024)]
            else:
                port_list = [i for i in range(0, 65535)]

        # Scan the individual ports.
        for port in port_list:
            result = scanner.scan(ip, port)
            state = result['scan'][ip]['tcp'][int(port)]['state']
            name = result['scan'][ip]['tcp'][int(port)]['name']
            product = result['scan'][ip]['tcp'][int(port)]['product']
            version = result['scan'][ip]['tcp'][int(port)]['version']
            extra_info = result['scan'][ip]['tcp'][int(port)]['extrainfo']
            lst.append([port, state, name, product, version, extra_info])
            cve_info_list.append({'port': port, 'name': name, 'product': product, 'version': version})
            cve_info[ip] = cve_info_list
        print("[!] Open Ports")
        df = pd.DataFrame(np.array(lst, dtype=object), columns=['port', 'state', 'name', 'product', 'version', 'extra_info']).astype(str)
        print(tabulate(df, headers='keys', tablefmt='psql'))
        return cve_info

    def run(self, ip, speed, port_list):
        """"
        Runs the nmap scan.
        :param: ip, speed.
        :return: cve_info.
        """
        return self.scan_target(ip, speed, port_list)
