import nmap
import numpy as np
import pandas as pd
import alive_progress
import time
from tabulate import tabulate
from .misc import *


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
        with alive_progress.alive_bar(len(port_list)) as bar:
            for port in port_list:
                result = scanner.scan(ip, str(port))
                try:
                    state = result['scan'][ip]['tcp'][int(port)]['state']
                except KeyError:
                    state = "" 
                try:
                    name = result['scan'][ip]['tcp'][int(port)]['name']
                except KeyError:
                    name = "" 
                try:
                    product = result['scan'][ip]['tcp'][int(port)]['product']
                except KeyError:
                    product = "" 
                try:
                    version = result['scan'][ip]['tcp'][int(port)]['version']
                except KeyError:
                    version = ""
                try: 
                    extra_info = result['scan'][ip]['tcp'][int(port)]['extrainfo']
                except KeyError:
                    extra_info = "" 
                lst.append([port, state, name, product, version, extra_info])
                cve_info_list.append({'port': port, 'name': name, 'product': product, 'version': version, 'state': state})
                cve_info[ip] = cve_info_list
                time.sleep(0.005)
                bar()
        print(print_green("\n[!] Open Ports"))
        df = pd.DataFrame(np.array(lst, dtype=object), columns=['port', 'state', 'name', 'product', 'version', 'extra_info']).astype(str)
        print(print_green(tabulate(df, headers='keys', tablefmt='psql')))
        return cve_info

    def run(self, ip, speed, port_list):
        """"
        Runs the nmap scan.
        :param: ip, speed.
        :return: cve_info.
        """
        return self.scan_target(ip, speed, port_list)
