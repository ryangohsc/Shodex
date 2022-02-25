<<<<<<< HEAD
import nmap


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
        if port_list:
            end = port_list[-1]
            port_range = "%s-%s" % (0, end)
        else:
            port_range = '0-1000'

        nmScan = nmap.PortScanner()
        cve_info = {}
        if speed == "quick":
            results = nmScan.scan(ip, port_range)
        else:
            results = nmScan.scan(ip, port_range)

        # Prints the summary details.
        print("\n\tSummary")
        print('\tCommand line: %s' % results['nmap']['command_line'])
        print('\tTime Stamp: %s' % results['nmap']['scanstats']['timestr'])
        print('\tNo. of hosts up: %s' % results['nmap']['scanstats']['uphosts'])
        print('\tNo. of hosts down: %s' % results['nmap']['scanstats']['downhosts'])
        print('\tTotal No. of hosts: %s\n' % results['nmap']['scanstats']['totalhosts'])

        # Prints the technical details of each port.
        keys = results['scan'].keys()
        # print(results['scan']) # Keep this for debugging purposes
        count = 1
        for ip in keys:
            temp = []
            print("\tTarget %s" % count)
            print('\tVendor: %s' % results['scan'][ip]['vendor'])
            try:
                sub_keys = results['scan'][ip]['tcp'].keys()
                for port in sub_keys:
                    print('\tPort: %s' % port)

                    state = results['scan'][ip]['tcp'][port]['state']
                    print('\tState: %s' % state)

                    name = results['scan'][ip]['tcp'][port]['name']
                    print('\tName: %s' % name)

                    product = results['scan'][ip]['tcp'][port]['product']
                    print('\tProduct: %s' % product)

                    version = results['scan'][ip]['tcp'][port]['version']
                    print('\tVersion: %s' % version)

                    extra_info = results['scan'][ip]['tcp'][port]['extrainfo']
                    print('\tExtra Info: %s\n' % extra_info)

                    temp.append({'port': port, 'name': name, 'product': product, 'version': version})

                    count += 1
                cve_info[ip] = temp
            except KeyError:
                pass
        return cve_info

    def run(self, ip, speed, port_list):
        """"
        Runs the nmap scan.
        :param: ip, speed.
        :return: cve_info.
        """
        return self.scan_target(ip, speed, port_list)
=======
import nmap


class Nmap:
    def __init__(self):
        """"
        Default constructor. 
        :param: self.
        :return: None.
        """
        self.results = {}

    def scan_target(self, ip, speed):
        """"
        Scans a particular target.
        :param: ip, speed.
        :return: cve_info.cve_List
        """
        nmScan = nmap.PortScanner()
        cve_info = {}
        if speed == "quick":
            results = nmScan.scan(ip, '0-110')
        else:
            results = nmScan.scan(ip, '0-65535')

        # Prints the summary details.
        print("Summary")
        print('Command line: %s' % results['nmap']['command_line'])
        print('Time Stamp: %s' % results['nmap']['scanstats']['timestr'])
        print('No. of hosts up: %s' % results['nmap']['scanstats']['uphosts'])
        print('No. of hosts down: %s' % results['nmap']['scanstats']['downhosts'])
        print('Total No. of hosts: %s\n' % results['nmap']['scanstats']['totalhosts'])

        # Prints the technical details of each port.
        keys = results['scan'].keys()
        # print(results['scan']) # Keep this for debugging purposes
        count = 1
        for ip in keys:
            print("Target %s" % count)
            print('Vendor: %s' % results['scan'][ip]['vendor'])
            try:
                sub_keys = results['scan'][ip]['tcp'].keys()
                for port in sub_keys:
                    print('Port: %s' % port)

                    state = results['scan'][ip]['tcp'][port]['state']
                    print('State: %s' % state)

                    name = results['scan'][ip]['tcp'][port]['name']
                    print('Name: %s' % name)

                    product = results['scan'][ip]['tcp'][port]['product']
                    print('Product: %s' % product)

                    version = results['scan'][ip]['tcp'][port]['version']
                    print('Version: %s' % version)

                    extra_info = results['scan'][ip]['tcp'][port]['extrainfo']
                    print('Extra Info: %s\n' % extra_info)

                    cve_info[ip] = {'port': port, 'name': name, 'product': product, 'version': version}

                    count += 1
            except KeyError:
                pass
        return cve_info

    def run(self, ip, speed):
        """"
        Runs the nmap scan.
        :param: ip, speed.
        :return: cve_info.
        """
        return self.scan_target(ip, speed)
>>>>>>> 4aea341f408aeab2298509fddfbdab6d5b4fe054
