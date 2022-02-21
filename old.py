import argparse
import shodan
import os

# Super vulnerabile IPs
# 45.79.111.38
# 194.195.213.197
# 123.59.120.129

SHODAN_API_KEY = "OooeRjrCHdbDI98zZV8VQqhoTT6WCqoc"
api = shodan.Shodan(SHODAN_API_KEY)


def main():
    # init_argparser()
    run()


def init_argparser():
    """
        Initialise the arg parser.
        :param: None
        :return: args
    """
    parser = argparse.ArgumentParser(description="ICT2206 - Codex", epilog="ICT2206 Assignment 1 Team x")
    # parser.add_argument()
    args = parser.parse_args()
    return args


def search():
    results = api.search('apache')
    count = 1

    for result in results['matches']:
        print("Hostnames: ", result['hostnames'])
        try:
            print(result['product'])
        except KeyError:
            pass
        print("Result ", count)
        print("IP String: ", result['ip_str'])
        print("Domains: ", result['domains'])
        print("OS: ", result['os'])
        print("Location: ", result['location'])
        print("=================================================================")
        print("")
        count += 1


def lookup_host():
    # To lookup a specific host
    # domains, hostnames, country code, org, city, latitude, ISP, longtitude, last update, country name, ip str, ports
    host = api.host('135.148.85.122')

    # Print all banners
    print(host)
    for item in host['data']:
        print("Port: %s" % item['port'])
        print("Banner: %s" % item['data'])



def lookup_ports():
    pass
#     pass
    #os.system("shodan scan submit --filename test 58.176.55.186")



    # KIV
    # Make a scan of a particular host (USELESS)
    # print(api.scan(ips='58.176.55.186', force=False))

    # KIV FIRST
    # Get the status of that scan
    # print(api.scan_status(scan_id='wgf6rINfEPymrL2h'))

    # Get the list of all scans on the current account
    # print(api.scans(page=1))

    # Download the scan results of a particular scan
    # os.system("shodan download --limit -1 {}-results scan:{}".format("wgf6rINfEPymrL2h", "wgf6rINfEPymrL2h"))

def run():
    # search()
    # lookup_host()
    lookup_ports()



if __name__ == '__main__':
    main()
