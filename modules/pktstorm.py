import re
import time
import os
import alive_progress
from requests import get
from json import loads


# Global variables 
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:58.0)Gecko/20100101 Firefox/58.0"}
CURRENT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


class Pkstorm:
    def __init__(self):
        """
        Default constructor. 
        :param:
        :return:
        """                
        self.host = "https://cvepremium.circl.lu/api/cve/"

    def search_cve(self, cve_list):
        """
        Searches for cve in packetstorm using cve.cirl.lu API.
        :param cve_list:
        :return: result['links']:
        :return: None:
        """
        for cve in cve_list:
            try:
                # Perform web requests for via API endpoint
                http_obj = get(self.host + cve.upper(), headers=HEADERS, timeout=4)
            except Exception as e:
                print(e)
                return None

            # Insert the references found into a list.
            if http_obj.json():
                pktstorm_link = []
                list_of_links = []
                json_obj = loads(http_obj.text)
                for i in json_obj["references"]:
                    if "packetstormsecurity.com/files/" in i:
                        pktstorm_link.append(i)
                total_count = len(pktstorm_link)
                with alive_progress.alive_bar(total_count) as bar:
                    for x in pktstorm_link:
                        list_of_links.append(x)
                        time.sleep(0.05)
                        bar()
                return list_of_links

    def download_files(self, link):
        """
        Downloads the chosen file.
        :param: link
        :return:
        """
        r = get(link, headers=HEADERS, timeout=10)
        pattern = "/files/download/(.*)/(.*).txt"
        result = re.search(pattern, str(r.content)).group()
        sep = '"'
        stripped = result.split(sep, 1)[0]
        download_link = "https://packetstormsecurity.com%s" % stripped
        r = get(download_link, headers=HEADERS, timeout=10)
        path = "%s/downloads/%s" % (CURRENT_PATH, stripped.rsplit("/", 1)[-1])
        with open(path, "wb") as f:
            f.write(r.content)

    def run(self, cve_list):
        """
        Returns a list of links.
        :param cve_list:
        :return link_list:
        """
        link_list = self.search_cve(cve_list)
        return link_list
