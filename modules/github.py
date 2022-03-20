import alive_progress
import os
import time
from requests import get
from json import loads
from modules.misc import *


# Global variables 
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:58.0)Gecko/20100101 Firefox/58.0"}
CURRENT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


class Github:
    def __init__(self):
        """
        Default constructor. 
        :param:
        :return:
        """        
        self.host = "https://api.github.com/search/repositories?q="  

    def search_cve(self, cve_list):
        """
        Searches the list of CVEs using the GitHub API.
        :param cve_list:
        :return list_of_links:
        """
        for cve in cve_list:
            try:
                # Perform web requests for via API endpoint
                http_obj = get(self.host + cve.upper(), headers=HEADERS, timeout=4)
            except Exception as e:
                print(e)
                return None

            if http_obj.json():
                list_of_links = []
                json_obj = loads(http_obj.text)
                total_count = len(json_obj["items"])
                with alive_progress.alive_bar(total_count) as bar:
                    for x in range(total_count):
                        list_of_links.append(json_obj["items"][x]["html_url"])
                        time.sleep(0.05)
                        bar()
                return list_of_links

    def download_files(self, arg_link):
        """
        Downloads the chosen link.
        :param arg_link:
        :return: 
        """
        folder_name = arg_link.rsplit("/", 1)[-1]
        path = "%s/downloads/%s" % (CURRENT_PATH, folder_name)
        git_link = "%s.git" % arg_link
        if not os.path.exists(path):
            print("[!] Downloading %s" % arg_link)
            git.Repo.clone_from(git_link, path, progress=CloneProgress())
        else:
            print("[!] The folder already exists!")

    def run(self, cve_list):
        """
        :param cve_list:
        :return link_list:
        """
        link_list = self.search_cve(cve_list)
        return link_list
