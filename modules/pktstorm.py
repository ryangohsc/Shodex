import re
import time
import alive_progress
from requests import get
from json import loads
import os

headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:58.0)Gecko/20100101 Firefox/58.0"}
current_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def search_cve(cve_list):
    """
    Searches for cve in packetstorm using cve.cirl.lu API
    :param cve_list:
    :return: result['links'] or None
    """
    host = "https://cvepremium.circl.lu/api/cve/"

    for cve in cve_list:
        try:
            # Perform web requests for via API endpoint
            http_obj = get(host + cve.upper(), headers=headers, timeout=4)
        except Exception as e:
            print(e)
            return None

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


def download_files(link):
    """
    Downloads the chosen file
    :param link:
    :return: None
    """
    r = get(link, headers=headers, timeout=10)
    pattern = "/files/download/(.*)/(.*).txt"
    result = re.search(pattern, str(r.content)).group()
    sep = '"'
    stripped = result.split(sep, 1)[0]
    download_link = "https://packetstormsecurity.com%s" % stripped
    r = get(download_link, headers=headers, timeout=10)
    path = "%s/downloads/%s" % (current_path, stripped.rsplit("/", 1)[-1])
    with open(path, "wb") as f:
        f.write(r.content)


def run(cve_list):
    """
    Returns a list of links
    :param cve_list:
    :return: link_list
    """
    link_list = search_cve(cve_list)
    return link_list


if __name__ == "__main__":
    cve_lists = ["CVE-2021-42013"]
    link = run(cve_lists)
    download_files(link[0])
