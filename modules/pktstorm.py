import re
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
    host = "http://cve.circl.lu/api/cve/"

    for cve in cve_list:
        try:
            # Perform web requests for via API endpoint
            http_obj = get(host + cve.upper(), headers=headers, timeout=4)
        except Exception as e:
            print(e)
            return None

        if http_obj.json():
            # dictionary object containing cve description and available exploits
            result = {'links': []}

            json_obj = loads(http_obj.text.encode('ascii', 'utf-8'))
            ref_misc = set()

            # cve publishing date and cve description
            result['description'] = json_obj['summary']
            result['date'] = json_obj['Published'][:10]

            if 'references' in json_obj:
                for idx_misc in json_obj['references']:
                    ref_misc.add(idx_misc)
                if len(ref_misc) > 0:
                    for link in sorted(ref_misc):
                        if "packetstormsecurity.com/files/" in link:
                            result['links'].append(link)
        return result['links']
    return None


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
    run(cve_lists)
    download_files(cve_lists[0])
