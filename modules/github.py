from requests import get
from json import loads
import os
import git

headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:58.0)Gecko/20100101 Firefox/58.0"}
current_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def search_cve(cve_list):
    """
    Searches the list of CVEs using the GitHub API
    :param cve_list:
    :return: list_of_links
    """
    host = "https://api.github.com/search/repositories?q="

    for cve in cve_list:
        try:
            # Perform web requests for via API endpoint
            http_obj = get(host + cve.upper(), headers=headers, timeout=4)
        except Exception as e:
            print(e)
            return None

        if http_obj.json():
            list_of_links = []
            json_obj = loads(http_obj.text)
            total_count = json_obj["total_count"]
            for i in range(total_count):
                list_of_links.append(json_obj["items"][i]["html_url"])
            return list_of_links


def download_files(arg_link):
    """
    Downloads the chosen link
    :param arg_link:
    :return: None
    """
    folder_name = arg_link.rsplit("/", 1)[-1]
    path = "%s/downloads/%s" % (current_path, folder_name)
    git_link = "%s.git" % arg_link
    if not os.path.exists(path):
        print("[+] Downloading %s" % arg_link)
        git.Repo.clone_from(git_link, path)
    else:
        print("[!] The folder already exists!")


def run(cve_list):
    """
    :param cve_list:
    :return: link_list
    """
    link_list = search_cve(cve_list)
    return link_list


if __name__ == "__main__":
    cve_lists = ["CVE-2021-42013"]
    link = run(cve_lists)
    download_files(link[0])
