import os
import pandas as pd
import csv
from os import path
from datetime import date

# Global Variables
CVE_URL = "cve.mitre.org/data/downloads/allitems.csv"
INDEX_URL = "cve.mitre.org/data/downloads/"
INDEX_FILE = "index.html"
OUTPUT_FILE = "allitems.csv"


class LocalCveParser:
    def __init__(self):
        """"
        Default constructor.
        :param: None.
        :return: None.
        """
        self.data_folder_path = ""
        self.last_update_file_path = ""
        self.cve_database_path = ""

    def check_last_update(self):
        """"

        :param:
        :return:
        """
        parent_dir = os.path.dirname(os.getcwd())
        self.data_folder_path = os.path.join(parent_dir, "data")
        self.last_update_file_path = os.path.join(self.data_folder_path, 'last_update.txt')

        # Check if the "data" folder exists.
        if path.exists(self.data_folder_path) is False:
            os.makedirs(self.data_folder_path)
            self.download_csv_file()

        # Check if the "cve.csv" exists within the "data" folder.
        cve_file = os.path.join(parent_dir, "data", "allitems.csv")
        if path.exists(cve_file) is False:
            self.download_csv_file()

        # Check the last update of the "cve.csv" and ask if the user wishes to update it.
        else:
            last_update_file = open(self.last_update_file_path, "r")
            last_update = last_update_file.read()
            print("[!] Last update was on %s" % last_update)
            update = input("[+] Do you wish to update the CVE database? (y/n): ")
            if update == "y":
                print("[*] Updating CVE database...")
                self.download_csv_file()

    def download_csv_file(self):
        """"

        :param:
        :return:
        """
        print("[*] Downloading CVE database...")
        output_path = os.path.join(self.data_folder_path, OUTPUT_FILE)
        download_url = "curl -s http://%s --output %s" % (CVE_URL, output_path)
        os.system(download_url)
        last_update_file = open(self.last_update_file_path, "w+")
        last_update_file.write(str(date.today()))
        last_update_file.close()
        print("[!] CVE database successfully downloaded!")

    def parse_cev(self):
        """"

        :param:
        :return:
        """
        self.cve_database_path = os.path.join(self.data_folder_path, OUTPUT_FILE)
        count = 0
        lst = []
        with open(self.cve_database_path, 'r', encoding="ISO-8859-1") as file:
            reader = csv.reader(file)
            for row in reader:
                if count >= 10:
                    data = [row[0], row[2]]
                    lst.append(data)
                count += 1
        df = pd.DataFrame(lst, columns=['name', 'description'])
        return df

    def search_cve(self, df, search_query):
        """"

        :param:
        :return:
        """
        return df[df.description.str.contains(search_query)]

    def run(self, target_cve_list):
        """"
        Runs the local CVE parser.
        :param: ip, speed.
        :return: cve_info.
        """
        self.check_last_update()
        df = self.parse_cev()
        search_list = []
        for service in target_cve_list:
            word_list = target_cve_list[service]['product'].split(" ")

            # Check that the product field is not empty.
            if len(word_list) != 0:
                # Include the product into the search list based on certain requirements.
                if len(word_list) > 1:
                    search_query = " ".join(word_list[:2])
                    search_list.append(search_query)
                else:
                    search_query = word_list[0]
                    search_list.append(search_query)

                # Include the version into the search list is it exist.
                version = target_cve_list[service]['version']
                if version != "":
                    search_query = "%s %s" % (search_query, version)
                    search_list.append(search_query)
                    final_query = "|".join(search_list)
                print(self.search_cve(df, final_query))


# Store the results into a list and return

