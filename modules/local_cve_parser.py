import os
import pandas as pd
import csv
import re
from os import path
from datetime import date
from itertools import combinations


# Global Variables
CVE_URL = "cve.mitre.org/data/downloads/allitems.csv"
INDEX_URL = "cve.mitre.org/data/downloads/"
INDEX_FILE = "index.html"
OUTPUT_FILE = "allitems.csv"
PORT = 0
NAME = 1 
PRODUCT = 2 
VERSION = 3 
KEY = 0 
VALUE = 1

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
        parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
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
            self.download_csv_file()

    def download_csv_file(self):
        """"

        :param:
        :return:
        """
        print("[+] Updating CVE database...")
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
        parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        self.data_folder_path = os.path.join(parent_dir, "data")
        self.cve_database_path = os.path.join(self.data_folder_path, OUTPUT_FILE)
        count = 0
        lst = []
        success = False 

        while success is False:
            try:
                with open(self.cve_database_path, 'r', encoding="ISO-8859-1") as file:
                    reader = csv.reader(file)
                    for row in reader:
                        if count >= 10:
                            data = [row[0], row[2]]
                            lst.append(data)
                        count += 1
                df = pd.DataFrame(lst, columns=['name', 'description'])
                success = True
            except FileNotFoundError:
                self.check_last_update()
        return df

    def search_cve(self, df, search_query):
        """"

        :param:
        :return:
        """
        return df[df.description.str.contains(search_query)]

    def run(self, service_list):
        """"
        Runs the local CVE parser.
        :param: ip, speed.
        :return: cve_info.
        """
        df = self.parse_cev()
        cve_list = []
        items = list(service_list.values())
      
        port = items[PORT]
        name = items[NAME]
        product = items[PRODUCT]
        version = items[VERSION]

        search_queries = [] 
        pattern = r".. [0-9].."

        if product == "" and version == "":
            pass 
        
        if product != "" and version != "":
            product_words = product.split(" ")
            version_words = version.split(" ")
            all_words = product_words + version_words

            total_combinations = []
            for n in range(0, len(all_words) + 1):
                total_combinations.append([i for i in combinations(all_words, n)])
            
            for item in total_combinations:
                for combination in item:
                    if len(combination) != 1:
                        search_query = " ".join(combination)
                        if re.search(pattern, search_query):
                            search_queries.append(search_query)

        for item in search_queries:
            result = self.search_cve(df, item)

            # Store the results into a list and return the list of CVEs.
            for row in result.itertuples():
                cve_list.append((row.name, row.description))

        return cve_list
