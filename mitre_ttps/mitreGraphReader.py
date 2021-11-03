import os
import json
import networkx as nx
import logging
import sys
import csv


# picked_techniques = {"/techniques/T1566/001",
#                      "/techniques/T1566/002",
#                      "/techniques/T1566/003",
#                      "/techniques/T1195/001",
#                      "/techniques/T1195/002",
#                      "/techniques/T1059/001",
#                      "/techniques/T1059/003",
#                      "/techniques/T1059/005",
#                      "/techniques/T1059/007",
#                      "/techniques/T1559/001",
#                      "/techniques/T1204/001",
#                      "/techniques/T1204/002",
#                      "/techniques/T1053/005",
#                      "/techniques/T1547/001",
#                      "/techniques/T1037/001",
#                      "/techniques/T1547/001",
#                      "/techniques/T1547/002",
#                      "/techniques/T1112",
#                      "/techniques/T1218/005",
#                      "/techniques/T1218/010",
#                      "/techniques/T1218/011",
#                      "/techniques/T1078/001",
#                      "/techniques/T1518/001",
#                      "/techniques/T1083",
#                      "/techniques/T1057",
#                      "/techniques/T1012",
#                      "/techniques/T1497/001",
#                      "/techniques/T1560/001",
#                      "/techniques/T1123",
#                      "/techniques/T1119",
#                      "/techniques/T1041"}
picked_techniques_name_dict = {"/techniques/T1566/001": "Phishing",
                     "/techniques/T1566/002": "Phishing",
                     "/techniques/T1566/003": "Phishing",
                     "/techniques/T1195/001": "Supply Chain Compromise",
                     "/techniques/T1195/002": "Supply Chain Compromise",
                     "/techniques/T1059/001": "Command and Scripting Interpreter",
                     "/techniques/T1059/003": "Command and Scripting Interpreter",
                     "/techniques/T1059/005": "Command and Scripting Interpreter",
                     "/techniques/T1059/007": "Command and Scripting Interpreter",
                     "/techniques/T1559/001": "Inter-Process Communication",
                     "/techniques/T1204/001": "User Execution: Malicious Link",
                     "/techniques/T1204/002": "User Execution: Malicious File",
                     "/techniques/T1053/005": "Scheduled Task/Job",
                     "/techniques/T1037/001": "Boot or Logon Initialization Scripts",
                     "/techniques/T1547/001": "Boot or Logon Autostart Execution",
                     "/techniques/T1547/002": "Boot or Logon Autostart Execution",
                     "/techniques/T1112": "Modify Registry",
                     "/techniques/T1012": "Query Registry",
                     "/techniques/T1218/005": "Signed Binary Proxy Execution: Mshta",
                     "/techniques/T1218/010": "Signed Binary Proxy Execution: REgsvr32",
                     "/techniques/T1218/011": "Signed Binary Proxy Execution: Rundll32",
                     "/techniques/T1078/001": "Valid Accounts",
                     "/techniques/T1518/001": "Software Discovery",
                     "/techniques/T1083": "File and Directory Discovery",
                     "/techniques/T1057": "Process Discovery",
                     "/techniques/T1497/001": "Virtualization/Sandbox Evasion",
                     "/techniques/T1560/001": "Archive Collected Data",
                     "/techniques/T1123": "Audio Capture",
                     "/techniques/T1119": "Automated Collection",
                     "/techniques/T1041": "Exfiltration Over C2 Channel"}
picked_techniques = set([technique_name[12:18] for technique_name in picked_techniques_name_dict.keys()])

class MitreGraphReader:
    mitre_graph: nx.Graph
    link_file_map: dict

    def __init__(self, gml_location: str = r"./Mitre_TTPs/Tactic_Technique_Reference_Example.gml", link_file_map_file:str = r"./data/cti/html/html_url_hash.csv"):
        self.mitre_graph = nx.read_gml(gml_location)
        self.link_file_map = read_csv_as_dict(link_file_map_file)

    def get_technique_list(self) -> list:
        technique_list = []

        for n in self.mitre_graph.nodes():
            if self.mitre_graph.nodes[n]["types"] == "technique" or self.mitre_graph.nodes[n]["types"] == "sub_technique":
                technique_list.append(n)

        return technique_list

    def get_tactic_list(self) -> list:
        tactic_list = []

        for n in self.mitre_graph.nodes():
            if self.mitre_graph.nodes[n]["types"] == "tactic":
                tactic_list.append(n)

        return tactic_list

    def get_technique_for_tactic(self, tactic_id: str) -> list:
        technique_list = []

        for n in self.mitre_graph.neighbors(tactic_id):
            if self.mitre_graph.nodes[n]["types"] == "technique" or self.mitre_graph.nodes[n]["types"] == "super_technique":
                technique_list.append(n)

        return technique_list

    # def get_variants_for_technique(self, technique_id: str):
    #     try:
    #         technique_template_path = r"/data/technique_template/" + technique_id[12:18] + ".json"
    #         print(technique_template_path)
    #         with open(technique_template_path) as template:
    #
    #     except:
    #         return None

    def get_name_for_technique(self, technique_id: str) -> list:
        return self.mitre_graph.nodes[technique_id]["name"]

    def get_super_for_technique(self, technique_id: str) -> str:
        if self.mitre_graph.nodes[technique_id]["types"] != "sub_technique":
            return technique_id

        for n in self.mitre_graph.neighbors(technique_id):
            if self.mitre_graph.nodes[n]["types"] == "super_technique":
                return n

    def get_super_sub_technique_dict(self):
        super_sub_technique_dict = {}

        for n in self.mitre_graph.nodes():
            if self.mitre_graph.nodes[n]["types"] == "technique":
                super_sub_technique_dict[n] = [n]

            elif self.mitre_graph.nodes[n]["types"] == "super_technique":
                super_sub_technique_dict[n] = []
                for m in self.mitre_graph.neighbors(n):
                    if self.mitre_graph.nodes[m]["types"] == "sub_technique":
                        super_sub_technique_dict[n].append(m)

        return super_sub_technique_dict

    def get_tactic_for_technique(self, technique_id: str) -> str:
        if self.mitre_graph.nodes[technique_id]["types"] == "sub_technique":
            technique_id = self.get_super_for_technique(technique_id)

        for n in self.mitre_graph.neighbors(technique_id):
            if self.mitre_graph.nodes[n]["types"] == "tactic":
                return(n)

    def find_examples_for_technique(self, technique_id: str) -> list:
        example_list = []

        for n in self.mitre_graph.neighbors(technique_id):
            if self.mitre_graph.nodes[n]["types"] == "examples":
                example_list.append(n)

        logging.info("---%s have %d examples---" % (technique_id, len(example_list)))
        return example_list

    def find_reports_for_technique(self, technique_id: str) -> list:
        report_link_list = []
        report_file_list = []

        for n in self.mitre_graph.neighbors(technique_id):
            if self.mitre_graph.nodes[n]["types"] == "reference":
                report_link_list.append(n)
                try:
                    report_file_list.append(self.link_file_map[n])
                except:
                    continue

        return report_file_list

    def find_techniques_relatedto_reports(self, report_url: str = r'https://arstechnica.com/information-technology/2020/08/intel-is-investigating-the-leak-of-20gb-of-its-source-code-and-private-data/') -> list:

        involved_technique_list = []

        try:
            for n in self.mitre_graph.neighbors(report_url):
                if "technique" in self.mitre_graph.nodes[n]["types"]:
                    if n in picked_techniques:
                        involved_technique_list.append(n)
        except:
            pass

        return involved_technique_list


# Example Data
# https://wiki.owasp.org/index.php/OAT-004_Fingerprinting, .\data\cti\html\5d69b8d9b672612b77b13e1cb34c80f0.html
def read_csv_as_dict(csv_file: str) -> dict:
    d = {}

    with open(csv_file) as csv_stream:
        csv_reader = csv.reader(csv_stream)
        for row in csv_reader:
            try:
                d[row[1]] = row[0]
            except:
                continue

    return d

# %%

if __name__ == '__main__':
    # logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    technique_id = "/techniques/T1059/001"
    mgr = MitreGraphReader()
    # example_list = mgr.find_examples_for_technique(technique_id)
    dd = mgr.get_super_sub_technique_dict()

    # %%

    # # Get and count example for all techniques.
    # mgr = MitreGraphReader()
    #
    # # technique_id_list = picked_techniques
    # technique_id_list = mgr.get_technique_list()
    # example_list = []
    # for technique_id in technique_id_list:
    #     print(mgr.get_tactic_for_technique(technique_id) + "#" + mgr.get_super_for_technique(technique_id) + "#" + mgr.get_name_for_technique(mgr.get_super_for_technique(technique_id)) + "#" + mgr.get_name_for_technique(technique_id) + "#" + str(len(mgr.find_examples_for_technique(technique_id))))
    #     example_list += mgr.find_examples_for_technique(technique_id)
    #     example_list.append(technique_id + "===========================")
    #
    # with open("produce_examples.txt", "w+") as output:
    #     for example in example_list:
    #         output.write(example + "\n")

    # %%

    # link_file_dict = read_csv_as_dict()
    # report_file_list = mgr.find_reports_for_technique(technique_id, link_file_dict)

    #%%

    # mgr = MitreGraphReader()
    # url_file_name_dict = read_csv_as_dict(csv_file=r'.\data\cti\html\html_url_hash.csv')
    #
    # cti_path = r".\data\cti\html"
    # with open(r"report_picked_technique.json", "w+") as output:
    #     report_technique_dict = {}
    #
    #     for file in os.listdir(cti_path):
    #         print(file)
    #         if file not in url_file_name_dict.keys():
    #             continue
    #
    #         report_url = url_file_name_dict[file]
    #         involved_technique_list = mgr.find_techniques_relatedto_reports(report_url)
    #         print(involved_technique_list)
    #
    #         report_technique_dict[file] = involved_technique_list
    #         # output.write(file)
    #         # output.write(str(involved_technique_list))
    #
    #     data_json = json.dumps(report_technique_dict)
    #     output.write(data_json)
