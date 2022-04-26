# Simplified technique matching
# Attack graph are stored in NetworkX instance

from attackGraph import *
from attackTemplate import *

import networkx as nx
import matplotlib.pyplot as plt
import logging
import os.path


# Return a score range from 0 to 10
def AttacKG_node_matching(node_a, node_b) -> float:
    similarity_score = 0

    # type matching
    if node_a["type"] != node_b["type"]:
        return 0

    # regex matching
    try:
        if node_a["regex"] != "" and node_b["regex"] != "":
            similarity_score = get_ioc_similarity(node_a["regex"], node_b["regex"])
    except:
        print("node_a: %s\n or node_b: %s\n have no regex" % (str(node_a), str(node_b)))

    # description matching
    try:
        if node_a["description"] != "" and node_b["description"] != "":
            ss = get_nlp_similarity(node_a["description"], node_b["description"])
            if ss > similarity_score:
                similarity_score = ss
    except:
        print("node_a: %s\n or node_b: %s\n have no description" % (str(node_a), str(node_b)))

    return similarity_score


def AttacKG_matching():
    pass


class Technique_identifier:
    technique_variant_tree = {}

    # attack_graph: nx.DiGraph
    source_nodes = []
    sink_nodes = []

    node_taglist = {}  # {node -> taglist}

    def add_technique_variant_tree(self, template: TechniqueTemplate, technique_name="UNKOWN"):
        self.technique_variant_tree[technique_name] = template


    def identify_technique_in_nodelist(self, node_list):

        pass

    def identify_technique_in_attackgraphfile(self, gml_file: str):
        if os.path.splitext(gml_file)[-1] == ".gml":
            g = nx.read_gml(gml_file)
            return self.identify_technique_in_attackgraph(g)
        else:
            return None

    def identify_technique_in_attackgraph(self, attack_graph: nx.DiGraph):
        logging.info("---S2: Identify Techniques!---")

        # Find source node
        logging.info("---S2.1: Find source node!---")
        self.find_source_node(attack_graph)

        # Tag propagation & Find sink node
        logging.info("---S2.2: Tag propagation!---")
        self.tag_propagation(attack_graph)

        # Find technique chain in sink node's tag list
        logging.info("---S2.3: Technique matching!---")
        self.technique_matching()

        pass

    def find_source_node(self, g: nx.DiGraph):
        self.source_nodes = []
        for node in g.nodes():
            logging.debug(node + ":" + str(g.in_degree(node)) + ":" + str(g.out_degree(node)))
            if g.in_degree(node) == 0:
                self.source_nodes.append(node)
            # if g.out_degree(node) == 0:
            #     self.sink_nodes.append(node)

        return self.source_nodes

    def tag_propagation(self, g: nx.DiGraph):
        for n in g.nodes():
            self.node_taglist[n] = [g.nodes[n]["type"]]

        for n in self.source_nodes:
            self.tag_propagation_recursion(g, n)

    def tag_propagation_recursion(self, g: nx.DiGraph, node):
        for successor in g.neighbors(node):
            self.node_taglist[successor] += self.node_taglist[node]
            if g.out_degree(successor) == 0:
                self.sink_nodes.append(successor)
            else:
                if len(self.node_taglist[successor]) == 1:
                    self.tag_propagation_recursion(g, successor)  # FIXME: Loop and single node

    def technique_matching(self):
        #
        for k, v in self.node_taglist.items():

            set_match_flag = 1
            for i in ["NetLoc", "ExeFile"]:
                node_match_flag = 0
                for j in v:
                    if i == j:
                        node_match_flag = 1
                        break
                if node_match_flag == 0:
                    set_match_flag = 0
                    break

            if set_match_flag == 1:
                logging.warning("Find email")
            # else:
            #     logging.warning("Don't find email")


# %%

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    # %%
    # Attack template loading unit testing.

    # with open("phishing_email.template", 'r') as f:
    #     tt = pickle.load(f)
    #
    #     key_nodes = tt.root_node.possible_follow_up()

    # %%
    # Technique identification unit testing.

    # attack_graph_file = r"C:\Users\xiaowan\Documents\GitHub\AttacKG\data\processed\0a84e7a880901bd265439bd57da61c5d.gml"
    # attack_graph_file = r"C:\Users\xiaowan\Documents\GitHub\AttacKG\data\processed\00ff15594bf36a552606ef462ff699e8.gml"
    #
    # ti = Technique_identifier()
    # ti.identify_technique_in_attackgraphfile(attack_graph_file)

    # %%

    gml_path = r"C:\Users\xiaowan\Documents\GitHub\AttacKG\data\processed"

    gml_files = os.listdir(gml_path)
    for file in gml_files:
        file_name = os.path.splitext(file)[0]
        file_ext = os.path.splitext(file)[-1]
        if file_ext == ".gml":
            logging.info(file)
            ti = Technique_identifier()
            ti.identify_technique_in_attackgraphfile(os.path.join(gml_path, file))

    # %%
    # Matching unit testing.

    # example_t1059_001_1 = "APT19 used PowerShell commands to execute payloads."
    # akg_t1059_001_1 = nx.DiGraph()
    # akg_t1059_001_1.add_nodes_from(["APT19",
    #                                 "PowerShell commands",
    #                                 "payloads"])
    # akg_t1059_001_1.add_edges_from([("APT19", "PowerShell commands"),
    #                                 ("PowerShell commands", "payloads")])
    # draw_AttacKG(akg_t1059_001_1)
    #
    # example_t1059_001_2 = "APT28 downloads and executes PowerShell scripts."
    # akg_t1059_001_2 = nx.DiGraph()
    # akg_t1059_001_2.add_nodes_from(["APT19",
    #                                 "PowerShell scripts"])
    # akg_t1059_001_2.add_edges_from([("APT19", "PowerShell scripts")])
    # draw_AttacKG(akg_t1059_001_2)




