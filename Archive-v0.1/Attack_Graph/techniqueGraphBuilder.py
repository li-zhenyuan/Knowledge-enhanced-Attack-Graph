from attackGraph import *
from attackTemplate import *
from techniqueIdentifier import *

import networkx as nx


class TechniqueGraphBuilder:
    # attack_graph: AttackGraph
    attack_match: AttackMatcher

    technique_graph_nx: nx.DiGraph
    technique_subgraph_dict: dict  # technique -> cluster

    # def __init__(self, attack_graph: AttackGraph, attack_match: AttackMatcher):
    def __init__(self, attack_graph_nx: nx.DiGraph, technique_template_list: list):
        # self.attack_graph = attack_graph
        self.technique_graph_nx = attack_graph_nx

        self.attack_match = AttackMatcher(attack_graph_nx)
        for tt in technique_template_list:
            ti = TechniqueIdentifier(tt)
            self.attack_match.add_technique_identifier(ti)
        self.attack_match.attack_matching()

        self.technique_subgraph_dict = self.attack_match.technique_matching_subgraph

    def identify_technique_cluster(self):
        pass


# %%

# if __name__ == '__main__':
tt_path = r"./data/picked_technique_template"
tt_file_list = os.listdir(tt_path)
template_list = []
for tt_file in tt_file_list:
    filename, ext = os.path.splitext(tt_file)
    if ext != ".json":
        continue
    tt = TechniqueTemplate(filename)
    template_list.append(tt)
    tt.load_from_file(os.path.join(tt_path, tt_file))

report_name = "048101ffcef13d80831ff6185738a883"
report_graph_file = r"./data/picked_extracted_attackgraph_20210807/%s.gml" % report_name
report_graph_nx = nx.read_gml(report_graph_file)

tgb = TechniqueGraphBuilder(attack_graph_nx=report_graph_nx, technique_template_list=template_list)
