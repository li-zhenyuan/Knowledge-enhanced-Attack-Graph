import itertools
import time
import xlsxwriter
import sys
sys.path.extend([".", "technique_knowledge_graph"])

from technique_knowledge_graph.technique_template import *


# Record TechniqueTemplate Matching Record
class TechniqueIdentifier:
    technique_template: TechniqueTemplate

    node_match_record: dict
    edge_match_record: dict
    node_count: int
    edge_count: int

    def __init__(self, technique_template: TechniqueTemplate):
        self.technique_template = technique_template
        logging.info(f"---technique identification: Init technique template {technique_template.technique_name} as identifier!---")

        self.node_match_record = {}
        self.node_count = len(self.technique_template.technique_node_list)
        self.edge_match_record = {}
        self.edge_count = len(self.technique_template.technique_edge_dict.keys())

    def node_alignment(self, attack_node: AttackGraphNode):
        index = 0
        for technique_node in self.technique_template.technique_node_list:
            node_similarity_score = technique_node.get_similarity(attack_node)

            if technique_node.instance_count == 0:
                index += 1
                continue

            # accept node as a match
            if node_similarity_score >= TechniqueTemplate.NODE_SIMILAR_ACCEPT_THRESHOLD:
                if index in self.node_match_record.keys():
                    self.node_match_record[index] = []
                self.node_match_record[index].append((attack_node, node_similarity_score))

            index += 1

    def to_nodematchrecord_list(self):
        k_list = []
        v_list = []
        for k, v in self.node_match_record.items():
            k_list.append(k)
            if v is None:
                v_list.append([''])
            else:
                v_list.append(v)

        self.node_match_record = {}
        for item in itertools.product(*v_list):
            for i in range(0, len(k_list)):
                self.node_match_record[k_list[i]] = v_list[i]

    def subgraph_alignment(self, subgraph: set, nx_graph: nx.DiGraph):
        for node in subgraph:
            self.node_alignment(node, nx_graph)

        k_list = []
        v_list = []
        for k, v in self.node_match_record.items():
            k_list.append(k)
            if v is None:
                v_list.append([''])
            else:
                v_list.append(v)

        self.node_match_record = {}
        best_match_score = 0
        best_match_record = None
        for item in itertools.product(*v_list):
            for i in range(0, len(k_list)):
                if item[i] == '':
                    self.node_match_record[k_list[i]] = None
                else:
                    self.node_match_record[k_list[i]] = item[i]

            for template_edge, instance_count in self.technique_template.technique_edge_dict.items():
                source_index = template_edge[0]
                sink_index = template_edge[1]

                # No matched node for edge
                if self.node_match_record[source_index] is None or self.node_match_record[sink_index] is None:
                    self.edge_match_record[template_edge] = 0.0
                    continue

                source_node = self.node_match_record[source_index][0]
                sink_node = self.node_match_record[sink_index][0]

                if source_node == sink_node:
                    distance = 1
                else:
                    try:
                        distance = nx.shortest_path_length(nx_graph, source_node, sink_node)
                    except:
                        self.edge_match_record[template_edge] = 0.0
                        continue

                source_node_matching_score = self.node_match_record[source_index][1]
                sink_node_matching_score = self.node_match_record[sink_index][1]

                edge_matching_score = math.sqrt(source_node_matching_score * sink_node_matching_score) / distance
                self.edge_match_record[template_edge] = edge_matching_score

            match_score = self.get_graph_alignment_score()
            if match_score > best_match_score:
                best_match_score = match_score
                best_match_record = self.node_match_record

        self.node_match_record = best_match_record

    def get_graph_alignment_score(self):
        return self.get_node_alignment_score() + self.get_edge_alignment_score()

    def get_node_alignment_score(self):
        node_alignment_score = 0.0

        if self.node_match_record is None:
            return 0
        index = 0
        for node_index, node_similarity in self.node_match_record.items():
            if self.technique_template.technique_node_list[node_index].node_type == "actor":
                continue

            if node_similarity is not None:
                node_alignment_score += node_similarity[1] * self.technique_template.technique_node_list[node_index].instance_count  # math.sqrt

            index += 1

        node_alignment_score /= (self.technique_template.node_normalization + 1)
        return node_alignment_score

    def get_edge_alignment_score(self):
        edge_alignment_score = 0.0

        for edge, edge_similarity in self.edge_match_record.items():
            edge_alignment_score += edge_similarity * (self.technique_template.technique_edge_dict[edge])

        edge_alignment_score /= (self.technique_template.edge_normalization + 1)

        return edge_alignment_score


# Matching process, involve multiple TechniqueIdentifier at one time
class AttackMatcher:
    attack_graph_nx: nx.DiGraph
    technique_identifier_list: list
    technique_matching_score: dict
    technique_matching_subgraph: dict
    technique_matching_record: dict

    normalized_factor: float

    def __init__(self, nx_graph: nx.DiGraph):
        self.attack_graph_nx = nx_graph
        self.technique_identifier_list = []
        self.technique_matching_score = {}
        self.technique_matching_subgraph = {}
        self.technique_matching_record = {}

        self.normalized_factor = nx_graph.number_of_nodes() + nx_graph.number_of_edges()

    def add_technique_identifier(self, technique_identifier: TechniqueIdentifier):
        if technique_identifier.edge_count == 0:
            return

        self.technique_identifier_list.append(technique_identifier)

    def attack_matching(self, nx_graph: nx.DiGraph = None):
        if nx_graph is not None:
            self.attack_graph_nx = nx_graph
        else:
            nx_graph = self.attack_graph_nx

        # subgraph_list = nx.strongly_connected_components(self.attack_graph_nx)
        subgraph_list = nx.connected_components(self.attack_graph_nx.to_undirected())
        for subgraph in subgraph_list:
            logging.debug("---Get subgraph: %s---" % subgraph)
            # matching_result = []

            for technique_identifier in self.technique_identifier_list:
                # print(technique_identifier.technique_template.technique_name)
                technique_identifier.init_node_match_record()
                technique_identifier.init_edge_match_record()

                technique_identifier.subgraph_alignment(subgraph, nx_graph)

            # for node in subgraph:
            #     # Try to find a match in technique_identifier_list
            #     for technique_identifier in self.technique_identifier_list:
            #         technique_identifier.node_alignment(node, nx_graph)

            # for edge in subgraph.edges():
            #     for technique_identifier in self.technique_identifier_list:
            #         technique_identifier.edge_alignment(edge, nx_graph)

            # find the most match technique
            for technique_identifier in self.technique_identifier_list:
                node_alignment_score = technique_identifier.get_graph_alignment_score() #/ self.normalized_factor

                if technique_identifier.technique_template.technique_name not in self.technique_matching_score.keys():
                    self.technique_matching_score[technique_identifier.technique_template.technique_name] = node_alignment_score
                    self.technique_matching_subgraph[technique_identifier.technique_template.technique_name] = subgraph
                    self.technique_matching_record[technique_identifier.technique_template.technique_name] = technique_identifier.node_match_record
                elif self.technique_matching_score[technique_identifier.technique_template.technique_name] < node_alignment_score:
                    self.technique_matching_score[technique_identifier.technique_template.technique_name] = node_alignment_score
                    self.technique_matching_subgraph[technique_identifier.technique_template.technique_name] = subgraph
                    self.technique_matching_record[technique_identifier.technique_template.technique_name] = technique_identifier.node_match_record

                # matching_result.append((technique_identifier.technique_template, node_alignment_score))
                logging.debug("---S3.2: matching result %s\n=====\n%s - %f!---" % (technique_identifier.technique_template.technique_name, subgraph, node_alignment_score))

    def print_match_result(self) -> dict:
        logging.info(str(self.technique_matching_score))
        logging.info(str(self.technique_matching_subgraph))
        logging.info(str(self.technique_matching_record))

        return self.technique_matching_score

    def print_selected_techniques(self) -> dict:
        selected_techniques_dict = {}

        for k, v in self.technique_matching_score.items():
            if v >= 1.4:
                selected_techniques_dict[k] = []
                for node in self.technique_matching_subgraph[k]:
                    if self.attack_graph_nx.nodes[node]["regex"] != "":
                        selected_techniques_dict[k].append((self.attack_graph_nx.nodes[node]["type"], self.attack_graph_nx.nodes[node]["regex"]))

        return selected_techniques_dict


class Evaluation:

    def __init__(self):
        self.book = xlsxwriter.Workbook("technique_matching_result.xlsx")
        self.sheet = self.book.add_worksheet('report_pickTechnique')
        self.column_count = 1

        self.match_format = self.book.add_format({'bg_color': '#FFC7CE', 'font_color': '#9C0006'})

    def add_technique_list(self, technique_list: list):
        row_count = 1
        for technique in technique_list:
            self.sheet.write(0, row_count, technique)
            row_count += 1

    def add_result(self, report_name: str, detection_result: dict, ground_truth: list):
        self.sheet.write(self.column_count, 0, report_name)

        row_count = 1
        for technique, result in detection_result.items():
            self.sheet.write(self.column_count, row_count, result)
            technique_name = technique.replace("'", "").replace("_", "/")
            if technique_name in ground_truth:
                self.sheet.conditional_format(self.column_count, row_count, self.column_count, row_count, {'type': '2_color_scale'})
            row_count += 1

        self.column_count += 1
