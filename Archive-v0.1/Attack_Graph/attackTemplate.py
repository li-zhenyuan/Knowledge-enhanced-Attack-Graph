

from attackGraph import *
from Mitre_TTPs.mitreGraphReader import *

import networkx as nx
from networkx.drawing.nx_agraph import to_agraph
import logging
import re
import Levenshtein
import json


def parse_networkx_node(node: str, nx_graph: nx.DiGraph) -> tuple:
    node_type = nx_graph.nodes[node]["type"]
    nlp = nx_graph.nodes[node]["nlp"]
    try:
        ioc = nx_graph.nodes[node]["regex"]
    except:
        ioc = ""

    return (node_type, nlp, ioc)


class TemplateNode(AttackGraphNode):
    node_type: str
    node_ioc_representation: str
    node_nlp_representation: str
    node_ioc_instance: list
    node_nlp_instance: list

    instance_count: int

    def dump_to_dict(self) -> dict:
        node_data = {
            "type": self.node_type,
            "description": self.node_nlp_instance,
            "ioc": self.node_ioc_instance,
            "count": self.instance_count}

        return node_data

    def load_from_dict(self, node_data: dict):
        self.node_type = node_data["type"]
        self.node_nlp_instance = node_data["description"]
        self.node_ioc_instance = node_data["ioc"]
        self.instance_count = node_data["count"]

    def __init__(self, node_info: tuple):
        self.node_nlp_instance = []
        self.node_ioc_instance = []

        self.node_type = node_info[0]
        if node_info[1] != "":
            self.node_nlp_instance.append(node_info[1])
        if node_info[2] != "":
            self.node_ioc_instance.append(node_info[2])

        self.instance_count = 1

        logging.info("---S3: Init TemplateNode %s!---" % (self))

    def __str__(self):
        return "%s-%s-%s-%s" % (
            self.node_type, str(self.node_nlp_instance), str(self.node_ioc_instance), str(self.instance_count))

    def get_similar_with(self, node_info: tuple):
        similarity_score = 0.0

        new_node_type = node_info[0]
        new_node_nlp = node_info[1]
        new_node_ioc = node_info[2]

        if self.node_type != new_node_type:
            return similarity_score
        else:
            similarity_score += 0.5


        max_nlp_similarity_score = 0
        for nlp_instance in self.node_nlp_instance:
            ss = get_nlp_similarity(new_node_nlp, nlp_instance)
            if ss >= max_nlp_similarity_score:
                max_nlp_similarity_score = ss
        # nlp_similarity_score_list = [get_nlp_similarity(new_node_nlp, nlp_instance) for nlp_instance in self.node_nlp_instance]

        max_ioc_similarity_score = 0
        for ioc_instance in self.node_ioc_instance:
            ss = get_ioc_similarity(new_node_ioc, ioc_instance)
            if ss >= max_ioc_similarity_score:
                max_ioc_similarity_score = ss

        # similarity_score = similarity_score + max_ioc_similarity_score * 1 + max_nlp_similarity_score
        similarity_score += 0.5 * max(max_ioc_similarity_score, max_nlp_similarity_score)
        # similarity_score += 0.5 * max_ioc_similarity_score

        return similarity_score

    NODE_NLP_SIMILAR_ACCEPT_THRESHOLD = 0.8
    NODE_IOC_SIMILAR_ACCEPT_THRESHOLD = 0.8

    def update_with(self, node_info: tuple):

        new_node_type = node_info[0]
        new_node_nlp = node_info[1]
        new_node_ioc = node_info[2]

        self.instance_count += 1

        max_nlp_similarity_score = 0
        for nlp_instance in self.node_nlp_instance:
            ss = get_nlp_similarity(new_node_nlp, nlp_instance)
            if ss >= max_nlp_similarity_score:
                max_nlp_similarity_score = ss
        if max_nlp_similarity_score < self.NODE_NLP_SIMILAR_ACCEPT_THRESHOLD:
            self.node_nlp_instance.append(new_node_nlp)

        max_ioc_similarity_score = 0
        for ioc_instance in self.node_ioc_instance:
            ss = get_ioc_similarity(new_node_ioc, ioc_instance)
            if ss >= max_ioc_similarity_score:
                max_ioc_similarity_score = ss
        if max_ioc_similarity_score < self.NODE_IOC_SIMILAR_ACCEPT_THRESHOLD:
            self.node_ioc_instance.append(new_node_ioc)

        return self


def get_ioc_similarity(ioc_a: str, ioc_b: str) -> float:
    return get_string_similarity(ioc_a, ioc_b)


def get_nlp_similarity(nlp_a: str, nlp_b: str) -> float:
    return get_string_similarity(nlp_a, nlp_b)


# https://blog.csdn.net/dcrmg/article/details/79228589
def get_string_similarity(a: str, b: str) -> float:
    similarity_score = Levenshtein.ratio(a, b)
    return similarity_score


class TechniqueTemplate:
    NODE_SIMILAR_ACCEPT_THRESHOLD = 0.5 + 0.2

    technique_name: str  # '/techniques/T1566/001'
    technique_node_list: list  # [TemplateNode, ...]
    technique_edge_dict: dict  # [(TN1, TN2): Count, ...]
    technique_instance_dict: dict  # [[(n1,n2), ...]...]
    total_instance_count: int

    node_normalization: float
    edge_normalization: float

    template_nx: nx.DiGraph

    def __init__(self, technique_name: str):
        self.technique_name = technique_name
        self.technique_node_list = []
        self.technique_edge_dict = {}
        self.technique_instance_dict = {}
        self.total_instance_count = 0

        self.node_normalization = 0
        self.edge_normalization = 0

    # def match_template(self, technique_sample_graph: nx.DiGraph):
    #     logging.info("---Match template!---")

    def statistic(self):
        variants_count = 0
        ioc_instance_count = 0

        for k, v in self.technique_instance_dict.items():
            if v >= (self.total_instance_count / 10):
                variants_count += 1

        for node in self.technique_node_list:
            ioc_instance_count += len(node.node_ioc_instance)

        output = ','.join([self.technique_name[14:19], str(variants_count), str(ioc_instance_count), '\n'])
        print(output)

        with open('technique_variants_count.csv', 'a+') as output_file:
            output_file.write(output)

    def calculate_normalization(self):
        for node in self.technique_node_list:
            self.node_normalization += (node.instance_count)
        for edge, instance_count in self.technique_edge_dict:
            self.edge_normalization += (instance_count)

    def update_template(self, technique_sample_graph: nx.DiGraph):
        logging.info("---Update template!---")

        self.total_instance_count += 1
        sample_node_template_node_dict = {}

        # node matching
        for node in technique_sample_graph.nodes:
            max_similarity_score = 0
            max_similarity_template_node_id = -1

            node_index = 0
            for template_node in self.technique_node_list:
                similarity_score = template_node.get_similar_with(parse_networkx_node(node, technique_sample_graph))
                if similarity_score > max_similarity_score:
                    max_similarity_score = similarity_score
                    max_similarity_template_node_id = node_index

                node_index += 1

            # whether node in new sample is aligned with exist template node
            if max_similarity_score > self.NODE_SIMILAR_ACCEPT_THRESHOLD:
                sample_node_template_node_dict[node] = max_similarity_template_node_id
                self.technique_node_list[max_similarity_template_node_id].update_with(
                    parse_networkx_node(node, technique_sample_graph))
            else:
                tn = TemplateNode(parse_networkx_node(node, technique_sample_graph))
                self.technique_node_list.append(tn)
                sample_node_template_node_dict[node] = len(self.technique_node_list) - 1

        instance = []
        for edge in technique_sample_graph.edges:
            technique_template_edge = (sample_node_template_node_dict[edge[0]], sample_node_template_node_dict[edge[1]])

            if technique_template_edge in self.technique_edge_dict.keys():
                self.technique_edge_dict[technique_template_edge] += 1
            else:
                self.technique_edge_dict[technique_template_edge] = 1

            instance.append(technique_template_edge)

        instance = tuple(instance)
        if instance in self.technique_instance_dict.keys():
            self.technique_instance_dict[instance] += 1
        else:
            self.technique_instance_dict[instance] = 1

    def pretty_print(self, image_name: str = "template.png"):
        self.template_nx = nx.DiGraph()

        for node in self.technique_node_list:
            self.template_nx.add_node(node)

        for edge in self.technique_edge_dict.keys():
            count = self.technique_edge_dict[edge]
            if count <= 2:
                continue

            source = self.technique_node_list[edge[0]]
            sink = self.technique_node_list[edge[1]]
            self.template_nx.add_edge(source, sink, count=str(count))

        A = to_agraph(self.template_nx)
        A.node_attr['shape'] = 'rectangle'
        A.layout('dot')
        A.draw(image_name)

    # refer to STIX
    def dump_to_dict(self) -> dict:
        data_dict = {}

        node_list = []
        for tn in self.technique_node_list:
            node_list.append(tn.dump_to_dict())
        data_dict["nodes"] = node_list
        data_dict["edges"] = list(self.technique_edge_dict.items())
        data_dict["instances"] = list(self.technique_instance_dict)
        data_dict["total_count"] = self.total_instance_count
        #
        # data_dict["node_normalization"] = self.node_normalization
        # data_dict["edge_normalization"] = self.edge_normalization
        return data_dict

    def dump_to_json(self) -> str:
        data_dict = self.dump_to_dict()
        data_json = json.dumps(data_dict)
        return data_json

    def dump_to_file(self, file_name: str = "template"):
        data_json = self.dump_to_json()
        with open(file_name + ".json", "w+") as json_file:
            json_file.write(data_json)

    def load_from_dict(self, data_dict: dict):
        self.total_instance_count = int(data_dict["total_count"])

        node_list = data_dict["nodes"]
        for node_info in node_list:
            tn = TemplateNode(("", "", ""))
            tn.load_from_dict(node_info)
            if tn.instance_count <= 2:
                tn.instance_count = 0
            self.technique_node_list.append(tn)

        edge_list = data_dict["edges"]
        for edge in edge_list:
            edge_info = edge[0]
            count = edge[1]
            if count <= 2:
                count = 0
            self.technique_edge_dict[tuple(edge_info)] = count

        self.calculate_normalization()

        instance_list = data_dict["instances"]
        for instance in instance_list:
            edge_in_instance = []
            for edge in instance:
                edge_in_instance.append(tuple(edge))
            self.technique_instance_dict[tuple(edge_in_instance)] = 1

        self.technique_edge_dict

    def load_from_json(self, data_json: str):
        data_dict = json.loads(data_json)
        self.load_from_dict(data_dict)

    def load_from_file(self, file_name: str):
        with open(file_name, 'r') as data_file:
            data_json = data_file.read()
            self.load_from_json(data_json)


def extract_technique_template_from_technique_list(technique_name: str, technique_list: list):
    example_list = []
    mgr = MitreGraphReader()
    for technique_id in technique_list:
        example_list += mgr.find_examples_for_technique(technique_id)

    technique_file_name = "./data/procedure_examples/" + technique_name
    with open(technique_file_name + ".txt", "w+") as t_file:
        for example in example_list:
            t_file.write(example + "\n")

    ner_model = IoCNer("./new_cti.model")
    ner_model.ner_with_regex()
    ner_model.add_coreference()

    technique_sample_graphs = []
    # example_list = example_list[0:20]
    index = 0
    for example in example_list:
        index += 1
        example = re.sub("\[[0-9]+\]+", "", example)
        print(example)

        ag = parse_attackgraph_from_text(ner_model, example)
        technique_sample_graphs.append(ag.attackgraph_nx)

        procedure_example_file_name = technique_file_name + "-" + str(index)
        draw_attackgraph_dot(ag.attackgraph_nx, output_file=procedure_example_file_name)
        nx.write_gml(ag.attackgraph_nx, procedure_example_file_name + ".gml")

    tt = TechniqueTemplate(str(technique_list))
    for tsg in technique_sample_graphs:
        tt.update_template(tsg)

    tt.statistic()
    template_file_name = "./data/technique_template/" + technique_name
    tt.dump_to_file(file_name=template_file_name)
    tt.pretty_print(image_name=template_file_name + ".png")
    # draw_attackgraph_plt(tt.template_nx)


# %%

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    # technique_list = [r'/techniques/T1566/001', r'/techniques/T1566/002',r'/techniques/T1566/003']
    # technique_list = [r'/techniques/T1053/005']
    # technique_list = [r'/techniques/T1547/001']
    # technique_id_list = [r'/techniques/T1547/001']

    # mgr = MitreGraphReader()
    # technique_id_list = picked_techniques  # from mitreGraphReader

    # extract_technique_template_from_technique_list(technique_list)

    # %%


    mgr = MitreGraphReader()
    # technique_id_list = mgr.get_technique_list()
    super_sub_dict = mgr.get_super_sub_technique_dict()

    # extract_technique_template_from_technique_list("T1547", super_sub_dict["/techniques/T1547"])
    for super_technique, sub_technique_list in super_sub_dict.items():
        extract_technique_template_from_technique_list(super_technique[12:18], sub_technique_list)
        # p = Process(target=extract_technique_template_from_technique_list, args=(super_technique[12:18], sub_technique_list,))
        # p.start()

    # %%

    # example_list = []
    # mgr = MitreGraphReader()
    # for technique_id in technique_list:
    #     example_list += mgr.find_examples_for_technique(technique_id)
    #
    # ner_model = IoCNer("./new_cti.model")
    # ner_model.add_coreference()
    #
    # technique_sample_graphs = []
    # # example_list = example_list[0:20]
    # for example in example_list:
    #     example = re.sub("\[[0-9]+\]+", "", example)
    #     print(example)
    #
    #     ag = parse_attackgraph_from_text(ner_model, example)
    #     # draw_attackgraph_plt(ag.attackgraph_nx)
    #     technique_sample_graphs.append(ag.attackgraph_nx)

    # %%

    # tt = TechniqueTemplate(technique_list)
    #
    # for tsg in technique_sample_graphs:
    #     tt.update_template(tsg)
    #
    # tt.dump_to_file()
    # tt.pretty_print()
    # draw_attackgraph_plt(tt.template_nx)
