import math
import Levenshtein
import graphviz
import networkx as nx
from nltk import Tree
import matplotlib.pyplot as plt
from pathlib import Path
import time
import spacy.tokens
from spacy.tokens import Span

from report_parser.report_parser import *
from report_parser.ioc_protection import *
from preprocess.report_preprocess import *
from mitre_ttps.mitreGraphReader import *


def to_nltk_tree(node):
    if node.n_lefts + node.n_rights > 0:
        return Tree(node.orth_, [to_nltk_tree(child) for child in node.children])
    else:
        return node.orth_


def tok_format(tok):
    return "@".join([tok.orth_, tok.tag_, tok.dep_, tok.ent_type_])  # , tok.dep_])


def to_nltk_formatted_tree(node):
    if node.n_lefts + node.n_rights > 0:
        return Tree(tok_format(node), [to_nltk_formatted_tree(child) for child in node.children])
    else:
        return tok_format(node)


# draw attack graph with matplot
def draw_attackgraph_plt(nx_graph: nx.DiGraph, image_file: str = None):
    graph_pos = nx.spring_layout(nx_graph)
    nx.draw_networkx_nodes(nx_graph, graph_pos, node_size=10, node_color='blue', alpha=0.3)
    nx.draw_networkx_edges(nx_graph, graph_pos)
    nx.draw_networkx_labels(nx_graph, graph_pos, font_size=8)
    edge_labels = nx.get_edge_attributes(nx_graph, 'action')
    nx.draw_networkx_edge_labels(nx_graph, graph_pos, edge_labels=edge_labels)

    if image_file is None:
        plt.show()
    else:
        plt.savefig(image_file)


node_shape = {
    "actor": "doublecircle",
    "executable": "oval",
    "file": "rectangle",
    "network": "diamond",
    "registry": "parallelogram",
    "vulnerability": "trapezium",
    "system": "invhouse",
}


def draw_attackgraph_dot(g: nx.DiGraph, clusters: dict = None, output_file: str = None) -> graphviz.Graph:
    dot = graphviz.Graph('G', filename=output_file)

    logging.warning("---Draw attack graph with dot!---")

    for node in g.nodes:
        logging.debug(node)

        nlp = ""
        try:
            nlp = g.nodes[node]["report_parser"]
            nlp = " ".join(nlp.split())
        except:
            pass

        regex = ""
        try:
            regex = g.nodes[node]["regex"]
        except:
            pass
        node_label = "##".join([node, nlp, regex])

        dot.node(node, label=node_label, shape=node_shape[g.nodes[node]["type"]])

    for edge in g.edges:
        dot.edge(edge[0], edge[1])

    # https://graphviz.readthedocs.io/en/stable/examples.html
    if clusters is not None:
        for key, value in clusters.items():
            with dot.subgraph(name=("cluster_" + key)) as t:
                t.attr(style='filled', color='lightgrey')
                t.attr(label=key)
                for tech in value:
                    t.node(tech)

    if output_file is not None:
        dot.format = "png"
        try:
            dot.render(output_file, view=False)
        except:
            logging.warning("%s dot rendering error!")

    return dot


class AttackGraphNode:
    id: str
    type: str

    ioc: str
    nlp: str

    word_position: int
    position: int
    #
    def __init__(self, entity: Span):
        self.id = entity.root.i  # entity could include multiple words, we only record the entity root token's position (word num) as unique id
        self.type = entity.root.ent_type_
        self.nlp = entity.text
        self.ioc = ""

    def __str__(self):
        return f"Node #{self.id}: [type: '{self.type}', nlp: '{self.nlp}', ioc: '{self.ioc}']"


# return token unique id for nx.graph
def get_token_id(tok: spacy.tokens.token.Token) -> str:
    return "_".join([tok.lower_, tok.ent_type_, str(tok.i)])


class AttackGraph:
    attackgraph_nx: nx.DiGraph
    original_attackgraph_nx: nx.DiGraph
    attackNode_dict: Dict[int, AttackGraphNode]  # coref nodes should point to the same attackGraphNode

    nlp_doc: spacy.tokens.doc.Doc
    ioc_identifier: IoCIdentifier
    techniques: Dict[str, list]  # technique name -> [node_list]

    def __init__(self, doc, ioc_identifier=None):
        self.attackgraph_nx = nx.DiGraph
        self.original_attackgraph_nx = nx.DiGraph
        self.attackNode_dict = {}

        self.nlp_doc = doc
        self.ioc_identifier = ioc_identifier
        self.techniques = {}

        self.generate()

    def generate(self):
        logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph!---")

        self.parse_entity()
        self.parse_coreference()
        self.parse_dependency()

        self.node_merge()
        self.simplify()
        self.clear_contraction_info()

    def parse_entity(self):
        logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph nodes!---")

        for entity in self.nlp_doc.ents:
            if entity.root.ent_type_ in ner_labels:
                attack_node = AttackGraphNode(entity)
                self.attackNode_dict[entity.root.i] = attack_node

                for token in entity:
                    self.attackNode_dict[token.i] = self.attackNode_dict[entity.root.i]
                    if (token.idx - 1) in self.ioc_identifier.replaced_ioc_dict.keys():
                        self.attackNode_dict[entity.root.i].ioc = self.ioc_identifier.replaced_ioc_dict[token.idx - 1]
            else:
                continue

    def parse_coreference(self):
        logging.info("---attack graph generation: Parsing NLP doc to get Co-references!---")

        for coref_set in self.nlp_doc._.coref_chains:
            # get ioc-related coreferences sets
            coref_origin = 0
            for coref_item in coref_set:
                if coref_item.root_index in self.attackNode_dict.keys():
                    coref_origin = coref_item.root_index
                    break

            # pasing the coreferences
            if coref_origin != 0:  # if coref_origin == 0, coref is not related to any iocs; otherwise, coref_origin record the position of related ioc
                logging.debug("---coref_origiin:---\n %s-%s" % (coref_token, coref_token.ent_type_))
                for coref_item in coref_set:
                    self.attackNode_dict[coref_item.root_index] = self.attackNode_dict[coref_origin]

                    coref_token = self.nlp_doc[coref_item.root_index]
                    logging.debug("%s-%s" % (coref_token, coref_token.ent_type_))

    def parse_dependency(self):
        logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph Edges!---")

        for sentence in self.nlp_doc.sents:
            self.parse_dependency_perSentence(sentence)

    def parse_dependency_perSentence(self, sentence):
        logging.info(f"---attack graph generation: Parsing sentence: {sentence}!---")

        node_queue = []
        tvb = ""
        tnode = ""

        root = sentence.root
        is_related_sentence = False

        # traverse the nltk tree
        node_queue.append(root)
        while node_queue:
            node = node_queue.pop(0)
            for child in node.children:
                node_queue.append(child)

            # process only the ioc_root
            if node.i in self.entity_ignored_list:
                continue

            if node.ent_type_ in ner_labels and re.match("NN.*", node.tag_):
                if node.ent_type_ == "actor":
                    node.ent_type_ = "executable"

                is_related_sentence = True

                # try getting node ioc value
                regex = ""
                if node.idx in self.ioc_identifier.replaced_ioc_dict.keys():
                    regex = self.ioc_identifier.replaced_ioc_dict[node.idx]
                    logging.debug("Recover IoC regex: %s" % regex)

                nlp = ""
                if node.i in self.entity_id_string_dict.keys():
                    nlp = self.entity_id_string_dict[node.i]
                else:
                    nlp = node.report_text

                n = get_token_id(node)  # + regex
                logging.debug(n)
                self.attackgraph_nx.add_node(n, type=node.ent_type_, nlp=nlp, regex=regex)

                if tnode != "":
                    self.attackgraph_nx.add_edge(tnode, n, action=tvb)
                tnode = n

            # edges with coreference nodes
            if node.i in self.ioc_coref_dict.keys():
                coref_node = self.nlp_doc[self.ioc_coref_dict[node.i]]

                regex = ""
                if node.idx in self.ioc_identifier.replaced_ioc_dict.keys():
                    regex = self.ioc_identifier.replaced_ioc_dict[node.idx]
                    logging.debug("Recover IoC regex: %s" % regex)

                nlp = ""
                if coref_node.i in self.entity_id_string_dict.keys():
                    nlp = self.entity_id_string_dict[coref_node.i]
                else:
                    nlp = coref_node.report_text

                n = get_token_id(coref_node)
                logging.debug(n)
                self.attackgraph_nx.add_node(n, type=coref_node.ent_type_, nlp=nlp, regex=regex)

                if tnode != "":
                    self.attackgraph_nx.add_edge(tnode, n, action=tvb)
                tnode = n

        if (is_related_sentence):
            logging.debug("Related sentence: %s" % sentence.report_text)

        return self.attackgraph_nx

    source_node_list: list
    visited_node_list: list

    def simplify(self):
        source_node_list = self.locate_all_source_node()
        self.visited_node_list = []

        for source_node in source_node_list:
            self.simplify_foreach_subgraph(source_node)

    def simplify_foreach_subgraph(self, source_node):
        if source_node not in self.visited_node_list:
            self.visited_node_list.append(source_node)
        else:
            return

        source_nlp = self.attackgraph_nx.nodes[source_node]["report_parser"]
        try:
            source_regex = self.attackgraph_nx.nodes[source_node]["regex"]
        except KeyError:
            source_regex = ""

        neighbor_list = self.attackgraph_nx.neighbors(source_node)
        for neighor in neighbor_list:
            self.simplify_foreach_subgraph(neighor)

            neighor_nlp = self.attackgraph_nx.nodes[neighor]["report_parser"]
            try:
                neighor_regex = self.attackgraph_nx.nodes[neighor]["regex"]
            except KeyError:
                neighor_regex = ""

            # check whether to merge the node or not
            if self.attackgraph_nx.nodes[source_node]["type"] == self.attackgraph_nx.nodes[neighor]["type"] \
                and self.attackgraph_nx.in_degree(neighor) == 1 \
                and (source_regex == "" or neighor_regex == ""):
                self.attackgraph_nx = nx.contracted_nodes(self.attackgraph_nx, source_node, neighor, self_loops=False)

                self.attackgraph_nx.nodes[source_node]["report_parser"] = source_nlp + " " + neighor_nlp
                self.attackgraph_nx.nodes[source_node]["regex"] = source_regex + neighor_regex

    def locate_all_source_node(self):
        self.source_node_list = []

        for node in self.attackgraph_nx.nodes():
            if self.attackgraph_nx.in_degree[node] == 0:
                self.source_node_list.append(node)

        return self.source_node_list

    merge_graph: nx.Graph

    def node_merge(self):
        self.original_attackgraph_nx = nx.DiGraph(self.attackgraph_nx)

        self.merge_graph = nx.Graph()
        node_list = list(self.attackgraph_nx.nodes())

        for m in range(0, len(node_list)):
            for n in range(m + 1, len(node_list)):
                node_m = node_list[m]
                node_n = node_list[n]

                m_position = int(node_m.split('#')[-1])
                n_position = int(node_n.split('#')[-1])

                m_type = self.attackgraph_nx.nodes[node_m]['type']
                n_type = self.attackgraph_nx.nodes[node_n]['type']
                m_nlp = self.attackgraph_nx.nodes[node_m]['report_parser']
                n_nlp = self.attackgraph_nx.nodes[node_n]['report_parser']
                m_ioc = self.attackgraph_nx.nodes[node_m]['regex']
                n_ioc = self.attackgraph_nx.nodes[node_n]['regex']

                similarity = 0
                if m_type == n_type:
                    similarity += 0.4
                # print(Levenshtein.ratio(m_nlp, n_nlp))
                # print(abs(n_position-m_position)+2)
                similarity += Levenshtein.ratio(m_nlp, n_nlp) / math.log(abs(n_position-m_position)+2)
                if (similarity >= 0.5 and ((m_ioc == '' and n_ioc == '') or m_ioc == n_ioc)):
                    self.merge_graph.add_edge(node_m, node_n)

                    # print(' '.join([node_m, node_n, str(Levenshtein.ratio(m_nlp, n_nlp)), str(similarity)]))

        for subgraph in nx.connected_components(self.merge_graph):
            subgraph_list = list(subgraph)
            # print(subgraph_list)
            a = subgraph_list[0]
            for b in subgraph_list[1:]:
                self.attackgraph_nx = nx.contracted_nodes(self.attackgraph_nx, a, b, self_loops=False)
            # self.attackgraph_nx.nodes[a]["contraction"] = ""

    def clear_contraction_info(self):
        for nodes in self.attackgraph_nx.nodes():
            self.attackgraph_nx.nodes[nodes]["contraction"] = ""
