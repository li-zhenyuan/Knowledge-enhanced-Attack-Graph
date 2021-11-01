import math
import Levenshtein
import graphviz
import networkx as nx
from matplotlib import figure
import matplotlib.pyplot as plt
from nltk import Tree
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


# node_shape = "so^>v<dph8"
# markers = {'.': 'point', ',': 'pixel', 'o': 'circle', 'v': 'triangle_down', '^': 'triangle_up', '<': 'triangle_left', '>': 'triangle_right', '1': 'tri_down', '2': 'tri_up', '3': 'tri_left', '4': 'tri_right', '8': 'octagon', 's': 'square', 'p': 'pentagon', '*': 'star', 'h': 'hexagon1', 'H': 'hexagon2', '+': 'plus', 'x': 'x', 'D': 'diamond', 'd': 'thin_diamond', '|': 'vline', '_': 'hline', 'P': 'plus_filled', 'X': 'x_filled', 0: 'tickleft', 1: 'tickright', 2: 'tickup', 3: 'tickdown', 4: 'caretleft', 5: 'caretright', 6: 'caretup', 7: 'caretdown', 8: 'caretleftbase', 9: 'caretrightbase', 10: 'caretupbase', 11: 'caretdownbase', 'None': 'nothing', None: 'nothing', ' ': 'nothing', '': 'nothing'}
node_shape_dict = {
    "actor": "o",
    "executable": "o",
    "file": "s",
    "network": "d",
    "registry": "p",
    "vulnerability": "8",
    "system": "^",
}


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


class AttackGraph:
    attackgraph_nx: nx.DiGraph
    original_attackgraph_nx: nx.DiGraph
    attackNode_dict: Dict[int, AttackGraphNode]  # coref nodes should point to the same attackGraphNode

    nlp_doc: spacy.tokens.doc.Doc
    ioc_identifier: IoCIdentifier

    related_sentences: List[str]
    techniques: Dict[str, list]  # technique name -> [node_list]

    def __init__(self, doc, ioc_identifier=None):
        self.attackgraph_nx = nx.DiGraph()
        self.original_attackgraph_nx = nx.DiGraph()
        self.attackNode_dict = {}

        self.nlp_doc = doc
        self.ioc_identifier = ioc_identifier

        self.related_sentences = []
        self.techniques = {}

        self.generate()

    # http://sparkandshine.net/en/networkx-application-notes-a-better-way-to-visualize-graphs/
    # https://networkx.org/documentation/latest/auto_examples/drawing/plot_chess_masters.html#sphx-glr-auto-examples-drawing-plot-chess-masters-py
    def draw(self, image_path: str = "") -> figure:
        fig, ax = plt.subplots(figsize=(24, 24))  # Todo: re-consider the figure size.

        graph_pos = nx.spring_layout(self.attackgraph_nx, scale=2)
        for label in ner_labels:
            nx.draw_networkx_nodes(self.attackgraph_nx,
                                   graph_pos,
                                   node_shape=node_shape_dict[label],
                                   nodelist=[node.id for node in filter(lambda n: n.type == label, self.attackNode_dict.values())],
                                   node_size=100,
                                   alpha=0.6)
        nx.draw_networkx_labels(self.attackgraph_nx,
                                graph_pos,
                                labels={node: self.attackNode_dict[node].__str__() for node in self.attackgraph_nx.nodes},
                                verticalalignment='top',
                                horizontalalignment='left',
                                font_size=6)
        nx.draw_networkx_edges(self.attackgraph_nx, graph_pos)
        nx.draw_networkx_edge_labels(self.attackgraph_nx,
                                     graph_pos,
                                     edge_labels=nx.get_edge_attributes(self.attackgraph_nx, 'action'),
                                     font_size=6)

        if image_path == "":
            plt.show()
        else:
            plt.savefig(image_path)

    def generate(self):
        logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph!---")

        self.parse_entity()
        self.parse_coreference()
        self.parse_dependency()

    def parse_entity(self):
        logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph nodes!---")

        for entity in self.nlp_doc.ents:
            if entity.root.ent_type_ in ner_labels:  # and re.match("NN.*", entity.root.tag_):  # Todo
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
                logging.debug("---coref_origin:---")
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
        tnode = -1

        root = sentence.root
        is_related_sentence = False

        # traverse the nltk tree
        node_queue.append(root)
        while node_queue:
            node = node_queue.pop(0)
            for child in node.children:
                node_queue.append(child)

            if node.i in self.attackNode_dict.keys():
                is_related_sentence = True
                self.attackgraph_nx.add_node(self.attackNode_dict[node.i].id)

                if tnode != -1:
                    self.attackgraph_nx.add_edge(tnode, node.i, action=tvb)
                tnode = node.i

        if (is_related_sentence):
            self.related_sentences.append(sentence.text)
            logging.debug("Related sentence: %s" % sentence.text)

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
                similarity += Levenshtein.ratio(m_nlp, n_nlp) / math.log(abs(n_position - m_position) + 2)
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
