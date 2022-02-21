from __future__ import annotations
import math
from typing import Set

import Levenshtein
from matplotlib import figure
import matplotlib.pyplot as plt
from nltk import Tree
import spacy.tokens
from spacy.tokens import Span

from report_parser.report_parser import *
from report_parser.ioc_protection import *
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
node_shape_dict = {
    "actor": "o",
    "executable": "o",
    "file": "s",
    "network": "d",
    "registry": "p",
    "vulnerability": "8",
    "system": "^",
}


def get_iocSet_similarity(set_m: Set[str], set_n: Set[str]) -> float:
    return get_stringSet_similarity(set_m, set_n)


def get_nlpSet_similarity(set_m: Set[str], set_n: Set[str]) -> float:
    return get_stringSet_similarity(set_m, set_n)


def get_stringSet_similarity(set_m: Set[str], set_n: Set[str]) -> float:
    max_similarity = 0.0
    for m in set_m:
        for n in set_n:
            similarity = get_string_similarity(m, n)
            max_similarity = max_similarity if max_similarity > similarity else similarity
    return max_similarity


# https://blog.csdn.net/dcrmg/article/details/79228589
def get_string_similarity(a: str, b: str) -> float:
    similarity_score = Levenshtein.ratio(a, b)
    return similarity_score


class AttackGraphNode:
    id: int
    type: str

    ioc: Set[str]
    nlp: Set[str]

    position: int

    def __init__(self, entity: Span):
        self.id = entity.root.i  # entity could include multiple words, we only record the entity root token's position (word num) as unique id
        self.type = entity.root.ent_type_
        self.nlp = {entity.text}
        self.ioc = set()
        self.position = entity.root.idx

    def __str__(self):
        return f"Node #{self.id}: [type: '{self.type}', nlp: '{self.nlp}', ioc: '{self.ioc}', position: '{self.position}']"

    def is_similar_with(self, node: AttackGraphNode) -> bool:
        if self.get_similarity(node) >= 0.4:
            return True
        else:
            return False

    def get_similarity(self, node: AttackGraphNode) -> float:  # Todo
        similarity = 0.0
        if self.type == node.type:
            similarity += 0.4
        similarity += max(get_stringSet_similarity(self.ioc, node.ioc), get_stringSet_similarity(self.nlp, node.nlp))
        return similarity

    def merge_node(self, node: AttackGraphNode):
        self.nlp |= node.nlp
        self.ioc |= node.ioc

        node.nlp = self.nlp
        node.ioc = self.ioc


class AttackGraph:
    attackgraph_nx: nx.DiGraph
    attackNode_dict: Dict[int, AttackGraphNode]  # coref nodes should point to the same attackGraphNode

    nlp_doc: spacy.tokens.doc.Doc
    ioc_identifier: IoCIdentifier

    related_sentences: List[str]
    techniques: Dict[str, list]  # technique name -> [node_list]

    def __init__(self, doc, ioc_identifier=None):
        self.attackgraph_nx = nx.DiGraph()
        self.attackNode_dict = {}

        self.nlp_doc = doc
        self.ioc_identifier = ioc_identifier

        self.related_sentences = []
        self.techniques = {}

        self.generate()

    # http://sparkandshine.net/en/networkx-application-notes-a-better-way-to-visualize-graphs/
    # https://networkx.org/documentation/latest/auto_examples/drawing/plot_chess_masters.html#sphx-glr-auto-examples-drawing-plot-chess-masters-py
    def draw(self, image_path: str = "") -> figure:
        fig_size = math.ceil(math.sqrt(self.attackgraph_nx.number_of_nodes())) * 10
        plt.subplots(figsize=(fig_size, fig_size))  # Todo: re-consider the figure size.

        graph_pos = nx.spring_layout(self.attackgraph_nx, scale=2)
        for label in ner_labels:
            nx.draw_networkx_nodes(self.attackgraph_nx,
                                   graph_pos,
                                   node_shape=node_shape_dict[label],
                                   nodelist=[node for node in filter(lambda n: self.attackNode_dict[n].type == label, self.attackgraph_nx.nodes)],
                                   # nodelist=[node.id for node in filter(lambda n: n.type == label, self.attackNode_dict.values())],
                                   node_size=100,
                                   alpha=0.6)
        nx.draw_networkx_labels(self.attackgraph_nx,
                                graph_pos,
                                labels={node: str(self.attackNode_dict[node]) for node in self.attackgraph_nx.nodes},
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

    def to_json(self):  # Todo
        pass

    def generate(self):
        logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph!---")

        self.parse_entity()
        self.parse_coreference()
        self.parse_dependency()

        logging.info("---attack graph generation: Simplify the Attack Graph!---")

        self.simplify()
        self.node_merge()

    def parse_entity(self):
        logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph nodes!---")

        for entity in self.nlp_doc.ents:
            if entity.root.ent_type_ in ner_labels:  # and re.match("NN.*", entity.root.tag_):  # Todo
                attack_node = AttackGraphNode(entity)
                self.attackNode_dict[entity.root.i] = attack_node

                for token in entity:
                    self.attackNode_dict[token.i] = self.attackNode_dict[entity.root.i]
                    if (token.idx - 1) in self.ioc_identifier.replaced_ioc_dict.keys():
                        self.attackNode_dict[entity.root.i].ioc.add(self.ioc_identifier.replaced_ioc_dict[token.idx - 1])
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

        if is_related_sentence:
            self.related_sentences.append(sentence.text)
            logging.debug("Related sentence: %s" % sentence.text)

        return self.attackgraph_nx

    source_node_list: list
    visited_node_list: list

    def simplify(self):
        logging.info(f"---attack graph generation: There are {self.attackgraph_nx.number_of_nodes()} nodes before simplification!---")
        source_node_list = self.locate_all_source_node()
        self.visited_node_list = []

        for source_node in source_node_list:
            self.simplify_foreach_subgraph(source_node)

        # self.clear_contraction_info()
        logging.info(f"---attack graph generation: There are {self.attackgraph_nx.number_of_nodes()} nodes after simplification!---")

    def simplify_foreach_subgraph(self, source_node):
        if source_node not in self.visited_node_list:
            self.visited_node_list.append(source_node)
        else:
            return

        neighbor_list = self.attackgraph_nx.neighbors(source_node)
        for neighor in neighbor_list:
            self.simplify_foreach_subgraph(neighor)  # recursion

            # check whether to merge the node or not
            if self.attackNode_dict[source_node].is_similar_with(self.attackNode_dict[neighor]) \
                    and self.attackgraph_nx.in_degree(neighor) == 1:
                self.attackgraph_nx = nx.contracted_nodes(self.attackgraph_nx, source_node, neighor, self_loops=False)
                self.attackNode_dict[source_node].merge_node(self.attackNode_dict[neighor])
                self.attackNode_dict.pop(neighor)

    def locate_all_source_node(self) -> List:
        self.source_node_list = []

        for node in self.attackgraph_nx.nodes():
            if self.attackgraph_nx.in_degree(node) == 0:
                self.source_node_list.append(node)

        return self.source_node_list

    def clear_contraction_info(self):
        for nodes in self.attackgraph_nx.nodes():
            self.attackgraph_nx.nodes[nodes]["contraction"] = ""

    def node_merge(self):
        self.original_attackgraph_nx = nx.DiGraph(self.attackgraph_nx)

        merge_graph = nx.Graph()
        node_list = list(self.attackgraph_nx.nodes())

        for m in range(0, len(node_list)):
            for n in range(m + 1, len(node_list)):
                node_m = self.attackNode_dict[node_list[m]]
                node_n = self.attackNode_dict[node_list[n]]

                if node_m.get_similarity(node_n) / math.log(abs(node_m.id - node_n.id) + 2) >= 0.4 \
                        and ((len(node_m.ioc) == 0 and len(node_n.ioc) == '') or len(node_m.ioc & node_n.ioc) != 0):
                    merge_graph.add_edge(node_list[m], node_list[n])

        for subgraph in nx.connected_components(merge_graph):
            subgraph_list = list(subgraph)
            # print(subgraph_list)
            a = subgraph_list[0]
            for b in subgraph_list[1:]:
                self.attackgraph_nx = nx.contracted_nodes(self.attackgraph_nx, a, b, self_loops=False)
                self.attackNode_dict[a].merge_node(self.attackNode_dict[b])
                self.attackNode_dict.pop(b)
            # self.attackgraph_nx.nodes[a]["contraction"] = ""

        logging.info(f"---attack graph generation: There are {self.attackgraph_nx.number_of_nodes()} nodes after node merge!---")
