import math

import Levenshtein

import sys; print('Python %s on %s' % (sys.version, sys.platform))
sys.path.extend(['.', './Attack_Graph'])

from NLP.iocNer import *
from NLP.iocRegex import *
from NLP.reportPreprocess import *
from Mitre_TTPs.mitreGraphReader import *
# from attackTemplate import *

import networkx as nx
import graphviz
import re
from nltk import Tree
import matplotlib.pyplot as plt
import logging
import sys
import os
from pathlib import Path
import time
import spacy.tokens


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


# https://graphviz.org/doc/info/shapes.html
# node_shape = {
#     "NetLoc": "diamond",
#     "E-mail": "diamond",
#     "C2C": "diamond",
#     "APTFamily": "doublecircle",
#     "ExeFile": "oval",
#     "ScriptsFile": "oval",
#     "DocumentFile": "rectangle",
#     "File": "rectangle",
#     "Registry": "parallelogram",
#     "Vulnerability": "trapezium",
#     "Service": "trapezium",
#     "SensInfo": "invhouse"
# }

node_shape = {
    "actor": "doublecircle",
    "network": "diamond",
    "executable": "oval",
    "file": "rectangle",
    "defender": "invhouse",
    "registry": "parallelogram",
    "vulnerability": "trapezium",
    "system": "trapezium",
    "service": "trapezium"
}


def draw_attackgraph_dot(g: nx.DiGraph, clusters: dict = None, output_file: str = None) -> graphviz.Graph:
    dot = graphviz.Graph('G', filename=output_file)

    logging.warning("---Draw attack graph with dot!---")

    for node in g.nodes:
        logging.debug(node)

        nlp = ""
        try:
            nlp = g.nodes[node]["nlp"]
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


# def extract_entity_list_from_spacydoc(nlp_doc):
#     logging.info("---Extract Entity List!---")
#     ent_list = []
#
#     for ent in nlp_doc.ents:
#         ent = ent[0]
#         if ent.ent_type_ in ner_labels:
#             n = "@".join([ent.text, ent.ent_type_])
#             logging.debug(n)
#             ent_list.append(n)
#
#     return ent_list


class AttackGraphNode:
    node_type: str
    node_ioc_representation: str
    node_nlp_representation: str

    def __init__(self, node_type):
        self.node_type = node_type

    def __str__(self):
        return "#".join(self.node_type, self.node_nlp_representation, self.node_ioc_representation)


# return token unique id for nx.graph
def get_token_id(tok: spacy.tokens.token.Token) -> str:
    # return "@".join([tok.lower_, tok.ent_type_])
    return "#".join([tok.lower_, tok.ent_type_, str(tok.i)])


class AttackGraph:
    attackgraph_nx: nx.DiGraph
    original_attackgraph_nx: nx.DiGraph
    nlp_doc: spacy.tokens.doc.Doc
    ioc_identifier: IoCIdentifier

    node_list: list
    edge_list: list

    ioc_coref_list: list
    ioc_coref_dict: dict

    # attack_node_list: list
    entity_root_token_string_dict: dict
    entity_ignore_token_list: list

    techniques = {}  # technique name -> [node_list]

    # def __init__(self, ioc_identifier = None):
    #     self.attackgraph_nx = None
    #     self.ioc_identifier = ioc_identifier
    #
    #     self.ioc_coref_list = []
    #     self.ioc_coref_dict = {}

    def __init__(self, doc, ioc_identifier=None):
        self.attackgraph_nx = None
        self.ioc_identifier = ioc_identifier

        self.ioc_coref_list = []
        self.ioc_coref_dict = {}

        self.entity_root_token_string_dict = {}
        self.entity_ignore_token_list = []

        self.nlp_doc = doc

    # def construct_nxgraph_from_spacydoc(self, doc):
    #     for sentence in doc.sents:
    #         try:
    #             self.attackgraph_nx = self.construct_nxgraph_from_spacysent(sentence)
    #         except:
    #             continue
    #
    #     return self.attackgraph_nx
    #
    # # construct graph with spacy tree
    # def construct_nxgraph_from_spacysent(self, sentence):
    #     logging.info("---Construct Attack Graph!---")
    #
    #     if self.attackgraph_nx == None:
    #         self.attackgraph_nx = nx.DiGraph()
    #
    #     node_queue = []
    #     tvb = ""
    #     tnode = ""
    #
    #     root = sentence.root
    #     # to_nltk_formatted_tree(root).pretty_print()
    #     is_related_sentence = False
    #
    #     # FIXME: Wrong relationships
    #     # traverse the nltk tree
    #     node_queue.append(root)
    #     while node_queue:
    #         node = node_queue.pop(0)
    #         # print("@".join([node.text, node.tag_, node.ent_type_]))
    #         if re.match("VB.*", node.tag_):
    #             tvb = node.text
    #         if re.match("NN.*", node.tag_):
    #             # if node.ent_type_ != "":
    #             if node.ent_type_ in ner_labels:
    #                 is_related_sentence = True
    #
    #                 n = "@".join([node.text, node.ent_type_])
    #                 logging.debug(n)
    #                 self.attackgraph_nx.add_node(n, type=node.ent_type_, nlp=node.text)
    #
    #                 if tnode != "" and tvb != "":
    #                     self.attackgraph_nx.add_edge(tnode, n, action=tvb)
    #                 tnode = n
    #         for child in node.children:
    #             node_queue.append(child)
    #
    #     if(is_related_sentence):
    #         logging.info("Related sentence: %s" % sentence.text)
    #
    #     return self.attackgraph_nx

    def parse(self):
        logging.info("---S1-1: Parsing NLP doc to get Attack Graph!---")

        if self.attackgraph_nx is None:
            self.attackgraph_nx = nx.DiGraph()

        # parse coreference
        self.parse_coref()
        # # parse node
        self.parse_node()
        # parse edge
        self.parse_edge()

    def parse_coref(self):
        logging.info("---S1-1.0: Parsing NLP doc to get Coreference!---")

        for coref_set in self.nlp_doc._.coref_chains:

            # get ioc-related coreferences sets
            coref_origin = 0
            for coref_item in coref_set:
                coref_token = self.nlp_doc[coref_item.root_index]
                # logging.debug("%s-%s" % (coref_token, coref_token.ent_type_))
                if coref_token.ent_type_ in ner_labels:
                    self.ioc_coref_list.append(coref_set)
                    coref_origin = coref_item.root_index
                    break

            # pasing the coreferences
            if coref_origin != 0:
                coref_token = self.nlp_doc[coref_origin]
                logging.debug("---coref_origiin:---\n %s-%s" % (coref_token, coref_token.ent_type_))
                for i in range(0, len(coref_set.mentions)):
                    coref_p = coref_set.mentions[i].root_index
                    if coref_p == coref_origin:
                        continue
                    coref_token = self.nlp_doc[coref_p]
                    self.ioc_coref_dict[coref_p] = coref_origin
                    logging.debug("%s-%s" % (coref_token, coref_token.ent_type_))

    def parse_node(self):
        logging.info("---S1-1.1: Parsing NLP doc to get Attack Graph Nodes!---")

        # parsing all ioc nodes
        for entity in self.nlp_doc.ents:
            ent_root = entity.root
            ent_root_i = ent_root.i
            self.entity_root_token_string_dict[ent_root_i] = entity.text
            for token in entity:
                if token.i not in self.entity_root_token_string_dict.keys():
                    ignore_token_i = token.i
                    self.entity_ignore_token_list.append(ignore_token_i)

        # last_ent_type = ''
        # ent_start_i = 0
        # # try to find entities' boundary
        # for token in self.nlp_doc:
        #     ent_type = token.ent_type_
        #     if ent_type in ner_labels:
        #         if ent_type != last_ent_type:
        #             ent_start_i = token.i
        #         else:
        #             self.entity_ignore_token_list.append(token.i-1)
        #     else:
        #         if last_ent_type in ner_labels:
        #             self.entity_root_token_string_dict[token.i-1] = self.nlp_doc[ent_start_i:token.i].text
        #         else:
        #             ent_start_i = 0
        #     last_ent_type = ent_type

        # parsing ioc recognized with iocRegex

    def parse_edge(self):
        logging.info("---S1-1.2: Parsing NLP doc to get Attack Graph Edges!---")

        for sentence in self.nlp_doc.sents:
            # try:
            self.parse_edge_sentence(sentence)
            # except:
            #     continue

        return self.attackgraph_nx


    edge_count = 0

    def parse_edge_sentence(self, sentence):
        node_queue = []
        tvb = ""
        tnode = ""

        root = sentence.root
        # to_nltk_formatted_tree(root).pretty_print()
        is_related_sentence = False

        # traverse the nltk tree
        node_queue.append(root)
        while node_queue:
            node = node_queue.pop(0)
            for child in node.children:
                node_queue.append(child)

            # process only the ioc_root
            if node.i in self.entity_ignore_token_list:
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
                if node.i in self.entity_root_token_string_dict.keys():
                    nlp = self.entity_root_token_string_dict[node.i]
                else:
                    nlp = node.text

                n = get_token_id(node)  # + regex
                logging.debug(n)
                self.attackgraph_nx.add_node(n, type=node.ent_type_, nlp=nlp, regex=regex)

                if tnode != "":
                    self.attackgraph_nx.add_edge(tnode, n, action=tvb, sequence=self.edge_count, nlp=sentence.text)
                    self.edge_count += 1
                tnode = n

            # edges with coreference nodes
            if node.i in self.ioc_coref_dict.keys():
                coref_node = self.nlp_doc[self.ioc_coref_dict[node.i]]

                regex = ""
                if node.idx in self.ioc_identifier.replaced_ioc_dict.keys():
                    regex = self.ioc_identifier.replaced_ioc_dict[node.idx]
                    logging.debug("Recover IoC regex: %s" % regex)

                nlp = ""
                if coref_node.i in self.entity_root_token_string_dict.keys():
                    nlp = self.entity_root_token_string_dict[coref_node.i]
                else:
                    nlp = coref_node.text

                n = get_token_id(coref_node)
                logging.debug(n)
                self.attackgraph_nx.add_node(n, type=coref_node.ent_type_, nlp=nlp, regex=regex)

                if tnode != "":
                    self.attackgraph_nx.add_edge(tnode, n, action=tvb, sequence=self.edge_count, nlp=sentence.text)
                    self.edge_count += 1
                tnode = n

        if (is_related_sentence):
            logging.debug("Related sentence: %s" % sentence.text)

        return self.attackgraph_nx

    # def parse_edge_sentence(self, sentence):
    #     # M1: find Shortest Dependency Path (SDP)
    #     # https://towardsdatascience.com/how-to-find-shortest-dependency-path-with-spacy-and-stanfordnlp-539d45d28239
    #
    #     ioc_nodes = []
    #     edges = []
    #     for token in sentence:
    #         if token.ent_type_ in ner_labels:
    #             ioc_nodes.append(token.i)
    #
    #         for child in token.children:
    #             edges.append(('{0}'.format(token.i), '{0}'.format(child.i)))
    #
    #     graph = nx.DiGraph(edges)
    #     draw_attackgraph_plt(graph)
    #
    #     # https://www.coder.work/article/3134983
    #     # https://stackoverflow.com/questions/61914713/removing-a-node-from-digraph-in-networkx-while-preserving-child-nodes-and-remapp
    #     # https://en.wikipedia.org/wiki/Edge_contraction

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

        source_nlp = self.attackgraph_nx.nodes[source_node]["nlp"]
        try:
            source_regex = self.attackgraph_nx.nodes[source_node]["regex"]
        except KeyError:
            source_regex = ""

        neighbor_list = self.attackgraph_nx.neighbors(source_node)
        for neighor in neighbor_list:
            self.simplify_foreach_subgraph(neighor)

            neighor_nlp = self.attackgraph_nx.nodes[neighor]["nlp"]
            try:
                neighor_regex = self.attackgraph_nx.nodes[neighor]["regex"]
            except KeyError:
                neighor_regex = ""

            # check whether to merge the node or not
            if self.attackgraph_nx.nodes[source_node]["type"] == self.attackgraph_nx.nodes[neighor]["type"] \
                and self.attackgraph_nx.in_degree(neighor) == 1 \
                and (source_regex == "" or neighor_regex == ""):
                self.attackgraph_nx = nx.contracted_nodes(self.attackgraph_nx, source_node, neighor, self_loops=False)

                self.attackgraph_nx.nodes[source_node]["nlp"] = source_nlp + " " + neighor_nlp
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
                m_nlp = self.attackgraph_nx.nodes[node_m]['nlp']
                n_nlp = self.attackgraph_nx.nodes[node_n]['nlp']
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

def parse_attackgraph_from_text(ner_model: IoCNer, text: str) -> AttackGraph:
    iid = IoCIdentifier(text)

    text_without_ioc = iid.replaced_text
    doc = ner_model.parser(text_without_ioc)
    ag = AttackGraph(doc, ioc_identifier=iid)

    ag.parse()
    ag.node_merge()
    ag.simplify()
    ag.clear_contraction_info()

    return ag


def parse_attackgraph_from_cti_report(ner_model: IoCNer,
                                      cti_file: str = r".\data\cti\html\0a84e7a880901bd265439bd57da61c5d.html",
                                      output_path: str = ""):
    logging.info("---Parsing %s---" % cti_file)

    # file_name = os.path.splitext(cti_file)[0]
    file_name = Path(cti_file).stem
    file_ext = os.path.splitext(cti_file)[-1]
    if file_ext == ".html":
        text = read_html(cti_file)
        if len(text) > 1000000:  # FIXME: cannot process text file with more than 1000000 characters.
            logging.warning("---Not support too long CTI reports yet!---")
            return
    else:
        logging.warning("---Not support non-html CTI reports yet!---")
        return

    ag = parse_attackgraph_from_text(ner_model, text)

    dot_graph = draw_attackgraph_dot(ag.attackgraph_nx)

    if output_path == "":
        dot_graph.view()
    else:
        nx.write_gml(ag.attackgraph_nx, os.path.join(output_path, file_name + ".gml"))
        draw_attackgraph_dot(ag.attackgraph_nx, output_file=os.path.join(output_path, file_name))

    return ag


# %%

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    # logging.basicConfig(filename="running_time_log.txt", filemode='a', level=logging.DEBUG)
    logging.info("======techniqueIdentifier.py: %s======", time.asctime(time.localtime(time.time())))

    ner_model = IoCNer("./new_cti.model")
    ner_model.add_coreference()


    # TC Firefox DNS Drakon APT
    sample = r"The attack started by browsing to http://128.55.12.167:8641/config.html, selecting DNS, entering hostname Xx--ls8h.com, file 938527054, and clicking the Visit button.  This triggered the Firefox backdoor to connect out via DNS to XX--ls8h.com.  Drakon APT was downloaded and executed and connected to 128.55.12.167:8640 for C2.  The attacker escalated privileges using the new File System Filter Driver, which looks for processes opening specific files which don’t exist and elevates them.  Once SYSTEM, the attacker exfil’ed the host and network files as well as a passwd file in the home directory."
    # TC Firefox Drakon APT Elevate Copykatz
    sample = r"irst attacked ta51-pivot-2 and deployed OC2, allowing us to run our attack from within the target network.  Exploited Firefox backdoor by again browsing to http://128.55.12.233.  Loader Drakon was executed in Firefox memory and connected out to 128.55.12.233:8000 and 128.55.12.233:443 for C2.  After the BBN reboot, driver signing was disabled, and we would now be able to use privilege escalation via our perfmon driver.  We loaded the copykatz module planning to recon data from the system; however, an error in our C2 resulted in loss of connection and a premature end to the test.  We re-ran this test later in the same day."
    # Firefox BITS Micro APT
    sample = r"Benign activity ran for most of the morning while the tools were being setup for the day.  The activity was modified so the hosts would open Firefox and browse to http://215.237.119.171/config.html.  The simulated host then entered URL for BITS Micro APT as http://68.149.51.179/ctfhost2.exe.   We used the exploited Firefox backdoor to initiate download of ctfhost2.exe via the Background Intelligent Transfer Service (BITS).  Our server indicated the file was successfully downloaded using the BITS protocol, and soon after Micro APT was executed on the target and connected out to 113.165.213.253:80 for C2.  The attacker tried to elevate using a few different drivers, but it failed once again due to the computer having been restarted without disabling driver signature enforcement.  BBN tried using BCDedit to permanently disable driver signing, but it did not seem to work during the engagement as the drivers failed to work unless driver signing was explicitly disabled during boot."
    # SSH BinFmt-Elevate
    sample = r"Copied files via SCP and connected via SSH from the ta1-pivot-2 host.  Sent files to the target included the privilege escalation driver load_helper and an elevate client.  Connected to target using SSH with stolen credentials.  Loaded the driver, and used it to gain root privileges.  As root, exfil’d /etc/passwd, /etc/shadow, and the admin’s home directory Documents files."
    # Frankenstein Campaign
    sample = r'''In order to compromise their victims, the threat actors sent the trojanized Microsoft Word documents, probably via email. The first vector relies on a trojanized document that fetches a remote template and then uses a known exploit. The second vector is a trojanized Word document that prompts the victim to enable macros and run a Visual Basic script. We were able to correlate these two techniques to the same threat campaign due to overlapping threat actor C2.
        In the first scenario, Talos discovered a document named "MinutesofMeeting-2May19.docx", that appeared to display the national flag of Jordan. Once the victim opens the document, it fetches a remove template from the actor-controlled website, hxxp://droobox[.]online:80/luncher.doc. Once the luncher.doc was downloaded, it used CVE-2017-11882, to execute code on the victim's machine. After the exploit, the file would run a command script to set up persistence as a scheduled task named "WinUpdate". That scheduled task would run a series of base64-encoded PowerShell commands that acted as a stager. The stager will be described in more detail in the next section.
        As soon as the user enabled the macro, a robust Visual Basic Application (VBA) script began to execute. The VBA script contained two anti-analysis features. First, it would query Windows Management Instrumentation (WMI) to check if any of the following applications were running.
        Once the evasion checks were complete, the threat actors used MSbuild to execute an actor-created file named "LOCALAPPDATA\Intel\instal.xml". Based on lexical analysis, we assess with high confidence that this component of the macro script was based on an open-source project called "MSBuild-inline-task." While this technique was previously documented last year, it has rarely been observed being used in operations. Talos suspects the adversary chose MSBuild because it is a signed Microsoft binary, meaning that it can bypass application whitelisting controls on the host when being used to execute arbitrary code.
        Once the "instal.xml" file began execution, it would deobfuscate the base64-encoded commands. This revealed a stager, or a small script designed to obtain an additional payload. While analyzing this stager, we noticed some similarities to the "Get-Data" function of the FruityC2 PowerShell agent. One notable difference is that this particular stager included functionality that allowed the stager to communicate with the command and control (C2) via an encrypted RC4 byte stream. In this sample, the threat actors' C2 server was the domain msdn[.]cloud.
        the C2 would return a string of characters. Once the string was RC4 decrypted, it launched a PowerShell Empire agent. The PowerShell script would attempt to enumerate the host to look for certain information. Once the aforementioned information was obtained, it was sent back to the threat actor's C2.
    '''
    # Cobalt Campaign
    sample = '''
        All observed attacks start with an email message, containing either a malicious attachment or a URL which leads to the first stage of the attack. The text of the emails is likely taken from legitimate email, such as mailing lists that targeted organizations may be subscribed to. Below are three examples, with the first one purporting to be sent by the European Banking Federation and is using a newly registered domain for the spoofed sender email address. The attachment is a malicious PDF file that entices the user to click on a URL to download and open a weaponized RTF file containing exploits for CVE-2017-11882, CVE-2017-8570 and CVE-2018-8174. The final payload is a JScript backdoor also known as More_eggs that allows the attacker to control the affected system remotely.
        Notable applications used in these attacks are cmstp and msxsl. The Microsoft Connection Manager Profile Installer (cmstp.exe) is a command-line program used to install Connection Manager service profiles. Cmstp accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections. A malicious INF file can be supplied as a parameter to download and execute remote code. Cmstp may also be used to load and execute COM scriptlets (SCT files) from remote servers.
        Microsoft allows developers to create COM+ objects in script code stored in an XML document, a so-called scriptlet file. Although it is common to use JScript or VBScript, as they are available in Windows by default, a scriptlet can contain COM+ objects implemented in other languages, including Perl and Python, which would be fully functional if the respective interpreters are installed.
        To bypass AppLocker and launching script code within a scriptlet, the attacker includes the malicious code within an XML script tag placed within the registration tag of the scriptlet file and calls cmstp with appropriate parameters.
        An earlier part of the second stage is implemented as an encrypted JScript scriptlet which eventually drops a randomly named COM server DLL binary with a .txt filename extension, for example, 9242.txt, in the user's home folder and registers the server using the regsvr32.exe utility.The dropper contains an encrypted data blob that is decrypted and written to the disk. The dropper then launches the next stage of the attack by starting PowerShell, msxsl or cmstp.exe as described above.
        The PowerShell chain is launched from an obfuscated JScript scriptlet previously downloaded from the command and control (C2) server and launched using cmstp.exe. The first PowerShell stage is a simple downloader that downloads the next PowerShell stage and launches a child instance of powershell.exe using the downloaded, randomly named script as the argument. The downloaded PowerShell script code is obfuscated in several layers before the last layer is reached. The last layer loads shellcode into memory and creates a thread within the PowerShell interpreter process space.
        On the PowerShell side of the infection chain, the downloaded final payload is a Cobalt Strike beacon, which provides the attacker with rich backdoor functionality.
    '''
    # OceanLotus Campaign
    sample = '''
        The Adobe_Flash_install.rar archive that was returned from the baomoivietnam.com website contained the files Flash_Adobe_Install.exe and goopdate.dll. The table below provides some basic information on all three of these files.
        The file goopdate.dll has the hidden file attribute set and will not show in Windows Explorer on systems using default settings. This results in the user seeing only the Flash_Adobe_Install.exe file to execute in order to install what they believe to be an update to Flash Player. When run, it will automatically load goopdate.dll due to search order hijacking. Goopdate.dll is a highly obfuscated loader whose ultimate purpose is to load a Cobalt Strike stager into memory and then execute it. The Cobalt Strike stager will simply try to download and execute a shellcode from a remote server, in this case using the following URL: summerevent.webhop.net/QuUA
    '''
    # Log4Shell Campaign
    sample = '''
        Due to its ubiquitous use, many common infrastructure products from Microsoft, Apple, Twitter, CloudFlare and others are vulnerable to Log4Shell attacks. Recently, VMware also issued guidance that some components of its Horizon service are vulnerable to Log4j exploits, leading OverWatch to add the VMware Horizon Tomcat web server service to their processes-to-watch list, researchers said.
        The Falcon OverWatch team noticed the Aquatic Panda intrusion when the threat actor performed multiple connectivity checks via DNS lookups for a subdomain under dns[.]1433[.]eu[.]org, executed under the Apache Tomcat service running on the VMware Horizon instance, they wrote in the post.
        “The threat actor then executed a series of Linux commands, including attempting to execute a bash-based interactive shell with a hardcoded IP address as well as curl and wget commands in order to retrieve threat-actor tooling hosted on remote infrastructure,” researchers wrote.
        The commands were executed on a Windows host under the Apache Tomcat service, researchers said. They triaged the initial activity and immediately sent a critical detection to the victim organization, later sharing additional details directly with their security team, they said.
        Eventually, researchers assessed that a modified version of the Log4j exploit was likely used during the course of the threat actor’s operations, and that the infrastructure used in the attack is linked to Aquatic Panda, they said.
        OverWatch researchers tracked the threat actor’s activity closely during the intrusion to provide continuous updates to academic institution as its security administrators scrambled to mitigate the attack, they said.
        Aquatic Panda engaged in reconnaissance from the host, using native OS binaries to understand current privilege levels as well as system and domain details. Researchers also observed the group attempt discover and stop a third-party endpoint detection and response (EDR) service, they said.
        The threat actors downloaded additional scripts and then executed a Base64-encoded command via PowerShell to retrieve malware from their toolkit. They also retrieved three files with VBS file extensions from remote infrastructure, which they then decoded.
        “Based on the telemetry available, OverWatch believes these files likely constituted a reverse shell, which was loaded into memory via DLL search-order hijacking,” researchers wrote.
        Aquatic Panda eventually made multiple attempts to harvest credentials by dumping the memory of the LSASS process using living-off-the-land binaries rdrleakdiag.exe and cdump.exe, a renamed copy of createdump.exe.
        “The threat actor used winRAR to compress the memory dump in preparation for exfiltration before attempting to cover their tracks by deleting all executables from the ProgramData and Windows\temp\ directories,” researchers wrote.
        The victim organization eventually patched the vulnerable application, which prevented further action from Aquatic Panda on the host and stopped the attack, researchers said.
        '''
    # Deputydog Campaign
    sample = '''
        On February 11, FireEye identified a zero-day exploit (CVE-2014-0322)  being served up from the U.S. Veterans of Foreign Wars’ website (vfw[.]org). We believe the attack is a strategic Web compromise targeting American military personnel amid a paralyzing snowstorm at the U.S. Capitol in the days leading up to the Presidents Day holiday weekend. Based on infrastructure overlaps and tradecraft similarities, we believe the actors behind this campaign are associated with two previously identified campaigns (Operation DeputyDog and Operation Ephemeral Hydra).
        This blog post examines the vulnerability and associated attacks, which we have dubbed “Operation SnowMan."
        Exploit/Delivery analysis
        After compromising the VFW website, the attackers added an iframe into the beginning of the website’s HTML code that loads the attacker’s page in the background. The attacker’s HTML/JavaScript page runs a Flash object, which orchestrates the remainder of the exploit. The exploit includes calling back to the IE 10 vulnerability trigger, which is embedded in the JavaScript.  Specifically, visitors to the VFW website were silently redirected through an iframe to the exploit at www.[REDACTED].com/Data/img/img.html.
        Mitigation
        The exploit targets IE 10 with Adobe Flash. It aborts exploitation if the user is browsing with a different version of IE or has installed Microsoft’s Experience Mitigation Toolkit (EMET). So installing EMET or updating to IE 11 prevents this exploit from functioning.
        Vulnerability analysis
        The vulnerability is a previously unknown use-after-free bug in Microsoft Internet Explorer 10. The vulnerability allows the attacker to modify one byte of memory at an arbitrary address. The attacker uses the vulnerability to do the following:
        Gain access to memory from Flash ActionScript, bypassing address space layout randomization (ASLR)
        Pivot to a return-oriented programing (ROP) exploit technique to bypass data execution prevention (DEP)
        EMET detection
        The attacker uses the Microsoft.XMLDOM ActiveX control to load a one-line XML string containing a file path to the EMET DLL. Then the exploit code parses the error resulting from the XML load order to determine whether the load failed because the EMET DLL is not present.  The exploit proceeds only if this check determines that the EMET DLL is not present.
        ASLR bypass
        Because the vulnerability allows attackers to modify memory to an arbitrary address, the attacker can use it to bypass ASLR. For example, the attacker corrupts a Flash Vector object and then accesses the corrupted object from within Flash to access memory. We have discussed this technique and other ASLR bypass approaches in our blog. One minor difference between the previous approaches and this attack is the heap spray address, which was changed to 0x1a1b2000 in this exploit.
        Code execution
        Once the attacker’s code has full memory access through the corrupted Flash Vector object, the code searches through loaded libraries gadgets by machine code. The attacker then overwrites the vftable pointer of a flash.Media.Sound() object in memory to point to the pivot and begin ROP. After successful exploitation, the code repairs the corrupted Flash Vector and flash.Media.Sound to continue execution.
        Shellcode analysis
        Subsequently, the malicious Flash code downloads a file containing the dropped malware payload. The beginning of the file is a JPG image; the end of the file (offset 36321) is the payload, encoded with an XOR key of 0x95. The attacker appends the payload to the shellcode before pivoting to code control. Then, when the shellcode is executed, the malware creates files “sqlrenew.txt” and “stream.exe”. The tail of the image file is decoded, and written to these files. “sqlrenew.txt” is then executed with the LoadLibraryA Windows API call.
        ZxShell payload analysis
        As documented above, this exploit dropped an XOR (0x95) payload that executed a ZxShell backdoor (MD5: 8455bbb9a210ce603a1b646b0d951bce). The compile date of the payload was 2014-02-11, and the last modified date of the exploit code was also 2014-02-11. This suggests that this instantiation of the exploit was very recent and was deployed for this specific strategic Web compromise of the Veterans of Foreign Wars website. A possible objective in the SnowMan attack is targeting military service members to steal military intelligence. In addition to retirees, active military personnel use the VFW website. It is probably no coincidence that Monday, Feb. 17, is a U.S. holiday, and much of the U.S. Capitol shut down Thursday amid a severe winter storm.
        The ZxShell backdoor is a widely used and publicly available tool used by multiple threat actors linked to cyber espionage operations. This particular variant called back to a command and control server located at newss[.]effers[.]com. This domain currently resolves to 118.99.60.142. The domain info[.]flnet[.]org also resolved to this IP address on 2014-02-12.
        Infrastructure analysis
        The info[.]flnet[.]org domain overlaps with icybin[.]flnet[.]org and book[.]flnet[.]org via the previous resolutions to the following IP addresses: 58.64.200.178; 58.64.200.179; 103.20.192.4
        We previously observed Gh0stRat samples with the custom packet flag “HTTPS” calling back to book[.]flnet[.]org and icybin[.]flnet[.]org. The threat actor responsible for Operation DeputyDog also used the “HTTPS” version of the Gh0st. We also observed another “HTTPS” Gh0st variant connecting to a related command and control server at me[.]scieron[.]com.
        The me[.]scieron[.]com domain previously resolved to 58.64.199.22. The book[.]flnet[.]org domain also resolved to another IP in the same subnet 58.64.199.0/24. Specifically, book[.]flnet[.]org previously resolved to 58.64.199.27.
        Others domain seen resolving to this same /24 subnet were dll[.]freshdns[.]org, ali[.]blankchair[.]com, and cht[.]blankchair[.]com. The domain dll[.]freshdns[.]org resolved to 58.64.199.25. Both ali[.]blankchair[.]com and cht[.]blankchair[.]com resolved to 58.64.199.22.
        A number of other related domains resolve to these IPs and other IPs also in this /24 subnet. For the purposes of this blog, we’ve chosen to focus on those domains and IP that relate to the previously discussed DeputyDog and Ephemeral Hydra campaigns.
        You may recall that dll[.]freshdns[.]org, ali[.]blankchair[.]com and cht[.]blankchair[.]com were all linked to both Operation DeputyDog and Operation Ephemeral Hydra. Figure 1 illustrates the infrastructure overlaps and connections we observed between the strategic Web compromise campaign leveraging the VFW’s website, the DeputyDog, and the Ephemeral Hydra operations.
        Links to DeputyDog and Ephemeral Hydra
        Other tradecraft similarities between the actor(s) responsible for this campaign and the actor(s) responsible for the DeputyDog/Ephemeral Hydra campaigns include:
        The use of zero-day exploits to deliver a remote access Trojan (RAT)
        The use of strategic web compromise as a vector to distribute remote access Trojans
        The use of a simple single-byte XOR encoded (0x95) payload obfuscated with a .jpg extension
        The use of Gh0stRat with the “HTTPS” packet flag
        The use of related command-and-control (CnC) infrastructure during the similar time frames
        We observed many similarities from the exploitation side as well. At a high level, this attack and the CVE-2013-3163 attack both leveraged a Flash file that orchestrated the exploit, and would call back into IE JavaScript to trigger an IE flaw. The code within the Flash files from each attack are extremely similar. They build ROP chains and shellcode the same way, both choose to corrupt a Flash Vector object, have some identical functions with common typos, and even share the same name.
    '''

    ag = parse_attackgraph_from_text(ner_model, sample)
    draw_attackgraph_dot(ag.attackgraph_nx).view()
    nx.write_gml(ag.attackgraph_nx, "G.gml")


    # %%

    # ag = parse_attackgraph_from_cti_report(ner_model, r"data/picked_html_APTs/Log4Shell.html")
    # draw_attackgraph_dot(ag.attackgraph_nx).view()
    # nx.write_gml(ag.attackgraph_nx, "x.gml")

    # %%
    # class AttackGraph unit test

    # cti_path = r"./data/cti/picked_html"
    # output_path = r"./data/picked_extracted_attackgraph_20210820/"
    #
    # cti_files = os.listdir(cti_path)
    # for file in cti_files:
    #     parse_attackgraph_from_cti_report(cti_file=os.path.join(cti_path, file), output_path=output_path, ner_model=ner_model)

    # %%
    # draw_AG() unit test

    # techniques = {
    #     "Scripting": ['script@ExeFile'],
    #     "Scripting": ['PowerShell@ExeFile'],
    #     "Phishing E-mails": ['actors@APTFamily', 'documents@DocumentFile', 'email@NetLoc']
    # }
    #
    # dot = AttacKG_AG.draw_AG(G, clusters=techniques)
    # dot.view()

    # %%
    # construct_AG_from_spacydoc() unit

    # sample = "APT12 has sent emails with malicious Microsoft Office documents and PDFs attached."
    # sample = "APT3 has used PowerShell on victim systems to download and run payloads after exploitation."
    # sample = "Sandworm Team has delivered malicious Microsoft Office attachments via spearphishing."
    # sample = "Windshift has sent spearphishing emails with attachment to harvest credentials and deliver malware."
    #
    # doc = ner_model.parser(sample)
    # G = ag.construct_AG_from_spacydoc(doc)
