import math
import Levenshtein
import graphviz
import networkx as nx
from nltk import Tree
import matplotlib.pyplot as plt
from pathlib import Path
import time
import spacy.tokens

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

    node_pos: int
    position: int

    def __init__(self, id: str, type: str, ioc: str = "", nlp: str = ""):
        self.id = id
        self.type = type
        self.ioc = ioc
        self.nlp = nlp

    def __str__(self):
        return f"Node #{self.id}: [type: '{self.type}', ioc: '{self.ioc}', nlp: '{self.nlp}']"


# return token unique id for nx.graph
def get_token_id(tok: spacy.tokens.token.Token) -> str:
    return "_".join([tok.lower_, tok.ent_type_, str(tok.i)])


class AttackGraph:
    attackgraph_nx: nx.DiGraph
    original_attackgraph_nx: nx.DiGraph

    nlp_doc: spacy.tokens.doc.Doc
    ioc_identifier: IoCIdentifier

    attackNode_dict: Dict[str, AttackGraphNode]
    attackDependecy_list: list

    ioc_coref_list: list
    ioc_coref_dict: dict

    entity_root_token_string_dict: dict
    entity_ignore_token_list: list

    techniques: Dict[str, list]  # technique name -> [node_list]

    def __init__(self, doc, ioc_identifier=None):
        self.attackgraph_nx = nx.DiGraph
        self.original_attackgraph_nx = nx.DiGraph

        self.nlp_doc = doc
        self.ioc_identifier = ioc_identifier

        self.attackNode_dict = {}
        self.attackDependecy_list = []

        self.ioc_coref_list = []
        self.ioc_coref_dict = {}

        self.entity_root_token_string_dict = {}
        self.entity_ignore_token_list = []

        self.techniques = {}

    def generate(self):
        logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph!---")

        self.parse_coref()
        self.parse_node()
        self.parse_edge()

        self.node_merge()
        self.simplify()
        self.clear_contraction_info()

    def parse_coref(self):
        logging.info("---attack graph generation: Parsing NLP doc to get Co-reference!---")

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
        logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph nodes!---")

        # parsing all ioc nodes
        for entity in self.nlp_doc.ents:
            ent_root = entity.root
            ent_root_i = ent_root.i
            self.entity_root_token_string_dict[ent_root_i] = entity.report_text
            for token in entity:
                if token.i not in self.entity_root_token_string_dict.keys():
                    ignore_token_i = token.i
                    self.entity_ignore_token_list.append(ignore_token_i)

    def parse_edge(self):
        logging.info("---attack graph generation: Parsing NLP doc to get Attack Graph Edges!---")

        for sentence in self.nlp_doc.sents:
            self.parse_edge_sentence(sentence)

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
                if coref_node.i in self.entity_root_token_string_dict.keys():
                    nlp = self.entity_root_token_string_dict[coref_node.i]
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


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    # logging.basicConfig(filename="running_time_log.txt", filemode='a', level=logging.DEBUG)
    logging.info("======techniqueIdentifier.py: %s======", time.asctime(time.localtime(time.time())))

    ner_model = IoCNer("./new_cti.model")
    ner_model.add_coreference()

    # sample = "APT3 has used PowerShell on victim systems to download and run payloads after exploitation."
    # sample = "Wizard Spider has used spearphishing attachments to deliver Microsoft documents containing macros or PDFs containing malicious links to download either Emotet, Bokbot, TrickBot, or Bazar."
    # sample = "Elderwood has delivered zero-day exploits and malware to victims via targeted emails containing a link to malicious content hosted on an uncommon Web server."
    # sample = "APT28 sent spearphishing emails which used a URL-shortener service to masquerade as a legitimate service and to redirect targets to credential harvesting sites."
    # sample = "Magic Hound sent shortened URL links over email to victims. The URLs linked to Word documents with malicious macros that execute PowerShells scripts to download Pupy."
    # sample = "DarkHydrus has sent spearphishing emails with password-protected RAR archives containing malicious Excel Web Query files (.iqy). The group has also sent spearphishing emails that contained malicious Microsoft Office documents that use the 'attachedTemplate' technique to load a template from a remote server."
    # sample = "Cardinal RAT establishes Persistence by setting the  HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load Registry key to point to its executable."
    # sample = "The \"SCOUT\" variant of NETEAGLE achieves persistence by adding itself to the HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run Registry key."
    # sample = "Cobalt Group has sent spearphishing emails with various attachment types to corporate and personal email accounts of victim organizations. Attachment types have included .rtf, .doc, .xls, archives containing LNK files, and password protected archives containing .exe and .scr executables"
    # sample = "The threat actors sent the trojanized Microsoft Word documents, probably via email. Talos discovered a document named  MinutesofMeeting-2May19.docx, that appeared to display the national flag of Jordan. Once the victim opens the document, it fetches a remove template from the actor-controlled website, hxxp://droobox[.]online:80/luncher.doc. Once the luncher.doc was downloaded, it used CVE-2017-11882, to execute code on the victim's machine. After the exploit, the file would write a series of base64-encoded PowerShell commands that acted as a stager and set up persistence by adding it to the HKCU\Software\Microsoft\Windows\CurrentVersion\Run Registry key. That scheduled task would run a series of base64-encoded PowerShell commands that acted as a stager."
    # sample = "The attacker ran an attack against ClearScope. The attacker found the e-mail address of the phone user, bob@bovia.com, previously from a data dump from a hacked website. The attacker sent a phishing e-mail to Bob impersonating the Bovia Company Benefits Open Enrollment group. The phishing e-mail included a link to a website hosted at www.nasa.ng, address 208.75.117.3:80. The website hosted a form asking for name, e-mail address, and password. The user unfortunately clicked on the link, entered the requested information, and submitted it. The results were sent back to www.foo1.com, address 208.75.117.2:80. The attacker now has access to Bob's e-mail account, including contact information for other Bovia company employees."
    # sample = "The TA1 Five Directions attack consisted of the host browsing to the malicious website http://215.237.119.171/config.html where a malicious dll named dbgstat.dll is downloaded.  The delivery method of the attack is the Application Verifier which is used to inject the Drakon APT into the Firefox process.  This attack utilizes the debugging capability built into Windows used to allow developers to debug memory allocations and runtime resouces.  Once the APT DLL has been loaded into Firefox, it connects back to C2.  This remains persistent and a connection to C2 is established each time Firefox is launched. In this attack the user relaunches Firefox four times and at callback gethostname, getusername, and getprocesslist calls are made from the C2."
    # sample = r"Tried multiple times to exploit the browser and use BITS to download and run the verifier executable.  This was done by browsing to http://215.237.119.171/config.html.  At this point, Firefox should have connected out to 68.149.51.179 to download and execute dbgstat.dll and tester.exe.  We think the files were downloaded but not executed, although we could find no instance of the files on disk where we would expect them.  Instead, we scp’ed the files to the target and ran them using an Administrator command prompt.  Tester.exe (verifier) opened dbgstat.dll (drakon.dll) and registered it as a verifier DLL for Firefox in the Windows registry.  The result is that every time a new Firefox process is started, drakon.dll is injected into it automatically and executed.  We configured the OC2 to automatically run the same script each time a new connection was received, including hostname, whoami, and ps.  We left the drakon.dll verifier enabled throughout the remaining engagement, resulting in 126 drakon instances and C2 connections."

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
        the C2 would return a string of characters. Once the string was RC4 decrypted, it launched a PowerShell Empire agent. The PowerShell script would attempt to enumerate the host to look for certain information. Once the aforementioned information was obtained, it was sent back to the threat actor's C2.'''
    sample = '''
        All observed attacks start with an email message, containing either a malicious attachment or a URL which leads to the first stage of the attack. The text of the emails is likely taken from legitimate email, such as mailing lists that targeted organizations may be subscribed to. Below are three examples, with the first one purporting to be sent by the European Banking Federation and is using a newly registered domain for the spoofed sender email address. The attachment is a malicious PDF file that entices the user to click on a URL to download and open a weaponized RTF file containing exploits for CVE-2017-11882, CVE-2017-8570 and CVE-2018-8174. The final payload is a JScript backdoor also known as More_eggs that allows the attacker to control the affected system remotely.
        Notable applications used in these attacks are cmstp and msxsl. The Microsoft Connection Manager Profile Installer (cmstp.exe) is a command-line program used to install Connection Manager service profiles. Cmstp accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections. A malicious INF file can be supplied as a parameter to download and execute remote code. Cmstp may also be used to load and execute COM scriptlets (SCT files) from remote servers.
        Microsoft allows developers to create COM+ objects in script code stored in an XML document, a so-called scriptlet file. Although it is common to use JScript or VBScript, as they are available in Windows by default, a scriptlet can contain COM+ objects implemented in other languages, including Perl and Python, which would be fully functional if the respective interpreters are installed.
        To bypass AppLocker and launching script code within a scriptlet, the attacker includes the malicious code within an XML script tag placed within the registration tag of the scriptlet file and calls cmstp with appropriate parameters.
        An earlier part of the second stage is implemented as an encrypted JScript scriptlet which eventually drops a randomly named COM server DLL binary with a .txt filename extension, for example, 9242.txt, in the user's home folder and registers the server using the regsvr32.exe utility.The dropper contains an encrypted data blob that is decrypted and written to the disk. The dropper then launches the next stage of the attack by starting PowerShell, msxsl or cmstp.exe as described above.
        The PowerShell chain is launched from an obfuscated JScript scriptlet previously downloaded from the command and control (C2) server and launched using cmstp.exe. The first PowerShell stage is a simple downloader that downloads the next PowerShell stage and launches a child instance of powershell.exe using the downloaded, randomly named script as the argument. The downloaded PowerShell script code is obfuscated in several layers before the last layer is reached. The last layer loads shellcode into memory and creates a thread within the PowerShell interpreter process space.
        On the PowerShell side of the infection chain, the downloaded final payload is a Cobalt Strike beacon, which provides the attacker with rich backdoor functionality.
    '''

    # ag = parse_attackgraph_from_text(ner_model, sample)
    # draw_attackgraph_dot(ag.attackgraph_nx).view()
    # nx.write_gml(ag.attackgraph_nx, "x.gml")


    # %%

    # ag = parse_attackgraph_from_cti_report(ner_model, r"data/picked_html_APTs/OceanLotus.html")

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
