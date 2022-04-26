import itertools

from attackTemplate import *

import networkx as nx
import logging
import time
import math
import os
import xlsxwriter
import eventlet


# Record TechniqueTemplate Matching Record
class TechniqueIdentifier:
    technique_template: TechniqueTemplate

    node_match_record: dict
    edge_match_record: dict
    node_count: int
    edge_count: int

    def __init__(self, technique_template: TechniqueTemplate):
        self.technique_template = technique_template
        logging.info("---S3.1: Init technique template %s as identifier!---" % technique_template.technique_name)

        self.init_node_match_record()
        self.init_edge_match_record()

    def init_node_match_record(self):
        self.node_match_record = {}

        index = 0
        for technique_node in self.technique_template.technique_node_list:
            self.node_match_record[index] = None
            index += 1

        self.node_count = len(self.technique_template.technique_node_list)

    def init_edge_match_record(self):
        self.edge_match_record = {}

        index = 0
        for technique_edge in self.technique_template.technique_edge_dict.keys():
            self.edge_match_record[technique_edge] = None
            index += 1

        self.edge_count = len(self.technique_template.technique_edge_dict.keys())

    def node_alignment(self, node: str, nx_graph: nx.DiGraph):
        # self.init_node_match_record()

        index = 0
        for technique_node in self.technique_template.technique_node_list:
            node_similarity_score = technique_node.get_similar_with(parse_networkx_node(node, nx_graph))

            if technique_node.instance_count == 0:
                index += 1
                continue

            # accept node as a match
            if node_similarity_score >= TechniqueTemplate.NODE_SIMILAR_ACCEPT_THRESHOLD:
                if self.node_match_record[index] is None:
                    self.node_match_record[index] = []
                self.node_match_record[index].append((node, node_similarity_score))
                # if self.node_match_record[index] is not None and self.node_match_record[index][1] > node_similarity_score:
                #     continue
                # else:
                #     self.node_match_record[index] = (node, node_similarity_score)

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
        # return self.get_node_alignment_score()
        # return self.get_edge_alignment_score()

    def get_node_alignment_score(self):
        node_alignment_score = 0.0

        if self.node_match_record is None:
            return 0
        index = 0
        for node_index, node_similarity in self.node_match_record.items():
            if self.technique_template.technique_node_list[node_index].node_type == "actor":
                continue

            if node_similarity is not None:
                node_alignment_score += node_similarity[1] * (self.technique_template.technique_node_list[node_index].instance_count) # math.sqrt
                # logging.debug("%d-%s-%f" % (index, node_similarity[0], node_alignment_score))

            index += 1

        # Normalization
        # node_alignment_score /= self.node_count + 1  # math.sqrt(self.node_count + 1)
        node_alignment_score /= (self.technique_template.node_normalization + 1)
        return node_alignment_score

    def get_edge_alignment_score(self):
        edge_alignment_score = 0.0

        for edge, edge_similarity in self.edge_match_record.items():
            edge_alignment_score += edge_similarity * (self.technique_template.technique_edge_dict[edge])

        # edge_alignment_score /= self.edge_count + 1
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

        # for technique, score in self.technique_matching_score.items():
        #     print(technique + str(score))
        #     for result in self.technique_matching_record[technique]:
        #

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


# %%

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    # logging.basicConfig(filename="running_time_log.txt", filemode='a', level=logging.INFO)
    logging.info("======techniqueIdentifier.py: %s======", time.asctime(time.localtime(time.time())))

    # %%

    # tt_file = r".\data\technique_template\'_techniques_T1059_001'.json"
    # technique_list = [r'/techniques/T1566/001', r'/techniques/T1566/002', r'/techniques/T1566/003']
    # tt = TechniqueTemplate(str(technique_list))
    # tt.load_from_file(tt_file)
    # ti = TechniqueIdentifier(tt)
    #
    # attack_graph_file = r".\data\\extracted_attackgraph_20210804\0a84e7a880901bd265439bd57da61c5d.gml"
    # attack_graph_nx = nx.read_gml(attack_graph_file)
    # am = AttackMatcher(attack_graph_nx)
    #
    # am.add_technique_identifier(ti)
    # am.attack_matching()

    # %%

    tt_path = r"./data/technique_template"
    tt_file_list = os.listdir(tt_path)
    identifier_list = []
    technique_list = []
    for tt_file in tt_file_list:
        filename, ext = os.path.splitext(tt_file)
        if ext != ".json":
            continue
        tt = TechniqueTemplate(filename)
        tt.load_from_file(os.path.join(tt_path, tt_file))
        ti = TechniqueIdentifier(tt)

        if ti.edge_count == 0:
            continue

        technique_list.append(filename)
        identifier_list.append(ti)

    xe = Evaluation()
    xe.add_technique_list(technique_list)

    # %%

    # Firefox DNS Drakon APT
    # sample = "The attack started by browsing to http://128.55.12.167:8641/config.html, selecting DNS, entering hostname Xx--ls8h.com, file 938527054, and clicking the Visit button.  This triggered the Firefox backdoor to connect out via DNS to XX--ls8h.com.  Drakon APT was downloaded and executed and connected to 128.55.12.167:8640 for C2.  The attacker escalated privileges using the new File System Filter Driver, which looks for processes opening specific files which don’t exist and elevates them.  Once SYSTEM, the attacker exfil’ed the host and network files as well as a passwd file in the home directory."

    # Firefox Drakon APT Elevate Copykatz
    # sample = '''
    #     First attacked ta51-pivot-2 and deployed OC2, allowing us to run our attack from within the target network.  Exploited Firefox backdoor by again browsing to http://128.55.12.233.  Loader Drakon was executed in Firefox memory and connected out to 128.55.12.233:8000 and 128.55.12.233:443 for C2.  After the BBN reboot, driver was disabled, and we would now be able to use privilege escalation via our perfmon driver.  We loaded the copykatz module to recon data from the system.
    # '''

    # Firefox BITS Micro APT
    # sample = '''
    #     Benign activity ran for most of the morning while the tools were being setup for the day.  The activity was modified so the hosts would open Firefox and browse to http://215.237.119.171/config.html.  The simulated host then entered URL for BITS Micro APT as http://68.149.51.179/ctfhost2.exe.   We used the exploited Firefox backdoor to initiate download of ctfhost2.exe via the Background Intelligent Transfer Service (BITS).  Our server indicated the file was successfully downloaded using the BITS protocol, and soon after Micro APT was executed on the target and connected out to 113.165.213.253:80 for C2.  The attacker tried to elevate using a few different drivers, but it failed once again due to the computer having been restarted without disabling driver signature enforcement.  BBN tried using BCDedit to permanently disable driver signing, but it did not seem to work during the engagement as the drivers failed to work unless driver signing was explicitly disabled during boot.
    # '''

    # SSH BinFmt-Elevate
    # sample = '''
    #     Copied files via SCP and connected via SSH from the ta1-pivot-2 host.  Sent files to the target included the privilege escalation driver load_helper and an elevate client.  Connected to target using SSH with stolen credentials.  Loaded the driver, and used it to gain root privileges.  As root, exfil’d /etc/passwd, /etc/shadow, and the admin’s home directory Documents files.
    # '''

    # Nginx Drakon APT
    # sample = '''
    #     The attacker first tried to attack from an outside host, using 98.23.182.25:80 to download Drakon APT and 108.192.100.31:80 for C2.  That failed, though, so the attacker switched to ta1-pivot-2 for the attack C2.  The malformed HTTP POST was sent from 128.55.12.167 and resulted in C2 to 128.55.12.233:80.  The attacker then repeated the same attack against ta1-cadets-1, exfil’ing /etc/password from both hosts.  The connections were both left open for later.
    #     The CADETS hosts were both attacked in succession using the Nginx Drakon APT simulacrum.
    #     For the attack against CADETS the exploits Nginx by simulation of remote code execution on the listening port of the webserver TCP 80.  A malicious HTTP post is sent to 128.55.12.75:80 and 128.55.12.51:80 respectively.   The callback is established to C2 and the following commands are sent to gather intellignece on the host environment: hostname, whoami, cat /etc/passwd, whoami, and hostname.
    # '''

    # Frankenstein Campaign
    # sample = r'''
    #     The threat actors sent the trojanized Microsoft Word documents, probably via email. Talos discovered a document named  MinutesofMeeting-2May19.docx. Once the victim opens the document, it fetches a remove template from the actor-controlled website, hxxp://droobox[.]online:80/luncher.doc. Once the luncher.doc was downloaded, it used CVE-2017-11882, to execute code on the victim's machine. After the exploit, the file would write a series of base64-encoded PowerShell commands that acted as a stager and set up persistence by adding it to the HKCU\Software\Microsoft\Windows\CurrentVersion\Run Registry key.
    #     Once the evasion checks were complete, the threat actors used MSbuild to execute an actor-created file named "LOCALAPPDATA\Intel\instal.xml". Based on lexical analysis, we assess with high confidence that this component of the macro script was based on an open-source project called "MSBuild-inline-task." While this technique was previously documented last year, it has rarely been observed being used in operations. Talos suspects the adversary chose MSBuild because it is a signed Microsoft binary, meaning that it can bypass application whitelisting controls on the host when being used to execute arbitrary code.
    #     Once the "instal.xml" file began execution, it would deobfuscate the base64-encoded commands. This revealed a stager, or a small script designed to obtain an additional payload. While analyzing this stager, we noticed some similarities to the "Get-Data" function of the FruityC2 PowerShell agent. One notable difference is that this particular stager included functionality that allowed the stager to communicate with the command and control (C2) via an encrypted RC4 byte stream. In this sample, the threat actors' C2 server was the domain msdn[.]cloud.
    #     the C2 would return a string of characters. Once the string was RC4 decrypted, it launched a PowerShell Empire agent. The PowerShell script would attempt to enumerate the host to look for certain information. Once the aforementioned information was obtained, it was sent back to the threat actor's C2.
    #     '''

    # OceanLotus (APT32) Campaign
    # sample = '''
    #     The Adobe_Flash_install.rar archive that was returned from the baomoivietnam.com website contained the files Flash_Adobe_Install.exe and goopdate.dll. The table below provides some basic information on all three of these files.
    #     The file goopdate.dll has the hidden file attribute set and will not show in Windows Explorer on systems using default settings. This results in the user seeing only the Flash_Adobe_Install.exe file to execute in order to install what they believe to be an update to Flash Player. When run, it will automatically load goopdate.dll due to search order hijacking. Goopdate.dll is a highly obfuscated loader whose ultimate purpose is to load a Cobalt Strike stager into memory and then execute it. The Cobalt Strike stager will simply try to download and execute a shellcode from a remote server, in this case using the following URL: summerevent.webhop.net/QuUA
    # '''

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
    #
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

    # DeputyDog Campaign
    sample = '''
    On February 11, FireEye identified a zero-day exploit (CVE-2014-0322)  being served up from the U.S. Veterans of Foreign Wars’ website (vfw[.]org). After compromising the VFW website, the attackers added an iframe into the beginning of the website’s HTML code that loads the attacker’s page in the background. The attacker’s HTML/JavaScript page runs a Flash object, which orchestrates the remainder of the exploit. The exploit includes calling back to the IE 10 vulnerability trigger, which is embedded in the JavaScript.  Specifically, visitors to the VFW website were silently redirected through an iframe to the exploit at www.[REDACTED].com/Data/img/img.html. The attacker uses the Microsoft.XMLDOM ActiveX control to load a one-line XML string containing a file path to the EMET DLL. Then the exploit code parses the error resulting from the XML load order to determine whether the load failed because the EMET DLL is not present.  The exploit proceeds only if this check determines that the EMET DLL is not present. Once the attacker’s code has full memory access through the corrupted Flash Vector object, the code searches through loaded libraries gadgets by machine code. The attacker then overwrites the vftable pointer of a flash.Media.Sound() object in memory to point to the pivot and begin ROP. After successful exploitation, the code repairs the corrupted Flash Vector and flash.Media.Sound to continue execution. Subsequently, the malicious Flash code downloads a file containing the dropped malware payload. The beginning of the file is a JPG image; the end of the file (offset 36321) is the payload, encoded with an XOR key of 0x95. The attacker appends the payload to the shellcode before pivoting to code control. Then, when the shellcode is executed, the malware creates files “sqlrenew.txt” and “stream.exe”. The tail of the image file is decoded, and written to these files. “sqlrenew.txt” is then executed with the LoadLibraryA Windows API call. As documented above, this exploit dropped an XOR (0x95) payload that executed a ZxShell backdoor (MD5: 8455bbb9a210ce603a1b646b0d951bce). The compile date of the payload was 2014-02-11, and the last modified date of the exploit code was also 2014-02-11. This suggests that this instantiation of the exploit was very recent and was deployed for this specific strategic Web compromise of the Veterans of Foreign Wars website. A possible objective in the SnowMan attack is targeting military service members to steal military intelligence. In addition to retirees, active military personnel use the VFW website. It is probably no coincidence that Monday, Feb. 17, is a U.S. holiday, and much of the U.S. Capitol shut down Thursday amid a severe winter storm. The ZxShell backdoor is a widely used and publicly available tool used by multiple threat actors linked to cyber espionage operations. This particular variant called back to a command and control server located at newss[.]effers[.]com. This domain currently resolves to 118.99.60.142. The domain info[.]flnet[.]org also resolved to this IP address on 2014-02-12.
    '''

    ner_model = IoCNer("./new_cti.model")
    ner_model.add_coreference()
    ag = parse_attackgraph_from_text(ner_model, sample)
    # ag = parse_attackgraph_from_cti_report(ner_model, r"data/picked_html_APTs/Log4Shell.html")

    am = AttackMatcher(ag.attackgraph_nx)
    for ti in identifier_list:
        am.add_technique_identifier(ti)
    am.attack_matching()
    matching_result = am.print_match_result()

    clusters = {}
    for key in am.technique_matching_score.keys():
        if am.technique_matching_score[key] > 1.9:
            print(key)
            print(am.technique_matching_record[key])

            clusters_node_list = []
            for k, v in am.technique_matching_record[key].items():
                if v is not None:
                    clusters_node_list.append(v[0])

            clusters[key] = clusters_node_list

    draw_attackgraph_dot(ag.attackgraph_nx, clusters=clusters).view()

    # %%
    # count = 0
    #
    # eventlet.monkey_patch()
    # time_limit = 10
    #
    # for file in os.listdir(r"./data/cti/html"):
    #     file_name, ext = os.path.splitext(file)
    #     if ext != ".html":
    #         continue
    #
    #     count += 1
    #     if count <= 269:
    #         continue
    #
    #     print(file)
    #     print(count)
    #
    #     with eventlet.Timeout(time_limit, False):
    #         ner_model = IoCNer("./new_cti.model")
    #         ner_model.add_coreference()
    #
    #         ag = parse_attackgraph_from_cti_report(ner_model, r"./data/cti/html/" + file, r"./data/attack_graph")
    #         print(",".join([str(ag.attackgraph_nx.number_of_nodes()), str(ag.attackgraph_nx.number_of_edges())]))
    #         if ag.attackgraph_nx.number_of_nodes() >= 50:
    #             continue
    #         # if len(ag.attackgraph_nx.nodes()) >= 150:
    #         #     continue
    #
    #         am = AttackMatcher(ag.attackgraph_nx)
    #         for ti in identifier_list:
    #             am.add_technique_identifier(ti)
    #         am.attack_matching()
    #         matching_result = am.print_selected_techniques()
    #         print(matching_result)
    #
    #         with open('technique_ioc_identification_result.txt', 'a+') as output_file:
    #             print(str([ioc_item.ioc_type for ioc_item in ag.ioc_identifier.ioc_list]))
    #             output_file.write(",".join([str(ag.attackgraph_nx.number_of_nodes()), str(ag.attackgraph_nx.number_of_edges())]) + str([ioc_item.ioc_type for ioc_item in ag.ioc_identifier.ioc_list]) + '\n')
    #
    #         with open('technique_identification_result.txt', 'a+') as output_file:
    #             output_file.write(file_name + str(matching_result) + '\n')


    # %%

    # ===================Technique Identification in Reports=================================================
    # with open(r"report_picked_technique.json", "r") as output:
    #     data_json = output.read()
    #     report_technique_dict = json.loads(data_json)

    # am_list = []
    # for report, ground_truth in report_technique_dict.items():
    #     report_name, ext = os.path.splitext(report)
    #     report_graph_file = r"./data/picked_extracted_attackgraph_20210807/%s.gml" % report_name
    #     logging.info(report_graph_file)
    #
    #     try:
    #         report_graph_nx = nx.read_gml(report_graph_file)
    #     except:
    #         continue
    #     am = AttackMatcher(report_graph_nx)
    #     for ti in identifier_list:
    #         am.add_technique_identifier(ti)
    #     am.attack_matching()
    #     matching_result = am.print_match_result()
    #
    #     xe.add_result(report, matching_result, ground_truth)
    #     am_list.append(am)

    # ===================Technique Identification in Examples=================================================
    # for file in os.listdir(r"./data/procedure_examples"):
    #     file_name, ext = os.path.splitext(file)
    #     if ext != ".gml":
    #         continue
    #
    #     example_graph = nx.read_gml(r"./data/procedure_examples/" + file)
    #     # if len(example_graph.nodes()) <= 1:
    #     #     continue
    #
    #     am = AttackMatcher(example_graph)
    #     for ti in identifier_list:
    #         am.add_technique_identifier(ti)
    #     am.attack_matching()
    #     matching_result = am.print_match_result()
    #
    #     xe.add_result(file_name, matching_result, [])
    #
    # # xe.book.save()
    # xe.book.close()
