import argparse
import logging
import sys
sys.path.extend([".", "technique_knowledge_graph"])

import os
import networkx as nx

from typing import Tuple
from typing import List
from spacy.tokens import Doc

from mitre_ttps.mitreGraphReader import MitreGraphReader, picked_techniques
from preprocess.report_preprocess import preprocess_file, clear_text
from report_parser.ioc_protection import IoCIdentifier
from report_parser.report_parser import parsingModel_training, IoCNer
from technique_knowledge_graph.attack_graph import AttackGraph
from technique_knowledge_graph.technique_identifier import TechniqueIdentifier, AttackMatcher
from technique_knowledge_graph.technique_template import TechniqueTemplate

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'


def ioc_protection(text: str) -> IoCIdentifier:
    iid = IoCIdentifier(text)
    iid.ioc_protect()
    # iid.check_replace_result()
    return iid


def report_parsing(text: str) -> Tuple[IoCIdentifier, Doc]:
    iid = ioc_protection(text)
    text_without_ioc = iid.replaced_text

    ner_model = IoCNer("./new_cti.model")
    doc = ner_model.parse(text_without_ioc)

    return iid, doc


def attackGraph_generating(text: str, output: str = None) -> AttackGraph:
    iid, doc = report_parsing(text)

    ag = AttackGraph(doc, ioc_identifier=iid)
    if output is not None:
        ag.draw(output)

    return ag


def techniqueTemplate_generating(output_path: str = None, technique_list: List[str] = None) -> List[TechniqueTemplate]:
    template_list = []

    mgr = MitreGraphReader()
    super_sub_dict = mgr.get_super_sub_technique_dict()
    for super_technique, sub_technique_list in super_sub_dict.items():
        if technique_list is not None and super_technique[12:18] not in technique_list:
            continue

        sample_list = []
        for sub_technique in sub_technique_list:
            sample_list += mgr.find_examples_for_technique(sub_technique)
        techniqueTemplate_generating_perTech(super_technique[12:18], sample_list, output_path)

    return template_list


def techniqueTemplate_generating_perTech(technique_name: str, techniqueSample_list: List[str], output_path: str = None) -> TechniqueTemplate:
    technique_template = TechniqueTemplate(technique_name)

    for sample in techniqueSample_list:
        sample_graph = attackGraph_generating(sample)
        technique_template.update_template(sample_graph)

    if output_path is not None:
        logging.warning(f"---technique template: Saving to {output_path}/{technique_name}!---")
        technique_template.pretty_print(f"{output_path}/{technique_name}.png")
        technique_template.dump_to_file(f"{output_path}/{technique_name}")

    return technique_template


def load_techniqueTemplate_fromFils(templatePath: str) -> List[TechniqueTemplate]:
    template_file_list = os.listdir(templatePath)
    template_list = []

    for template_file in template_file_list:
        technique_name, ext = os.path.splitext(template_file)
        if ext != ".json":
            continue

        template = TechniqueTemplate(technique_name)
        template.load_from_file(os.path.join(templatePath, template_file))
        template_list.append(template)

    return template_list


def technique_identifying(text: str, technique_list: List[str], template_path: str) -> AttackMatcher:
    ag = attackGraph_generating(text)
    if template_path == "":
        tt_list = techniqueTemplate_generating(technique_list=technique_list)
    else:
        tt_list = load_techniqueTemplate_fromFils(template_path)

    attackMatcher = technique_identifying_forAttackGraph(ag, tt_list)
    return attackMatcher


def technique_identifying_forAttackGraph(graph: AttackGraph, template_list: List[TechniqueTemplate]) -> AttackMatcher:
    attackMatcher = AttackMatcher(graph)
    for template in template_list:
        attackMatcher.add_technique_identifier(TechniqueIdentifier(template))
    attackMatcher.attack_matching()
    attackMatcher.print_match_result()

    return attackMatcher


attack_graph = None
attack_matcher = None

if __name__ == '__main__':
    # logging.basicConfig(stream=sys.stdout, level=logging.WARNING)

    parser = argparse.ArgumentParser()

    # Examples:
    # python main.py -M iocProtection -R ./data/cti/html/003495c4cb6041c52db4b9f7ead95f05.html
    # python main.py -M reportParsing -C "Cardinal RAT establishes Persistence by setting the  HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load Registry key to point to its executable."
    # python main.py -M attackGraphGeneration -C "Cardinal RAT establishes Persistence by setting the  HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load Registry key to point to its executable."
    # python main.py -M techniqueTemplateGeneration
    # python main.py -M attackGraphGeneration -R "C:\Users\workshop\Documents\GitHub\AttacKG\data\picked_html_APTs\Log4Shell.html" -O ./output.pdf
    # python main.py -M techniqueTemplateGeneration -O C:/Users/workshop/Documents/GitHub/Knowledge-enhanced-Attack-Graph/templates
    # python main.py -M techniqueIdentification -T C:/Users/workshop/Documents/GitHub/Knowledge-enhanced-Attack-Graph/templates -R "C:\Users\workshop\Documents\GitHub\AttacKG\data\picked_html_APTs\Log4Shell.html" -O ./output.pdf
    parser.add_argument('-M', '--mode', required=True, type=str, default="", help="The running mode options: 'iocProtection', 'nlpModelTraining', 'reportParsing', 'attackGraphGeneration', 'techniqueTemplateGeneration', 'techniqueIdentification")
    parser.add_argument('-L', '--logPath', required=False, type=str, default="", help="Log file's path.")
    parser.add_argument('-C', '--ctiText', required=False, type=str, default="", help="Target CTI text.")
    parser.add_argument('-R', '--reportPath', required=False, type=str, default="../AttacKG/data/cti/html/003495c4cb6041c52db4b9f7ead95f05.html", help="Target report's path.")
    parser.add_argument('-T', '--templatePath', required=False, type=str, default="", help="Technique template's path.")
    parser.add_argument('-O', '--outputPath', required=False, type=str, default="", help="Output file's path.")
    parser.add_argument('--trainingSetPath', required=False, type=str, default="../AttacKG/NLP/Doccano/20210813.jsonl", help="NLP model training dataset's path.")
    parser.add_argument('--nlpModelPath', required=False, type=str, default="../AttacKG/new_cti.model", help="NLP model's path.")

    arguments = parser.parse_args(sys.argv[1:])

    log_path = arguments.logPath
    log_level = logging.DEBUG
    if log_path == "":
        logging.basicConfig(stream=sys.stdout, level=log_level)
    else:
        logging.basicConfig(filename=log_path, filemode='a', level=log_level)

    logging.info(f"---Running arguments: {arguments}!---")

    cti_text = arguments.ctiText
    report_path = arguments.reportPath
    report_text = clear_text(cti_text) if len(cti_text) != 0 else preprocess_file(report_path)

    running_mode = arguments.mode
    print(f"Running mode: {running_mode}")
    if running_mode == "iocProtection":
        ioc_identifier = ioc_protection(report_text)
    elif running_mode == "nlpModelTraining":
        trainingSet_path = arguments.trainingSetPath
        parsingModel_training(trainingSet_path)
    elif running_mode == "reportParsing":
        cti_doc = report_parsing(report_text)
    elif running_mode == "attackGraphGeneration":
        attack_graph = attackGraph_generating(report_text, arguments.outputPath)
    elif running_mode == "techniqueTemplateGeneration":
        techniqueTemplate_generating(output_path=arguments.outputPath)
    elif running_mode == "techniqueIdentification":
        attack_matcher = technique_identifying(report_text, picked_techniques, arguments.templatePath)
    else:
        print("Unknown running mode!")

    logging.info(f"---Done!---")
