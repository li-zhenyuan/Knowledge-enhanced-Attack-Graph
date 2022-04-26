# References:
# https://towardsdatascience.com/custom-named-entity-recognition-using-spacy-7140ebbb3718
# https://spacy.io/usage/training#api

import spacy
from spacy import displacy
from spacy.training import Example
# import neuralcoref
import random
import json
import logging
import coreferee
import os


# ner_labels = ["NetLoc", "APTFamily", "ExeFile", "ScriptsFile", "DocumentFile", "E-mail", "Registry", "File", "Vulnerability", "C2C", "SensInfo", "Service"]
# ner_labels = ["FilePath", "NetLoc", "FileName", "Vulnerability", "Registry", "Attacker", "ExeFile", "DocFIle","Service"]
# ner_labels = ["actor", "network", "executable", "file", "defender", "registry", "vulnerability", "system"]
ner_labels = ["actor", "network", "executable", "file", "defender", "registry", "vulnerability", "system", "service"]


def read_labeled_data(path: str) -> list:
    labeled_data_path = path
    labeled_data = []
    with open(labeled_data_path, "r") as read_file:
        for line in read_file:
            data = json.loads(line)
            labeled_data.append(data)

    logging.info('---Read Labeled Data(%d)!---' % len(labeled_data))
    return labeled_data


class IoCNer:
    model_location = None

    nlp = None
    optimizer = None

    def __init__(self, model_location=None):
        self.model_location = model_location

        if self.model_location is None:
            self.nlp = spacy.blank('en')
            logging.info("---Created Blank 'en' Model!---")
        else:
            self.nlp = spacy.load(self.model_location)
            logging.info("---Load Model: %s!---" % self.model_location)

        # self.nlp.max_length = 3000000
        self.create_optimizer()

    def convert_data_format(self, labeled_data: list) -> list:
        # Data format converting
        spacy_data = []
        for entry in labeled_data:
            entities = []
            for e in entry['label']:
                entities.append((e[0], e[1], e[2]))
            try:
                spacy_data.append(Example.from_dict(self.nlp.make_doc(entry['data']), {"entities": entities}))
            except:
                logging.warning("Wrong format: %s!" % entry['data'])
        return spacy_data

    def create_optimizer(self):
        if 'ner' not in self.nlp.pipe_names:
            ner = self.nlp.add_pipe("ner")
        else:
            ner = self.nlp.get_pipe("ner")
        logging.info("---Add Pipe 'ner'!---")

        for label in ner_labels:
            ner.add_label(label)

        if self.model_location is None:
            self.optimizer = self.nlp.begin_training()
        else:
            self.optimizer = ner.create_optimizer()
        logging.info("---Created Optimizer!---")

    def train_model(self, spacy_data: list, new_model_location="./new_cti.model"):
        logging.info("---Start Training!---")

        # Loop
        # other_pipes = ["tagger", "parser", "attribute_ruler", "lemmatizer"]
        # other_pipes = [pipe for pipe in self.nlp.pipe_names if pipe != 'ner']
        other_pipes = []

        # https://towardsdatascience.com/how-to-fine-tune-bert-transformer-with-spacy-3-6a90bfe57647
        # https://spacy.io/usage/training
        with self.nlp.disable_pipes(*other_pipes):
            for itn in range(4):
                random.shuffle(spacy_data)
                losses = ()

                # Batch the examples
                for batch in spacy.util.minibatch(spacy_data, size=2):
                    # Update the model
                    self.nlp.update(batch, sgd=self.optimizer)  # , drop=0.35, losses=losses
                    # print('Losses', losses)

        self.nlp.to_disk(new_model_location)
        logging.info("---Save Model to %s!---" % new_model_location)

    def test_model(self,
                   sample: str = "APT3 has used PowerShell on victim systems to download and run payloads after exploitation."):
        # nlp = spacy.load(new_model_location)
        doc = self.nlp(sample)
        displacy.render(doc, style='ent')

    # https://stackoverflow.com/questions/57667710/using-regex-for-phrase-pattern-in-entityruler
    # https://python.plainenglish.io/a-closer-look-at-entityruler-in-spacy-rule-based-matching-44d01c43fb6
    patterns = [
        {"label": "actor", "pattern": [{"TEXT": {"REGEX": "APT[A-Za-z0-9-]+"}}]},
        {"label": "actor", "pattern": [{"TEXT": {"REGEX": "(T|t)eam"}}]},
        {"label": "actor", "pattern": [{"TEXT": {"REGEX": "(A|a)ctor[s]*"}}]},
        {"label": "actor", "pattern": [{"TEXT": {"REGEX": "(A|a)ttacker[s]*"}}]},

        {"label": "executable", "pattern": [{"TEXT": {"REGEX": "(P|p)ayload[s]*"}}]},
        {"label": "executable", "pattern": [{"TEXT": {"REGEX": "(S|s)cript[s]*"}}]},
        {"label": "executable", "pattern": [{"TEXT": {"REGEX": "(C|c)ommand[s]*"}}]},
        {"label": "executable", "pattern": [{"TEXT": {"REGEX": "(M|m)alware"}}]},
        {"label": "executable", "pattern": [{"TEXT": {"REGEX": "(S|s)tager"}}]},
        {"label": "executable", "pattern": [{"TEXT": {"REGEX": "(E|e)xecutable"}}]},
        {"label": "executable", "pattern": [{"TEXT": {"REGEX": "(F|f)irefox"}}]},
        {"label": "executable", "pattern": [{"TEXT": {"REGEX": "(M|m)odule"}}]},
        {"label": "executable", "pattern": [{"TEXT": {"REGEX": "SSH"}}]},
        {"label": "executable", "pattern": [{"TEXT": {"REGEX": "SCP"}}]},

        {"label": "file", "pattern": [{"TEXT": {"REGEX": "(D|d)ocument[s]*"}}]},
        {"label": "file", "pattern": [{"TEXT": {"REGEX": "(C|c)redential[s]*"}}]},
        {"label": "file", "pattern": [{"TEXT": {"REGEX": "(A|a)ttachment[s]*"}}]},
        {"label": "file", "pattern": [{"TEXT": {"REGEX": "(F|f)ile[s]*"}}]},

        {"label": "file", "pattern": [{"TEXT": {"REGEX": "(F|f)ile[s]*"}}]},
        {"label": "file", "pattern": [{"TEXT": {"REGEX": "(P|p)ath"}}]},

        {"label": "network", "pattern": [{"TEXT": {"REGEX": "(E|e)[-]*mail[s]*"}}]},
        {"label": "network", "pattern": [{"TEXT": {"REGEX": "(N|n)etwork"}}]},
        {"label": "network", "pattern": [{"TEXT": {"REGEX": "DNS"}}]},
        {"label": "network", "pattern": [{"TEXT": {"REGEX": "C2"}}]},
        {"label": "network", "pattern": [{"TEXT": {"REGEX": "C&C"}}]},

        {"label": "system", "pattern": [{"TEXT": {"REGEX": "(T|t)ask[s]*"}}]},
        {"label": "system", "pattern": [{"TEXT": {"REGEX": "(D|d)river"}}]},
        {"label": "system", "pattern": [{"TEXT": {"REGEX": "passwd"}}]},
        {"label": "system", "pattern": [{"TEXT": {"REGEX": "(S|s)ystem"}}]},
        {"label": "system", "pattern": [{"TEXT": {"REGEX": "(S|s)ervice "}}]},
        {"label": "system", "pattern": [{"TEXT": {"REGEX": "(C|c)redential[s]* "}}]},

        {"label": "vulnerability", "pattern": [{"TEXT": {"REGEX": "(E|e)xploit"}}]},

        {"label": "registry", "pattern": [{"TEXT": {"REGEX": "(R|r)egistry"}}]}
    ]

    config = {
        "phrase_matcher_attr": None,
        "validate": True,
        "overwrite_ents": False,
        "ent_id_sep": "||",
    }

    def ner_with_regex(self):
        logging.info("---Add Regex-based NER Pipe!---")

        ruler = self.nlp.add_pipe("entity_ruler", config=self.config, before="ner")
        ruler.add_patterns(self.patterns)

        # doc = self.nlp("APT3 has used PowerShell on victim systems to download and run payloads after exploitation.")
        # print([(ent.text, ent.label_) for ent in doc.ents])

    def add_coreference(self):
        self.nlp.add_pipe('coreferee')

    def parser(self, text: str, model_location="./new_cti.model"):
        logging.info("---S1-1: Parse clean text to NLP doc!---")
        self.nlp = spacy.load(model_location)
        self.ner_with_regex()
        self.add_coreference()

        nlp_doc = self.nlp(text)
        return nlp_doc


# %%

if __name__ == '__main__':

    # %%
    # model training flow

    ner_model = IoCNer("en_core_web_sm")
    # ner_model = IoCNer("en_core_web_trf")

    labeled_data = read_labeled_data(r".\NLP\Doccano\20210813.jsonl")
    spacy_data = ner_model.convert_data_format(labeled_data)
    ner_model.train_model(spacy_data)

    # %%
    # model testing flow

    # https://zhuanlan.zhihu.com/p/158474472
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

    ner_model = IoCNer("./new_cti.model")
    # ner_model = IoCNer("en_core_web_trf")

    sample = "APT3 has used PowerShell on victim systems to download and run payloads after exploitation."
    sample = "Wizard Spider has used spearphishing attachments to deliver Microsoft documents containing macros or PDFs containing malicious links to download either Emotet, Bokbot, TrickBot, or Bazar."
    sample = "Elderwood has delivered zero-day exploits and malware to victims via targeted emails containing a link to malicious content hosted on an uncommon Web server."
    sample = "APT28 sent spearphishing emails which used a URL-shortener service to masquerade as a legitimate service and to redirect targets to credential harvesting sites."
    sample = "Magic Hound sent shortened URL links over email to victims. The URLs linked to Word documents with malicious macros that execute PowerShells scripts to download Pupy."
    sample = "DarkHydrus has sent spearphishing emails with password-protected RAR archives containing malicious Excel Web Query files (.iqy). The group has also sent spearphishing emails that contained malicious Microsoft Office documents that use the 'attachedTemplate' technique to load a template from a remote server."
    sample = "Cardinal RAT establishes Persistence by setting the  HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load Registry key to point to its executable."

    doc = ner_model.nlp(sample)
    print([(ent.text, ent.label_) for ent in doc.ents])

    ner_model.ner_with_regex()
    doc = ner_model.nlp(sample)
    print([(ent.text, ent.label_) for ent in doc.ents])

    sample = "Although he was very busy with his work, Peter had had enough of it. He and his wife decided they needed a holiday. They travelled to Spain because they loved the country very much."

    ner_model.add_coreference()
    doc = ner_model.nlp(sample)
    doc._.coref_chains.print()
