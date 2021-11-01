from typing import List, Dict, Tuple
import re
import json
import logging


class IoCItem:          # original IoC item     # replaced IoC item
    ioc_string: str     # original IoC string   # replaced IoC string
    ioc_type: str       # IoC type
    ioc_location: Tuple[int, int]  # original

    def __init__(self, ioc_string, ioc_type, start_pos, end_pos):
        self.ioc_string = ioc_string
        self.ioc_type = ioc_type
        self.ioc_location = (start_pos, end_pos)

    def __str__(self):
        return "%s - %s: %d, %d" % (self.ioc_string, self.ioc_type, self.ioc_location[0], self.ioc_location[1])


# For list sorting
def get_iocitem_key(item: IoCItem):
    return item.ioc_location[0]


class IoCIdentifier:
    # IoC pattern stored in json file: "./ioc_regexPattern.json" and "./ioc_replaceWord.json"
    # https://github.com/PaloAltoNetworks/ioc-parser/blob/master/patterns.ini
    ioc_regexPattern = {}
    ioc_replaceWord = {}

    report_text: str
    ioc_list: List[IoCItem]

    deleted_character_count: int
    replaced_text: str
    replaced_ioc_list: List[IoCItem]
    replaced_ioc_dict: Dict[int, str]

    def __init__(self, text: str = None):
        self.ioc_list = []

        self.replaced_text = ""
        self.replaced_ioc_list = []
        self.replaced_ioc_dict = {}
        self.deleted_character_count = 0

        self.load_ioc_pattern()
        self.report_text = text

    def load_ioc_pattern(self, ioc_regexPattern_path: str = "./ioc_regexPattern.json", ioc_replaceWord: str = "./ioc_replaceWord.json"):
        with open(ioc_regexPattern_path) as pattern_file:
            self.ioc_regexPattern = json.load(pattern_file)
        with open(ioc_replaceWord) as word_file:
            self.ioc_replaceWord = json.load(word_file)

    def ioc_protect(self) -> str:
        logging.info("---ioc protection: Identify and replace IoC items with regex in cti text!---")

        self.ioc_identify()
        self.ioc_replace()

        return self.replaced_text

    def ioc_identify(self, text: str = None):
        logging.info("---ioc protection: Identify IoC items with regex in cti text!---")
        self.report_text = text if text is not None else self.report_text

        # Find all IoC item in the text
        for ioc_type, regex_list in self.ioc_regexPattern.items():
            for regex in regex_list:
                matchs = re.finditer(regex, self.report_text)
                for m in matchs:
                    ioc_item = IoCItem(m.group(), ioc_type, m.span()[0], m.span()[1])
                    logging.debug("Find IoC matching: %s" % str(ioc_item))
                    self.ioc_list.append(ioc_item)

        self.ioc_overlap_remove()

    # check if the iocs have overlaps, and leave only the longest
    def ioc_overlap_remove(self):
        if len(self.ioc_list) == 0:
            return

        # Sort the IoC item list
        self.ioc_list.sort(key=get_iocitem_key)

        last_word = self.ioc_list[0].ioc_location[1]
        cleared_ioc_list = [self.ioc_list[0]]
        for i in range(1, len(self.ioc_list)):
            # no overlap
            if last_word <= self.ioc_list[i].ioc_location[0]:
                cleared_ioc_list.append(self.ioc_list[i])
                last_word = self.ioc_list[i].ioc_location[1]

        self.ioc_list = cleared_ioc_list

    def ioc_replace(self):
        logging.info("---ioc protection: Replace IoC items with protecting words!---")
        self.replaced_text = ""
        self.deleted_character_count = 0

        text_block_start = 0
        text_block_end = 0
        for ioc_item in self.ioc_list:
            original_ioc_string = ioc_item.ioc_string
            replaced_word = self.ioc_replaceWord[ioc_item.ioc_type]

            text_block_end = ioc_item.ioc_location[0]
            self.replaced_text += self.report_text[text_block_start: text_block_end]
            self.replaced_text += f" {replaced_word} "

            replaced_word_end = len(self.replaced_text)
            replaced_word_start = replaced_word_end - len(replaced_word) - 2  # -2 for two blank space
            replaced_ioc_item = IoCItem(original_ioc_string, ioc_item.ioc_type, replaced_word_start, replaced_word_end)
            self.replaced_ioc_list.append(replaced_ioc_item)
            self.replaced_ioc_dict[replaced_word_start] = original_ioc_string

            round_deleted_character_count = len(original_ioc_string) - len(replaced_word)
            self.deleted_character_count += round_deleted_character_count

            text_block_start = ioc_item.ioc_location[1]

            logging.debug("Replaced with: %s - %s" % (self.report_text[ioc_item.ioc_location[0]: ioc_item.ioc_location[1]], self.replaced_text[replaced_ioc_item.ioc_location[0]: replaced_ioc_item.ioc_location[1]]))

        self.replaced_text += self.report_text[text_block_start: len(self.report_text)]

    def to_jsonl(self) -> str:
        iocs = []
        for ioc_item in self.ioc_list:
            iocs.append([ioc_item.ioc_location[0], ioc_item.ioc_location[1], ioc_item.ioc_type])

        output = {"data": self.report_text, "label": iocs}
        output = json.dumps(output)
        return output

    def display_iocs(self):
        for ioc in self.ioc_list:
            print("--".join([ioc.ioc_type, ioc.ioc_string]))

    def check_replace_result(self):
        print("---ioc protection: Checking IoC replace result!---")
        for replaced_ioc_item in self.replaced_ioc_list:
            replaced_string = self.replaced_text[replaced_ioc_item.ioc_location[0]: replaced_ioc_item.ioc_location[1]]
            original_string = replaced_ioc_item.ioc_string
            print("%d:%d:%s- %s" % (replaced_ioc_item.ioc_location[0], replaced_ioc_item.ioc_location[1], replaced_string, original_string))
