from preprocess.report_preprocess import clear_text

import re
import json
import logging
import sys

IoC_regex = {
    "NetLoc": [
        r"\b([a-z]{3,}\:\/\/[\S]{16,})\b",
        r"\b(([a-z0-9\-]{2,}\[?\.\]?)+(abogado|ac|academy|accountants|active|actor|ad|adult|ae|aero|af|ag|agency|ai|airforce|al|allfinanz|alsace|am|amsterdam|an|android|ao|aq|aquarelle|ar|archi|army|arpa|as|asia|associates|at|attorney|au|auction|audio|autos|aw|ax|axa|az|ba|band|bank|bar|barclaycard|barclays|bargains|bayern|bb|bd|be|beer|berlin|best|bf|bg|bh|bi|bid|bike|bingo|bio|biz|bj|black|blackfriday|bloomberg|blue|bm|bmw|bn|bnpparibas|bo|boo|boutique|br|brussels|bs|bt|budapest|build|builders|business|buzz|bv|bw|by|bz|bzh|ca|cal|camera|camp|cancerresearch|canon|capetown|capital|caravan|cards|care|career|careers|cartier|casa|cash|cat|catering|cc|cd|center|ceo|cern|cf|cg|ch|channel|chat|cheap|christmas|chrome|church|ci|citic|city|ck|cl|claims|cleaning|click|clinic|clothing|club|cm|cn|co|coach|codes|coffee|college|cologne|com|community|company|computer|condos|construction|consulting|contractors|cooking|cool|coop|country|cr|credit|creditcard|cricket|crs|cruises|cu|cuisinella|cv|cw|cx|cy|cymru|cz|dabur|dad|dance|dating|day|dclk|de|deals|degree|delivery|democrat|dental|dentist|desi|design|dev|diamonds|diet|digital|direct|directory|discount|dj|dk|dm|dnp|do|docs|domains|doosan|durban|dvag|dz|eat|ec|edu|education|ee|eg|email|emerck|energy|engineer|engineering|enterprises|equipment|er|es|esq|estate|et|eu|eurovision|eus|events|everbank|exchange|expert|exposed|fail|farm|fashion|feedback|fi|finance|financial|firmdale|fish|fishing|fit|fitness|fj|fk|flights|florist|flowers|flsmidth|fly|fm|fo|foo|forsale|foundation|fr|frl|frogans|fund|furniture|futbol|ga|gal|gallery|garden|gb|gbiz|gd|ge|gent|gf|gg|ggee|gh|gi|gift|gifts|gives|gl|glass|gle|global|globo|gm|gmail|gmo|gmx|gn|goog|google|gop|gov|gp|gq|gr|graphics|gratis|green|gripe|gs|gt|gu|guide|guitars|guru|gw|gy|hamburg|hangout|haus|healthcare|help|here|hermes|hiphop|hiv|hk|hm|hn|holdings|holiday|homes|horse|host|hosting|house|how|hr|ht|hu|ibm|id|ie|ifm|il|im|immo|immobilien|in|industries|info|ing|ink|institute|insure|int|international|investments|io|iq|ir|irish|is|it|iwc|jcb|je|jetzt|jm|jo|jobs|joburg|jp|juegos|kaufen|kddi|ke|kg|kh|ki|kim|kitchen|kiwi|km|kn|koeln|kp|kr|krd|kred|kw|ky|kyoto|kz|la|lacaixa|land|lat|latrobe|lawyer|lb|lc|lds|lease|legal|lgbt|li|lidl|life|lighting|limited|limo|link|lk|loans|london|lotte|lotto|lr|ls|lt|ltda|lu|luxe|luxury|lv|ly|ma|madrid|maison|management|mango|market|marketing|marriott|mc|md|me|media|meet|melbourne|meme|memorial|menu|mg|mh|miami|mil|mini|mk|ml|mm|mn|mo|mobi|moda|moe|monash|money|mormon|mortgage|moscow|motorcycles|mov|mp|mq|mr|ms|mt|mu|museum|mv|mw|mx|my|mz|na|nagoya|name|navy|nc|ne|net|network|neustar|new|nexus|nf|ng|ngo|nhk|ni|ninja|nl|no|np|nr|nra|nrw|ntt|nu|nyc|nz|okinawa|om|one|ong|onl|ooo|org|organic|osaka|otsuka|ovh|pa|paris|partners|parts|party|pe|pf|pg|ph|pharmacy|photo|photography|photos|physio|pics|pictures|pink|pizza|pk|pl|place|plumbing|pm|pn|pohl|poker|porn|post|pr|praxi|press|pro|prod|productions|prof|properties|property|ps|pt|pub|pw|qa|qpon|quebec|re|realtor|recipes|red|rehab|reise|reisen|reit|ren|rentals|repair|report|republican|rest|restaurant|reviews|rich|rio|rip|ro|rocks|rodeo|rs|rsvp|ru|ruhr|rw|ryukyu|sa|saarland|sale|samsung|sarl|sb|sc|sca|scb|schmidt|schule|schwarz|science|scot|sd|se|services|sew|sexy|sg|sh|shiksha|shoes|shriram|si|singles|sj|sk|sky|sl|sm|sn|so|social|software|sohu|solar|solutions|soy|space|spiegel|sr|st|style|su|supplies|supply|support|surf|surgery|suzuki|sv|sx|sy|sydney|systems|sz|taipei|tatar|tattoo|tax|tc|td|technology|tel|temasek|tennis|tf|tg|th|tienda|tips|tires|tirol|tj|tk|tl|tm|tn|to|today|tokyo|tools|top|toshiba|town|toys|tp|tr|trade|training|travel|trust|tt|tui|tv|tw|tz|ua|ug|uk|university|uno|uol|us|uy|uz|va|vacations|vc|ve|vegas|ventures|versicherung|vet|vg|vi|viajes|video|villas|vision|vlaanderen|vn|vodka|vote|voting|voto|voyage|vu|wales|wang|watch|webcam|website|wed|wedding|wf|whoswho|wien|wiki|williamhill|wme|work|works|world|ws|wtc|wtf|xyz|yachts|yandex|ye|yoga|yokohama|youtube|yt|za|zm|zone|zuerich|zw))\b",
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"],
    "E-mail": [r"\b([a-z][_a-z0-9-.]+@[a-z0-9-]+\.[a-z]+)\b"],
    "DocFile": [
        r"\b([A-Za-z0-9-_\.]+\.(sys|htm|html|js|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif))\b"],
    "ExeFile": [r"\b([A-Za-z0-9-_\.]+\.(exe|dll|bat|jar))\b"],
    "FileHash": [
        r"\b([a-f0-9]{32}|[A-F0-9]{32})\b",
        r"\b([a-f0-9]{40}|[A-F0-9]{40})\b",
        r"\b([a-f0-9]{64}|[A-F0-9]{64})\b"
    ],
    "Registry": [
        r"\b((KCU|HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|SOFTWARE).{0,1}\\[\\A-Za-z0-9-_]+)\b",
        r"\b((HKLM|HKCU|HKEY_LOCAL_MACHINE|HKU)\\\\[\\\\A-Za-z0-9-_]+)\b"
    ],
    "FilePath": [
        r"\b[A-Z]:\\[A-Za-z0-9-_\.\\]+\b",
        r"[~]*/[A-Za-z0-9-_\./]{2,}\b"
        r"[%A-Za-z0-9]*\\[A-Za-z0-9-_\.\\%]+\b"
    ],  # %ALLUSERPROFILE%\Application Data\Microsoft\MediaPlayer\
    # "FileName": [r"\b([A-Za-z0-9-_\.]+\.(exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif))\b"],
    "Vulnerability": [r"\b(CVE\-[0-9]{4}\-[0-9]{4,6})\b"],
    "Arguments": [r"\s[-/\\][0-9a-zA-Z]+\s"]
}

IoC_replacedWord = {
    "NetLoc": "network",
    "E-mail": "email",
    "FileHash": "file",
    "DocFile": "document",
    "ExeFile": "executable",
    "FilePath": "path",
    "Vulnerability": "exploit",
    "Registry": "registry",
    "Arguments": " "  # remove arguments
}


class IoCItem:          # original IoC item     # replaced IoC item
    ioc_string: str     # original IoC string   # replaced IoC string
    ioc_type: str       # IoC type
    ioc_location: list  # original

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
    text: str
    ioc_list: list

    deleted_character_count: int
    replaced_text: str
    replaced_ioc_list: list
    replaced_ioc_dict: dict

    def __init__(self, text: str = ""):
        self.text = text
        self.ioc_list = []

        self.deleted_character_count = 0
        self.replaced_text = ""
        self.replaced_ioc_list = []
        self.replaced_ioc_dict = {}

        if text != "":
            self.ioc_identify()

    def ioc_identify_from_file(self, file) -> str:
        self.text = ""
        self.ioc_list = []

        output = ""
        with open(file, "r") as input:
            text = input.read()
            output = self.ioc_identify(text)

        return output

    # check if the iocs have overlaps, and leave only the longest
    def add_check_overlap_iocs(self, ioc_item: IoCItem):
        for i in range(0, len(self.ioc_list)):
            # no overlap
            if not (ioc_item.ioc_location[1] <= self.ioc_list[i].ioc_location[0] or ioc_item.ioc_location[0] >= self.ioc_list[i].ioc_location[1]):
                return
        self.ioc_list.append(ioc_item)

    def ioc_identify(self, text: str = None) -> str:
        logging.info("---S0-2: Identify IoC with Regex in text!---")

        if text is None:
            text = self.text
        else:
            self.text = text

        self.replaced_text = text

        # Find all IoC item in the text, need sorting
        for ioc_type, regex_list in IoC_regex.items():
            for regex in regex_list:
                matchs = re.finditer(regex, text)
                for m in matchs:
                    logging.debug("Find IoC matching: %s - %s" % (ioc_type, m))
                    # output["label"].append([match.span()[0], match.span()[1], ioc_type])
                    ioc_item = IoCItem(m.group(), ioc_type, m.span()[0], m.span()[1])
                    self.add_check_overlap_iocs(ioc_item)

        # Sort the IoC item list
        self.ioc_list.sort(key=get_iocitem_key)

        self.deleted_character_count = 0
        last_ioc_end = 0
        for ioc_item in self.ioc_list:
            original_ioc_string = ioc_item.ioc_string
            replaced_word = IoC_replacedWord[ioc_item.ioc_type]

            ioc_start_pos = self.replaced_text.find(original_ioc_string)
            if ioc_start_pos == -1:  # avoid IoCs with overlap
                continue

            if last_ioc_end >= ioc_item.ioc_location[1]:
                last_ioc_end = ioc_item.ioc_location[1]
                continue
            last_ioc_end = ioc_item.ioc_location[1]

            replaced_word_start = ioc_item.ioc_location[0]-self.deleted_character_count
            round_deleted_character_count = len(original_ioc_string) - len(replaced_word)
            self.deleted_character_count += round_deleted_character_count
            replaced_word_end = ioc_item.ioc_location[1]-self.deleted_character_count
            replaced_ioc_item = IoCItem(original_ioc_string, ioc_item.ioc_type, replaced_word_start, replaced_word_end)

            if replaced_word_start != ioc_start_pos:
                # raise Exception("IoC Regex Align Failed!")
                continue

            # if replaced_word_start != ioc_start_pos:
            #     raise Exception("IoC Regex Align Failed!")

            # replace iocs with replace_word
            # self.replaced_text = re.sub(ioc_item.ioc_string, IoC_replacedWord[ioc_item.ioc_type], self.replaced_text, count=1)
            self.replaced_text = self.replaced_text[:replaced_word_start] + replaced_word + self.replaced_text[replaced_word_start+len(original_ioc_string):]
            self.replaced_ioc_list.append(replaced_ioc_item)
            # self.replaced_text = self.replaced_text.replace(original_ioc_string, replaced_word)

            logging.debug("Replaced with: %s - %s" % (self.text[ioc_item.ioc_location[0]: ioc_item.ioc_location[1]], self.replaced_text[replaced_ioc_item.ioc_location[0]: replaced_ioc_item.ioc_location[1]]))
            self.replaced_ioc_dict[replaced_ioc_item.ioc_location[0]] = replaced_ioc_item.ioc_string

        return self.replaced_text

    # def ioc_identify_old(self, text: str = None) -> str:
    #     logging.info("---S0-2: Identify IoC with Regex in text!---")
    #
    #     if text is None:
    #         text = self.text
    #     else:
    #         self.text = text
    #
    #     self.deleted_character_count = 0
    #     self.replaced_text = text
    #
    #     for ioc_type, regex_list in IoC_regex.items():
    #         for regex in regex_list:
    #             matchs = re.finditer(regex, text)
    #             for m in matchs:
    #                 logging.debug("Find IoC matching: %s - %s" % (ioc_type, m))
    #                 # output["label"].append([match.span()[0], match.span()[1], ioc_type])
    #                 ioc_item = IoCItem(m.group(), ioc_type, m.span()[0], m.span()[1])
    #                 self.ioc_list.append(ioc_item)
    #
    #                 # replace iocs with replace_word
    #                 self.replaced_text = re.sub(regex, IoC_replacedWord[ioc_type], self.replaced_text, count=1)
    #                 # self.replaced_text = self.replaced_text[:m.span()[0]] + IoC_replacedWord[ioc_type] + self.replaced_text[m.span()[1]]
    #                 # self.replaced_text = self.replaced_text.replace(m.group(), IoC_replacedWord[ioc_type])
    #
    #                 replaced_ioc_item = IoCItem(
    #                     m.group(),
    #                     ioc_type,
    #                     m.span()[0]-self.deleted_character_count,
    #                     m.span()[1]-(self.deleted_character_count + (len(str(m.group()))-len(IoC_replacedWord[ioc_type]))))
    #                 self.deleted_character_count += (len(str(m.group())) - len(IoC_replacedWord[ioc_type]))
    #                 logging.debug("Replaced with: %s - %s" % (self.text[ioc_item.ioc_location[0]: ioc_item.ioc_location[1]], self.replaced_text[replaced_ioc_item.ioc_location[0]: replaced_ioc_item.ioc_location[1]]))
    #                 self.replaced_ioc_list.append(replaced_ioc_item)
    #                 # self.replaced_ioc_dict[replaced_ioc_item.ioc_location[0]] = replaced_ioc_item.ioc_string
    #
    #     return self.replaced_text

    def to_jsonl(self) -> str:
        iocs = []
        for ioc_item in self.ioc_list:
            iocs.append([ioc_item.ioc_location[0], ioc_item.ioc_location[1], ioc_item.ioc_type])

        output = {"data": self.text, "label": iocs}
        output = json.dumps(output)
        return output

    def display_iocs(self):
        for ioc in self.ioc_list:
            print("--".join([ioc.ioc_type, ioc.ioc_string]))

    def check_replace_result(self):
        print("---Checking IoC replace result!---")
        for replaced_ioc_item in self.replaced_ioc_list:
            replaced_string = self.replaced_text[replaced_ioc_item.ioc_location[0]: replaced_ioc_item.ioc_location[1]]
            original_string = replaced_ioc_item.ioc_string
            print("%d:%d:%s-%s" % (replaced_ioc_item.ioc_location[0], replaced_ioc_item.ioc_location[1], replaced_string, original_string))


# %%

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    iid = IoCIdentifier()

    # print(iid.ioc_identify("APT29 has exploited CVE-2019-19781 for Citrix, CVE-2019-11510 for Pulse Secure VPNs, CVE-2018-13379 for FortiGate VPNs, and CVE-2019-9670 in Zimbra software to gain access."))
    # print(iid.to_jsonl())
    # iid.check_replace_result()

    # iid.ioc_identify(read_html(r".\data\cti\html\0a84e7a880901bd265439bd57da61c5d.html"))
    iid.ioc_identify(read_html(r".\data\cti\html\003495c4cb6041c52db4b9f7ead95f05.html"))
    # print(iid.to_jsonl())
    iid.check_replace_result()
