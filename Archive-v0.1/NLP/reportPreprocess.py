# %%
import logging
import os

import pdfplumber
from html2text import html2text
from bs4 import BeautifulSoup
import spacy
import re
import sys

# sys.path.append("..")
# from Attack_Graph import AttacKG

# %%

# todo: how to handle pdf new lines
def read_pdf(file):
    with pdfplumber.open(file) as plumber:
        for page in plumber.pages:
            text = page.extract_text()
            text = text.replace('\n', '')
            print(text)
            # spacy_stentencizer(text)


# %%

# ToDo: Remove special characters with regex
# https://www.nhooo.com/note/qa3hxo.html
# https://www.shuzhiduo.com/A/8Bz8PNpXzx/

def read_html(file) -> str:
    logging.info("---S0-1: Read clear HTML text!---")

    with open(file, 'rb') as html_content:
        html = str(html_content.read())

        # text = html2text(html)
        soup = BeautifulSoup(html, 'lxml')
        text = soup.text

        cleartext = clear_text(text)

        # logging.info(cleartext)
        return cleartext


def clear_text(text: str) -> str:
    cleartext = text

    cleartext = cleartext.replace("\\n", "\n")
    cleartext = cleartext.replace("\\t", "\t")
    cleartext = cleartext.replace("\\r", " ")

    multint = re.compile('[\n]+')
    cleartext = multint.sub('\n', cleartext)

    hex = re.compile(r'(\\*x[0-9a-f]{2}){2,}')
    cleartext = hex.sub(' ', cleartext)

    cleartext = cleartext.replace("Windows NT", "WindowsNT")

    cleartext = cleartext.encode("ascii", "ignore")
    cleartext = cleartext.decode()

    # comp = re.compile('[^A-Z^a-z^0-9^\u4e00-\u9fa5]') #[^A-Z^a-z^0-9^\u4e00-\u9fa5]
    # cleartext = comp.sub('', text)

    # logging.DEBUG(str(cleartext))
    return cleartext


# %%

if __name__ == '__main__':

    # %%

    # file = r"./data/cti/html/0a84e7a880901bd265439bd57da61c5d.html"
    # text = read_html(file)

    # %%

    cti_path = r"./data/cti/html/"
    output_path = r"./data/cti/text/"

    cti_files = os.listdir(cti_path)
    for file in cti_files:
        file_name, ext = os.path.splitext(file)
        text = read_html(os.path.join(cti_path, file))
        with open(os.path.join(output_path, file_name+".txt"), "w+") as output:
            output.write(text)
