import logging
import os

import pdfplumber
from bs4 import BeautifulSoup
import re


# Todo: how to handle pdf new lines
def read_pdf(report_file: str):
    report_text = ""

    with pdfplumber.open(report_file) as plumber:
        for page in plumber.pages:
            page_text = page.extract_text()
            report_text += page_text

    return report_text


# Remove special characters with regex
# https://www.nhooo.com/note/qa3hxo.html
# https://www.shuzhiduo.com/A/8Bz8PNpXzx/
def read_html(report_file: str) -> str:
    with open(report_file, 'rb') as html_content:
        html = str(html_content.read())

        soup = BeautifulSoup(html, 'lxml')
        report_text = soup.text

        return report_text


def clear_text(report_text: str) -> str:
    cleartext = report_text.lower()
    cleartext = " ".join(cleartext.split())

    cleartext = cleartext.replace("\\n", "\n")
    cleartext = cleartext.replace("\\t", "\t")
    cleartext = cleartext.replace("\\r", " ")

    multint = re.compile('[\n]+')
    cleartext = multint.sub('\n', cleartext)

    hex = re.compile(r'(\\*x[0-9a-f]{2}){2,}')
    cleartext = hex.sub(' ', cleartext)

    cleartext = cleartext.replace("windows nt", "windowsnt")

    cleartext = cleartext.encode("ascii", "ignore")
    cleartext = cleartext.decode()

    # comp = re.compile('[^A-Z^a-z^0-9^\u4e00-\u9fa5]') #[^A-Z^a-z^0-9^\u4e00-\u9fa5]
    # cleartext = comp.sub('', text)

    return cleartext


def preprocess_file(report_file: str) -> str:
    logging.info(f"---preprocess: Reading and clearing CTI report: {report_file}!---")
    file_path, extension = os.path.splitext(report_file)

    if extension == ".html":
        report_text = read_html(report_file)
    elif extension == ".pdf":
        report_text = read_pdf(report_file)
    else:
        raise Exception(f"Unknown report file type: {extension} in {report_file}!")

    cleared_text = clear_text(report_text)
    logging.debug(f"---preprocess: Cleared text: {cleared_text} ---")

    return cleared_text


if __name__ == '__main__':
    cti_path = r"./data/cti/html/"
    output_path = r"./data/cti/text/"

    cti_files = os.listdir(cti_path)
    for file in cti_files:
        file_name, ext = os.path.splitext(file)
        text = preprocess_file(os.path.join(cti_path, file))
        with open(os.path.join(output_path, file_name+".txt"), "w+") as output:
            output.write(text)
