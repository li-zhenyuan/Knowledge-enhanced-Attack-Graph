import argparse
import logging
import sys

from preprocess.report_preprocess import preprocess_file
from report_parser.ioc_protection import IoCIdentifier


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-L', '--logPath', required=False, type=str, default="", help="Log file's path.")
    parser.add_argument('-M', '--mode', required=True, type=str, default="", help="The running mode.")
    parser.add_argument('-R', '--reportPath', required=True, type=str, default="", help="Target report's path.")

    arguments = parser.parse_args(sys.argv[1:])

    log_path = arguments.logPath
    if log_path == "":
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    else:
        logging.basicConfig(filename=log_path, filemode='a', level=logging.DEBUG)

    report_path = arguments.reportPath
    report_text = preprocess_file(report_path)

    running_mode = arguments.mode
    if running_mode == "iocExtraction":
        ioc_identifier = IoCIdentifier(report_text)
        ioc_identifier.ioc_protect()
        ioc_identifier.check_replace_result()
    else:
        print("Unknown running mode!")
