import argparse
import sys


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--mode', required=True, type=str, default="", help='')


    arguments = parser.parse_args(sys.argv[1:])
