from argparse import ArgumentParser
import os

import binanalyzer
import disassembler
import decompiler

if __name__ == "__main__":
    
    parser = ArgumentParser()
    required = parser.add_argument_group("required arguments")
    required.add_argument("-f", "--file", required=True, help="the binary file to analyze")

    args = parser.parse_args()

    try:
        os.stat(args.file)

    except FileNotFoundError as e:
        print("The specified file could not be found. Quitting.")
        exit(1)

    
    try:
        binaryFile = binanalyzer.analyzeFile(args.file)

    except Exception as e:
        print("An error occurred while analyzing the binary: {}".format(e))
        exit(1)
