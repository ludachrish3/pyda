#!/usr/bin/env python3

from argparse import ArgumentParser
import os

import analyzer
from decompilers import decompiler

import logging

logger = logging.getLogger(__package__)

if __name__ == "__main__":

    debugLevels = [
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR"
    ]

    parser = ArgumentParser(add_help=False)
    required = parser.add_argument_group("required arguments")
    required.add_argument("-f", "--file", required=True, help="the binary file to analyze")

    optional = parser.add_argument_group("optional arguments")
    optional.add_argument("-l", "--log-level", choices=debugLevels, default="INFO", type=str.upper, metavar="", help="Log level to use when printing logs")
    optional.add_argument("-h", "--help", action="help", help="Show this help message and exit")

    args = parser.parse_args()

    # Set up a handler and formatter for the global logger that all files will use.
    # Assign the log level to be the one specified on the command line.
    logHandler = logging.StreamHandler()
    logFormatter = logging.Formatter("[{levelname:^7s}] {message}", style="{")
    logHandler.setFormatter(logFormatter)
    logger.addHandler(logHandler)
    logger.setLevel(args.log_level)

    try:
        os.stat(args.file)

    except FileNotFoundError as e:
        logger.error("The specified file could not be found. Quitting.")
        exit(1)

    try:
        binaryFile = analyzer.analyzeFile(args.file)

    except Exception as e:
        logger.error("An error occurred while analyzing the binary: {}".format(e))
        exit(1)