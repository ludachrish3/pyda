from argparse import ArgumentParser
import traceback
import os

from pyda import analyzer
from pyda.decompilers import decompiler

import logging

logger = logging.getLogger(__package__)

def main():

    debugLevels = [
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR"
    ]

    parser = ArgumentParser(add_help=False)
    required = parser.add_argument_group("required arguments")
    required.add_argument("file", nargs="+", help="the binary file(s) to analyze")

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

    # TODO: Add support for handling multiple files together and link them
    # against each other.
    for filename in args.file:

        if not os.path.isfile(filename):
            logger.error(f"'{filename}' could not be found. Quitting.")
            exit(1)

        try:
            binaryFile = analyzer.analyzeFile(filename)

        except Exception as e:
            logger.error(f"An error occurred while analyzing the binary: {e}")
            traceback.print_tb(e.__traceback__)
            exit(1)

if __name__ == "__main__":

    main()
