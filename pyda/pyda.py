"""
Name:           pyda.py

Description:    This file is the CLI frontend for interacting with the pyda
                library.
"""

from argparse import ArgumentParser
import traceback
import os, sys

from pyda.exeParsers import exeParser
from pyda.decompilers import decompiler

import logging

logger = logging.getLogger(__package__)

helpMessage = """
[l]ist - list the available things
[s]how - show a function
[h]elp - show this help output
[e]xit - exit the program (same as quit)
[q]uit - quit the program (same as exit)
"""

listHelpMessage = """
list [f]unctions        - lists the names of all functions
list [g]lobal variables - lists the names of all global variables
list [s]ymbols          - lists all symbols and their info
"""

showHelpMessage = """
show [[a]ssembly] <function name> - shows a function's code, or its assembly if
                                    "assembly" is also provided
"""


def runTui( executables ):
    """
    Description:    Work loop to take user input and print the desired info

    Arguments:      executables - List of Executable objects to interact with

    Return:         None
    """

    prompt = "pyda> "

    listCommands = ["l", "list"]
    showCommands = ["s", "show"]
    exitCommands = ["q", "e", "quit", "exit"]
    helpCommands = ["h", "help"]

    # TODO: Support multiple executables that are imported together
    executable = executables[0]

    while True:

        print(f"{prompt}", end='')
        line = input().strip().lower()

        tokens = line.split(" ")

        if tokens[0] in exitCommands:
            break

        elif tokens[0] in helpCommands:

            # Show the main help if no specific command is chosen
            if len(tokens) == 1:

                print(f"{helpMessage}")

            elif len(tokens) == 2 and tokens[1] in listCommands:

                print(f"{listHelpMessage}")

            elif len(tokens) == 2 and tokens[1] in showCommands:

                print(f"{showHelpMessage}")

            else:

                print(f"'{tokens[1]}' is not a valid command")

        elif tokens[0] in listCommands:

            print("listing things")

        elif tokens[0] in showCommands:

            print("showing things")

        else:
            print(f"'{tokens[0]}' is not a valid command")


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
    optional.add_argument("-l", "--log-level", choices=debugLevels, default="WARNING", type=str.upper, metavar="", help="Log level to use when printing logs")
    optional.add_argument("-h", "--help", action="help", help="Show this help message and exit")

    args = parser.parse_args()

    # Set up a handler and formatter for the global logger that all files will use.
    # Assign the log level to be the one specified on the command line.
    logHandler = logging.StreamHandler()
    logFormatter = logging.Formatter("[{levelname:^7s}] {message}", style="{")
    logHandler.setFormatter(logFormatter)
    logger.addHandler(logHandler)
    logger.setLevel(args.log_level)

    executables = []

    # TODO: Add support for handling multiple files together and link them
    # against each other.
    for filename in args.file:

        if not os.path.isfile(filename):
            logger.error(f"'{filename}' could not be found. Quitting.")
            exit(1)

        try:
            executables.append(exeParser.parseExe(filename))

        except Exception as e:
            logger.error(f"An error occurred while parsing the executable: {e}")
            traceback.print_tb(e.__traceback__)
            exit(1)

    runTui(executables)


if __name__ == "__main__":

    main()
