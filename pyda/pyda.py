"""
Name:           pyda.py

Description:    This file is the CLI frontend for interacting with the pyda
                library.
"""

from argparse import ArgumentParser
import traceback
import os, sys

from pyda.exeParsers import exeParser, executable
from pyda.decompilers import decompiler

import logging

logger = logging.getLogger(__package__)

helpMessage = """
l\u0332ist - list the available things
s\u0332how - show a function
h\u0332elp - show this help output
e\u0332xit - exit the program (same as quit)
q\u0332uit - quit the program (same as exit)
"""

listHelpMessage = """
list f\u0332unctions - lists the names of all functions
list g\u0332lobals   - lists the names of all global variables
list s\u0332ymbols   - lists all symbols and their info
"""

showHelpMessage = """
show [a\u0332ssembly] <function name> - shows a function's code, or its assembly if
                                  "assembly" is also provided
"""


def listCommand( exe, tokens ):
    """
    Description:    Performs the list command based on the tokens from the
                    user's input.

    Arguments:      exe    - Executable object to inspect
                    tokens - List of tokens after the initial 'list' token

    Return:         None
    """

    # TODO: Support sorting by a certain column in ascending or descending order

    if len(tokens) == 0:
        print(f"Invalid list command.\n{listHelpMessage}")
        return

    if tokens[0] in ["f", "functions"]:

        functions = exe.getSymbols(symbolType=executable.SYMBOL_TYPE_FUNCTION, byName=True)

        # Convert the functions into a table-friendly format
        functions = [ {"Name": func.getName(), "Address": f"{func.getAddress():#010x}"} for func in functions ]

        printTable(functions)

    elif tokens[0] in ["g", "globals"]:

        globalVars = exe.getSymbols(symbolType=executable.SYMBOL_TYPE_GLOBAL, byName=True)

        # Convert the global variables into a table-friendly format
        globalVars = [ {"Name": var.getName(), "Address": f"{var.getAddress():#010x}"} for var in globalVars ]

        printTable(globalVars)

    elif tokens[0] in ["s", "symbols"]:

        symbols = exe.getSymbols(byName=True)

        # Convert the symbols into a table-friendly format
        symbols = [ {"Name": sym.getName(), "Address": f"{sym.getAddress():#010x}"} for sym in symbols ]

        printTable(symbols)

    else:
        print(f"'{tokens[0]}' is not a valid object to list")


def showCommand( exe, tokens ):

    print("showing things")



def printTable( data ):
    """
    Description:    Prints a list of data entries in a table. The header of
                    each column is the key for value, and all values are
                    expected to be strings in the format in which they should
                    be printed.

    Arguments:      data - Dictionary keyed on column name containing formatted
                           strings for the values.

    Return:         None
    """

    if len(data) == 0:

        print("No results")
        return

    widths = {}
    titles = []

    rowSeparator = "+"

    for key in data[0]:

        # Take max of list of data entries with the given key.
        # Also take width of title into account just in case it is longer than
        # any of the values.
        keyMaxWidth = max([ len(entry[key]) for entry in data ])
        keyMaxWidth = max(keyMaxWidth, len(key))

        widths[key] = keyMaxWidth
        titles.append(key.ljust(keyMaxWidth))
        rowSeparator += "-" * (keyMaxWidth + 2) + "+"

    # Print the header
    header = "| " +  " | ".join(titles) + " |"
    print(rowSeparator)
    print(header)
    print(rowSeparator)

    # Print the data, everything right aligned because numbers look better that way
    for entry in data:

        values = [ value.ljust(widths[key]) for key, value in entry.items() ]
        print("| " + " | ".join(values) + " |")
        print(rowSeparator)


def runTui( executables ):
    """
    Description:    Work loop to take user input and print the desired info

    Arguments:      executables - List of Executable objects to interact with

    Return:         None
    """

    listCommands = ["l", "list"]
    showCommands = ["s", "show"]
    exitCommands = ["q", "e", "quit", "exit"]
    helpCommands = ["h", "help"]

    # TODO: Support multiple executables that are imported together
    exe = executables[0]

    while True:

        line = input("pyda> ").strip().lower()

        # Split up the tokens by whitespace, and remove any extra spaces
        tokens = line.split(" ")
        tokens = [ token for token in tokens if len(token) > 0 ]

        if len(tokens) == 0:
            continue

        if tokens[0] in exitCommands:
            break

        elif tokens[0] in listCommands:

            listCommand(exe, tokens[1:])

        elif tokens[0] in showCommands:

            print("showing things")
            showCommand(exe, tokens[1:])

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
