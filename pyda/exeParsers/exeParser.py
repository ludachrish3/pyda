"""
Name:           exeParser.py

Description:    This file is responsible for determining the type of executable
                file and using the appropriate module for parsing its data.
"""

import os
import mmap

from pyda.exeParsers import executable, elf

import logging
logger = logging.getLogger(__name__)

# Magic numbers used to determine file types
MAGIC_NUM_ELF = b'\x7fELF'

def getExecutable( exeMap ):
    """
    Description:    Analyzes just enough to figure out the type of file

    Arguments:      fileMap - Memory map object that contains the executable

    Return:         Object that is derived from the Binary class
    """

    # TODO: Do a more thorough check for different file types. This is only good
    # enough for ELF files.
    fileHeader = exeMap[:4]

    if fileHeader == MAGIC_NUM_ELF:
        return elf.ElfExecutable(exeMap)

    else:
        raise executable.AnalysisError("The file type could not be determined")


def parseExe( filename ):

    # stat the file to get the size
    try:
        exeStat = os.stat(filename)

    except FileNotFoundError as e:
        return None

    # TODO: Create a global value for this size, and name it to represent the
    # minimum size of an executable to determine its type.
    if exeStat.st_size < 4:
        return None

    with open(filename, "rb") as exeFile:

        exeMap = mmap.mmap(exeFile.fileno(), 0, access=mmap.ACCESS_READ)

    exe = getExecutable(exeMap)
    exe.parse()

    logger.info(exe)

    return exe
