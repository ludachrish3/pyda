"""
Name:           analyzer.py

Description:    This file is responsible for determining the type of executable
                file and using the appropriate module for parsing its data.
"""

import os

from binaries import binary
from binaries import elf

from disassemblers import x64asm

import logging
logger = logging.getLogger(__name__)

# Magic numbers used to determine file types
MAGIC_NUM_ELF = b'\x7fELF'

def getBinary(fd):
    """
    Description:    Analyzes just enough to figure out the type of file

    Arguments:      fd - File descriptor of an open file

    Return:         Object that is derived from the Binary class
    """

    # TODO: Do a more thorough check for different file types. This is only good
    # enough for ELF files.
    fileHeader = fd.read(4)

    if fileHeader == MAGIC_NUM_ELF:
        # Set the file position back to zero so that the full file can be parsed
        fd.seek(0)
        return elf.ElfBinary()

    else:
        raise binary.AnalysisError("The file type could not be determined")


def analyzeFile(filename):

    # stat the file to get the size
    try:
        binStat = os.stat(filename)

    except FileNotFoundError as e:
        return None

    if binStat.st_size < 4:
        return None

    with open(filename, "rb") as binaryFile:

        exe = getBinary(binaryFile)
        exe.analyze(binaryFile)

        logger.info(exe)

        for funcName in exe.functionsByName:

            functionToAnalyze = exe.getFunctionByName(funcName)

            logger.debug("Function: {}".format(functionToAnalyze.assembly))

            if exe.getISA() == binary.ISA_X86_64:

                if funcName[0] != '_':
                    instructions = x64asm.disassemble(functionToAnalyze)
                    logger.info("{} Instructions (src, dst)".format(funcName))

                    for inst in instructions:
                        logger.info(inst)

    return None
