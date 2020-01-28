"""
Name:           analyzer.py

Description:    This file is responsible for determining the type of executable
                file and using the appropriate module for parsing its data.
"""

import os

from pyda.binaries import binary, elf

from pyda.disassemblers.x64 import asm as x64asm

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

    # If the executable did not have a symbol table, then the .text section
    # needs to be broken up into functions and disassembled
    if exe.isStripped:

        codeSection = exe.getExecutableCode()
        instructions = x64asm.disassemble(codeSection.data, codeSection.virtualAddr)
        for inst in instructions:
            logger.info(inst)

        listOfAddrsAndSizes = x64asm.findFunctions(instructions)

    # Otherwise, disassemble all functions in the executable
    else:

        # Disassemble all functions in the executable
        for funcName in exe.functionsByName:

            function = exe.getFunctionByName(funcName)

            logger.debug(f"Function: {function.assembly}")

            if exe.getISA() == binary.ISA_X86_64:

                instructions = x64asm.disassemble(function.assembly, function.addr)
                logger.info(f"{funcName} Instructions (src, dst)")

                for inst in instructions:
                    logger.info(inst)





    return None
