"""
Name:           analyzer.py

Description:    This file is responsible for determining the type of executable
                file and using the appropriate module for parsing its data.
"""

import os
import mmap

from pyda.binaries import binary, elf

from pyda.disassemblers.x64 import asm as x64asm

import logging
logger = logging.getLogger(__name__)

# Magic numbers used to determine file types
MAGIC_NUM_ELF = b'\x7fELF'

def getBinary( exeMap ):
    """
    Description:    Analyzes just enough to figure out the type of file

    Arguments:      fileMap - Memory map object that contains the executable

    Return:         Object that is derived from the Binary class
    """

    # TODO: Do a more thorough check for different file types. This is only good
    # enough for ELF files.
    fileHeader = exeMap[:4]

    if fileHeader == MAGIC_NUM_ELF:
        return elf.ElfBinary(exeMap)

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

        exeMap = mmap.mmap(binaryFile.fileno(), 0, access=mmap.ACCESS_READ)

    exe = getBinary(exeMap)
    exe.analyze()

    logger.info(exe)

    # Resolve external symbols
    exe.resolveExternalSymbols()

    # If the executable did not have a symbol table, then the .text section
    # needs to be broken up into functions and disassembled
    if exe.isStripped:

        # Execution starts at the executable's start address, not necessarily
        # at the beginning of the code section. Pass the code section starting
        # at the start address so that it is guaranteed that the first
        # instruction is the beginning of a function.
        codeSection = exe.getExecutableCode()
        startOffset = exe.getStartAddr() - codeSection.virtualAddr
        code = codeSection.data[startOffset:]

        instructions = x64asm.disassemble(code, exe.getStartAddr())
        for inst in instructions:
            logger.info(inst)

        listOfAddrsAndSizes = x64asm.findFunctions(instructions)
        for addr, size in listOfAddrsAndSizes:
            logger.info(f"func_{addr:08x}: {size}")

    # Otherwise, disassemble all functions in the executable
    else:

        # Disassemble all functions in the executable
        for symbolKey, symbol in exe.getSymbols().items():

            # Disassemble each function. Every symbol has an entry for its name
            # and its address, so only handle symbols by name to avoid redundancy.
            if isinstance(symbol, binary.Function) and type(symbolKey) == str:
                logger.info(f"function: {symbol}")

                if exe.getISA() == binary.ISA_X86_64:

                    instructions = x64asm.disassemble(symbol.getAssembly(), symbol.getAddress())
                    symbol.setInstructions(instructions)

                for inst in instructions:
                    logger.info(f"{inst}")

    # TODO: Update instructions to use symbols instead of numbers for all known
    # symbols because they should all be known by this point.

    return None
