import os

import binary
import elf

# Magic numbers used to determine file types
MAGIC_NUM_ELF = b'\x7fELF'

# Analyzes just enough to figure out the type of file
def getBinary(fd):
    # TODO: Do a more thorough check for different file types. This is only good
    # enough for ELF files.
    fileHeader = fd.read(4)
    print("Magic number: {}".format(fileHeader))

    if fileHeader == MAGIC_NUM_ELF:
        # Set the file position back to zero so that the full file can be parsed
        fd.seek(0)
        return elf.ElfBinary()

    else:
        raise binary.AnalysisError("The file type could not be determined")


def analyzeFile(filename):

    binary = None

    try:
        binStat = os.stat(filename)

    except FileNotFoundError as e:
        return None

    if binStat.st_size < 4:
        return None

    with open(filename, "rb") as binaryFile:

        binary = getBinary(binaryFile)
        binary.analyze(binaryFile)

        print(binary)


    return None
