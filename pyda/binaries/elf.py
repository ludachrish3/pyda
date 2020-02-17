from pyda.binaries import binary

import logging

logger = logging.getLogger(__name__)

# ELF architecture type
ARCH_NONE  = 0
ARCH_32BIT = 1
ARCH_64BIT = 2

# ELF endianness
ENDIAN_NONE   = 0
ENDIAN_LITTLE = 1
ENDIAN_BIG    = 2

# ELF version number
VERSION_NONE    = 0
VERSION_CURRENT = 1

# ELF operating system
OS_SYSTEM_V = 0
OS_HP_UX    = 1
OS_NET_BSD  = 2
OS_LINUX    = 3
OS_GNU_HURD = 4
OS_SOLARIS  = 5
OS_FREE_BSD = 8
OS_OPEN_BSD = 11

OS_STR = {
    OS_SYSTEM_V: "System V",
    OS_HP_UX:    "HP-US",
    OS_NET_BSD:  "NetBSD",
    OS_LINUX:    "Linux",
    OS_GNU_HURD: "GNU Hurd",
    OS_SOLARIS:  "Solaris",
    OS_FREE_BSD: "FreeBSD",
    OS_OPEN_BSD: "OpenBSD",
}


# ELF file types
TYPE_NONE       = 0
TYPE_RELOC      = 1
TYPE_EXEC       = 2
TYPE_SHARED_OBJ = 3
TYPE_CORE       = 4

ALLOWED_TYPES = [
    TYPE_NONE,
    TYPE_RELOC,
    TYPE_EXEC,
    TYPE_SHARED_OBJ,
    TYPE_CORE,
]

TYPE_STR = {
    TYPE_RELOC:      "relocatable",
    TYPE_EXEC:       "executable",
    TYPE_SHARED_OBJ: "shared object",
    TYPE_CORE:       "core",
}

ISA_NONE        = 0x00
ISA_SPARC       = 0x02
ISA_X86         = 0x03
ISA_MIPS        = 0x08
ISA_POWER_PC    = 0x14
ISA_POWER_PC_64 = 0x15
ISA_ARM         = 0x28
ISA_SUPER_H     = 0x2a
ISA_IA_64       = 0x32
ISA_X86_64      = 0x3e

ALLOWED_ISAS = [
    ISA_SPARC,
    ISA_X86,
    ISA_MIPS,
    ISA_POWER_PC,
    ISA_POWER_PC_64,
    ISA_ARM,
    ISA_SUPER_H,
    ISA_IA_64,
    ISA_X86_64,
]

ISA_STR = {
    ISA_SPARC:       binary.ISA_SPARC,
    ISA_X86:         binary.ISA_X86,
    ISA_MIPS:        binary.ISA_MIPS,
    ISA_POWER_PC:    binary.ISA_POWER_PC,
    ISA_POWER_PC_64: binary.ISA_POWER_PC_64,
    ISA_ARM:         binary.ISA_ARM,
    ISA_SUPER_H:     binary.ISA_SUPER_H,
    ISA_IA_64:       binary.ISA_IA_64,
    ISA_X86_64:      binary.ISA_X86_64,
}


SEGMENT_TYPE_NULL         = 0
SEGMENT_TYPE_LOAD         = 1
SEGMENT_TYPE_DYNAMIC      = 2
SEGMENT_TYPE_INTERP       = 3
SEGMENT_TYPE_NOTE         = 4
SEGMENT_TYPE_SHARED_LIB   = 5
SEGMENT_TYPE_PROG_HDR     = 6
SEGMENT_TYPE_GNU_EH_FRAME = 1685382480
SEGMENT_TYPE_GNU_STACK    = 1685382481
SEGMENT_TYPE_GNU_RELRO    = 1685382482


ALLOWED_SEGMENT_TYPES = [
    SEGMENT_TYPE_LOAD,
    SEGMENT_TYPE_DYNAMIC,
    SEGMENT_TYPE_INTERP,
    SEGMENT_TYPE_NOTE,
    SEGMENT_TYPE_PROG_HDR,
    SEGMENT_TYPE_GNU_EH_FRAME,
    SEGMENT_TYPE_GNU_STACK,
    SEGMENT_TYPE_GNU_RELRO,
]


SEGMENT_TYPE_STR = {
    SEGMENT_TYPE_NULL:         "null",
    SEGMENT_TYPE_LOAD:         "loadable",
    SEGMENT_TYPE_DYNAMIC:      "dynamic",
    SEGMENT_TYPE_INTERP:       "interpreter",
    SEGMENT_TYPE_NOTE:         "note",
    SEGMENT_TYPE_SHARED_LIB:   "shared library", # this should not be used
    SEGMENT_TYPE_PROG_HDR:     "program header",
    SEGMENT_TYPE_GNU_EH_FRAME: "GNU exception handling frame",
    SEGMENT_TYPE_GNU_STACK:    "GNU stack",
    SEGMENT_TYPE_GNU_RELRO:    "GNU read-only after relocation",
}


SECTION_TYPE_NULL          = 0
SECTION_TYPE_PROGRAM_DATA  = 1
SECTION_TYPE_SYMBOL_TABLE  = 2
SECTION_TYPE_STRING_TABLE  = 3
SECTION_TYPE_RELOC_ADDEND  = 4
SECTION_TYPE_SYMBOL_HASH   = 5
SECTION_TYPE_DYNAMIC_LINK  = 6
SECTION_TYPE_NOTES         = 7
SECTION_TYPE_NO_DATA       = 8
SECTION_TYPE_RELOC_NO_ADD  = 9
SECTION_TYPE_SHARED_LIB    = 10
SECTION_TYPE_DYN_SYM_TABLE = 11
SECTION_TYPE_INIT_ARRAY    = 14
SECTION_TYPE_FINISH_ARRAY  = 15
SECTION_TYPE_PREINIT_ARRAY = 16
SECTION_TYPE_GROUP         = 17
SECTION_TYPE_MORE_INDICES  = 18
SECTION_TYPE_NUM_TYPES     = 19
SECTION_TYPE_GNU_HASH      = 1879048182
SECTION_TYPE_GNU_VERNEED   = 1879048190
SECTION_TYPE_GNU_VERSION   = 1879048191


ALLOWED_SECTION_TYPES = [
    SECTION_TYPE_NULL,
    SECTION_TYPE_PROGRAM_DATA,
    SECTION_TYPE_SYMBOL_TABLE,
    SECTION_TYPE_STRING_TABLE,
    SECTION_TYPE_RELOC_ADDEND,
    SECTION_TYPE_SYMBOL_HASH,
    SECTION_TYPE_DYNAMIC_LINK,
    SECTION_TYPE_NOTES,
    SECTION_TYPE_NO_DATA,
    SECTION_TYPE_RELOC_NO_ADD,
    SECTION_TYPE_SHARED_LIB,
    SECTION_TYPE_DYN_SYM_TABLE,
    SECTION_TYPE_INIT_ARRAY,
    SECTION_TYPE_FINISH_ARRAY,
    SECTION_TYPE_PREINIT_ARRAY,
    SECTION_TYPE_GROUP,
    SECTION_TYPE_MORE_INDICES,
    SECTION_TYPE_GNU_HASH,
    SECTION_TYPE_GNU_VERNEED,
    SECTION_TYPE_GNU_VERSION,
]

SECTION_TYPE_STR = {
    SECTION_TYPE_NULL:          "null",
    SECTION_TYPE_PROGRAM_DATA:  "program data",
    SECTION_TYPE_SYMBOL_TABLE:  "symbol table",
    SECTION_TYPE_STRING_TABLE:  "string table",
    SECTION_TYPE_RELOC_ADDEND:  "relocation entries with addends",
    SECTION_TYPE_SYMBOL_HASH:   "symbol hash table",
    SECTION_TYPE_DYNAMIC_LINK:  "dynamic",
    SECTION_TYPE_NOTES:         "notes",
    SECTION_TYPE_NO_DATA:       "no data (bss)",
    SECTION_TYPE_RELOC_NO_ADD:  "relocation entries with no addends",
    SECTION_TYPE_SHARED_LIB:    "shared library",
    SECTION_TYPE_DYN_SYM_TABLE: "dynamic linker symbol table",
    SECTION_TYPE_INIT_ARRAY:    "constructors",
    SECTION_TYPE_FINISH_ARRAY:  "destructors",
    SECTION_TYPE_PREINIT_ARRAY: "pre-constructors",
    SECTION_TYPE_GROUP:         "group",
    SECTION_TYPE_MORE_INDICES:  "extended section indices",
    SECTION_TYPE_NUM_TYPES:     "number of defined types",
    SECTION_TYPE_GNU_HASH:      "GNU symbol hash table",
    SECTION_TYPE_GNU_VERNEED:   "GNU version needed",
    SECTION_TYPE_GNU_VERSION:   "GNU version",
}

SECTION_NAME_SECTION_NAMES = ".shstrtab"
SECTION_NAME_STRING_TABLE = ".strtab"
SECTION_NAME_SYMBOL_TABLE = ".symtab"
SECTION_NAME_DYN_SYMBOL_TABLE = ".dynsym"
SECTION_NAME_DYN_STRING_TABLE = ".dynstr"
SECTION_NAME_GLOBAL_OFFSET_TABLE = ".got"
SECTION_NAME_INIT = ".init"
SECTION_NAME_DATA = ".data"
SECTION_NAME_TEXT = ".text"
SECTION_NAME_RODATA = ".rodata"


SYMBOL_BIND_LOCAL  = 0
SYMBOL_BIND_GLOBAL = 1
SYMBOL_BIND_WEAK   = 2

SYMBOL_BIND_STR = {
    SYMBOL_BIND_LOCAL:  "local",
    SYMBOL_BIND_GLOBAL: "global",
    SYMBOL_BIND_WEAK:   "weak"
}

SYMBOL_TYPE_NOTYPE   = 0
SYMBOL_TYPE_OBJECT   = 1
SYMBOL_TYPE_FUNCTION = 2
SYMBOL_TYPE_SECTION  = 3
SYMBOL_TYPE_FILE     = 4
SYMBOL_TYPE_COMMON   = 5

SYMBOL_TYPE_STR = {
    SYMBOL_TYPE_NOTYPE:   "no type",
    SYMBOL_TYPE_OBJECT:   "object",
    SYMBOL_TYPE_FUNCTION: "function",
    SYMBOL_TYPE_SECTION:  "section",
    SYMBOL_TYPE_FILE:     "file",
    SYMBOL_TYPE_COMMON:   "common"
}


SYMBOL_VIS_DEFAULT   = 0
SYMBOL_VIS_INTERNAL  = 1
SYMBOL_VIS_HIDDEN    = 2
SYMBOL_VIS_PROTECTED = 3

SYMBOL_VIS_STR = {
    SYMBOL_VIS_DEFAULT:   "default",
    SYMBOL_VIS_INTERNAL:  "internal",
    SYMBOL_VIS_HIDDEN:    "hidden",
    SYMBOL_VIS_PROTECTED: "protected"
}

RELOC_TYPE_NONE      = 0
RELOC_TYPE_GLOB_DATA = 6
RELOC_TYPE_JUMP_SLOT = 7
RELOC_TYPE_RELATIVE  = 8

RELOC_TYPE_STR = {
    RELOC_TYPE_NONE:      "no type",
    RELOC_TYPE_GLOB_DATA: "global data",
    RELOC_TYPE_JUMP_SLOT: "jump slot",
    RELOC_TYPE_RELATIVE:  "relative",
}

class ElfBinary(binary.Binary):

    def __init__(self):

        self._type = None
        self._segments = []

        self._sectionList = [] # Needed to associate sections by index number
        self._sectionDict = {}

        # By default, assume the binary is stripped. This is changed to False if a
        # symbol table section is found later.
        isStripped = True

        # Dictionary keyed on section name that contains the string at a given index
        # Example:
        # {
        #     '.strtab': {
        #         0:  '',
        #         1:  'crtstuff.c',
        #         12: 'deregister_tm_clones',
        #         ...
        #     },
        #     '.shstrtab': {
        #         0: '',
        #         27: '.interp',
        #         35: '.note.ABI-tag',
        #         ...
        #     }
        # }
        self._strings = {}

        # TODO: Update the key for the symbol table to be whatever is useful
        # Right now it is one big dictionary keyed on value, but maybe split it
        # up by type and key on something else if it makes more sense.
        self.functionsByName = {}
        self.functionsByAddr = {}
        self.objectsByName = {}
        self.objectsByAddr = {}

        # These values are determined by looking at the differences between the
        # virtual addresses and the file offsets of the code and Global Offset
        # Table sections, respectively.
        self.codeOffset = 0
        self.globOffset = 0


    def __repr__(self):
        return (
            f"Architecture: {self.arch}\n"
            f"Endianness:   {self.endianness}\n"
            f"File Type:    {TYPE_STR[self._type]}\n"
            f"ISA:          {ISA_STR[self.isa]}\n"
            f"addr:         {self.startAddr:08x}"
        )


    def bytesToInt(self, byteArray, signed=False):

        return int.from_bytes(byteArray, byteorder=self.endianness, signed=signed)


    # Reads an integer value from a memory mapped file
    def readInt( self, exeMap, size ):

        return self.bytesToInt(exeMap.read(size))


    def getStringFromTable( self, section, index ):
        """
        Description:    Looks up a string starting at an offset into a section.

        Arguments:      section - ElfSection object that is a string table.
                        index   - Starting location of the string in the section.

        Return:         The string found in the string table.
        """

        sectionName = section.name

        # If this section has never been queried before, add it to the dictionary
        if sectionName not in self._strings:
            self._strings[sectionName] = {}

        # If this string has been asked for before, return the saved value
        elif index in self._strings and index in self._strings[sectionName]:
            return self._strings[sectionName][index]

        # Make sure that the index is sane
        if index < 0 or index >= section.size:
            raise IndexError(f"The requested string index is out of bounds of the string table: {index}")

        # Set the position in the file to the beginning of the string based
        # on the table offset and the section's index.
        currentPos = index

        while section.data[currentPos] != 0:
            currentChar = section.data[currentPos]
            currentPos += 1

        string = section.data[index:currentPos].decode("ascii")
        self._strings[sectionName][index] = string

        return string


    def setArch(self, arch):

        if arch == ARCH_32BIT:
            self.arch = binary.BIN_ARCH_32BIT
            self.addrSize = 4

        elif arch == ARCH_64BIT:
            self.arch = binary.BIN_ARCH_64BIT
            self.addrSize = 8

        else:
            raise binary.AnalysisError(f"The architecture could not be determined: {arch}")


    def setEndianness(self, endianness):
        if endianness == ENDIAN_LITTLE:
            self.endianness = binary.BIN_ENDIAN_LITTLE

        elif endianness == ENDIAN_BIG:
            self.endianness = binary.BIN_ENDIAN_BIG

        else:
            raise binary.AnalysisError(f"The endianness could not be determined: {endianness}")


    def setFileType(self, fileType):

        fileTypeVal = self.bytesToInt(fileType)

        # Make sure that the file type is one of the defined types
        if fileTypeVal not in ALLOWED_TYPES:
            raise binary.AnalysisError(f"The ELF file type could not be determined: {fileTypeVal}")

        # Do not allow relocatable files for now because they are not supported
        if fileTypeVal == TYPE_RELOC:
            raise NotImplementedError("Relocatable files are not supported")

        self._type = fileTypeVal


    def getISA(self):

        return ISA_STR[self.isa]


    def setISA(self, isa):

        isaVal = self.bytesToInt(isa)

        if isaVal not in ALLOWED_ISAS:
            raise binary.AnalysisError(f"The ISA could not be determined: {isaVal}")

        # Many ISAs are not currently suported, so throw exceptions for them
        if isaVal == ISA_X86:
            raise NotImplementedError("32-bit x86 files are not supported")

        elif isaVal == ISA_ARM:
            raise NotImplementedError("ARM files are not supported")

        elif isaVal == ISA_SPARC:
            raise NotImplementedError("SPARC files are not supported")

        elif isaVal == ISA_MIPS:
            raise NotImplementedError("MIPS files are not supported")

        elif isaVal == ISA_POWER_PC:
            raise NotImplementedError("PowerPC files are not supported")

        elif isaVal == ISA_POWER_PC_64:
            raise NotImplementedError("64-bit PowerPC files are not supported")

        elif isaVal == ISA_IA_64:
            raise NotImplementedError("Intel IA-64 files are not supported")

        self.isa = isaVal


    def setVersion( self, version ):

        self.version = self.bytesToInt(version)


    def getVersion( self ):

        return self.version


    def setStartAddr(self, startAddr):

        self.startAddr = self.bytesToInt(startAddr)
        logger.debug(f"Start addr:            0x{self.startAddr:0>8x}")


    def getStartAddr(self):

        return self.startAddr


    def setProgHdrOffset(self, offset):

        self.progHdrOffset = self.bytesToInt(offset)
        logger.debug(f"Program header offset: 0x{self.progHdrOffset:<8x}")


    def setSectionHdrOffset(self, offset):

        self.sectionHdrOffset = self.bytesToInt(offset)
        logger.debug(f"Section header offset: 0x{self.sectionHdrOffset:<8x}")

    def setFlags(self, flags):

        self.flags = self.bytesToInt(flags)

        if self.flags != 0:
            raise binary.AnalysisError(f"Flags were set for the architecture, but they cannot be handled: {self.flags:<8}")


    def setElfHdrSize(self, hdrSize):

        self.elfHdrSize = self.bytesToInt(hdrSize)
        logger.debug(f"ELF header size: {self.elfHdrSize}")


    def setProgHdrEntrySize(self, entrySize):

        self.progHdrEntrySize = self.bytesToInt(entrySize)
        logger.debug(f"Program header entry size: {self.progHdrEntrySize}")

    def setNumProgHdrEntries(self, numEntries):

        self.numProgHdrEntries = self.bytesToInt(numEntries)
        logger.debug(f"Number of program header entries: {self.numProgHdrEntries}")


    def setSectionHdrEntrySize(self, entrySize):

        self.sectionHdrEntrySize = self.bytesToInt(entrySize)
        logger.debug(f"Section header entry size: {self.sectionHdrEntrySize}")


    def setNumSectionHdrEntries(self, numEntries):

        self.numSectionHdrEntries = self.bytesToInt(numEntries)
        logger.debug(f"Number of section header entries: {self.numSectionHdrEntries}")


    def setNameIndex(self, index):

        self._sectionNameIndex = self.bytesToInt(index)
        logger.debug(f"Index of the section that contains the section names: {self._sectionNameIndex}")


    def parseElfHeader(self, exeMap):

        # Get the architecture
        self.setArch(exeMap[4])

        # Now that the architecture is known, save a local copy of the number of
        # bytes in an address
        addrSize = self.addrSize

        # Get endianness
        self.setEndianness(exeMap[5])

        # Get the ELF version number. The only allowed value is the most current
        # value. Anything else is considered an error.
        elfVersion = exeMap[6]
        if elfVersion != VERSION_CURRENT:
            raise binary.AnalysisError(f"An invalid ELF version number was found: {elfVersion}")

        # Get the OS (not usually set, so not used by this module)
        fileOs = exeMap[7]
        if fileOs not in OS_STR:
            raise NotImplementedError(f"The OS is not supported: {fileOs}")

        # Get the type of file, like executable or shared object
        self.setFileType(exeMap[16:18])

        # Get the ISA
        self.setISA(exeMap[18:20])

        # Get the ELF version (currently not used by this module)
        self.setVersion(exeMap[20:24])

        # Seek to the location where 32-bit and 64-bit binaries start to
        # diverge in format due to different field sizes.
        exeMap.seek(24)

        # Get the starting virtual address for the program. The size of the
        # starting address varies based on the system's architecture.
        self.setStartAddr(exeMap.read(addrSize))

        # Get the start of the program header table in the file
        self.setProgHdrOffset(exeMap.read(addrSize))

        # Get the start of the section header table in the file
        self.setSectionHdrOffset(exeMap.read(addrSize))

        # Get the flags for the architecture
        self.setFlags(exeMap.read(4))

        # Get the size of the ELF header
        self.setElfHdrSize(exeMap.read(2))

        # Get info about the program header
        self.setProgHdrEntrySize(exeMap.read(2))
        self.setNumProgHdrEntries(exeMap.read(2))

        # Get info about the section header
        self.setSectionHdrEntrySize(exeMap.read(2))
        self.setNumSectionHdrEntries(exeMap.read(2))

        # Get the index of the section header that contains the section names
        self.setNameIndex(exeMap.read(2))


    def parseProgHdrs( self, exeMap ):

        # Save a local copy of the number of bytes in an address
        addrSize = self.addrSize

        # Set the position in the file to the beginning of the program header
        exeMap.seek(self.progHdrOffset)

        for entry in range(self.numProgHdrEntries):

            segmentType = self.readInt(exeMap, 4)

            newSegment = ElfSegment(segmentType)

            # The 32- and 64-bit formats have slightly different orders. The
            # only difference between the two is the position of the flags
            # field, so a deviation can be made for just this field based on
            # the architecture when it is appropriate.
            if self.arch == binary.BIN_ARCH_64BIT:
                newSegment.flags = self.readInt(exeMap, 4)

            newSegment.offset       = self.readInt(exeMap, addrSize)
            newSegment.virtualAddr  = self.readInt(exeMap, addrSize)
            newSegment.physicalAddr = self.readInt(exeMap, addrSize)
            newSegment.size         = self.readInt(exeMap, addrSize)
            newSegment.memorySize   = self.readInt(exeMap, addrSize)

            # Now is the appropriate time to check for the flags field if the
            # architecture is 32-bit.
            if self.arch == binary.BIN_ARCH_32BIT:
                newSegment.flags = self.readInt(exeMap, 4)

            newSegment.alignment = self.readInt(exeMap, addrSize)

            self._segments.append(newSegment)


    def parseSectionHdrs( self, exeMap ):

        # Save a local copy of the number of bytes in an address
        addrSize = self.addrSize

        # Set the position in the file to the beginning of the program header
        exeMap.seek(self.sectionHdrOffset)

        for entry in range(self.numSectionHdrEntries):

            sectionNameIndex = self.readInt(exeMap, 4)
            sectionType = self.readInt(exeMap, 4)

            newSection = ElfSection(sectionType, nameIndex=sectionNameIndex)

            newSection.flags = self.readInt(exeMap, addrSize)
            newSection.virtualAddr = self.readInt(exeMap, addrSize)
            newSection.fileOffset = self.readInt(exeMap, addrSize)
            newSection.size = self.readInt(exeMap, addrSize)
            newSection.link = self.readInt(exeMap, 4)
            newSection.info = self.readInt(exeMap, 4)
            newSection.alignment = self.readInt(exeMap, addrSize)
            newSection.entrySize = self.readInt(exeMap, addrSize)

            self._sectionList.append(newSection)

            # Save the section that has the names of all other sections so that
            # it can be used to identify the others in the next step
            if entry == self._sectionNameIndex:
                newSection.name = SECTION_NAME_SECTION_NAMES
                self._sectionDict[SECTION_NAME_SECTION_NAMES] = newSection

        # Set the data for the section that contains all section names so that
        # it can be used to look up the names of other sections.
        sectionNameSection = self._sectionDict[SECTION_NAME_SECTION_NAMES]
        exeMap.seek(sectionNameSection.fileOffset)
        self._sectionList[self._sectionNameIndex].data = exeMap.read(sectionNameSection.size)

        # Save each section as a byte string so that the file does not need to
        # be read from anymore.
        for section in self._sectionList:

            exeMap.seek(section.fileOffset)
            section.data = exeMap.read(section.size)

        logger.info("Sections:")

        # Now that all data is stored in objects for sections rather than just
        # in the file, get the section names from the string table.
        for section in self._sectionList:

            section.name = self.getStringFromTable(self._sectionList[self._sectionNameIndex], section.nameIndex)

            # Now that the section's name is known, it can be correctly assigned
            self._sectionDict[section.name] = section

            logger.info(f"{section}")


    def addSymbol( self, exeMap, symbol ):
        """
        Description:    Adds a symbol to dictionaries so it can be looked up by
                        name and by address. The offsets are used to make sure
                        the address is calculated to match up with how the
                        binary calls it.

        Arguments:      exeMap       - File descriptor to read from for assembly
                        symbol       - ElfSymbol object to update and add

        Return:         None
        """

        logger.debug(f"Symbol: {symbol}")

        if symbol.type == SYMBOL_TYPE_FUNCTION:

            logger.debug(f"function symbol: {symbol}")

            # Save the assembly bytes of the function with the object so that
            # the file is no longer needed. The address offset of the .text
            # section must be subtracted to get the file location of the
            # function. The value for the symbol is the virtual address.
            #
            # If exeMap is None, like when resolving dynamic symbols, do not
            # bother trying to get the bytes for the symbol because there are
            # none until they are resolved.
            if exeMap is not None:
                exeMap.seek(symbol.getAddress() - self.codeOffset)
                symbol.assembly = exeMap.read(symbol.getSize())

            self.functionsByName[symbol.getName()] = symbol

            # If the symbol's value is 0, then the address must be figured out
            # later when resolving external symbols.
            if symbol.getAddress() > 0 and symbol.size > 0:
                self.functionsByAddr[symbol.getAddress()] = symbol

        else:

            self.objectsByName[symbol.getName()]    = symbol
            self.objectsByAddr[symbol.getAddress()] = symbol


    def parseSymbolTable( self, section, exeMap=None ):
        """
        Description:    Parses the symbol table and creates symbol objects for
                        all entries. The string table is the section found by
                        looking at the link member of the symbol table section.

        Arguments:      exeMap  - Memory map object of the binary file.
                        section - ElfSection object that is a symbol table.

        Return:         None
        """

        symbolData  = section.data

        # Determine the size of each entry. This is saved in the section's
        # information in the ELF header.
        entrySize = section.entrySize

        for pos in range(0, section.size, entrySize):
            if self.arch == binary.BIN_ARCH_32BIT:
                symbolIndex     = self.bytesToInt(symbolData[pos:pos+4])
                stringTable     = self._sectionList[section.link]
                name            = self.getStringFromTable(stringTable, symbolIndex)
                address         = self.bytesToInt(symbolData[pos+4:pos+8])
                size            = bytesToInt(symbolData[pos+8:pos+12])
                symbolInfo      = symbolData[pos+12]
                bind            = symbolInfo >> 4
                symbolType      = symbolInfo & 0xf
                symbolOther     = symbolData[pos+13]
                visibility      = symbolOther & 0x3
                sectionIndex    = self.bytesToInt(symbolData[pos+14:pos+16])

            elif self.arch == binary.BIN_ARCH_64BIT:
                symbolIndex     = self.bytesToInt(symbolData[pos:pos+4])
                stringTable     = self._sectionList[section.link]
                name            = self.getStringFromTable(stringTable, symbolIndex)
                symbolInfo      = symbolData[pos+4]
                bind            = symbolInfo >> 4
                symbolType      = symbolInfo & 0xf
                symbolOther     = symbolData[pos+5]
                visibility      = symbolOther & 0x3
                sectionIndex    = self.bytesToInt(symbolData[pos+6:pos+8])
                address         = self.bytesToInt(symbolData[pos+8:pos+16])
                size            = self.bytesToInt(symbolData[pos+16:pos+24])

            if symbolType == SYMBOL_TYPE_FUNCTION:
                newSymbol = ElfFunction(name, address, size, bind, visibility, sectionIndex)

            elif symbolType == SYMBOL_TYPE_SECTION:

                # The names of section symbols are not set by the symbol table,
                # so looking them up based on the saved section info is needed.
                name = self._sectionList[newSymbol.sectionIndex].name
                newSymbol = ElfSymbol(name, address, size, symbolType, bind, visibility, sectionIndex)

            else:
                newSymbol = ElfSymbol(name, address, size, symbolType, bind, visibility, sectionIndex)

            self.addSymbol(exeMap, newSymbol)

        return True


    def parseRelocation( self, section, hasAddend ):
        """
        Description:    Parses relocation sections.

        Arguments:      section     - ElfSection object that is a relocation.
                        hasAddent   - Whether this relocation has an addend.

        Return:         None
        """

        relocData = section.data
        addrSize  = self.addrSize

        # The section that a relocation section refers to is determined by the
        # name that trails the ".rel" or ".rela" name of the relocation section.
        if hasAddend:
            relocSectionNameStart = len(".rela")
        else:
            relocSectionNameStart = len(".rel")

        relocSectionName = section.name[relocSectionNameStart:]

        relocSection = self._sectionDict.get(relocSectionName, None)

        logger.debug(f"Parsing relocations for {section.name}")

        # Determine the size of each entry. This is saved in the section's
        # information in the ELF header.
        entrySize = section.entrySize

        addend = 0

        # Iterate through each entry. The size of each member is the size of an
        # address. The layout of each entry is as follows:
        #   - address
        #   - info, which is a combination of symbol table index and relocation
        #     type
        #   - addend (only if hasAddend is True)

        for pos in range(0, section.size, entrySize):
            offset = self.bytesToInt(relocData[pos:pos+addrSize])
            info   = self.bytesToInt(relocData[pos+addrSize:pos+2*addrSize])

            if hasAddend:
                addend = self.bytesToInt(relocData[pos+2*addrSize:pos+3*addrSize], True)

            if self.arch == binary.BIN_ARCH_32BIT:
                symTableIndex = info >> 8
                relocType     = info & 0xff

            elif self.arch == binary.BIN_ARCH_64BIT:
                symTableIndex = info >> 32
                relocType     = info & 0xffffffff

            logger.debug(f"offset: {offset+addend:x}, info: {info:x}")
            logger.debug(f"symbol table index: {symTableIndex}")
            logger.debug(f"type: {RELOC_TYPE_STR[relocType]}")
            logger.debug(f"symbol table: {section.info}")

            # Use the value in the GOT to fill out the original address
            # of the symbol name. The value at the location pointed to by the
            # offset into the GOT is the location in the PLT (or whatever the
            # current relocation section is).

            # Get the symbol's name and set its value because it is known now.
            if relocType == RELOC_TYPE_JUMP_SLOT and section.link > 0:
                # Get the symbol's string table index
                stringTableIndex = self._sectionList[section.link].link
                stringTableName  = self._sectionList[stringTableIndex].name
                stringTableList  = list(self._strings[stringTableName].values())
                symbolName       = stringTableList[symTableIndex]
                symbol = self.functionsByName[symbolName]

                # Get the address to which the GOT points, which is the address
                # that should be called by other functions. This points to the
                # instruction just after the actual start of the stub.
                gotSection = self._sectionList[section.info]
                gotOffset  = offset - gotSection.virtualAddr

                # Figure out the address of the previous instruction so that
                # the start of the stub is the address associated with the
                # symbol.
                relocNextInstAddr = self.bytesToInt(gotSection.data[gotOffset:gotOffset+self.addrSize])
                relocSymbolAddr = relocNextInstAddr - (relocNextInstAddr % relocSection.entrySize)

                # Update the symbol's address and add the symbol to the symbols
                # keyed by address.
                symbol.setAddress(relocSymbolAddr)
                symbol.setSize(relocSection.entrySize)

                # Set the assembly for the function so that it can be disassembled
                assemblyStart = symbol.getAddress() - relocSection.virtualAddr
                assemblyEnd = assemblyStart + relocSection.entrySize
                symbol.assembly = relocSection.data[assemblyStart:assemblyEnd]

                self.functionsByAddr[relocSymbolAddr] = symbol


    def analyze( self, exeMap ):

        # Parse the ELF header to get basic information about the file
        self.parseElfHeader(exeMap)

        # TODO: Maybe don't do this because the info is in the section headers
        # Handle the program headers if there are any
        if self.progHdrOffset > 0:
            self.parseProgHdrs(exeMap)

        # Handle sections and save them
        self.parseSectionHdrs(exeMap)

        # Set the code and global offsets for use when creating symbols
        codeSection      = self._sectionDict[SECTION_NAME_TEXT]
        globSection      = self._sectionDict[SECTION_NAME_GLOBAL_OFFSET_TABLE]
        self.codeOffset  = codeSection.virtualAddr - codeSection.fileOffset
        self.globOffset  = globSection.virtualAddr - globSection.fileOffset

        for section in self._sectionList:

            if section.type == SECTION_TYPE_SYMBOL_TABLE:
                logger.debug(f"symbol table: {section}")
                logger.debug(f"strings: {self._sectionList[section.link]}")
                self.isStripped = False
                self.parseSymbolTable(section, exeMap)


    def resolveExternalSymbols( self ):
        """
        Description:    Resolves external symbols that are normally resolved
                        during linking.

                        This is done in ELF files by looking at the Procedure
                        Linkage Table (PLT) and the Global Offset Table (GOT).
                        The PLT holds stubs that jump to a location in the GOT.
                        The image initially holds PLT locations at each spot in
                        the GOT that are one instruction after the actual start
                        of the stub. The reason for this is because the first
                        reference to an external symbol uses the address in the
                        GOT to jump back to the PLT. From there, it jumps to
                        the PLT entry that patches GOT entries with the true
                        address to the external symbol so that the lookup does
                        not need to be done again.

                        In order to figure this out, the relocation sections
                        are used to look at the GOT entry for each function and
                        to see the address to which the PLT each one points to.
                        This is the only starting point when handling external
                        symbol addresses. This address then needs to be walked
                        back by one instruction because, as mentioned earlier,
                        the GOT address points to the instruction after the
                        start of the PLT stub.

        Arguments:      None

        Return:         None
        """

        # First, the dynamic symbol table must be parsed so that the symbol
        # objects exist for modification later when the addresses are resolved.
        for section in self._sectionList:

            if section.type == SECTION_TYPE_DYN_SYM_TABLE:
                self.parseSymbolTable(section)

        # Look through all relocation sections and resolve their addresses
        for section in self._sectionList:

            if section.type == SECTION_TYPE_RELOC_ADDEND:
                self.parseRelocation(section, True)

            elif section.type == SECTION_TYPE_RELOC_NO_ADD:
                self.parseRelocation(section, False)


    def getFunctionByName(self, name):

        return self.functionsByName.get(name, None)


    def getFunctionByAddr(self, address):

        return self.functionsByAddr.get(address, None)


    def getExecutableCode(self):

        return self._sectionDict.get(SECTION_NAME_TEXT, None)


class ElfSegment():

    def __init__(self, segmentType):

        if segmentType in ALLOWED_SEGMENT_TYPES:
            self._type = segmentType

        else:
            raise binary.AnalysisError(f"An invalid segment type was found: {segmentType}")

        self.flags        = 0
        self.offset       = 0
        self.virtualAddr  = 0
        self.physicalAddr = 0
        self.size         = 0
        self.memorySize   = 0
        self.alignment    = 0

    def __repr__(self):

        return (
            f"type: {SEGMENT_TYPE_STR[self.type]},"
            f" flags: {self.flags},"
            f" offset: {self.offset},"
            f" virtualAddr: {self.virtualAddr},"
            f" physicalAddr: {self.physicalAddr},"
            f" size: {self.size},"
            f" memorySize: {self.memorySize},"
            f" alignment: {self.alignment}"
        )


class ElfSection():

    def __init__(self, sectionType, name=".null", nameIndex=0):

        if sectionType in ALLOWED_SECTION_TYPES:
            self.type = sectionType

        else:
            raise binary.AnalysisError(f"An invalid section type was found: {sectionType}")

        self.nameIndex   = nameIndex
        self.name        = name
        self.flags       = 0
        self.virtualAddr = 0
        self.fileOffset  = 0
        self.size        = 0
        self.link        = 0
        self.info        = 0
        self.alignment   = 0
        self.entrySize   = 0
        self.data        = None


    def __repr__(self):

        return (
            f"name: {self.name},"
            f" type: {SECTION_TYPE_STR[self.type]},"
            f" flags: {self.flags},"
            f" virtualAddr: {hex(self.virtualAddr)},"
            f" fileOffset: {hex(self.fileOffset)},"
            f" size: {self.size},"
            f" link: {self.link},"
            f" info: {self.info},"
            f" alignment: {self.alignment},"
            f" entrySize: {self.entrySize},"
            f" nameIndex: {self.nameIndex}"
        )


class ElfSymbol( binary.Symbol ):

    def __init__( self, name, address, size, symbolType, bind, visibility, sectionIndex ):

        self.setName(name)
        self.setAddress(address)
        self.setSize(size)
        self.bind = bind
        self.type = symbolType
        self.visibility = visibility
        self.sectionIndex = sectionIndex

    def setName(self, name):

        if len(name) == 0:
            self.name = None

        else:
            self.name = name

    def getName(self):

        return self.name

    def setAddress(self, address):

        self.address = address

    def getAddress(self):

        return self.address

    def setSize(self, size):

        self.size = size

    def getSize(self):

        return self.size

    def __repr__(self):

        return (
            f"name: {self.getName()}, "
            f"address: {self.getAddress():0>8x}, "
            f"size: {self.getSize()}, "
            f"type: {SYMBOL_TYPE_STR[self.type]}, "
            f"bind: {SYMBOL_BIND_STR[self.bind]}, "
            f"visibility: {SYMBOL_VIS_STR[self.visibility]}, "
            f"section index: {self.sectionIndex}"
        )


class ElfFunction( ElfSymbol ):

    def __init__( self, name, address, size, bind, visibility, sectionIndex ):

        super().__init__(name, address, size, SYMBOL_TYPE_FUNCTION, bind, visibility, sectionIndex)

        self.assembly = bytes() # Only used if the symbol is a function
        self.instructions = []  # Only used if the symbol is a function

    def __repr__( self ):

        # Backslashes are not allowed in braces in an f-string, so define the
        # newline character for use in the f-string.
        nl = "\n"

        return (
            f"{super().__repr__()}, "
            f"number of instructions: {len(self.instructions)}"
        )

