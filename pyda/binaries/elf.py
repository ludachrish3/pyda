from pyda.binaries import binary
import ctypes

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
    SECTION_TYPE_RELOC_ADDEND:  "relocation with addends",
    SECTION_TYPE_SYMBOL_HASH:   "symbol hash table",
    SECTION_TYPE_DYNAMIC_LINK:  "dynamic",
    SECTION_TYPE_NOTES:         "notes",
    SECTION_TYPE_NO_DATA:       "no data (bss)",
    SECTION_TYPE_RELOC_NO_ADD:  "relocation without addends",
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

    def __init__( self, exeMap ):

        self._exeMap   = exeMap
        self._type     = None

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

        # Dictionary to hold symbols. Each symbol has an entry for its address
        # and its name, if a name can be found.
        self._symbols = {}

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
            f"addr:         {self.getStartAddr():08x}"
        )


    def bytesToInt(self, byteArray, signed=False):

        return int.from_bytes(byteArray, byteorder=self.endianness, signed=signed)


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
        start = section.fileOffset + index
        currentPos = start

        while self._exeMap[currentPos] != 0:
            currentChar = self._exeMap[currentPos]
            currentPos += 1

        string = self._exeMap[start:currentPos].decode("ascii")
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

        # Make sure that the file type is one of the defined types
        if fileType not in ALLOWED_TYPES:
            raise binary.AnalysisError(f"The ELF file type could not be determined: {fileType}")

        # Do not allow relocatable files for now because they are not supported
        if fileType == TYPE_RELOC:
            raise NotImplementedError("Relocatable files are not supported")

        self._type = fileType


    def getISA(self):

        return ISA_STR[self.isa]


    def setISA( self, isa ):

        if isa not in ALLOWED_ISAS:
            raise binary.AnalysisError(f"The ISA could not be determined: {isa}")

        # Many ISAs are not currently suported, so throw exceptions for them
        if isa == ISA_X86:
            raise NotImplementedError("32-bit x86 files are not supported")

        elif isa == ISA_ARM:
            raise NotImplementedError("ARM files are not supported")

        elif isa == ISA_SPARC:
            raise NotImplementedError("SPARC files are not supported")

        elif isa == ISA_MIPS:
            raise NotImplementedError("MIPS files are not supported")

        elif isa == ISA_POWER_PC:
            raise NotImplementedError("PowerPC files are not supported")

        elif isa == ISA_POWER_PC_64:
            raise NotImplementedError("64-bit PowerPC files are not supported")

        elif isa == ISA_IA_64:
            raise NotImplementedError("Intel IA-64 files are not supported")

        self.isa = isa


    def parseElfHeader( self ):

        elfHeader = Elf64Header.from_buffer_copy(self._exeMap)

        if elfHeader.arch == ARCH_32BIT:
            elfHeader = Elf32Header.from_buffer_copy(self._exeMap)

        self.setArch(elfHeader.arch)
        self.setEndianness(elfHeader.endianness)
        self.setFileType(elfHeader.fileType)
        self.setISA(elfHeader.isa)
        self.setStartAddr(elfHeader.startAddr)

        self.programHdrOffset = elfHeader.programHeaderOffset
        self.sectionHdrOffset = elfHeader.sectionHeaderOffset
        self.programEntrySize = elfHeader.programEntrySize
        self.numProgramEntries = elfHeader.numProgramEntries
        self.sectionEntrySize = elfHeader.sectionEntrySize
        self.numSectionEntries = elfHeader.numSectionEntries
        self.sectionNameIndex = elfHeader.nameSectionIndex

        logger.debug(f"Start addr:     0x{self.getStartAddr():08x}")


    def parseSectionEntries( self ):

        # Determine which structure to overlay onto each entry
        if self.arch == binary.BIN_ARCH_32BIT:
            sectionClass = Elf32SectionEntry

        elif self.arch == binary.BIN_ARCH_64BIT:
            sectionClass = Elf64SectionEntry

        # Create a ctypes object from each entry. Then convert it into a proper
        # Python object so that attributes can be added to it.
        for entryIndex in range(self.numSectionEntries):

            start = self.sectionHdrOffset + self.sectionEntrySize * entryIndex

            sectionEntry = sectionClass.from_buffer_copy(self._exeMap[start:start+self.sectionEntrySize])

            sectionObject = ElfSection(sectionEntry)
            self._sectionList.append(sectionObject)

        sectionNameSection = self._sectionList[self.sectionNameIndex]

        logger.info("Sections:")

        # Now that all data is stored in objects for sections rather than just
        # in the file, get the section names from the string table.
        for section in self._sectionList:

            section.name = self.getStringFromTable(sectionNameSection, section.nameIndex)

            # Now that the section's name is known, it can be correctly assigned
            self._sectionDict[section.name] = section

            logger.info(f"{section}")


    def addSymbol( self, symbol ):
        """
        Description:    Adds a symbol to dictionaries so it can be looked up by
                        name and by address. The offsets are used to make sure
                        the address is calculated to match up with how the
                        binary calls it.

        Arguments:      symbol  - ElfSymbol object to update and add

        Return:         None
        """

        logger.debug(f"Symbol: {symbol}")

        if symbol.type == SYMBOL_TYPE_FUNCTION:

            logger.debug(f"function symbol: {symbol}")

            # Save the assembly bytes of the function with the object so that
            # the file is no longer needed. The address offset of the .text
            # section must be subtracted to get the file location of the
            # function. The value for the symbol is the virtual address.
            address = symbol.getAddress()
            size    = symbol.getSize()

            symbol.setAssembly(self._exeMap[address:address+size])

        self.setSymbol(symbol)


    def parseSymbolTable( self, section ):
        """
        Description:    Parses the symbol table and creates symbol objects for
                        all entries. The string table is the section found by
                        looking at the link member of the symbol table section.

        Arguments:      section - ElfSection object that is a symbol table.

        Return:         None
        """

        # Determine which structure to overlay onto the entry
        if self.arch == binary.BIN_ARCH_32BIT:

            symboClass = Elf32SymbolEntry

        elif self.arch == binary.BIN_ARCH_64BIT:

            symbolClass = Elf64SymbolEntry

        for entry in range(section.fileOffset, section.fileOffset + section.size, section.entrySize):

            symbolStruct = symbolClass.from_buffer_copy(self._exeMap[entry:entry+section.entrySize])

            # Create the real Python objects based on the ctypes structures
            # and assign the symbols their names
            if symbolStruct.type == SYMBOL_TYPE_SECTION:

                # Unlike other symbol types, the names of section symbols are
                # not set by the symbol table index, so looking them up based
                # on the saved section info is needed.
                name = self._sectionList[symbolStruct.sectionIndex].name
                symbol = ElfSymbol(name, symbolStruct)

            else:

                # Look up the name of the symbol
                stringTable     = self._sectionList[section.link]
                name            = self.getStringFromTable(stringTable, symbolStruct.nameIndex)

                if symbolStruct.type == SYMBOL_TYPE_FUNCTION:
                    symbol = ElfFunction(name, symbolStruct)

                else:
                    symbol = ElfSymbol(name, symbolStruct)

            self.addSymbol(symbol)

        return True


    def parseRelocation( self, section, hasAddend ):
        """
        Description:    Parses relocation sections.

        Arguments:      section     - ElfSection object that is a relocation.
                        hasAddent   - Whether this relocation has an addend.

        Return:         None
        """

        logger.debug(f"Parsing relocations for {section.name}")

        # Save the entry size for convenience later
        entrySize = section.entrySize

        # Convert the strings into a list because the indices for the names are
        # an index into the list of strings, not an index into the entire
        # section where the string begins.
        stringTableIndex = self._sectionList[section.link].link
        stringTableName  = self._sectionList[stringTableIndex].name
        stringTableList  = list(self._strings[stringTableName].values())

        # Determine which structure to overlay onto each entry
        if self.arch == binary.BIN_ARCH_32BIT and hasAddend:
            relocationClass = Elf32RelocationAddend

        elif self.arch == binary.BIN_ARCH_32BIT and not hasAddend:
            relocationClass = Elf32Relocation

        elif self.arch == binary.BIN_ARCH_64BIT and hasAddend:
            relocationClass = Elf64RelocationAddend

        elif self.arch == binary.BIN_ARCH_64BIT and not hasAddend:
            relocationClass = Elf64Relocation

        # Iterate through each relocation entry
        for entry in range(section.fileOffset, section.fileOffset + section.size, entrySize):

            relocation = relocationClass.from_buffer_copy(self._exeMap[entry:entry+entrySize])

            if hasattr(relocation, "addend"):
                logger.debug(f"addend: {relocation.addend:x}")

            logger.debug(f"offset: {relocation.offset:x}")
            logger.debug(f"symbol table index: {relocation.symbolIndex}")
            logger.debug(f"type: {RELOC_TYPE_STR[relocation.type]}")

            # Figure out the section that holds the relocation value so that
            # its file offset can be used to find the value.
            # relocValueOffset is the file offset at which the file holds the
            # relocation value's address.
            # relocValue is the value of the relocation.
            holdingSection = self.getSectionFromAddr(relocation.offset)
            relocValueOffset = holdingSection.fileOffset + relocation.offset - holdingSection.address
            relocValue = self.bytesToInt(self._exeMap[relocValueOffset:relocValueOffset+self.addrSize])

            logger.debug(f"relocation value: {relocValue:x}")

            # Get the symbol's name and set its value because it is known now.
            if relocation.type == RELOC_TYPE_JUMP_SLOT and section.link > 0:

                # Get the symbol's string table index
                symbolName       = stringTableList[relocation.symbolIndex]

                symbol = self.getSymbol(symbolName)

                logger.debug(f"Symbol {symbolName}: {symbol}")

                # Figure out the address of the previous instruction so that
                # the start of the stub is the address associated with the
                # symbol.
                relocSection = self.getSectionFromAddr(relocValue)
                relocSymbolAddr = relocValue - (relocValue % relocSection.entrySize)

                # Update the symbol's address and add the symbol to the symbols
                # keyed by address.
                symbol.setAddress(relocSymbolAddr)
                symbol.setSize(relocSection.entrySize)

                # Set the assembly for the function so that it can be disassembled
                # Account for the virtual address offset by subtracting the file
                # offset from the virtual address so that the file location of
                # the assembly can be determined.
                assemblyStart = relocSection.address - relocSection.fileOffset + relocValue
                assemblyEnd = assemblyStart + relocSection.entrySize
                symbol.setAssembly(self._exeMap[assemblyStart:assemblyEnd])
                symbol.setIsExternal(True)

                self.setSymbol(symbol)


    def analyze( self ):

        # Parse the ELF header to get basic information about the file
        self.parseElfHeader()

        # Handle sections and save them
        self.parseSectionEntries()

        # Set the code and global offsets for use when creating symbols
        codeSection      = self._sectionDict[SECTION_NAME_TEXT]
        globSection      = self._sectionDict[SECTION_NAME_GLOBAL_OFFSET_TABLE]
        self.codeOffset  = codeSection.address - codeSection.fileOffset
        self.globOffset  = globSection.address - globSection.fileOffset

        for section in self._sectionList:

            if section.type == SECTION_TYPE_SYMBOL_TABLE:
                logger.debug(f"symbol table: {section}")
                logger.debug(f"strings: {self._sectionList[section.link]}")
                self.isStripped = False
                self.parseSymbolTable(section)


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


    def getSectionFromAddr( self, address ):
        """
        Description:    Determines which section holds an address.

        Arguments:      address - Address to look up

        Return:         Section containing the address if one is found.
                        None if no section contains the address.
        """

        for section in self._sectionList:

            if address >= section.address and address < section.address + section.size:
                return section

        return None


    def getExecutableCode(self):

        return self._sectionDict.get(SECTION_NAME_TEXT, None)


class Elf32Header(binary.FlexibleCStruct):

    _fields_ = [
        ("magic",               ctypes.c_char * 4),
        ("arch",                ctypes.c_uint8),
        ("endianness",          ctypes.c_uint8),
        ("headerVersion",       ctypes.c_uint8),
        ("operatingSystem",     ctypes.c_uint8),
        ("padding",             ctypes.c_uint8 * 8),
        ("fileType",            ctypes.c_uint16),
        ("isa",                 ctypes.c_uint16),
        ("elfVersion",          ctypes.c_uint32),
        ("startAddr",           ctypes.c_uint32),
        ("programHeaderOffset", ctypes.c_uint32),
        ("sectionHeaderOffset", ctypes.c_uint32),
        ("flags",               ctypes.c_uint32),
        ("elfHeaderSize",       ctypes.c_uint16),
        ("programEntrySize",    ctypes.c_uint16),
        ("numProgramEntries",   ctypes.c_uint16),
        ("sectionEntrySize",    ctypes.c_uint16),
        ("numSectionEntries",   ctypes.c_uint16),
        ("nameSectionIndex",    ctypes.c_uint16),
    ]


class Elf64Header(binary.FlexibleCStruct):

    _fields_ = [
        ("magic",               ctypes.c_char * 4),
        ("arch",                ctypes.c_uint8),
        ("endianness",          ctypes.c_uint8),
        ("headerVersion",       ctypes.c_uint8),
        ("operatingSystem",     ctypes.c_uint8),
        ("padding",             ctypes.c_uint8 * 8),
        ("fileType",            ctypes.c_uint16),
        ("isa",                 ctypes.c_uint16),
        ("elfVersion",          ctypes.c_uint32),
        ("startAddr",           ctypes.c_uint64),
        ("programHeaderOffset", ctypes.c_uint64),
        ("sectionHeaderOffset", ctypes.c_uint64),
        ("flags",               ctypes.c_uint32),
        ("elfHeaderSize",       ctypes.c_uint16),
        ("programEntrySize",    ctypes.c_uint16),
        ("numProgramEntries",   ctypes.c_uint16),
        ("sectionEntrySize",    ctypes.c_uint16),
        ("numSectionEntries",   ctypes.c_uint16),
        ("nameSectionIndex",    ctypes.c_uint16),
    ]


class Elf32SectionEntry(binary.FlexibleCStruct):

    _fields_ = [
        ("nameIndex",   ctypes.c_uint32),
        ("type",        ctypes.c_uint32),
        ("flags",       ctypes.c_uint32),
        ("address",     ctypes.c_uint32),
        ("fileOffset",  ctypes.c_uint32),
        ("size",        ctypes.c_uint32),
        ("link",        ctypes.c_uint32),
        ("info",        ctypes.c_uint32),
        ("alignment",   ctypes.c_uint32),
        ("entrySize",   ctypes.c_uint32),
    ]


class Elf64SectionEntry(binary.FlexibleCStruct):

    _fields_ = [
        ("nameIndex",   ctypes.c_uint32),
        ("type",        ctypes.c_uint32),
        ("flags",       ctypes.c_uint64),
        ("address",     ctypes.c_uint64),
        ("fileOffset",  ctypes.c_uint64),
        ("size",        ctypes.c_uint64),
        ("link",        ctypes.c_uint32),
        ("info",        ctypes.c_uint32),
        ("alignment",   ctypes.c_uint64),
        ("entrySize",   ctypes.c_uint64),
    ]


class Elf32SymbolEntry(binary.FlexibleCStruct):

    _fields_ = [
        ("nameIndex",       ctypes.c_uint32),
        ("address",         ctypes.c_uint32),
        ("size",            ctypes.c_uint32),
        ("type",            ctypes.c_uint8,     4),
        ("bind",            ctypes.c_uint8,     4),
        ("visibility",      ctypes.c_uint8,     2),
        ("padding",         ctypes.c_uint8,     6),
        ("sectionIndex",    ctypes.c_uint16),
    ]


class Elf64SymbolEntry(binary.FlexibleCStruct):

    _fields_ = [
        ("nameIndex",       ctypes.c_uint32),
        ("type",            ctypes.c_uint8,     4),
        ("bind",            ctypes.c_uint8,     4),
        ("visibility",      ctypes.c_uint8,     2),
        ("padding",         ctypes.c_uint8,     6),
        ("sectionIndex",    ctypes.c_uint16),
        ("address",         ctypes.c_uint64),
        ("size",            ctypes.c_uint64),
    ]


class Elf32Relocation(binary.FlexibleCStruct):

    _fields_ = [
        ("offset",      ctypes.c_uint32),
        ("type",        ctypes.c_uint32,     8),
        ("symbolIndex", ctypes.c_uint32,     24),
    ]


class Elf32RelocationAddend(Elf32Relocation):

    _fields_ = [
        ("addend",      ctypes.c_int32),
    ]


class Elf64Relocation(binary.FlexibleCStruct):

    _fields_ = [
        ("offset",      ctypes.c_uint64),
        ("type",        ctypes.c_uint64,     32),
        ("symbolIndex", ctypes.c_uint64,     32),
    ]


class Elf64RelocationAddend(Elf64Relocation):

    _fields_ = [
        ("addend",      ctypes.c_int64),
    ]


class ElfSection():

    def __init__ ( self, section, name=".null" ):

        self.__dict__.update(section.getDictionary())
        self.name = name

    def __repr__(self):

        return (
            f"name: {self.name}, "
            f"type: {SECTION_TYPE_STR[self.type]}, "
            f"flags: {self.flags}, "
            f"address: {hex(self.address)}, "
            f"fileOffset: {hex(self.fileOffset)}, "
            f"size: {self.size}, "
            f"link: {self.link}, "
            f"info: {self.info}, "
            f"alignment: {self.alignment}, "
            f"entrySize: {self.entrySize}, "
            f"nameIndex: {self.nameIndex}"
        )

class ElfSymbol( binary.Symbol ):

    def __init__( self, name, symbol ):

        # Set all values that the ctypes symbol had
        self.__dict__.update(symbol.getDictionary())

        # Reset all values based on the helper functions to make sure they are
        # set properly
        self.setName(name)
        self.setAddress(symbol.address)
        self.setSize(symbol.size)
        self.setType(symbol.type)
        self.setIsExternal(False)


    def __repr__(self):

        return (
            f"name: {self.getName()}, "
            f"address: {self.getAddress():0>8x}, "
            f"size: {self.getSize()}, "
            f"type: {SYMBOL_TYPE_STR[self.getType()]}, "
            f"bind: {SYMBOL_BIND_STR[self.bind]}, "
            f"visibility: {SYMBOL_VIS_STR[self.visibility]}, "
            f"section index: {self.sectionIndex}"
        )


class ElfFunction( binary.Function, ElfSymbol ):

    def __init__( self, name, function ):

        super().__init__(name, function)

        if self.type != SYMBOL_TYPE_FUNCTION:
            raise Exception("Cannot create an ElfFunction with a symbol type other than function")

        self.assembly = bytes() # Only used if the symbol is a function
        self.instructions = []  # Only used if the symbol is a function

    def __repr__( self ):

        return (
            f"{super().__repr__()}, "
            f"number of instructions: {len(self.instructions)}"
        )

