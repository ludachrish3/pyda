import binary

# ELF architecture type
ELF_ARCH_NONE  = b'\x00'
ELF_ARCH_32BIT = b'\x01'
ELF_ARCH_64BIT = b'\x02'

# ELF endianness
ELF_ENDIAN_NONE   = b'\x00'
ELF_ENDIAN_LITTLE = b'\x01'
ELF_ENDIAN_BIG    = b'\x02'

# ELF version number
ELF_VERSION_NONE    = 0
ELF_VERSION_CURRENT = 1

# ELF operating system
ELF_OS_SYSTEM_V = 0
ELF_OS_HP_UX    = 1
ELF_OS_NET_BSD  = 2
ELF_OS_LINUX    = 3
ELF_OS_GNU_HURD = 4
ELF_OS_SOLARIS  = 5
ELF_OS_FREE_BSD = 8
ELF_OS_OPEN_BSD = 11

ELF_OS_STR = {
    ELF_OS_SYSTEM_V: "System V",
    ELF_OS_HP_UX:    "HP-US",
    ELF_OS_NET_BSD:  "NetBSD",
    ELF_OS_LINUX:    "Linux",
    ELF_OS_GNU_HURD: "GNU Hurd",
    ELF_OS_SOLARIS:  "Solaris",
    ELF_OS_FREE_BSD: "FreeBSD",
    ELF_OS_OPEN_BSD: "OpenBSD",
}


# ELF file types
ELF_TYPE_NONE       = 0
ELF_TYPE_RELOC      = 1
ELF_TYPE_EXEC       = 2
ELF_TYPE_SHARED_OBJ = 3
ELF_TYPE_CORE       = 4

ALLOWED_ELF_TYPES = [
    ELF_TYPE_NONE,
    ELF_TYPE_RELOC,
    ELF_TYPE_EXEC,
    ELF_TYPE_SHARED_OBJ,
    ELF_TYPE_CORE,
]

ELF_TYPE_STR = {
    ELF_TYPE_RELOC:      "relocatable",
    ELF_TYPE_EXEC:       "executable",
    ELF_TYPE_SHARED_OBJ: "shared object",
    ELF_TYPE_CORE:       "core",
}

ELF_ISA_NONE        = 0x00
ELF_ISA_SPARC       = 0x02
ELF_ISA_X86         = 0x03
ELF_ISA_MIPS        = 0x08
ELF_ISA_POWER_PC    = 0x14
ELF_ISA_POWER_PC_64 = 0x15
ELF_ISA_ARM         = 0x28
ELF_ISA_SUPER_H     = 0x2a
ELF_ISA_IA_64       = 0x32
ELF_ISA_X86_64      = 0x3e

ALLOWED_ELF_ISAS = [
    ELF_ISA_SPARC,
    ELF_ISA_X86,
    ELF_ISA_MIPS,
    ELF_ISA_POWER_PC,
    ELF_ISA_POWER_PC_64,
    ELF_ISA_ARM,
    ELF_ISA_SUPER_H,
    ELF_ISA_IA_64,
    ELF_ISA_X86_64,
]

ELF_ISA_STR = {
    ELF_ISA_SPARC:       "SPARC",
    ELF_ISA_X86:         "x86",
    ELF_ISA_MIPS:        "MIPS",
    ELF_ISA_POWER_PC:    "PowerPC",
    ELF_ISA_POWER_PC_64: "64-bit PowerPC",
    ELF_ISA_ARM:         "ARM",
    ELF_ISA_SUPER_H:     "SuperH",
    ELF_ISA_IA_64:       "Intel IA-64",
    ELF_ISA_X86_64:      "64-bit x86",
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

class ElfBinary(binary.Binary):

    def __init__(self):
        #TODO: Fill this with default values
        self.segments = []
        self.sections = []


    def __repr__(self):
        return "Architecture: {}\n".format(self.arch) + \
               "Endianness:   {}\n".format(self.endianness) + \
               "File Type:    {}\n".format(ELF_TYPE_STR[self.type]) + \
               "ISA:          {}".format(ELF_ISA_STR[self.isa])


    def bytesToInt(self, byteArray, signed=False):

        return int.from_bytes(byteArray, byteorder=self.endianness, signed=signed)


    # Reads an integer value from a file
    def readInt(self, fd, size):

        return self.bytesToInt(fd.read(size))


    def setArch(self, arch):

        if arch == ELF_ARCH_32BIT:
            self.arch = binary.BIN_ARCH_32BIT
            self.addrSize = 4

        elif arch == ELF_ARCH_64BIT:
            self.arch = binary.BIN_ARCH_64BIT
            self.addrSize = 8

        else:
            raise binary.AnalysisError("The architecture could not be determined: {}".format(arch))


    def setEndianness(self, endianness):
        if endianness == ELF_ENDIAN_LITTLE:
            self.endianness = binary.BIN_ENDIAN_LITTLE

        elif endianness == ELF_ENDIAN_BIG:
            self.endianness = binary.BIN_ENDIAN_BIG

        else:
            raise binary.AnalysisError("The endianness could not be determined: {}".format(endianness))


    def setFileType(self, fileType):

        fileTypeVal = self.bytesToInt(fileType)

        # Make sure that the file type is one of the defined types
        if fileTypeVal not in ALLOWED_ELF_TYPES:
            raise binary.AnalysisError("The ELF file type could not be determined: {}".format(fileTypeVal))

        # Do not allow relocatable files for now because they are not supported
        if fileTypeVal == ELF_TYPE_RELOC:
            raise NotImplementedError("Relocatable files are not supported")

        self.type = fileTypeVal


    def setISA(self, isa):
        
        isaVal = self.bytesToInt(isa)

        if isaVal not in ALLOWED_ELF_ISAS:
            raise binary.AnalysisError("The ISA could not be determined: {}".format(isaVal))

        # Many ISAs are not currently suported, so throw exceptions for them
        if isaVal == ELF_ISA_X86:
            raise NotImplementedError("32-bit x86 files are not supported")

        elif isaVal == ELF_ISA_ARM:
            raise NotImplementedError("ARM files are not supported")
            
        elif isaVal == ELF_ISA_SPARC:
            raise NotImplementedError("SPARC files are not supported")

        elif isaVal == ELF_ISA_MIPS:
            raise NotImplementedError("MIPS files are not supported")

        elif isaVal == ELF_ISA_POWER_PC:
            raise NotImplementedError("PowerPC files are not supported")

        elif isaVal == ELF_ISA_POWER_PC_64:
            raise NotImplementedError("64-bit PowerPC files are not supported")

        elif isaVal == ELF_ISA_IA_64:
            raise NotImplementedError("Intel IA-64 files are not supported")

        self.isa = isaVal

    def setStartAddr(self, startAddr):
        
        self.startAddr = self.bytesToInt(startAddr)
        print("Start addr:            0x{0:0>8x}".format(self.startAddr))


    def setProgHdrOffset(self, offset):

        self.progHdrOffset = self.bytesToInt(offset)
        print("Program header offset: 0x{0:<8x}".format(self.progHdrOffset))


    def setSectionHdrOffset(self, offset):

        self.sectionHdrOffset = self.bytesToInt(offset)
        print("Section header offset: 0x{0:<8x}".format(self.sectionHdrOffset))

    def setFlags(self, flags):

        self.flags = self.bytesToInt(flags)

        if self.flags != 0:
            raise binary.AnalysisError("Flags were set for the architecture, but they cannot be handled: {0:<8}".format(self.flags))


    def setElfHdrSize(self, hdrSize):

        self.elfHdrSize = self.bytesToInt(hdrSize)
        print("ELF header size: {}".format(self.elfHdrSize))


    def setProgHdrEntrySize(self, entrySize):

        self.progHdrEntrySize = self.bytesToInt(entrySize)
        print("Program header entry size: {}".format(self.progHdrEntrySize))

    def setNumProgHdrEntries(self, numEntries):

        self.numProgHdrEntries = self.bytesToInt(numEntries)
        print("Number of program header entries: {}".format(self.numProgHdrEntries))


    def setSectionHdrEntrySize(self, entrySize):

        self.sectionHdrEntrySize = self.bytesToInt(entrySize)
        print("Section header entry size: {}".format(self.sectionHdrEntrySize))


    def setNumSectionHdrEntries(self, numEntries):

        self.numSectionHdrEntries = self.bytesToInt(numEntries)
        print("Number of section header entries: {}".format(self.numSectionHdrEntries))


    def setNameIndex(self, index):

        self.nameIndex = self.bytesToInt(index)
        print("Index of the section that contains the section names: {}".format(self.nameIndex))


    def parseElfHeader(self, fd):

        # Skip over the magic number because it was already used
        fd.read(4)
        
        # Get the architecture
        self.setArch(fd.read(1))

        # Now that the architecture is known, save a local copy of the number of
        # bytes in an address
        addrSize = self.addrSize

        # Get endianness
        self.setEndianness(fd.read(1))
        
        # Get the ELF version number. The only allowed value is the most current
        # value. Anything else is considered an error.
        elfVersion = self.readInt(fd, 1)
        if elfVersion != ELF_VERSION_CURRENT:
            raise binary.AnalysisError("An invalid ELF version number was found: {}".format(elfVersion))

        # Get the OS (not usually set, so not used by this module)
        fileOs = self.readInt(fd, 1)
        if fileOs != 0:
            raise NotImplementedError("The OS is not supported: {}".format(ELF_OS_STR[fileOs]))

        # Skip over the padding bytes
        fd.read(8)

        # Get the type of file, like executable or shared object
        self.setFileType(fd.read(2))

        # Get the ISA
        self.setISA(fd.read(2))

        # Get the ELF version (currently not used by this module)
        fd.read(1)

        # Skip over some more padding bytes
        fd.read(3)

        # Get the starting virtual address for the program. The size of the
        #starting address varies based on the system's architecture.
        self.setStartAddr(fd.read(addrSize))

        # Get the start of the program header table in the file
        self.setProgHdrOffset(fd.read(addrSize))

        # Get the start of the section header table in the file
        self.setSectionHdrOffset(fd.read(addrSize))

        # Get the flags for the architecture
        self.setFlags(fd.read(4))

        # Get the size of the ELF header
        self.setElfHdrSize(fd.read(2))

        # Get info about the program header
        self.setProgHdrEntrySize(fd.read(2))
        self.setNumProgHdrEntries(fd.read(2))

        # Get info about the section header
        self.setSectionHdrEntrySize(fd.read(2))
        self.setNumSectionHdrEntries(fd.read(2))

        # Get the index of the section header that contains the section names
        self.setNameIndex(fd.read(2))


    def parseProgHdrs(self, fd):

        # Save a local copy of the number of bytes in an address
        addrSize = self.addrSize

        # Set the position in the file to the beginning of the program header
        fd.seek(self.progHdrOffset)

        for entry in range(self.numProgHdrEntries):

            segmentType = self.readInt(fd, 4)

            newSegment = ElfSegment(segmentType)

            # The 32- and 64-bit formats have slightly different orders. The
            # only difference between the two is the position of the flags
            # field, so a deviation can be made for just this field based on
            # the architecture when it is appropriate.
            if self.arch == binary.BIN_ARCH_64BIT:
                newSegment.flags = self.readInt(fd, 4)

            newSegment.offset       = self.readInt(fd, addrSize)
            newSegment.virtualAddr  = self.readInt(fd, addrSize)
            newSegment.physicalAddr = self.readInt(fd, addrSize)
            newSegment.fileSize     = self.readInt(fd, addrSize)
            newSegment.memorySize   = self.readInt(fd, addrSize)
                
            # Now is the appropriate time to check for the flags field if the
            # architecture is 32-bit.
            if self.arch == binary.BIN_ARCH_32BIT:
                newSegment.flags = self.readInt(fd, 4)

            newSegment.alignment = self.readInt(fd, addrSize)

            print("Segment [{}]: {}".format(entry, newSegment))
            
            self.segments.append(newSegment)

    def parseSectionHdrs(self, fd):

        # Save a local copy of the number of bytes in an address
        addrSize = self.addrSize

        # Set the position in the file to the beginning of the program header
        fd.seek(self.sectionHdrOffset)

        for entry in range(self.numSectionHdrEntries):

            sectionNameIndex = self.readInt(fd, 4)
            sectionType = self.readInt(fd, 4)

            newSection = ElfSection(sectionType, sectionNameIndex)

            newSection.flags = self.readInt(fd, addrSize)
            newSection.virtualAddr = self.readInt(fd, addrSize)
            newSection.fileOffset = self.readInt(fd, addrSize)
            newSection.fileSize = self.readInt(fd, addrSize)
            newSection.link = self.readInt(fd, 4)
            newSection.info = self.readInt(fd, 4)
            newSection.alignment = self.readInt(fd, addrSize)
            newSection.entrySize = self.readInt(fd, addrSize)

            self.sections.append(newSection)
            print("Section [{}]: {}".format(entry, newSection))

        # TODO: Assign the section names now that all sections have been parsed
        

    def analyze(self, fd):

        # Parse the ELF header to get basic information about the file
        self.parseElfHeader(fd)

        # TODO: Maybe don't do this because the info might be all in the sections
        # Handle the program headers if there are any
        if self.progHdrOffset > 0:
            self.parseProgHdrs(fd)

        # TODO: Handle sections
        self.parseSectionHdrs(fd)


class ElfSegment():

    def __init__(self, segmentType):
        
        if segmentType in ALLOWED_SEGMENT_TYPES:
            self._type = segmentType

        else:
            raise binary.AnalysisError("An invalid segment type was found: {}".format(segmentType))

        self.flags        = 0
        self.offset       = 0
        self.virtualAddr  = 0
        self.physicalAddr = 0
        self.fileSize     = 0
        self.memorySize   = 0
        self.alignment   = 0

    def __repr__(self):

        return "{{type: {},".format(SEGMENT_TYPE_STR[self._type]) \
             + " flags: {},".format(self.flags)                   \
             + " offset: {},".format(self.offset)                 \
             + " virtualAddr: {},".format(self.virtualAddr)       \
             + " physicalAddr: {},".format(self.physicalAddr)     \
             + " fileSize: {},".format(self.fileSize)             \
             + " memorySize: {},".format(self.memorySize)         \
             + " alignment: {}}}".format(self.alignment)


class ElfSection():

    def __init__(self, sectionType, name=".null", nameIndex=0):

        if sectionType in ALLOWED_SECTION_TYPES:
            self._type = sectionType

        else:
            raise binary.AnalysisError("An invalid section type was found: {}".format(sectionType))

        self._nameIndex  = nameIndex
        self.name        = name
        self.flags       = 0
        self.virtualAddr = 0
        self.fileOffset  = 0
        self.fileSize    = 0
        self.link        = 0
        self.info        = 0
        self.alignment   = 0
        self.entrySize   = 0


    def __repr__(self):
        return "{{type: {},".format(SECTION_TYPE_STR[self._type]) \
             + " name: {},".format(self.name)                     \
             + " flags: {},".format(self.flags)                   \
             + " virtualAddr: {},".format(self.virtualAddr)       \
             + " fileOffset: {},".format(self.fileOffset)         \
             + " fileSize: {},".format(self.fileSize)             \
             + " link: {},".format(self.link)                     \
             + " info: {},".format(self.info)                     \
             + " alignment: {}}}".format(self.alignment)          \
             + " entrySize: {}}}".format(self.entrySize)

