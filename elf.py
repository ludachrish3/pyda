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
ELF_VERSION_NONE    = b'\x00'
ELF_VERSION_CURRENT = b'\x01'

# ELF operating system
ELF_OS_SYSTEM_V = '\x00'
ELF_OS_HP_UX    = '\x01'
ELF_OS_NET_BSD  = '\x02'
ELF_OS_LINUX    = '\x03'
ELF_OS_GNU_HURD = '\x04'
ELF_OS_SOLARIS  = '\x05'
ELF_OS_FREE_BSD = '\x08'
ELF_OS_OPEN_BSD = '\x0b'


# ELF file types
ELF_TYPE_NONE       = 0
ELF_TYPE_RELOC      = 1
ELF_TYPE_EXEC       = 2
ELF_TYPE_SHARED_OBJ = 3
ELF_TYPE_CORE       = 4

ELF_TYPE_RELOC_STR      = "relocatable"
ELF_TYPE_EXEC_STR       = "executable"
ELF_TYPE_SHARED_OBJ_STR = "shared object"

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


ELF_ISA_SPARC_STR       = "SPARC"
ELF_ISA_X86_STR         = "x86"
ELF_ISA_MIPS_STR        = "MIPS"
ELF_ISA_POWER_PC_STR    = "PowerPC"
ELF_ISA_POWER_PC_64_STR = "64-bit PowerPC"
ELF_ISA_ARM_STR         = "ARM"
ELF_ISA_SUPER_H_ST      = "SuperH"
ELF_ISA_IA_64_STR       = "Intel IA-64"
ELF_ISA_X86_64_STR      = "64-bit x86"


class ElfBinary(binary.Binary):

    def __init__(self):
        #TODO: Fill this with default values
        pass


    def __repr__(self):
        return "Architecture: {}\n".format(self.arch) + \
               "Endianness:   {}\n".format(self.endianness) + \
               "File Type:    {}\n".format(self.type) + \
               "ISA:          {}".format(self.isa)


    def bytesToInt(self, byteArray, signed=False):
        return int.from_bytes(byteArray, byteorder=self.getEndianness(), signed=signed)


    # Reads an integer value from a file
    def readInt(self, fd, size):
        return self.bytesToInt(fd.read(size))

    def getArch(self):
        return self.arch


    def getAddrSize(self):
        return self.addrSize

    def setArch(self, arch):

        if arch == ELF_ARCH_32BIT:
            self.arch = binary.BIN_ARCH_32BIT
            self.addrSize = 4

        elif arch == ELF_ARCH_64BIT:
            self.arch = binary.BIN_ARCH_64BIT
            self.addrSize = 8

        else:
            raise binary.AnalysisError("The architecture could not be determined: {}".format(arch))


    def getEndianness(self):
        return self.endianness


    def setEndianness(self, endianness):
        if endianness == ELF_ENDIAN_LITTLE:
            self.endianness = binary.BIN_ENDIAN_LITTLE

        elif endianness == ELF_ENDIAN_BIG:
            self.endianness = binary.BIN_ENDIAN_BIG

        else:
            raise binary.AnalysisError("The endianness could not be determined: {}".format(endianness))


    def setFileType(self, fileType):

        fileTypeVal = self.bytesToInt(fileType)

        if fileTypeVal == ELF_TYPE_EXEC:
            self.type = ELF_TYPE_EXEC_STR

        # TODO: Maybe implement support for this type
        elif fileTypeVal == ELF_TYPE_RELOC:
            self.type = ELF_TYPE_RELOC_STR
            raise NotImplementedError("Relocatable files are not supported")

        elif fileTypeVal == ELF_TYPE_SHARED_OBJ:
            self.type = ELF_TYPE_SHARED_OBJ_STR

        else:
            raise binary.AnalysisError("The ELF file type could not be determined: {}".format(fileTypeVal))


    def setISA(self, isa):
        
        isaVal = self.bytesToInt(isa)

        if isaVal == ELF_ISA_X86_64:
            self.isa = ELF_ISA_X86_64_STR

        elif isaVal == ELF_ISA_X86:
            self.isa = ELF_ISA_X86_STR
            raise NotImplementedError("32-bit x86 files are not supported")

        elif isaVal == ELF_ISA_ARM:
            self.isa = ELF_ISA_ARM_STR
            raise NotImplementedError("ARM files are not supported")
            
        elif isVal == ELF_ISA_SPARC:
            self.isa = ELF_ISA_SPARC_STR
            raise NotImplementedError("SPARC files are not supported")

        elif isVal == ELF_ISA_MIPS:
            self.isa = ELF_ISA_MIPS_STR
            raise NotImplementedError("MIPS files are not supported")

        elif isVal == ELF_ISA_POWER_PC_STR:
            self.isa = ELF_ISA_POWER_PC_STR
            raise NotImplementedError("PowerPC files are not supported")

        elif isVal == ELF_ISA_POWER_PC_64_STR:
            self.isa = ELF_ISA_POWER_PC_64_STR
            raise NotImplementedError("64-bit PowerPC files are not supported")

        elif isVal == ELF_ISA_IA_64:
            self.isa = ELF_ISA_IA_64_STR
            raise NotImplementedError("Intel IA-64 files are not supported")

        else:
            raise binary.AnalysisError("The ISA could not be determined: {}".format(isaVal))


    def setStartAddr(self, startAddr):
        
        self.startAddr = self.bytesToInt(startAddr)
        print("Start addr:            0x{0:0>8x}".format(self.startAddr))


    def setProgHdrOffset(self, progHdrOffset):

        self.progHdrOffset = self.bytesToInt(progHdrOffset)
        print("Program header offset: 0x{0:<8x}".format(self.progHdrOffset))


    def setSectionHdrOffset(self, sectionHdrOffset):

        self.sectionHdrOffset = self.bytesToInt(sectionHdrOffset)
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
        addrSize = self.getAddrSize()

        # Get endianness
        self.setEndianness(fd.read(1))
        
        # Get version number (currently not used by this module)
        fd.read(1)

        # Get the OS (not usually set, so not used by this module)
        fd.read(1)

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

        # Get the size of each program header entry
        self.setProgHdrEntrySize(fd.read(2))

        # Get the number of program header entries
        self.setNumProgHdrEntries(fd.read(2))

        # Get the size of each section header entry
        self.setSectionHdrEntrySize(fd.read(2))

        # Get the number of section header entries
        self.setNumSectionHdrEntries(fd.read(2))

        # Get the index of the section header that contains the section names
        self.setNameIndex(fd.read(2))

    def analyze(self, fd):

        # Parse the ELF header to get basic information about the file
        self.parseElfHeader(fd)
