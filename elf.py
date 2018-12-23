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


    def getArch(self):
        return self.arch


    def setArch(self, arch):

        if arch == ELF_ARCH_32BIT:
            self.arch = binary.BIN_ARCH_32BIT

        elif arch == ELF_ARCH_64BIT:
            self.arch = binary.BIN_ARCH_64BIT

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


    def setISA(self, isa):
        # TODO: Make this a required function in the abstract class
        
        isaVal = self.bytesToInt(isa)

        if isaVal == ELF_ISA_X86_64:
            self.isa = ELF_ISA_X86_64_STR

        elif isaVal == ELF_ISA_X86:
            self.isa = ELF_ISA_X86_STR
            raise NotImplementedError("32-bit x86 files are not supported")

        elif isaVal == ELF_ISA_ARM:
            self.isa = ELF_ISA_ARM_STR
            raise NotImplementedError("ARM files are not supported")
            
        # TODO: Fill out cases for all other defined types at the top of this file

        else:
            raise binary.AnalysisError("The ISA could not be determined: {}".format(isaVal))


    def bytesToInt(self, byteArray, signed=False):
        return int.from_bytes(byteArray, byteorder=self.getEndianness(), signed=signed)


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


    def analyze(self, fd):
        # Skip over the magic number because it was already used
        fd.read(4)
        
        # Get the architecture
        self.setArch(fd.read(1))

        # Get endianness
        self.setEndianness(fd.read(1))
        
        # Get version number (currently not used)
        fd.read(1)

        # Get the OS (not usually set, so not used)
        fd.read(1)

        # Skip over the padding bytes
        fd.read(8)

        # Get the type of file, like executable or shared object
        self.setFileType(fd.read(2))

        # Get the ISA
        self.setISA(fd.read(2))
