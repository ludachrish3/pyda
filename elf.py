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
ELF_OS_NET_BSD = '\x02'
ELF_OS_LINUX = '\x03'
ELF_OS_GNU_HURD = '\x04'
ELF_OS_SOLARIS = '\x05'
ELF_OS_AIX = '\x06'
ELF_OS_IRIX = '\x07'
ELF_OS_FREE_BSD = '\x08'
ELF_OS_TRU_64 = '\x09'
ELF_OS_NOVELL_MODESTO = '\x0a'
ELF_OS_OPEN_BSD = '\x0b'
ELF_OS_OPEN_VMS = '\x0c'


# ELF file types
ELF_TYPE_NONE       = 0
ELF_TYPE_RELOC      = 1
ELF_TYPE_EXEC       = 2
ELF_TYPE_SHARED_OBJ = 3
ELF_TYPE_CORE       = 4

ELF_TYPE_RELOC_STR      = "relocatable"
ELF_TYPE_EXEC_STR       = "executable"
ELF_TYPE_SHARED_OBJ_STR = "shared object"

class ElfBinary(binary.Binary):

    def __init__(self):
        #TODO: Fill this with default values
        pass


    def __repr__(self):
        return "Architecture: {}\n".format(self.arch) + \
               "Endianness:   {}\n".format(self.endianness) + \
               "File Type:    {}".format(self.type)


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


    def bytesToInt(self, byteArray, signed=False):
        print(self.getEndianness())
        return int.from_bytes(byteArray, byteorder=self.getEndianness(), signed=signed)


    def setFileType(self, fileType):
        print("Setting the file type")

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
