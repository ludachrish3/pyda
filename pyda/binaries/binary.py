import abc

BIN_ARCH_32BIT = "32-bit"
BIN_ARCH_64BIT = "64-bit"

ISA_X86_64      = "64-bit x86"
ISA_X86         = "x86"
ISA_ARM         = "ARM"
ISA_SPARC       = "SPARC"
ISA_POWER_PC    = "PowerPC"
ISA_POWER_PC_64 = "64-bit PowerPC"
ISA_MIPS        = "MIPS"
ISA_SUPER_H     = "SuperH"
ISA_IA_64       = "Intel IA-64"

BIN_ENDIAN_LITTLE = "little"
BIN_ENDIAN_BIG    = "big"

class Binary(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def analyze(self, fd):
        """
        Parse a binary file to get its basic arch info and sections
        """
        pass

    @abc.abstractmethod
    def setArch(self, arch):
        pass

    @abc.abstractmethod
    def setEndianness(self, endianness):
        pass

    @abc.abstractmethod
    def setISA(self, isa):
        pass

    @abc.abstractmethod
    def getISA(self):
        pass

    @abc.abstractmethod
    def getFunctionByName(self, name):
        pass

    @abc.abstractmethod
    def getFunctionByAddr(self, addr):
        pass

    @abc.abstractmethod
    def getExecutableCode(self):
        pass


class Function():

    def __init__(self, name, addr, size, assembly):

        self.name         = name
        self.addr         = addr
        self.size         = size
        self.assembly     = assembly
        self.instructions = []

    def __repr__(self):

        return "{{name: {},".format(self.name) \
             + " addr: 0x{0:0>8x},".format(self.addr)  \
             + " size: {}}}".format(self.size)

class AnalysisError(Exception):
    pass


