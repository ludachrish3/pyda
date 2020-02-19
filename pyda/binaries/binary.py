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

class Binary(abc.ABC):

    @abc.abstractmethod
    def analyze(self, exeMap):
        """
        Parse a binary file to get its basic arch info, sections, and symbols.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def resolveExternalSymbols(self, exeMap):
        """
        Resolve all external symbols if there are any.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def setArch(self, arch):
        raise NotImplementedError

    @abc.abstractmethod
    def setEndianness(self, endianness):
        raise NotImplementedError

    @abc.abstractmethod
    def setISA(self, isa):
        raise NotImplementedError

    @abc.abstractmethod
    def getISA(self):
        raise NotImplementedError

    @abc.abstractmethod
    def getFunctionByName(self, name):
        raise NotImplementedError

    @abc.abstractmethod
    def getFunctionByAddr(self, addr):
        raise NotImplementedError

    @abc.abstractmethod
    def getExecutableCode(self):
        raise NotImplementedError

    @abc.abstractmethod
    def setStartAddr(self, startAddr):
        raise NotImplementedError

    @abc.abstractmethod
    def getStartAddr(self):
        raise NotImplementedError


class Symbol(abc.ABC):

    @abc.abstractmethod
    def setName(self, name):
        raise NotImplementedError

    @abc.abstractmethod
    def getName(self):
        raise NotImplementedError

    @abc.abstractmethod
    def setAddress(self, address):
        raise NotImplementedError

    @abc.abstractmethod
    def getAddress(self):
        raise NotImplementedError

    @abc.abstractmethod
    def setSize(self, size):
        raise NotImplementedError

    @abc.abstractmethod
    def getSize(self):
        raise NotImplementedError

    @abc.abstractmethod
    def setIsExternal(self, isExternal):
        raise NotImplementedError

    @abc.abstractmethod
    def getIsExternal(self):
        raise NotImplementedError

    def __repr__(self):

        return (
            f"name: {self.getName()}, "
            f"addr: 0x{self.getAddr():0>8x}, "
            f"size: {self.size}"
        )

class AnalysisError(Exception):
    pass


