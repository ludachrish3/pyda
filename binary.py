import abc

BIN_ARCH_32BIT = "32-bit"
BIN_ARCH_64BIT = "64-bit"

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

class AnalysisError(Exception):
    pass


