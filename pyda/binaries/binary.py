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

class Binary( abc.ABC ):

    @abc.abstractmethod
    def analyze( self, exeMap ):
        """
        Parse a binary file to get its basic arch info, sections, and symbols.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def resolveExternalSymbols( self, exeMap ):
        """
        Resolve all external symbols if there are any.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def setArch( self, arch ):
        raise NotImplementedError

    @abc.abstractmethod
    def setEndianness( self, endianness ):
        raise NotImplementedError

    @abc.abstractmethod
    def setISA( self, isa ):
        raise NotImplementedError

    @abc.abstractmethod
    def getISA( self ):
        raise NotImplementedError


    def getSymbol( self, symbolIdentifier ):

        return self._symbols.get(symbolIdentifier, None)


    def getSymbols( self ):

        return self._symbols


    def setSymbol( self, symbol ):

        name    = symbol.getName()
        address = symbol.getAddress()

        if name not in [ None, "" ]:
            self._symbols[name] = symbol

        if address != 0:
            self._symbols[address] = symbol


    @abc.abstractmethod
    def getExecutableCode( self ):
        raise NotImplementedError

    @abc.abstractmethod
    def setStartAddr( self, startAddr ):
        raise NotImplementedError

    @abc.abstractmethod
    def getStartAddr( self ):
        raise NotImplementedError


class Symbol( abc.ABC ):

    def setName( self, name ):

        if len(name) == 0:
            self.name = None

        else:
            self.name = name


    def getName( self ):

        return self.name


    def setAddress( self, address ):

        self.address = address


    def getAddress( self ):

        return self.address


    def setSize( self, size ):

        self.size = size


    def getSize( self ):

        return self.size


    def setIsExternal( self, isExternal ):

        self.isExternal = isExternal


    def setIsExternal( self, isExternal ):

        self.isExternal = isExternal


    def getIsExternal( self ):

        return self.isExternal

    def __repr__( self ):

        return (
            f"name: {self.getName()}, "
            f"addr: 0x{self.getAddr():0>8x}, "
            f"size: {self.size}"
        )

class Function( Symbol ):

    def setInstructions( self, instructions ):

        self.instructions = instructions

    def getInstructions( self ):

        return self.instructions

    def setAssembly( self, assembly ):

        self.assembly = assembly

    def getAssembly( self ):

        return self.assembly


class AnalysisError( Exception ):
    pass


