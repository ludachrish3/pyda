import abc
import ctypes

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


    def getSymbol( self, symbolIdentifier, symbolType=None ):
        """
        Description:    Gets a symbol by its identifier. Looking up a symbol by
                        name only needs to be done using the symbolIdentifier.
                        Looking up a symbol by address will also require a type
                        to ensure the correct type of symbol is retrieved from
                        the address.

                        If there are no collisions at the address, then a type
                        is not required.

        Arguments:      symbolIdentifier    - Name or address of the symbol
                        symbolType          - Type of symbol, as defined by the
                                              executable

        Return:         Symbol object if one is found.
                        None if no object matches the identifier and/or type.
        """

        # There is a 1 to 1 mapping for symbol names and symbols, so just do a
        # simple dictionary lookup.
        if type(symbolIdentifier) == str:

            return self._symbols.get(symbolIdentifier, None)

        # Looking up a symbol by address can result in a collision if two
        # symbols happen to have the same address, like if a function beings at
        # the start of a code section. This is resolved by also looking up the
        # symbol by type, which is executable-defined.
        if type(symbolIdentifier) == int:

            symbolTypeDict = self._symbols.get(symbolIdentifier, None)

            if symbolTypeDict is not None:

                # Have a shortcut to lookup symbols using an address if there is
                # only one symbol at the address. This way a type is not needed
                # if there are no collisions. dict.items() returns a tuple of
                # the key and the value, so indexing to the zeroth entry gets
                # the first key value pair, and the first index of that gets
                # the value, which is the symbol.
                if symbolType is None and len(symbolTypeDict) == 1:

                    return list(symbolTypeDict.items())[0][1]

                else:

                    return symbolTypeDict.get(symbolType, None)

        return None


    def setSymbol( self, symbol ):
        """
        Description:    Adds or replaces a symbol to the symbol dictionary. An
                        entry is created by name and by address. When adding a
                        symbol by address, the type is used to create an entry
                        in a sub-dictionary so that symbols at the same address
                        can be differentiated.

        Arguments:      symbol  - Symbol object

        Return:         None
        """

        name       = symbol.getName()
        address    = symbol.getAddress()
        symbolType = symbol.getType()

        if name not in [ None, "" ]:

            self._symbols[name] = symbol

        if address != 0:

            if address not in self._symbols:
                self._symbols[address] = {symbolType: symbol}

            else:
                self._symbols[address][symbolType] = symbol


    def getSymbols( self ):

        return self._symbols


    @abc.abstractmethod
    def getExecutableCode( self ):
        raise NotImplementedError


    def setStartAddr( self, startAddr ):

        if startAddr > 0:
            self._startAddr = startAddr


    def getStartAddr( self ):

        return self._startAddr


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


    def setType ( self, symbolType ):

        self.type = symbolType


    def getType ( self ):

        return self.type


    def setIsExternal( self, isExternal ):

        self.isExternal = isExternal


    def getIsExternal( self ):

        return self.isExternal

    def __repr__( self ):

        return (
            f"name: {self.getName()}, "
            f"addr: 0x{self.getAddress():0>8x}, "
            f"size: {self.getSize()}"
        )

class Function( Symbol ):

    def setInstructions( self, instructions ):

        self.instructions = instructions


    def getInstructions( self ):

        return self.instructions


    def setFileOffset( self, offset ):

        self.fileOffset = offset


    def getFileOffset( self ):

        return self.fileOffset


class FlexibleCStruct(ctypes.Structure):

    def getDictionary( self ):

        dictionary = {}

        # TODO: Make this more robust. Need to handle lists
        for field, *_  in self._fields_:

            value = getattr(self, field)
            dictionary[field] = value

        return dictionary


class AnalysisError( Exception ):
    pass


