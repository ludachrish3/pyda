"""
Name:           executable.py

Description:    This file is responsible for determining the type of executable
                file and using the appropriate module for parsing its data.
"""

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

SYMBOL_TYPE_NONE     = "none"
SYMBOL_TYPE_GLOBAL   = "global"
SYMBOL_TYPE_FUNCTION = "function"
SYMBOL_TYPE_SECTION  = "section"

class Executable( abc.ABC ):

    @abc.abstractmethod
    def parse( self, exeMap ):
        """
        Parse a binary file to get its basic arch info, sections, and symbols.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def resolveExternalSymbols( self ):
        """
        Resolve any external symbols by binding their names to their addresses.
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


    def getSymbols( self, symbolType=None, byName=False ):
        """
        Description:    Retrieves all symbols for the executable. The list can
                        be filtered by symbol type to only retrieve all symbols
                        of a certain type. By default a dictionary of all
                        symbols is returned that contains keys for both the
                        names and addresses of all symbols.

        Arguments:      symbolType - The type of symbols to return. The default
                                     is None, which returns all symbol types.
                        byName     - Whether to only return symbols keyed on
                                     name instead of on name and address. The
                                     default is False, which returns all keys.

        Return:         Dictionary of symbols keyed on name and potentially
                        address if byName is False.

        """

        # By default, return all of the symbols
        if symbolType is None and not byName:

            return self._symbols

        # Return symbols by name. Look only for strings as key, and add them to
        # the dictionary of matching symbols if the symbol type matches.
        if byName:

            matchingSymbols = {}

            for name, symbol in self._symbols.items():

                if type(name) == str and symbol.getType() == symbolType:
                    matchingSymbols[name] = symbol

                # Add all symbols regardless of type if symbolType is None
                elif type(name) == str and symbolType is None:
                    matchingSymbols[name] = symbol

        # If symbols by address are requested, then look for only integers as
        # keys, and add them to the list of matching symbols if the symbol type
        # is available for the address.
        else:

            matchingSymbols = []

            for addr, types in self._symbols.items():

                if type(addr) == int and symbolType in types:
                    matchingSymbols.append(types[symbolType])

        return matchingSymbols


    def setStartAddr( self, startAddr ):

        if startAddr > 0:
            self._startAddr = startAddr


    def getStartAddr( self ):

        return self._startAddr

class Section (abc.ABC ):

    def __init__( self ):

        self._instructions = []

    def getBytes( self, start=None, end=None ):

        return self._bytes[start:end]

    def setBytes( self, sectionContent ):

        self._bytes = sectionContent

    def getInstructions( self ):

        return self._instructions

    def setInstructions( self, instructions ):

        self._instructions = instructions


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


    @abc.abstractmethod
    def setType ( self, symbolType ):
        """
        Set the type to be a generic type in the child class
        """
        raise NotImplementedError


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
    """
    This class is based on a ctypes Structure, but those cannot have additional
    fields. This way standard ELF structures can be extended for pyda purposes.
    """

    def getDictionary( self ):

        dictionary = {}

        # TODO: Make this more robust. Need to handle lists
        for field, *_  in self._fields_:

            value = getattr(self, field)
            dictionary[field] = value

        return dictionary


class AnalysisError( Exception ):
    pass


