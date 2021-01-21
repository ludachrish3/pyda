from pyda.disassemblers.disassembler import Instruction, Operand
from pyda.disassemblers.x86_64.definitions import *

import math
import copy
import logging

logger = logging.getLogger(__name__)

class X86_64Instruction( Instruction ):

    def __init__( self, mnemonic="byte", addr=0, operands=[], exchange=False, destIsAlsoSource=True ):

        super().__init__(mnemonic, addr, operands, exchange, destIsAlsoSource)

        # Set defaults for all values
        self.sizePrefix    = None   # The size operands should be based on the prefix
        self.segmentPrefix = 0      # Opcode of the segment
        self.legacyPrefix  = None   # Lock, repeat, or operand size prefix
        self.addressSize   = REG_SIZE_64
        self.hasModRm      = False
        self.extendBase    = False
        self.extendIndex   = False
        self.extendReg     = False


    def setAttributes( self, opcode, info ):

        # Create deep copies so that the dictionary of infos remains unchanged
        # and this specific instruction's info can be updated as needed.
        self.info = copy.deepcopy(info)
        self.mnemonic = copy.deepcopy(info.mnemonic)

        logger.debug(f"ops:  {self.info.operandKwargs}")
        logger.debug(f"inst: {self.info.instKwargs}")

        info = self.info
        opKwargs  = info.operandKwargs

        # Update instruction attributes based on the instruction kwargs
        self.__dict__.update(info.instKwargs)

        ############################
        #  HANDLE LEGACY PREFIXES  #
        ############################

        # Handle renaming the mnemonic for Group 1 prefixes
        # TODO: There are special cases for some of these, so that will need to
        # be handled in the future.
        if self.legacyPrefix == PREFIX_LOCK:
            self.mnemonic = "lock " + self.mnemonic

        elif self.legacyPrefix == PREFIX_REPEAT_NZERO:
            self.mnemonic = "repnz " + self.mnemonic

        elif self.legacyPrefix == PREFIX_REPEAT_ZERO:
            self.mnemonic = "repz " + self.mnemonic

        #####################
        #  CREATE OPERANDS  #
        #####################

        for curKwargs in opKwargs:

            # Determine the size of each operand
            size    = curKwargs.get("size",    None)
            maxSize = curKwargs.get("maxSize", REG_SIZE_128)
            curKwargs["size"] = self.getOperandSize(opcode, self.sizePrefix, size, maxSize)

            # If this operand gets its value from the opcode
            valueIsOpcodeRegVal = curKwargs.get("opcodeRegVal", False)
            if valueIsOpcodeRegVal:
                curKwargs["value"] = opcode & OP_REG_MASK

            logger.debug(f"operand kwargs: {curKwargs}")

            self.operands.append(X86_64Operand(**curKwargs))


    @classmethod
    def getOperandSize( cls, opcode, sizePrefix, infoSize, maxSize ):
        """
        Description:    Figures out what the operand size should be based on the
                        opcode, the size of the instruction if one was set by a
                        prefix byte, and the info from the opcode dictionary.

                        The size of the operands because of a prefix is used if one
                        was found and neither the info nor the size bit indicate
                        that the size should be 8 bits.

                        Next, the value in the info dictionary should be used if given
                        because it is an override of the normal behavior.

                        Otherwise, the size bit is used to choose between an 8 bits
                        if it is not set or 32 bit if the bit is set.

                        The reason this works is because based on looking for
                        patterns in the opcodes, it seems like the size bit is
                        almost always present. If it is and it is 0, then the
                        operand is 8 bits and cannot be changed. For any cases that
                        this does not hold true, the info for the opcode should
                        provide an override size for the operand so that it can
                        either be that value or be affected by prefix bytes.

        Arguments:      opcode     - The instruction opcode
                        sizePrefix - The size based on a prefix byte
                        infoSize   - The size from the table of opcodes
                        maxSize    - The maximum allowed size for the operand

        Return:         The size that should be used for the operand.
        """

        sizeBit = opcode & OP_SIZE_MASK

        logger.debug(f"sizePrefix: {sizePrefix}, infoSize: {infoSize}, maxSize: {maxSize}, sizeBit: {sizeBit}")

        # If the REX 8-bit prefix is not there, then the size remains the normal
        # 8-bit register. Also, if there is no infoSize and the size bit is 0, the
        # operand is 8 bits. The REX 8-bit prefix only applies in these cases.
        if infoSize == REG_SIZE_8 or (infoSize is None and sizeBit == 0):
            if sizePrefix == REG_SIZE_8_REX:
                return REG_SIZE_8_REX

            return REG_SIZE_8

        # A register with an info size of 128 bits will always be that size
        # unless the maximum size is limiting it.
        if infoSize == REG_SIZE_128:
            return maxSize

        # The REX 8-bit prefix has no effect if the operand isn't originally 8 bits
        if sizePrefix == REG_SIZE_8_REX:
            sizePrefix = None

        # If there is a prefix size within the allowed range and there is no info
        # size override, trust the size bit to determine the default size of the
        # operand. If the bit is 0, then the operand is 8 bits and cannot be changed
        # Or if an info size is specified because then the size bit doesn't matter.
        if sizePrefix is not None and sizePrefix <= maxSize:
            size = sizePrefix

        elif infoSize is not None and infoSize <= maxSize:
            size = infoSize

        elif infoSize is not None and infoSize > maxSize:
            size = maxSize

        elif infoSize is None and sizeBit == 0:
            return REG_SIZE_8

        elif infoSize is None and sizeBit == 1:
            size = REG_SIZE_32

        # If the info size somehow exceeds the maximum, use the maximum instead
        # because the size bit shold not be used if an info size was specified.
        if size > maxSize:
            logger.debug("Capping to max size")
            size = maxSize

        return size


class X86_64Operand( Operand ):

    def __init__( self, value=0, size=REG_SIZE_32, maxSize=REG_SIZE_64, segmentReg=0,
                  isDestination=False, modRm=False, reg=False, isOffset=False, isSigned=False,
                  isImmediate=False, indirect=False, opcodeRegVal=False, mmRegister=False, floatReg=False ):

        super().__init__(size, value, isDestination)
        self.maxSize = maxSize              # The maximum size allowed for the operand
        self.modRm = modRm                  # Whether the operand uses the Mod R/M values in the Mod R/M byte
        self.reg   = reg                    # Whether the operand uses the Reg value in the Mod R/M byte
        self.isOffset = isOffset            # Whether the operand is an offset from the end of the instruction
        self.isImmediate = isImmediate      # Whether the operand is an immediate
        self.segmentReg = segmentReg        # The segment register to use as a base value
        self.opcodeRegVal = opcodeRegVal    # Whether the operand gets its value from the opcode
        self.mmRegister = mmRegister        # Whether the operand is an MM register
        self.floatReg = floatReg            # Whether the operand is a floating point register
        self.indirect = indirect            # Whether the addressing is indirect
        self.displacement = 0               # Value of the displacement from the register value
        self.scale = 0                      # Factor to multiply the index by if SIB byte is present
        self.index = None                   # Index register if SIB byte is present


    def __repr__( self ):

        value    = self.value
        scale    = self.scale
        index    = self.index
        displace = self.displacement

        if self.isImmediate and value is not None:
            return f"{hex(value)}"

        # If the register is a floating point one, it cannot actually be
        # indirect even if a Mod R/M byte had an indirect addressing mode.
        if self.value is not None and (self.value & REG_FLOAT) == REG_FLOAT:
            self.indirect = False

        if not self.indirect:
            regName = REG_NAMES[value][self.size]
            return regName

        # If this is an indirect value, use the name of the 64 bit register
        regName      = ""
        indexName    = ""
        scaleStr     = ""
        segmentStr   = ""
        displaceStr  = ""
        baseIndexStr = ""

        # Use a different syntax for segment registers because they are just a
        # segment name with a displacement separated by a colon.
        if self.segmentReg in SEGMENT_REG_NAMES:
            segmentStr = f"{SEGMENT_REG_NAMES[self.segmentReg]}:"

        # If the value was not changed to None because of SIB displacement,
        # set it to the name according to the register name dictionary.
        if value is not None:
            regName    = REG_NAMES[value][REG_SIZE_64]

        # There is only an index if the scale was set to be nonzero
        if scale > 0 and index is not None:
            indexName  = REG_NAMES[index][REG_SIZE_64]

        # Handle the scale and index values. They should only be there if
        # scale is greater than 0 and the index has a valid name. It will not
        # have a valid name if it is RSP because that is not a valid index.
        if scale > 0 and indexName != "":

            # Only print the scale value if it is not 1 to make it more clean
            if scale > 1:
                scaleStr = f"{scale} * "

        # Handle the displacement value
        if displace != 0:

            if displace > 0:
                signStr = " + "

            elif displace < 0:
                signStr = " - "

            displaceStr = f"{signStr}{hex(abs(displace))}"

        # Handle combining the base and index values. If at least one value is
        # not an empty string, then the values need to go in brackets. If both
        # are set, then they need to be separated by a plus sign. If only one is
        # set, then just putting them all next to each other in brackets is okay
        # because one will be nothing and the other will be the only value.
        if regName != "" or indexName != "":

            if regName != "" and indexName != "":
                baseIndexStr = f"[{regName} + {scaleStr}{indexName}{displaceStr}]"

            else:
                baseIndexStr = f"[{regName}{scaleStr}{indexName}{displaceStr}]"

        # If neither the register name nor the index name are present, then the
        # result is just the displacment, which does not need square brackets
        # around it or any kind of spacing around the sign.
        else:
            baseIndexStr = f"{hex(displace)}"

        return f"{segmentStr}{baseIndexStr}"


class X86_64InstructionInfo():

    def __init__( self, mnemonic, extOpcode=False, destinations=[0], numOperands=2,
                  **kwargs):

        # Opcode info
        self.mnemonic      = mnemonic       # The name of the instruction
        self.extOpcode     = extOpcode      # Whether the opcode is extended into the ModR/M

        self.instKwargs = { key.split("_")[0]: value for (key, value) in kwargs.items() if key.endswith("_inst") }
        self.operandKwargs = []

        # If there are no operands, then make sure the list of destinations is
        # empty. There can't be destinations if there are no operands. The
        # opposite is not true, however, so a lack of destinations does not
        # imply that there are no operands.
        if numOperands == 0:
            destinations = []

        for operandIndex in range(numOperands):

            # Create a list of kwargs dictionaries for each operand
            self.operandKwargs.append({ key.split("_")[0]: value for (key, value) in kwargs.items() if key.endswith((f"_{operandIndex}", "_op")) })

            curKwargs = self.operandKwargs[operandIndex]
            if "modRm" in curKwargs or "reg" in curKwargs:
                self.instKwargs["hasModRm"] = True

            logger.debug(f"operand kwargs #{operandIndex}: {self.operandKwargs[operandIndex]}")

        # Operands with an index in destinations gets the isDestination value
        # set to True
        for dest in destinations:
            self.operandKwargs[dest]["isDestination"] = True


# The structure for opcodes and their info is a dictionary keyed on the primary
# opcode. If there are any prefixes that change the opcode's meaning or
# secondary opcodes, there are nested dictionaries to handle these cases.
# Finally, there is a layer of dictionaries for extended opcodes. They are keyed
# on the Op value of the Mod R/M byte. If needed, the Mode field is used to
# determine which addressing mode is used, which sometimes changes the info that
# should be used. The structure is the following if there are secondary opcodes:
#   primaryOpcode: {
#       secondaryOpcode1: {
#           None:    X86_64InstructionInfo(...),
#           prefix1: X86_64InstructionInfo(...),
#           prefix2: X86_64InstructionInfo(...),
#           prefix3: {
#               extendedOpcode1: {
#                   None:       X86_64InstructionInfo(...),
#                   MOD_DIRECT: X86_64InstructionInfo(...),
#               },
#               extendedOpcode2: X86_64InstructionInfo(...),
#               extendedOpcode3: X86_64InstructionInfo(...),
#               extendedOpcode4: X86_64InstructionInfo(...),
#               extendedOpcode5: X86_64InstructionInfo(...),
#               extendedOpcode6: X86_64InstructionInfo(...),
#               extendedOpcode7: X86_64InstructionInfo(...),
#               extendedOpcode8: X86_64InstructionInfo(...),
#       },
#       secondaryOpcode2: {
#           None:    X86_64InstructionInfo(...),
#           prefix1: X86_64InstructionInfo(...),
#           prefix2: X86_64InstructionInfo(...),
#       },
#   }
#
#   NOTE: Secondary opcode dictionaries should have a value for the key None
#   if the opcode does not have a required prefix.
#
# If there is not a secondary opcode, then the structure is the following:
#   primaryOpcode: {
#       None: {
#           None:    X86_64InstructionInfo(...),
#           prefix1: X86_64InstructionInfo(...),
#           prefix2: X86_64InstructionInfo(...),
#           prefix3: X86_64InstructionInfo(...),
#       }
#   }

oneByteOpcodes = {

    0x00: X86_64InstructionInfo("add",   modRm_0=True, reg_1=True),
    0x01: X86_64InstructionInfo("add",   modRm_0=True, reg_1=True),
    0x02: X86_64InstructionInfo("add",   reg_0=True,   modRm_1=True),
    0x03: X86_64InstructionInfo("add",   reg_0=True,   modRm_1=True),
    0x04: X86_64InstructionInfo("add",   isImmediate_1=True),
    0x05: X86_64InstructionInfo("add",   isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x06: Invalid
#   0x07: Invalid
    0x08: X86_64InstructionInfo("or",    modRm_0=True, reg_1=True),
    0x09: X86_64InstructionInfo("or",    modRm_0=True, reg_1=True),
    0x0a: X86_64InstructionInfo("or",    reg_0=True,   modRm_1=True),
    0x0b: X86_64InstructionInfo("or",    reg_0=True,   modRm_1=True),
    0x0c: X86_64InstructionInfo("or",    isImmediate_1=True),
    0x0d: X86_64InstructionInfo("or",    isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x0e: Invalid
#   0x0f: 2 byte operand prefix
    0x10: X86_64InstructionInfo("adc",   modRm_0=True, reg_1=True),
    0x11: X86_64InstructionInfo("adc",   modRm_0=True, reg_1=True),
    0x12: X86_64InstructionInfo("adc",   reg_0=True,   modRm_1=True),
    0x13: X86_64InstructionInfo("adc",   reg_0=True,   modRm_1=True),
    0x14: X86_64InstructionInfo("adc",   isImmediate_1=True),
    0x15: X86_64InstructionInfo("adc",   isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x16: Invalid
#   0x17: Invalid
    0x18: X86_64InstructionInfo("sbb",   modRm_0=True, reg_1=True),
    0x19: X86_64InstructionInfo("sbb",   modRm_0=True, reg_1=True),
    0x1a: X86_64InstructionInfo("sbb",   reg_0=True,   modRm_1=True),
    0x1b: X86_64InstructionInfo("sbb",   reg_0=True,   modRm_1=True),
    0x1c: X86_64InstructionInfo("sbb",   isImmediate_1=True),
    0x1d: X86_64InstructionInfo("sbb",   isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x1e: Invalid
#   0x1f: Invalid
    0x20: X86_64InstructionInfo("and",   modRm_0=True, reg_1=True),
    0x21: X86_64InstructionInfo("and",   modRm_0=True, reg_1=True),
    0x22: X86_64InstructionInfo("and",   reg_0=True,   modRm_1=True),
    0x23: X86_64InstructionInfo("and",   reg_0=True,   modRm_1=True),
    0x24: X86_64InstructionInfo("and",   isImmediate_1=True),
    0x25: X86_64InstructionInfo("and",   isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x26: ES Segment Register Prefix
#   0x27: Invalid
    0x28: X86_64InstructionInfo("sub",   modRm_0=True, reg_1=True),
    0x29: X86_64InstructionInfo("sub",   modRm_0=True, reg_1=True),
    0x2a: X86_64InstructionInfo("sub",   reg_0=True,   modRm_1=True),
    0x2b: X86_64InstructionInfo("sub",   reg_0=True,   modRm_1=True),
    0x2c: X86_64InstructionInfo("sub",   isImmediate_1=True),
    0x2d: X86_64InstructionInfo("sub",   isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x2e: CS Segment Register Prefix
#   0x2f: Invalid
    0x30: X86_64InstructionInfo("xor",   modRm_0=True, reg_1=True),
    0x31: X86_64InstructionInfo("xor",   modRm_0=True, reg_1=True),
    0x32: X86_64InstructionInfo("xor",   reg_0=True,   modRm_1=True),
    0x33: X86_64InstructionInfo("xor",   reg_0=True,   modRm_1=True),
    0x34: X86_64InstructionInfo("xor",   isImmediate_1=True),
    0x35: X86_64InstructionInfo("xor",   isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x36: SS Segment Register Prefix
#   0x37: Invalid
    0x38: X86_64InstructionInfo("cmp",   destinations=[], modRm_0=True, reg_1=True),
    0x39: X86_64InstructionInfo("cmp",   destinations=[], modRm_0=True, reg_1=True),
    0x3a: X86_64InstructionInfo("cmp",   destinations=[], reg_0=True,   modRm_1=True),
    0x3b: X86_64InstructionInfo("cmp",   destinations=[], reg_0=True,   modRm_1=True),
    0x3c: X86_64InstructionInfo("cmp",   destinations=[], isImmediate_1=True),
    0x3d: X86_64InstructionInfo("cmp",   destinations=[], isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x3e: DS Segment Register Prefix
#   0x3f: Invalid
#   0x40: REX Prefix (accesses extended 8-bit registers)
#   0x41: REX.B Prefix
#   0x42: REX.X Prefix
#   0x43: REX.XB Prefix
#   0x44: REX.R Prefix
#   0x45: REX.RB Prefix
#   0x46: REX.RX Prefix
#   0x47: REX.RXB Prefix
#   0x48: REX.W Prefix (64-bit operand size prefix)
#   0x49: REX.WB Prefix
#   0x4a: REX.WX Prefix
#   0x4b: REX.WXB Prefix
#   0x4c: REX.WR Prefix
#   0x4d: REX.WRB Prefix
#   0x4e: REX.WRX Prefix
#   0x4f: REX.WRXB Prefix
    0x50: X86_64InstructionInfo("push",  numOperands=1, destinations=[], opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x51: X86_64InstructionInfo("push",  numOperands=1, destinations=[], opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x52: X86_64InstructionInfo("push",  numOperands=1, destinations=[], opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x53: X86_64InstructionInfo("push",  numOperands=1, destinations=[], opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x54: X86_64InstructionInfo("push",  numOperands=1, destinations=[], opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x55: X86_64InstructionInfo("push",  numOperands=1, destinations=[], opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x56: X86_64InstructionInfo("push",  numOperands=1, destinations=[], opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x57: X86_64InstructionInfo("push",  numOperands=1, destinations=[], opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x58: X86_64InstructionInfo("pop",   numOperands=1, destIsAlsoSource_inst=False, opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x59: X86_64InstructionInfo("pop",   numOperands=1, destIsAlsoSource_inst=False, opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x5a: X86_64InstructionInfo("pop",   numOperands=1, destIsAlsoSource_inst=False, opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x5b: X86_64InstructionInfo("pop",   numOperands=1, destIsAlsoSource_inst=False, opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x5c: X86_64InstructionInfo("pop",   numOperands=1, destIsAlsoSource_inst=False, opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x5d: X86_64InstructionInfo("pop",   numOperands=1, destIsAlsoSource_inst=False, opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x5e: X86_64InstructionInfo("pop",   numOperands=1, destIsAlsoSource_inst=False, opcodeRegVal_0=True, size_op=REG_SIZE_64),
    0x5f: X86_64InstructionInfo("pop",   numOperands=1, destIsAlsoSource_inst=False, opcodeRegVal_0=True, size_op=REG_SIZE_64),
#   0x60: Invalid
#   0x61: Invalid
#   0x62: Invalid
    0x63: X86_64InstructionInfo("movsxd", reg_0=True, modRm_1=True, size_0=REG_SIZE_32, size_1=REG_SIZE_32, maxSize_1=REG_SIZE_32, destIsAlsoSource_inst=False),
#   0x64: FS Segment Register Prefix
#   0x65: GS Segment Register Prefix
#   0x66: 16-bit Operand Size Prefix or access to Double Quadword Registers
#   0x67: TODO: 32-bit Address Size Prefix
    0x68: X86_64InstructionInfo("push",  numOperands=1, destinations=[], isImmediate_0=True, size_0=REG_SIZE_32),
    0x69: X86_64InstructionInfo("imul",  numOperands=3, reg_0=True, modRm_1=True, size_op=REG_SIZE_32, isImmediate_2=True, maxSize_2=REG_SIZE_32, destIsAlsoSource_inst=False),
    0x6a: X86_64InstructionInfo("push",  numOperands=1, destinations=[], isImmediate_1=True, size_1=REG_SIZE_8),
    0x6b: X86_64InstructionInfo("imul",  numOperands=3, reg_0=True, modRm_1=True, size_0=REG_SIZE_32, size_1=REG_SIZE_32, isImmediate_2=True, size_2=REG_SIZE_8, destIsAlsoSource_inst=False),
#   0x6c: Debug input port to string
#   0x6d: Debug input port to string
#   0x6e: Debug output string to port
#   0x6f: Debug output string to port
    0x70: X86_64InstructionInfo("jo",    destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Overflow
    0x71: X86_64InstructionInfo("jno",   destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Not overflow
    0x72: X86_64InstructionInfo("jb",    destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Less than (unsigned)
    0x73: X86_64InstructionInfo("jae",   destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Greater than or equal (unsigned)
    0x74: X86_64InstructionInfo("je",    destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Equal
    0x75: X86_64InstructionInfo("jne",   destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Not equal
    0x76: X86_64InstructionInfo("jbe",   destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Less than or equal (unsigned)
    0x77: X86_64InstructionInfo("ja",    destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Greater than (unsigned)
    0x78: X86_64InstructionInfo("js",    destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Signed
    0x79: X86_64InstructionInfo("jns",   destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Unsigned
    0x7a: X86_64InstructionInfo("jp",    destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Parity
    0x7b: X86_64InstructionInfo("jnp",   destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Not parity
    0x7c: X86_64InstructionInfo("jlt",   destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Less than (signed)
    0x7d: X86_64InstructionInfo("jge",   destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Greater than or equal (signed)
    0x7e: X86_64InstructionInfo("jle",   destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Less than or equal (signed)
    0x7f: X86_64InstructionInfo("jgt",   destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8), # Greater than (signed)
    0x80: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("add", modRm_0=True, isImmediate_1=True),
                1: X86_64InstructionInfo("or",  modRm_0=True, isImmediate_1=True),
                2: X86_64InstructionInfo("adc", modRm_0=True, isImmediate_1=True),
                3: X86_64InstructionInfo("sbb", modRm_0=True, isImmediate_1=True),
                4: X86_64InstructionInfo("and", modRm_0=True, isImmediate_1=True),
                5: X86_64InstructionInfo("sub", modRm_0=True, isImmediate_1=True),
                6: X86_64InstructionInfo("xor", modRm_0=True, isImmediate_1=True),
                7: X86_64InstructionInfo("cmp", destinations=[], modRm_0=True, isImmediate_1=True, size_0=REG_SIZE_8, size_1=REG_SIZE_8),
            },
        },
    },
    0x81: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("add", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                1: X86_64InstructionInfo("or",  modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                2: X86_64InstructionInfo("adc", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                3: X86_64InstructionInfo("sbb", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                4: X86_64InstructionInfo("and", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                5: X86_64InstructionInfo("sub", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                6: X86_64InstructionInfo("xor", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                7: X86_64InstructionInfo("cmp", destinations=[], modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
            },
        },
    },
#   0x82: Invalid
    0x83: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("add", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                1: X86_64InstructionInfo("or",  modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                2: X86_64InstructionInfo("adc", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                3: X86_64InstructionInfo("sbb", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                4: X86_64InstructionInfo("and", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                5: X86_64InstructionInfo("sub", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                6: X86_64InstructionInfo("xor", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                7: X86_64InstructionInfo("cmp", destinations=[], modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
            },
        },
    },
    0x84: X86_64InstructionInfo("test",  destinations=[], modRm_0=True, reg_1=True),
    0x85: X86_64InstructionInfo("test",  destinations=[], modRm_0=True, reg_1=True),
    0x86: X86_64InstructionInfo("xchg",  modRm_1=True, reg_0=True, exchange_inst=True),
    0x87: X86_64InstructionInfo("xchg",  modRm_1=True, reg_0=True, exchange_inst=True),
    0x88: X86_64InstructionInfo("mov",   modRm_0=True, reg_1=True, destIsAlsoSource_inst=False),
    0x89: X86_64InstructionInfo("mov",   modRm_0=True, reg_1=True, destIsAlsoSource_inst=False),
    0x8a: X86_64InstructionInfo("mov",   modRm_1=True, reg_0=True, destIsAlsoSource_inst=False),
    0x8b: X86_64InstructionInfo("mov",   modRm_1=True, reg_0=True, destIsAlsoSource_inst=False),
#   0x8c: TODO: X86_64InstructionInfo("mov",   modRm=MODRM_SRC), A lot is strange about this instruction. It refers to a segment register in the Mod R/M byte or a memory location that is always a word long
    0x8d: X86_64InstructionInfo("lea",   modRm_1=True, reg_0=True, destIsAlsoSource_inst=False),
#   0x8e: TODO: X86_64InstructionInfo("mov",   modRm=MODRM_SRC), A lot is strange about this instruction. It refers to a segment register in the Mod R/M byte
    0x8f: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("pop", numOperands=1, modRm_0=True, size_0=REG_SIZE_64, destIsAlsoSource_inst=False),
            },
        },
    },
    0x90: {
        None: { # There are no secondary opcodes
            None: X86_64InstructionInfo("nop", numOperands=0), # This is a special case of exchange instructions that would exchange EAX with EAX
            0xf3: X86_64InstructionInfo("pause", numOperands=0),
        },
    },
    0x91: X86_64InstructionInfo("xchg",  opcodeRegVal_0=True, exchange_inst=True, size_op=REG_SIZE_32),
    0x92: X86_64InstructionInfo("xchg",  opcodeRegVal_0=True, exchange_inst=True, size_op=REG_SIZE_32),
    0x93: X86_64InstructionInfo("xchg",  opcodeRegVal_0=True, exchange_inst=True, size_op=REG_SIZE_32),
    0x94: X86_64InstructionInfo("xchg",  opcodeRegVal_0=True, exchange_inst=True, size_op=REG_SIZE_32),
    0x95: X86_64InstructionInfo("xchg",  opcodeRegVal_0=True, exchange_inst=True, size_op=REG_SIZE_32),
    0x96: X86_64InstructionInfo("xchg",  opcodeRegVal_0=True, exchange_inst=True, size_op=REG_SIZE_32),
    0x97: X86_64InstructionInfo("xchg",  opcodeRegVal_0=True, exchange_inst=True, size_op=REG_SIZE_32),
    0x98: {
        None: { # There are no secondary opcodes
            PREFIX_16_BIT_OPERAND: X86_64InstructionInfo("cbw",  size_0=REG_SIZE_16, size_1=REG_SIZE_8,  destIsAlsoSource_inst=False),
            None:                  X86_64InstructionInfo("cwde", size_0=REG_SIZE_32, size_1=REG_SIZE_16, destIsAlsoSource_inst=False),
            REG_SIZE_64:           X86_64InstructionInfo("cdqe", size_0=REG_SIZE_64, size_1=REG_SIZE_32, destIsAlsoSource_inst=False),
        },
    },
    0x99: {
        None: { # There are no secondary opcodes
            PREFIX_16_BIT_OPERAND: X86_64InstructionInfo("cwd", value_0=REG_RDX, destIsAlsoSource_inst=False),
            None:                  X86_64InstructionInfo("cdq", value_0=REG_RDX, destIsAlsoSource_inst=False),
            REG_SIZE_64:           X86_64InstructionInfo("cqo", value_0=REG_RDX, destIsAlsoSource_inst=False),
        },
    },
#   0x9a: Invalid
    0x9b: X86_64InstructionInfo("fwait", numOperands=0),
    0x9c: X86_64InstructionInfo("pushf", numOperands=0),
    0x9d: X86_64InstructionInfo("popf",  numOperands=0),
    0x9e: X86_64InstructionInfo("sahf",  destinations=[], value_0=REG_RSP, size_0=REG_SIZE_8, maxSize_0=REG_SIZE_8),              # REG_RSP is the value for %ah at 8 bits
    0x9f: X86_64InstructionInfo("lahf",  value_0=REG_RSP, size_0=REG_SIZE_8, maxSize_0=REG_SIZE_8, destIsAlsoSource_inst=False),  # REG_RSP is the value for %ah at 8 bits
#   0xa0: X86_64InstructionInfo("mov",   ), TODO: Requires a displacement to place data, maybe use REG_RIP and an immediate?
#   0xa1: X86_64InstructionInfo("mov",   ), TODO: Requires a displacement to place data, maybe use REG_RIP and an immediate?
#   0xa2: X86_64InstructionInfo("mov",   ), TODO: Requires a displacement to place data, maybe use REG_RIP and an immediate?
#   0xa3: X86_64InstructionInfo("mov",   ), TODO: Requires a displacement to place data, maybe use REG_RIP and an immediate?
    0xa4: X86_64InstructionInfo("movs",  segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI, segmentReg_1=SEGMENT_REG_DS, value_1=REG_RSI, destIsAlsoSource_inst=False),
    0xa5: X86_64InstructionInfo("movs",  segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI, segmentReg_1=SEGMENT_REG_DS, value_1=REG_RSI, destIsAlsoSource_inst=False),
    0xa6: X86_64InstructionInfo("cmps",  destinations=[], segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI, segmentReg_1=SEGMENT_REG_DS, value_1=REG_RSI),
    0xa7: X86_64InstructionInfo("cmps",  destinations=[], segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI, segmentReg_1=SEGMENT_REG_DS, value_1=REG_RSI),
    0xa8: X86_64InstructionInfo("test",  destinations=[], isImmediate_1=True),
    0xa9: X86_64InstructionInfo("test",  destinations=[], isImmediate_1=True, maxSize_1=REG_SIZE_32),
    0xaa: X86_64InstructionInfo("stors", segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI),
    0xab: X86_64InstructionInfo("stors", segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI),
    0xac: X86_64InstructionInfo("loads", segmentReg_1=SEGMENT_REG_DS, value_1=REG_RSI),
    0xad: X86_64InstructionInfo("loads", segmentReg_1=SEGMENT_REG_DS, value_1=REG_RSI),
    0xae: X86_64InstructionInfo("scans", destinations=[], segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI),
    0xaf: X86_64InstructionInfo("scans", destinations=[], segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI),
    0xb0: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_8, destIsAlsoSource_inst=False),
    0xb1: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_8, destIsAlsoSource_inst=False),
    0xb2: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_8, destIsAlsoSource_inst=False),
    0xb3: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_8, destIsAlsoSource_inst=False),
    0xb4: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_8, destIsAlsoSource_inst=False),
    0xb5: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_8, destIsAlsoSource_inst=False),
    0xb6: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_8, destIsAlsoSource_inst=False),
    0xb7: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_8, destIsAlsoSource_inst=False),
    0xb8: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_32, destIsAlsoSource_inst=False),
    0xb9: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_32, destIsAlsoSource_inst=False),
    0xba: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_32, destIsAlsoSource_inst=False),
    0xbb: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_32, destIsAlsoSource_inst=False),
    0xbc: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_32, destIsAlsoSource_inst=False),
    0xbd: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_32, destIsAlsoSource_inst=False),
    0xbe: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_32, destIsAlsoSource_inst=False),
    0xbf: X86_64InstructionInfo("mov",   opcodeRegVal_0=True, isImmediate_1=True, size_op=REG_SIZE_32, destIsAlsoSource_inst=False),
    0xc0: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("rol", modRm_0=True, isImmediate_1=True),
                1: X86_64InstructionInfo("ror", modRm_0=True, isImmediate_1=True),
                2: X86_64InstructionInfo("rcl", modRm_0=True, isImmediate_1=True),
                3: X86_64InstructionInfo("rcr", modRm_0=True, isImmediate_1=True),
                4: X86_64InstructionInfo("shl", modRm_0=True, isImmediate_1=True),
                5: X86_64InstructionInfo("shr", modRm_0=True, isImmediate_1=True),
                6: X86_64InstructionInfo("sal", modRm_0=True, isImmediate_1=True),
                7: X86_64InstructionInfo("sar", modRm_0=True, isImmediate_1=True),
            },
        },
    },
    0xc1: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("rol", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                1: X86_64InstructionInfo("ror", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                2: X86_64InstructionInfo("rcl", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                3: X86_64InstructionInfo("rcr", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                4: X86_64InstructionInfo("shl", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                5: X86_64InstructionInfo("shr", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                6: X86_64InstructionInfo("sal", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                7: X86_64InstructionInfo("sar", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
            },
        },
    },
    0xc2: X86_64InstructionInfo("ret",   destinations=[], numOperands=1, size_0=REG_SIZE_16, maxSize_0=REG_SIZE_16),
    0xc3: X86_64InstructionInfo("ret",   numOperands=0),
#   0xc4: Invalid
#   0xc5: Invalid
    0xc6: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("mov", modRm_0=True, isImmediate_1=True, destIsAlsoSource_inst=False),
            },
        },
    },
    0xc7: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("mov", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32, destIsAlsoSource_inst=False),
            },
        },
    },
    0xc8: X86_64InstructionInfo("enter", numOperands=3, value_0=REG_RBP, isImmediate_1=True, isImmediate_2=True, size_0=REG_SIZE_64, size_1=REG_SIZE_16, size_2=REG_SIZE_8, destIsAlsoSource_inst=False),
    0xc9: X86_64InstructionInfo("leave", destinations=[], numOperands=1, value_0=REG_RBP, size_0=REG_SIZE_64),
    0xca: X86_64InstructionInfo("retf",  destinations=[], numOperands=1, isImmediate_0=True,  size_0=REG_SIZE_16),
    0xcb: X86_64InstructionInfo("retf",  numOperands=0),
    0xcc: X86_64InstructionInfo("int3",  destinations=[], isImmediate_0=True, value_0=3, value_1=REG_RFLAGS),
    0xcd: X86_64InstructionInfo("int",   destinations=[], isImmediate_0=True, value_1=REG_RFLAGS, size_0=REG_SIZE_8),
    0xce: X86_64InstructionInfo("into",  destinations=[], value_0=REG_RFLAGS),
    0xcf: X86_64InstructionInfo("iret",  destinations=[], value_0=REG_RFLAGS),
    0xd0: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("rol", modRm_0=True, isImmediate_1=True, value_1=1),
                1: X86_64InstructionInfo("ror", modRm_0=True, isImmediate_1=True, value_1=1),
                2: X86_64InstructionInfo("rcl", modRm_0=True, isImmediate_1=True, value_1=1),
                3: X86_64InstructionInfo("rcr", modRm_0=True, isImmediate_1=True, value_1=1),
                4: X86_64InstructionInfo("shl", modRm_0=True, isImmediate_1=True, value_1=1),
                5: X86_64InstructionInfo("shr", modRm_0=True, isImmediate_1=True, value_1=1),
                6: X86_64InstructionInfo("sal", modRm_0=True, isImmediate_1=True, value_1=1),
                7: X86_64InstructionInfo("sar", modRm_0=True, isImmediate_1=True, value_1=1),
            },
        },
    },
    0xd1: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("rol", modRm_0=True, isImmediate_1=True, value_1=1),
                1: X86_64InstructionInfo("ror", modRm_0=True, isImmediate_1=True, value_1=1),
                2: X86_64InstructionInfo("rcl", modRm_0=True, isImmediate_1=True, value_1=1),
                3: X86_64InstructionInfo("rcr", modRm_0=True, isImmediate_1=True, value_1=1),
                4: X86_64InstructionInfo("shl", modRm_0=True, isImmediate_1=True, value_1=1),
                5: X86_64InstructionInfo("shr", modRm_0=True, isImmediate_1=True, value_1=1),
                6: X86_64InstructionInfo("sal", modRm_0=True, isImmediate_1=True, value_1=1),
                7: X86_64InstructionInfo("sar", modRm_0=True, isImmediate_1=True, value_1=1),
            },
        },
    },
    0xd2: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("rol", modRm_0=True, value_1=REG_RCX),
                1: X86_64InstructionInfo("ror", modRm_0=True, value_1=REG_RCX),
                2: X86_64InstructionInfo("rcl", modRm_0=True, value_1=REG_RCX),
                3: X86_64InstructionInfo("rcr", modRm_0=True, value_1=REG_RCX),
                4: X86_64InstructionInfo("shl", modRm_0=True, value_1=REG_RCX),
                5: X86_64InstructionInfo("shr", modRm_0=True, value_1=REG_RCX),
                6: X86_64InstructionInfo("sal", modRm_0=True, value_1=REG_RCX),
                7: X86_64InstructionInfo("sar", modRm_0=True, value_1=REG_RCX),
            },
        },
    },
    0xd3: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("rol", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                1: X86_64InstructionInfo("ror", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                2: X86_64InstructionInfo("rcl", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                3: X86_64InstructionInfo("rcr", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                4: X86_64InstructionInfo("shl", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                5: X86_64InstructionInfo("shr", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                6: X86_64InstructionInfo("sal", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                7: X86_64InstructionInfo("sar", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
            },
        },
    },
#   0xd4: Invalid
#   0xd5: Invalid
#   0xd6: Invalid
    0xd7: X86_64InstructionInfo("xlat", size_op=REG_SIZE_8, segmentReg_1=SEGMENT_REG_DS),  # TODO: Check this instruction with objdump
    0xd8: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: {
                    None:       X86_64InstructionInfo("fadd",  value_0=REG_ST0, modRm_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_64),
                    MOD_DIRECT: X86_64InstructionInfo("fadd",  value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_64),
                },
                1: {
                    None:       X86_64InstructionInfo("fmul",  value_0=REG_ST0, modRm_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_64),
                    MOD_DIRECT: X86_64InstructionInfo("fmul",  value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_64),
                },
                2: {
                    MOD_DIRECT: X86_64InstructionInfo("fcom",  destinations=[], value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_64),
                },
                3: {
                    MOD_DIRECT: X86_64InstructionInfo("fcomp", destinations=[], value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_64),
                },
                4: {
                    None:       X86_64InstructionInfo("fsub",  value_0=REG_ST0, modRm_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                    MOD_DIRECT: X86_64InstructionInfo("fsub",  value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                },
                5: {
                    None:       X86_64InstructionInfo("fsubr", value_0=REG_ST0, modRm_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                    MOD_DIRECT: X86_64InstructionInfo("fsubr", value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                },
                6: {
                    None:       X86_64InstructionInfo("fdiv",  value_0=REG_ST0, modRm_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                    MOD_DIRECT: X86_64InstructionInfo("fdiv",  value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                },
                7: {
                    None:       X86_64InstructionInfo("fdivr", value_0=REG_ST0, modRm_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                    MOD_DIRECT: X86_64InstructionInfo("fdivr", value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                },
            },
        },
    },
    0xd9: {
        None: { # Secondary opcodes
            None: { # Prefixes
                0: X86_64InstructionInfo("fld",  floatReg_op=True, modRm_1=True, size_op=REG_SIZE_32, value_0=REG_ST0, destIsAlsoSource_inst=False),
                1: X86_64InstructionInfo("fxch", floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_1=REG_ST0, exchange_inst=True),
                2: {
                    # Direct addressing mode is invalid for this instruction
                    MOD_INDIRECT:    X86_64InstructionInfo("fst", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_32, value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_1_BYTE_DISP: X86_64InstructionInfo("fst", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_32, value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_4_BYTE_DISP: X86_64InstructionInfo("fst", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_32, value_1=REG_ST0, destIsAlsoSource_inst=False),
                },
                3: X86_64InstructionInfo("fstp",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_1=REG_ST0, destIsAlsoSource_inst=False),
                4: {
                    # Direct addressing mode is invalid for this instruction
                    MOD_INDIRECT:    X86_64InstructionInfo("fldenv", modRm_1=True, size_op=REG_SIZE_64, value_0=REG_FPENV, destIsAlsoSource_inst=False),
                    MOD_1_BYTE_DISP: X86_64InstructionInfo("fldenv", modRm_1=True, size_op=REG_SIZE_64, value_0=REG_FPENV, destIsAlsoSource_inst=False),
                    MOD_4_BYTE_DISP: X86_64InstructionInfo("fldenv", modRm_1=True, size_op=REG_SIZE_64, value_0=REG_FPENV, destIsAlsoSource_inst=False),
                },
                5: {
                    MOD_INDIRECT:    X86_64InstructionInfo("fldcw",  modRm_1=True, size_op=REG_SIZE_16, value_0=REG_FPENV, destIsAlsoSource_inst=False),
                    MOD_1_BYTE_DISP: X86_64InstructionInfo("fldcw",  modRm_1=True, size_op=REG_SIZE_16, value_0=REG_FPENV, destIsAlsoSource_inst=False),
                    MOD_4_BYTE_DISP: X86_64InstructionInfo("fldcw",  modRm_1=True, size_op=REG_SIZE_16, value_0=REG_FPENV, destIsAlsoSource_inst=False),
                },
                6: {
                    MOD_INDIRECT:    X86_64InstructionInfo("fstenv", modRm_0=True, size_op=REG_SIZE_64, value_1=REG_FPENV, destIsAlsoSource_inst=False),
                    MOD_1_BYTE_DISP: X86_64InstructionInfo("fstenv", modRm_0=True, size_op=REG_SIZE_64, value_1=REG_FPENV, destIsAlsoSource_inst=False),
                    MOD_4_BYTE_DISP: X86_64InstructionInfo("fstenv", modRm_0=True, size_op=REG_SIZE_64, value_1=REG_FPENV, destIsAlsoSource_inst=False),
                },
                7: {
                    MOD_INDIRECT:    X86_64InstructionInfo("fstcw", modRm_0=True, size_op=REG_SIZE_16, value_1=REG_FPENV, destIsAlsoSource_inst=False),
                    MOD_1_BYTE_DISP: X86_64InstructionInfo("fstcw", modRm_0=True, size_op=REG_SIZE_16, value_1=REG_FPENV, destIsAlsoSource_inst=False),
                    MOD_4_BYTE_DISP: X86_64InstructionInfo("fstcw", modRm_0=True, size_op=REG_SIZE_16, value_1=REG_FPENV, destIsAlsoSource_inst=False),
                },
            },
        },
        0xd0: X86_64InstructionInfo("fnop",    numOperands=0),
        0xe0: X86_64InstructionInfo("fchs",    numOperands=1, value=REG_ST0, size_0=REG_SIZE_64),
        0xe1: X86_64InstructionInfo("fabs",    numOperands=1, value=REG_ST0, size_0=REG_SIZE_64),
        0xe4: X86_64InstructionInfo("ftst",    destinations=[], numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xe5: X86_64InstructionInfo("fxam",    destinations=[], numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xe8: X86_64InstructionInfo("fld1",    value_0=REG_ST0, value_1=1.0, isImmediate_1=True, size_op=REG_SIZE_64, destIsAlsoSource_inst=False),
        0xe9: X86_64InstructionInfo("fldl2t",  value_0=REG_ST0, value_1=math.log(10, 2),      isImmediate_1=True, size_op=REG_SIZE_64, destIsAlsoSource_inst=False),
        0xea: X86_64InstructionInfo("fldl2e",  value_0=REG_ST0, value_1=math.log(10, math.e), isImmediate_1=True, size_op=REG_SIZE_64, destIsAlsoSource_inst=False),
        0xeb: X86_64InstructionInfo("fldpi",   value_0=REG_ST0, value_1=math.pi,              isImmediate_1=True, size_op=REG_SIZE_64, destIsAlsoSource_inst=False),
        0xec: X86_64InstructionInfo("fldlg2",  value_0=REG_ST0, value_1=math.log(2, 10),      isImmediate_1=True, size_op=REG_SIZE_64, destIsAlsoSource_inst=False),
        0xed: X86_64InstructionInfo("fldln2",  value_0=REG_ST0, value_1=math.log(math.e, 2),  isImmediate_1=True, size_op=REG_SIZE_64, destIsAlsoSource_inst=False),
        0xee: X86_64InstructionInfo("fldz",    value_0=REG_ST0, value_1=0.0, isImmediate_1=True, size_op=REG_SIZE_64, destIsAlsoSource_inst=False),
        0xf0: X86_64InstructionInfo("f2xm1",   numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xf1: X86_64InstructionInfo("fyl2x",   value_0=REG_ST1, value_1=REG_ST0, size_op=REG_SIZE_64),
        0xf2: X86_64InstructionInfo("fptan",   numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xf3: X86_64InstructionInfo("fpatan",  value_0=REG_ST1, value_1=REG_ST0, size_op=REG_SIZE_64),
        0xf4: X86_64InstructionInfo("fxtract", numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xf5: X86_64InstructionInfo("fprem1",  value_0=REG_ST1, value_1=REG_ST0, size_op=REG_SIZE_64),
        0xf6: X86_64InstructionInfo("fdecstp", numOperands=0),
        0xf7: X86_64InstructionInfo("fincstp", numOperands=0),
        0xf8: X86_64InstructionInfo("fprem",   value_0=REG_ST0, value_1=REG_ST1, size_op=REG_SIZE_64),
        0xf9: X86_64InstructionInfo("fyl2xp1", value_0=REG_ST1, value_1=REG_ST0, size_op=REG_SIZE_64),
        0xfa: X86_64InstructionInfo("fsqrt",   numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xfb: X86_64InstructionInfo("fsincos", numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xfc: X86_64InstructionInfo("frndint", numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xfd: X86_64InstructionInfo("fscale",  value_0=REG_ST0, value_1=REG_ST1, size_op=REG_SIZE_64),
        0xfe: X86_64InstructionInfo("fsin",    numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xff: X86_64InstructionInfo("fcos",    numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
    },
#   0xda: TODO:
    0xdb: {
        None: { # Secondary opcodes
            None: { # There are no prefixes
                0: {
                    None:       X86_64InstructionInfo("fild",    floatReg_op=True, modRm_1=True, value_0=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("cmovnb",  floatReg_op=True, modRm_1=True, value_0=REG_ST0, destIsAlsoSource_inst=False),
                },
                1: {
                    None:       X86_64InstructionInfo("fisttp",   floatReg_op=True, modRm_0=True, value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("fcmovne",  floatReg_op=True, modRm_0=True, value_1=REG_ST0, destIsAlsoSource_inst=False),
                },
                2: {
                    None:       X86_64InstructionInfo("fist",     floatReg_op=True, modRm_0=True, value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("fcmovnbe", floatReg_op=True, modRm_0=True, value_1=REG_ST0, destIsAlsoSource_inst=False),
                },
                3: {
                    None:       X86_64InstructionInfo("fistp",    floatReg_op=True, modRm_0=True, value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("fcmovnu",  floatReg_op=True, modRm_0=True, value_1=REG_ST0, destIsAlsoSource_inst=False),
                },
                # 4 handled as secondary opcodes
                5: {
                    None:       X86_64InstructionInfo("fld",      floatReg_op=True, modRm_1=True, value_0=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("fucomi",   destinations=[], floatReg_op=True, modRm_1=True, value_0=REG_ST0),
                },
                6: X86_64InstructionInfo("fcomi", destinations=[], floatReg_op=True, modRm_1=True, value_0=REG_ST0),
                7: {
                    MOD_INDIRECT:    X86_64InstructionInfo("fstp", floatReg_op=True, modRm_0=True, value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_1_BYTE_DISP: X86_64InstructionInfo("fstp", floatReg_op=True, modRm_0=True, value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_4_BYTE_DISP: X86_64InstructionInfo("fstp", floatReg_op=True, modRm_0=True, value_1=REG_ST0, destIsAlsoSource_inst=False),
                },
            },
        },
        0xe0: X86_64InstructionInfo("nop",     numOperands=0),
        0xe1: X86_64InstructionInfo("nop",     numOperands=0),
        0xe2: X86_64InstructionInfo("fclex",   numOperands=0),
        0xe3: X86_64InstructionInfo("finit",   numOperands=0),
        0xe4: X86_64InstructionInfo("nop",     numOperands=0),
    },
    0xdc: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: {
                    None:       X86_64InstructionInfo("fadd",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fadd",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                1: {
                    None:       X86_64InstructionInfo("fmul",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fmul",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                2: X86_64InstructionInfo("fcom",   destinations=[], floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                3: X86_64InstructionInfo("fcomp",  destinations=[], floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                4: {
                    None:       X86_64InstructionInfo("fsub",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fsubr",  floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                5: {
                    None:       X86_64InstructionInfo("fsubr",  floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fsub",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                6: {
                    None:       X86_64InstructionInfo("fdiv",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fdivr",  floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                7: {
                    None:       X86_64InstructionInfo("fdivr",  floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fdiv",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
            },
        },
    },
    0xdd: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: {
                    None:       X86_64InstructionInfo("fld",    floatReg_op=True, modR_1=True, size=REG_SIZE_64, value_0=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("ffree",  destinations=[], numOperands=1, floatReg_op=True, modRm_0=True, size_0=REG_SIZE_64),
                },
                1: {
                    None:       X86_64InstructionInfo("fisttp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("fxch",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0, exchange_inst=True),
                },
                2: {
                    None:       X86_64InstructionInfo("fst",    floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("fst",    floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0, destIsAlsoSource_inst=False),
                },
                3: {
                    None:       X86_64InstructionInfo("fstp",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("fstp",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0, destIsAlsoSource_inst=False),
                },
                4: {
                    None:       X86_64InstructionInfo("frstor", destinations=[], numOperands=1, floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64),
                    MOD_DIRECT: X86_64InstructionInfo("fucom",  destinations=[], floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                },
                5: {
                    MOD_DIRECT: X86_64InstructionInfo("fucomp", destinations=[], floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                },
                6: {
                    MOD_INDIRECT:    X86_64InstructionInfo("fsave", numOperands=1, floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64),
                    MOD_1_BYTE_DISP: X86_64InstructionInfo("fsave", numOperands=1, floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64),
                    MOD_4_BYTE_DISP: X86_64InstructionInfo("fsave", numOperands=1, floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64),
                },
                7: {
                    MOD_INDIRECT:    X86_64InstructionInfo("fstsw", numOperands=1, modRm_0=True, size_0=REG_SIZE_16),
                    MOD_1_BYTE_DISP: X86_64InstructionInfo("fstsw", numOperands=1, modRm_0=True, size_0=REG_SIZE_16),
                    MOD_1_BYTE_DISP: X86_64InstructionInfo("fstsw", numOperands=1, modRm_0=True, size_0=REG_SIZE_16),
                },
            },
        },
    },
    0xde: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: {
                    None:       X86_64InstructionInfo("fiadd", floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("faddp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                1: {
                    None:       X86_64InstructionInfo("fimul", floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fmulp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                2: {
                    None:       X86_64InstructionInfo("ficom",  destinations=[], floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fcomp",  destinations=[], floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                },
                3: {
                    None:       X86_64InstructionInfo("ficomp", destinations=[], floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fcompp", destinations=[], floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                },
                4: {
                    None:       X86_64InstructionInfo("fisub",  floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fsubrp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                5: {
                    None:       X86_64InstructionInfo("fisubr", floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fsubp",  floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                6: {
                    None:       X86_64InstructionInfo("fidiv",  floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fdivrp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                7: {
                    None:       X86_64InstructionInfo("fidivr", floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X86_64InstructionInfo("fdivp",  floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
            },
        },
    },
    0xdf: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: {
                    None:       X86_64InstructionInfo("fild",   floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16, value_0=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("ffreep", destinations=[], numOperands=1, floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64),
                },
                1: {
                    None:       X86_64InstructionInfo("fistp",  floatReg_op=True, modRm_0=True, size_1=REG_SIZE_16,  value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("fxch",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0, exchange_inst=True),
                },
                2: {
                    None:       X86_64InstructionInfo("fist",   floatReg_op=True, modRm_0=True, size_1=REG_SIZE_16,  value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("fstp",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0, destIsAlsoSource_inst=False),
                },
                3: {
                    None:       X86_64InstructionInfo("fistp",  floatReg_op=True, modRm_0=True, size_1=REG_SIZE_16,  value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("fstp",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0, destIsAlsoSource_inst=False),
                },
                4: {
                    None:       X86_64InstructionInfo("fbld",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0, destIsAlsoSource_inst=False), # bcd value
                    MOD_DIRECT: X86_64InstructionInfo("fstw",   numOperands=1, size_op=REG_SIZE_16, value_0=REG_RAX, destIsAlsoSource_inst=False),
                },
                5: {
                    None:       X86_64InstructionInfo("fild",    floatReg_op=True, modRm_1=True, size_1=REG_SIZE_64,  value_0=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_DIRECT: X86_64InstructionInfo("fucomip", destinations=[], floatReg_op=True, modRm_1=True, value_0=REG_ST0),
                },
                6: {
                    None:       X86_64InstructionInfo("fbstp",  floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0, destIsAlsoSource_inst=False), # bcd value
                    MOD_DIRECT: X86_64InstructionInfo("fcomip", destinations=[], floatReg_op=True, modRm_1=True, value_0=REG_ST0),
                },
                7: {
                    MOD_INDIRECT:    X86_64InstructionInfo("fistp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_1_BYTE_DISP: X86_64InstructionInfo("fistp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0, destIsAlsoSource_inst=False),
                    MOD_4_BYTE_DISP: X86_64InstructionInfo("fistp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0, destIsAlsoSource_inst=False),
                },
            },
        },
    },
#   0xe0: TODO:
#   0xe1: TODO:
#   0xe2: TODO:
#   0xe3: TODO:
#   0xe4: TODO:
#   0xe5: TODO:
#   0xe6: TODO:
#   0xe7: TODO:
    0xe8: X86_64InstructionInfo("call",  destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_32, maxSize_0=REG_SIZE_32),
    0xe9: X86_64InstructionInfo("jmp",   destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_32, maxSize_0=REG_SIZE_32),
#   0xea: Invalid
    0xeb: X86_64InstructionInfo("jmp",   destinations=[], numOperands=1, isOffset_0=True, size_0=REG_SIZE_8),
#   0xec: TODO:
#   0xed: TODO:
#   0xee: TODO:
#   0xef: TODO:
#   0xf0: Lock Prefix
#   0xf1: TODO:
#   0xf2: Repeat while not zero prefix
#   0xf3: Repeat while zero prefix
    0xf4: X86_64InstructionInfo("hlt",   numOperands=0),
    0xf5: X86_64InstructionInfo("cmc",   numOperands=0),
    0xf6: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("test", destinations=[], modRm_0=True, isImmediate_1=True),
                1: X86_64InstructionInfo("test", destinations=[], modRm_0=True, isImmediate_1=True),
                2: X86_64InstructionInfo("not",  numOperands=1, modRm_0=True),
                3: X86_64InstructionInfo("neg",  numOperands=1, modRm_0=True),
                4: X86_64InstructionInfo("mul",  numOperands=3, modRm_2=True, size_0=REG_SIZE_16),
                5: X86_64InstructionInfo("imul", numOperands=3, modRm_2=True, size_0=REG_SIZE_16),
                6: X86_64InstructionInfo("div",  numOperands=4, destinations=[0,1], modRm_3=True, value_1=REG_RSP, size_2=REG_SIZE_16), # REG_RSP is the value for %ah at 8 bits
                7: X86_64InstructionInfo("idiv", numOperands=4, destinations=[0,1], modRm_3=True, value_1=REG_RSP, size_2=REG_SIZE_16), # REG_RSP is the value for %ah at 8 bits
            },
        },
    },
    0xf7: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X86_64InstructionInfo("test", destinations=[], modRm_0=True, isImmediate_1=True),
                1: X86_64InstructionInfo("test", destinations=[], modRm_0=True, isImmediate_1=True),
                2: X86_64InstructionInfo("not",  numOperands=1, modRm_0=True),
                3: X86_64InstructionInfo("neg",  numOperands=1, modRm_0=True),
                4: X86_64InstructionInfo("mul",  numOperands=3, destinations=[0,1], modRm_2=True, value_0=REG_RDX),
                5: X86_64InstructionInfo("imul", numOperands=3, destinations=[0,1], modRm_2=True, value_0=REG_RDX),
                6: X86_64InstructionInfo("mul",  numOperands=3, destinations=[0,1], modRm_2=True, value_0=REG_RDX),
                7: X86_64InstructionInfo("imul", numOperands=3, destinations=[0,1], modRm_2=True, value_0=REG_RDX),
            },
        },
    },
    0xf8: X86_64InstructionInfo("clc",   numOperands=0),
    0xf9: X86_64InstructionInfo("stc",   numOperands=0),
    0xfa: X86_64InstructionInfo("cli",   numOperands=0),
    0xfb: X86_64InstructionInfo("sti",   numOperands=0),
    0xfc: X86_64InstructionInfo("cld",   numOperands=0),
    0xfd: X86_64InstructionInfo("std",   numOperands=0),
    0xfe: {
        None: {
            None: {
                0: X86_64InstructionInfo("inc", numOperands=1, modRm_0=True),
                1: X86_64InstructionInfo("dec", numOperands=1, modRm_0=True),
            },
        },
    },
    0xff: {
        None: {
            None: {
                0: X86_64InstructionInfo("inc",   numOperands=1, modRm_0=True),
                1: X86_64InstructionInfo("dec",   numOperands=1, modRm_0=True),
                2: X86_64InstructionInfo("call",  numOperands=1, destinations=[], modRm_0=True, size_0=REG_SIZE_64),
                3: X86_64InstructionInfo("callf", numOperands=1, destinations=[], modRm_0=True, size_0=REG_SIZE_64), #TODO: Needs to be done correctly. See Intel documentation.
                4: X86_64InstructionInfo("jmp",   numOperands=1, destinations=[], modRm_0=True, size_0=REG_SIZE_64),
                5: X86_64InstructionInfo("jmpf",  numOperands=1, destinations=[], modRm_0=True, size_0=REG_SIZE_64), #TODO: Needs to be done correctly. See Intel documentation.
                6: X86_64InstructionInfo("push",  numOperands=1, destinations=[], modRm_0=True, size_0=REG_SIZE_64),
            },
        },
    },
}

twoByteOpcodes = {
#   0x00: TODO:
#   0x01: TODO:
#   0x02: TODO:
#   0x03: TODO:
#   0x04: TODO:
#   0x05: TODO:
#   0x06: TODO:
#   0x07: TODO:
#   0x08: TODO:
#   0x09: TODO:
#   0x0a: TODO:
#   0x0b: TODO:
#   0x0c: TODO:
#   0x0d: TODO:
#   0x0e: TODO:
#   0x0f: TODO:
    0x10: {
        None: {
            None: X86_64InstructionInfo("movups", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("movupd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf2: X86_64InstructionInfo("movsd",  modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("movss",  modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x11: {
        None: {
            None: X86_64InstructionInfo("movups", modRm_0=True, reg_1=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("movupd", modRm_0=True, reg_1=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf2: X86_64InstructionInfo("movsd",  modRm_0=True, reg_1=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("movss",  modRm_0=True, reg_1=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
#   0x12: TODO:
#   0x13: TODO:
#   0x14: TODO:
#   0x15: TODO:
#   0x16: TODO:
#   0x17: TODO:
#   0x18: TODO:
    0x19: X86_64InstructionInfo("nop", modRm_0=True),
    0x1a: X86_64InstructionInfo("nop", modRm_0=True),
    0x1b: X86_64InstructionInfo("nop", modRm_0=True),
    0x1c: X86_64InstructionInfo("nop", modRm_0=True),
    0x1d: X86_64InstructionInfo("nop", modRm_0=True),
    0x1e: X86_64InstructionInfo("nop", modRm_0=True),
    0x1f: X86_64InstructionInfo("nop", modRm_0=True),
#   0x20: TODO:
#   0x21: TODO:
#   0x22: TODO:
#   0x23: TODO:
#   0x24: TODO:
#   0x25: TODO:
#   0x26: TODO:
#   0x27: TODO:
    0x28: {
        None: {
            None: X86_64InstructionInfo("movaps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("movapd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x29: {
        None: {
            None: X86_64InstructionInfo("movaps", modRm_0=True, reg_1=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("movapd", modRm_0=True, reg_1=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x2a: {
        None: {
            None: X86_64InstructionInfo("cvtpi2ps", modRm_1=True, reg_0=True, mmRegister_op=True, size_1=REG_SIZE_64, size_0=REG_SIZE_128),
            0x66: X86_64InstructionInfo("cvtpi2pd", modRm_1=True, reg_0=True, mmRegister_op=True, size_1=REG_SIZE_64, size_0=REG_SIZE_128),
            0xf2: X86_64InstructionInfo("cvtsi2sd", modRm_1=True, reg_0=True, mmRegister_0=True,  size_1=REG_SIZE_32, size_0=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("cvtsi2ss", modRm_1=True, reg_0=True, mmRegister_0=True,  size_1=REG_SIZE_32, size_0=REG_SIZE_128),
        },
    },
#   0x2b: TODO:
    0x2c: {
        None: {
            None: X86_64InstructionInfo("cvttps2pi", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_64),
            0x66: X86_64InstructionInfo("cvttpd2pi", modRm_1=True, reg_0=True, mmRegister_op=True, size_1=REG_SIZE_128, size_0=REG_SIZE_64),
            0xf2: X86_64InstructionInfo("cvttsd2si", modRm_1=True, reg_0=True, mmRegister_1=True,  size_1=REG_SIZE_128, size_0=REG_SIZE_32),
            0xf3: X86_64InstructionInfo("cvttss2si", modRm_1=True, reg_0=True, mmRegister_1=True,  size_1=REG_SIZE_128, size_0=REG_SIZE_32),
        },
    },
#   0x2d: TODO:
    0x2e: {
        None: {
            None: X86_64InstructionInfo("ucomiss", numOperands=3, modRm_2=True, reg_1=True, value_0=REG_RFLAGS, mmRegister_1=True, mmRegister_2=True, size_1=REG_SIZE_128, size_2=REG_SIZE_128),
            0x66: X86_64InstructionInfo("ucomisd", numOperands=3, modRm_2=True, reg_1=True, value_0=REG_RFLAGS, mmRegister_1=True, mmRegister_2=True, size_1=REG_SIZE_128, size_2=REG_SIZE_128),
        },
    },
    0x2f: {
        None: {
            None: X86_64InstructionInfo("comiss", numOperands=3, modRm_2=True, reg_1=True, value_0=REG_RFLAGS, mmRegister_1=True, mmRegister_2=True, size_1=REG_SIZE_128, size_2=REG_SIZE_128),
            0x66: X86_64InstructionInfo("comisd", numOperands=3, modRm_2=True, reg_1=True, value_0=REG_RFLAGS, mmRegister_1=True, mmRegister_2=True, size_1=REG_SIZE_128, size_2=REG_SIZE_128),
        },
    },
#   0x30: TODO:
#   0x31: TODO:
#   0x32: TODO:
#   0x33: TODO:
#   0x34: TODO:
#   0x35: TODO:
#   0x36: TODO:
#   0x37: TODO:
#   0x38: TODO:
#   0x39: TODO:
#   0x3a: TODO:
#   0x3b: TODO:
#   0x3c: TODO:
#   0x3d: TODO:
#   0x3e: TODO:
#   0x3f: TODO:
    0x40: X86_64InstructionInfo("cmovo",  modRm_1=True, reg_0=True), # Overflow
    0x41: X86_64InstructionInfo("cmovno", modRm_1=True, reg_0=True), # Not overflow
    0x42: X86_64InstructionInfo("cmovb",  modRm_1=True, reg_0=True), # Less than (unsigned)
    0x43: X86_64InstructionInfo("cmovae", modRm_1=True, reg_0=True), # Greater than or equal (unsigned)
    0x44: X86_64InstructionInfo("cmove",  modRm_1=True, reg_0=True), # Equal
    0x45: X86_64InstructionInfo("cmovne", modRm_1=True, reg_0=True), # Not equal
    0x46: X86_64InstructionInfo("cmovbe", modRm_1=True, reg_0=True), # Less than or equal (unsigned)
    0x47: X86_64InstructionInfo("cmova",  modRm_1=True, reg_0=True), # Greater than (unsigned)
    0x48: X86_64InstructionInfo("cmovs",  modRm_1=True, reg_0=True), # Signed
    0x49: X86_64InstructionInfo("cmovns", modRm_1=True, reg_0=True), # Unsigned
    0x4a: X86_64InstructionInfo("cmovp",  modRm_1=True, reg_0=True), # Parity
    0x4b: X86_64InstructionInfo("cmovnp", modRm_1=True, reg_0=True), # Not parity
    0x4c: X86_64InstructionInfo("cmovlt", modRm_1=True, reg_0=True), # Less than (signed)
    0x4d: X86_64InstructionInfo("cmovge", modRm_1=True, reg_0=True), # Greater than or equal (signed)
    0x4e: X86_64InstructionInfo("cmovle", modRm_1=True, reg_0=True), # Less than or equal (signed)
    0x4f: X86_64InstructionInfo("cmovgt", modRm_1=True, reg_0=True), # Greater than (signed)
#   0x50: TODO:
    0x51: {
        None: {
            None: X86_64InstructionInfo("sqrtps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("sqrtpd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf2: X86_64InstructionInfo("sqrtsd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("sqrtss", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x52: {
        None: {
            None: X86_64InstructionInfo("rsqrtps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("rsqrtss", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x53: {
        None: {
            None: X86_64InstructionInfo("rcpps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("rcpss", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x54: {
        None: {
            None: X86_64InstructionInfo("andps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("andpd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x55: {
        None: {
            None: X86_64InstructionInfo("addps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("addpd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x56: {
        None: {
            None: X86_64InstructionInfo("orps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("orpd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x57: {
        None: {
            None: X86_64InstructionInfo("xorps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("xorpd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x58: {
        None: {
            None: X86_64InstructionInfo("addps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("addpd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf2: X86_64InstructionInfo("addsd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("addss", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x59: {
        None: {
            None: X86_64InstructionInfo("mulps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("mulpd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf2: X86_64InstructionInfo("mulsd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("mulss", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
#   0x5a: TODO:
#   0x5b: TODO:
    0x5c: {
        None: {
            None: X86_64InstructionInfo("subps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("subpd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf2: X86_64InstructionInfo("subsd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("subss", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x5d: {
        None: {
            None: X86_64InstructionInfo("minps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("minpd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf2: X86_64InstructionInfo("minsd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("minss", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x5e: {
        None: {
            None: X86_64InstructionInfo("divps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("divpd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf2: X86_64InstructionInfo("divsd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("divss", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
    0x5f: {
        None: {
            None: X86_64InstructionInfo("maxps", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0x66: X86_64InstructionInfo("maxpd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf2: X86_64InstructionInfo("maxsd", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("maxss", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
#   0x60: TODO:
#   0x61: TODO:
#   0x62: TODO:
#   0x63: TODO:
#   0x64: TODO:
#   0x65: TODO:
#   0x66: TODO:
#   0x67: TODO:
#   0x68: TODO:
#   0x69: TODO:
#   0x6a: TODO:
#   0x6b: TODO:
#   0x6c: TODO:
#   0x6d: TODO:
#   0x6e: TODO:
    0x6f: {
        None: {
            None: X86_64InstructionInfo("movq",   modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_64),
            0x66: X86_64InstructionInfo("movdqa", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
            0xf3: X86_64InstructionInfo("movdqu", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
#   0x70: TODO:
#   0x71: TODO:
#   0x72: TODO:
#   0x73: TODO:
#   0x74: TODO:
#   0x75: TODO:
#   0x76: TODO:
#   0x77: TODO:
#   0x78: TODO:
#   0x79: TODO:
#   0x7a: TODO:
#   0x7b: TODO:
#   0x7c: TODO:
#   0x7d: TODO:
#   0x7e: TODO:
#   0x7f: TODO:
    0x80: X86_64InstructionInfo("jo",    numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Overflow
    0x81: X86_64InstructionInfo("jno",   numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Not overflow
    0x82: X86_64InstructionInfo("jb",    numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Less than (unsigned)
    0x83: X86_64InstructionInfo("jae",   numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Greater than or equal (unsigned)
    0x84: X86_64InstructionInfo("je",    numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Equal
    0x85: X86_64InstructionInfo("jne",   numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Not equal
    0x86: X86_64InstructionInfo("jbe",   numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Less than or equal (unsigned)
    0x87: X86_64InstructionInfo("ja",    numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Greater than (unsigned)
    0x88: X86_64InstructionInfo("js",    numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Signed
    0x89: X86_64InstructionInfo("jns",   numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Unsigned
    0x8a: X86_64InstructionInfo("jp",    numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Parity
    0x8b: X86_64InstructionInfo("jnp",   numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Not parity
    0x8c: X86_64InstructionInfo("jlt",   numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Less than (signed)
    0x8d: X86_64InstructionInfo("jge",   numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Greater than or equal (signed)
    0x8e: X86_64InstructionInfo("jle",   numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Less than or equal (signed)
    0x8f: X86_64InstructionInfo("jgt",   numOperands=1, isOffset_0=True, size_0=REG_SIZE_32), # Greater than (signed)
    0x90: X86_64InstructionInfo("seto",  numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Overflow
    0x91: X86_64InstructionInfo("setno", numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Not Overflow
    0x92: X86_64InstructionInfo("setb",  numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Less than (unsigned)
    0x93: X86_64InstructionInfo("setae", numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Greater than or equal (unsigned)
    0x94: X86_64InstructionInfo("sete",  numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Equal
    0x95: X86_64InstructionInfo("setne", numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Not equal
    0x96: X86_64InstructionInfo("setbe", numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Less than or equal (unsigned)
    0x97: X86_64InstructionInfo("seta",  numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Greater than (unsigned)
    0x98: X86_64InstructionInfo("sets",  numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Signed
    0x99: X86_64InstructionInfo("setns", numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Not signed
    0x9a: X86_64InstructionInfo("setp",  numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Parity
    0x9b: X86_64InstructionInfo("setnp", numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Not parity
    0x9c: X86_64InstructionInfo("setl",  numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Less than (signed)
    0x9d: X86_64InstructionInfo("setge", numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Greater than or equal (signed)
    0x9e: X86_64InstructionInfo("setle", numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Less than or equal (signed)
    0x9f: X86_64InstructionInfo("setg",  numOperands=1, modRm_0=True, size_0=REG_SIZE_8), # Greater than (signed)
#   0xa0: TODO:
#   0xa1: TODO:
#   0xa2: TODO:
    0xa3: X86_64InstructionInfo("bt",    modRm_0=True, reg_1=True, size_op=REG_SIZE_32),
#   0xa4: TODO:
#   0xa5: TODO:
#   0xa6: TODO:
#   0xa7: TODO:
#   0xa8: TODO:
#   0xa9: TODO:
#   0xaa: TODO:
#   0xab: TODO:
#   0xac: TODO:
#   0xad: TODO:
#   0xae: TODO:
    0xaf: X86_64InstructionInfo("imul",  modRm_1=True, reg_0=True, size_op=REG_SIZE_32),
#   0xb0: TODO:
#   0xb1: TODO:
#   0xb2: TODO:
#   0xb3: TODO:
#   0xb4: TODO:
#   0xb5: TODO:
    0xb6: X86_64InstructionInfo("movzx", modRm_1=True, reg_0=True, size_1=REG_SIZE_8,  size_0=REG_SIZE_32),
    0xb7: X86_64InstructionInfo("movzx", modRm_1=True, reg_0=True, size_1=REG_SIZE_16, size_0=REG_SIZE_32, src_maxSize=REG_SIZE_16),
    0xbe: X86_64InstructionInfo("movsx", reg_0=True, modRm_1=True, size_0=REG_SIZE_32,  size_1=REG_SIZE_8),
    0xbf: X86_64InstructionInfo("movsx", reg_0=True, modRm_1=True, size_0=REG_SIZE_32,  size_1=REG_SIZE_16),

    0xef: {
        None: {
            None: X86_64InstructionInfo("pxor", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_64),
            0x66: X86_64InstructionInfo("pxor", modRm_1=True, reg_0=True, mmRegister_op=True, size_op=REG_SIZE_128),
        },
    },
}
