from pyda.disassemblers.disassembler import Instruction, Operand
from pyda.disassemblers.x64.definitions import *

import math
import copy
import logging

logger = logging.getLogger(__name__)

class X64Instruction( Instruction ):

    def __init__( self, mnemonic="byte", addr=0, operands=[], exchange=False ):

        super().__init__(mnemonic, addr, operands, exchange)

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
            logger.debug(f"operand kwargs: {curKwargs}")

            self.operands.append(X64Operand(**curKwargs))


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

        # If a register size is 0, that means it should not exist and the size
        # should remain 0 no matter what.
        if infoSize == REG_SIZE_0:
            return infoSize

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


class X64Operand( Operand ):

    def __init__( self, value=0, size=REG_SIZE_32, maxSize=REG_SIZE_64, segmentReg=0,
                  isDestination=False, modRm=False, reg=False,
                  isImmediate=False, indirect=False, mmRegister=False, floatReg=False ):

        super().__init__(size, value, isDestination)
        self.maxSize = maxSize              # The maximum size allowed for the operand
        self.modRm = modRm                  # Whether the operand uses the Mod R/M values in the Mod R/M byte
        self.reg   = reg                    # Whether the operand uses the Reg value in the Mod R/M byte
        self.isImmediate = isImmediate      # Whether the operand is an immediate
        self.segmentReg = segmentReg        # The segment register to use as a base value
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


class X64InstructionInfo():

    def __init__( self, mnemonic, extOpcode=False, relativeJump=False,
                  isConversion=False, destinations=[0], numOperands=2, **kwargs):

        # Opcode info
        self.mnemonic      = mnemonic       # The name of the instruction
        self.extOpcode     = extOpcode      # Whether the opcode is extended into the ModR/M
        self.isConversion  = isConversion   # Whether the instruction is size conversion
        self.relativeJump  = relativeJump   # Whether the instruction is a relative jump and expects an immediate to follow the opcode

        # Relative jumps always have only 1 operand
        if relativeJump:
            numOperands = 1

        self.instKwargs = { key.split("_")[0]: value for (key, value) in kwargs.items() if key.endswith("_inst") }
        self.operandKwargs = []

        # If there are no operands, then make sure the list of destinations is
        # empty. There can't be destinations if there are no operands. The
        # opposite is not true, however, so a lack of destinations does not
        # imply that there are no operands.
        if numOperands == 0:
            destinations = []

        for operandIndex in range(numOperands):

            self.operandKwargs.append({ key.split("_")[0]: value for (key, value) in kwargs.items() if key.endswith((f"_{operandIndex}", "_op")) })

            curKwargs = self.operandKwargs[operandIndex]
            if "modRm" in curKwargs or "reg" in curKwargs:
                self.instKwargs["hasModRm"] = True

            logger.debug(f"operand kwargs #{operandIndex}: {self.operandKwargs[operandIndex]}")


        # Operands with an index in destinations gets the isDestination value
        # set to True
        for dest in destinations:
            self.operandKwargs[dest]["isDestination"] = True

        # Set properties that are always true if the instruction is a relative jump.
        # They can always be negative, so sign extension must be true.
        # They are always immediate values, so isImmediate must be true.
        if self.relativeJump:
            self.operandKwargs[0]["isImmediate"] = True


# The structure for opcodes and their info is a dictionary keyed on the primary
# opcode. If there are any prefixes that change the opcode's meaning or
# secondary opcodes, there are nested dictionaries to handle these cases.
# Finally, there is a layer of dictionaries for extended opcodes. They are keyed
# on the Op value of the Mod R/M byte. If needed, the Mode field is used to
# determine which addressing mode is used, which sometimes changes the info that
# should be used. The structure is the following if there are secondary opcodes:
#   primaryOpcode: {
#       secondaryOpcode1: {
#           None:    X64InstructionInfo(...),
#           prefix1: X64InstructionInfo(...),
#           prefix2: X64InstructionInfo(...),
#           prefix3: {
#               extendedOpcode1: {
#                   None:       X64InstructionInfo(...),
#                   MOD_DIRECT: X64InstructionInfo(...),
#               },
#               extendedOpcode2: X64InstructionInfo(...),
#               extendedOpcode3: X64InstructionInfo(...),
#               extendedOpcode4: X64InstructionInfo(...),
#               extendedOpcode5: X64InstructionInfo(...),
#               extendedOpcode6: X64InstructionInfo(...),
#               extendedOpcode7: X64InstructionInfo(...),
#               extendedOpcode8: X64InstructionInfo(...),
#       },
#       secondaryOpcode2: {
#           None:    X64InstructionInfo(...),
#           prefix1: X64InstructionInfo(...),
#           prefix2: X64InstructionInfo(...),
#       },
#   }
#
#   NOTE: Secondary opcode dictionaries should have a value for the key None
#   if the opcode does not have a required prefix.
#
# If there is not a secondary opcode, then the structure is the following:
#   primaryOpcode: {
#       None: {
#           None:    X64InstructionInfo(...),
#           prefix1: X64InstructionInfo(...),
#           prefix2: X64InstructionInfo(...),
#           prefix3: X64InstructionInfo(...),
#       }
#   }

oneByteOpcodes = {

    0x00: X64InstructionInfo("add",   modRm_0=True, reg_1=True),
    0x01: X64InstructionInfo("add",   modRm_0=True, reg_1=True),
    0x02: X64InstructionInfo("add",   reg_0=True,   modRm_1=True),
    0x03: X64InstructionInfo("add",   reg_0=True,   modRm_1=True),
    0x04: X64InstructionInfo("add",   isImmediate_1=True),
    0x05: X64InstructionInfo("add",   isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x06: Invalid
#   0x07: Invalid
    0x08: X64InstructionInfo("or",    modRm_0=True, reg_1=True),
    0x09: X64InstructionInfo("or",    modRm_0=True, reg_1=True),
    0x0a: X64InstructionInfo("or",    reg_0=True,   modRm_1=True),
    0x0b: X64InstructionInfo("or",    reg_0=True,   modRm_1=True),
    0x0c: X64InstructionInfo("or",    isImmediate_1=True),
    0x0d: X64InstructionInfo("or",    isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x0e: Invalid
#   0x0f: 2 byte operand prefix
    0x10: X64InstructionInfo("adc",   modRm_0=True, reg_1=True),
    0x11: X64InstructionInfo("adc",   modRm_0=True, reg_1=True),
    0x12: X64InstructionInfo("adc",   reg_0=True,   modRm_1=True),
    0x13: X64InstructionInfo("adc",   reg_0=True,   modRm_1=True),
    0x14: X64InstructionInfo("adc",   isImmediate_1=True),
    0x15: X64InstructionInfo("adc",   isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x16: Invalid
#   0x17: Invalid
    0x18: X64InstructionInfo("sbb",   modRm_0=True, reg_1=True),
    0x19: X64InstructionInfo("sbb",   modRm_0=True, reg_1=True),
    0x1a: X64InstructionInfo("sbb",   reg_0=True,   modRm_1=True),
    0x1b: X64InstructionInfo("sbb",   reg_0=True,   modRm_1=True),
    0x1c: X64InstructionInfo("sbb",   isImmediate_1=True),
    0x1d: X64InstructionInfo("sbb",   isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x1e: Invalid
#   0x1f: Invalid
    0x20: X64InstructionInfo("and",   modRm_0=True, reg_1=True),
    0x21: X64InstructionInfo("and",   modRm_0=True, reg_1=True),
    0x22: X64InstructionInfo("and",   reg_0=True,   modRm_1=True),
    0x23: X64InstructionInfo("and",   reg_0=True,   modRm_1=True),
    0x24: X64InstructionInfo("and",   isImmediate_1=True),
    0x25: X64InstructionInfo("and",   isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x26: ES Segment Register Prefix
#   0x27: Invalid
    0x28: X64InstructionInfo("sub",   modRm_0=True, reg_1=True),
    0x29: X64InstructionInfo("sub",   modRm_0=True, reg_1=True),
    0x2a: X64InstructionInfo("sub",   reg_0=True,   modRm_1=True),
    0x2b: X64InstructionInfo("sub",   reg_0=True,   modRm_1=True),
    0x2c: X64InstructionInfo("sub",   isImmediate_1=True),
    0x2d: X64InstructionInfo("sub",   isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x2e: CS Segment Register Prefix
#   0x2f: Invalid
    0x30: X64InstructionInfo("xor",   modRm_0=True, reg_1=True),
    0x31: X64InstructionInfo("xor",   modRm_0=True, reg_1=True),
    0x32: X64InstructionInfo("xor",   reg_0=True,   modRm_1=True),
    0x33: X64InstructionInfo("xor",   reg_0=True,   modRm_1=True),
    0x34: X64InstructionInfo("xor",   isImmediate_1=True),
    0x35: X64InstructionInfo("xor",   isImmediate_1=True, maxSize_1=REG_SIZE_32),
#   0x36: SS Segment Register Prefix
#   0x37: Invalid
    0x38: X64InstructionInfo("cmp",   numOperands=3, value_0=REG_RFLAGS, modRm_1=True, reg_2=True),
    0x39: X64InstructionInfo("cmp",   numOperands=3, value_0=REG_RFLAGS, modRm_1=True, reg_2=True),
    0x3a: X64InstructionInfo("cmp",   numOperands=3, value_0=REG_RFLAGS, reg_1=True,   modRm_2=True),
    0x3b: X64InstructionInfo("cmp",   numOperands=3, value_0=REG_RFLAGS, reg_1=True,   modRm_2=True),
    0x3c: X64InstructionInfo("cmp",   numOperands=3, value_0=REG_RFLAGS, isImmediate_2=True),
    0x3d: X64InstructionInfo("cmp",   numOperands=3, value_0=REG_RFLAGS, isImmediate_2=True, maxSize_2=REG_SIZE_32),
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
    0x50: X64InstructionInfo("push",  value_0=REG_STACK, value_1=REG_RAX, size_op=REG_SIZE_64),
    0x51: X64InstructionInfo("push",  value_0=REG_STACK, value_1=REG_RCX, size_op=REG_SIZE_64),
    0x52: X64InstructionInfo("push",  value_0=REG_STACK, value_1=REG_RDX, size_op=REG_SIZE_64),
    0x53: X64InstructionInfo("push",  value_0=REG_STACK, value_1=REG_RBX, size_op=REG_SIZE_64),
    0x54: X64InstructionInfo("push",  value_0=REG_STACK, value_1=REG_RSP, size_op=REG_SIZE_64),
    0x55: X64InstructionInfo("push",  value_0=REG_STACK, value_1=REG_RBP, size_op=REG_SIZE_64),
    0x56: X64InstructionInfo("push",  value_0=REG_STACK, value_1=REG_RSI, size_op=REG_SIZE_64),
    0x57: X64InstructionInfo("push",  value_0=REG_STACK, value_1=REG_RDI, size_op=REG_SIZE_64),
    0x59: X64InstructionInfo("pop",   value_1=REG_STACK, value_0=REG_RAX, size_op=REG_SIZE_64),
    0x5a: X64InstructionInfo("pop",   value_1=REG_STACK, value_0=REG_RCX, size_op=REG_SIZE_64),
    0x5b: X64InstructionInfo("pop",   value_1=REG_STACK, value_0=REG_RDX, size_op=REG_SIZE_64),
    0x5c: X64InstructionInfo("pop",   value_1=REG_STACK, value_0=REG_RBX, size_op=REG_SIZE_64),
    0x5d: X64InstructionInfo("pop",   value_1=REG_STACK, value_0=REG_RSP, size_op=REG_SIZE_64),
    0x5e: X64InstructionInfo("pop",   value_1=REG_STACK, value_0=REG_RBP, size_op=REG_SIZE_64),
    0x5f: X64InstructionInfo("pop",   value_1=REG_STACK, value_0=REG_RSI, size_op=REG_SIZE_64),
    0x58: X64InstructionInfo("pop",   value_1=REG_STACK, value_0=REG_RDI, size_op=REG_SIZE_64),
#   0x60: Invalid
#   0x61: Invalid
#   0x62: Invalid
    0x63: X64InstructionInfo("movsxd", reg_0=True, modRm_1=True, size_0=REG_SIZE_32, size_1=REG_SIZE_32, maxSize_1=REG_SIZE_32),
#   0x64: FS Segment Register Prefix
#   0x65: GS Segment Register Prefix
#   0x66: 16-bit Operand Size Prefix or access to Double Quadword Registers
#   0x67: TODO: 32-bit Address Size Prefix
    0x68: X64InstructionInfo("push",  value_0=REG_STACK, isImmediate_1=True, size_0=REG_SIZE_64, size_1=REG_SIZE_32),
    0x69: X64InstructionInfo("imul",  numOperands=3, reg_0=True, modRm_1=True, size_op=REG_SIZE_32, isImmediate_2=True, maxSize_2=REG_SIZE_32),
    0x6a: X64InstructionInfo("push",  value_0=REG_STACK, isImmediate_1=True, size_0=REG_SIZE_64, size_1=REG_SIZE_8),
    0x6b: X64InstructionInfo("imul",  numOperands=3, reg_0=True, modRm_1=True, size_0=REG_SIZE_32, size_1=REG_SIZE_32, isImmediate_2=True, size_2=REG_SIZE_8),
#   0x6c: Debug input port to string
#   0x6d: Debug input port to string
#   0x6e: Debug output string to port
#   0x6f: Debug output string to port
    0x70: X64InstructionInfo("jo",    numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Overflow
    0x71: X64InstructionInfo("jno",   numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Not overflow
    0x72: X64InstructionInfo("jb",    numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Less than (unsigned)
    0x73: X64InstructionInfo("jae",   numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Greater than or equal (unsigned)
    0x74: X64InstructionInfo("je",    numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Equal
    0x75: X64InstructionInfo("jne",   numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Not equal
    0x76: X64InstructionInfo("jbe",   numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Less than or equal (unsigned)
    0x77: X64InstructionInfo("ja",    numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Greater than (unsigned)
    0x78: X64InstructionInfo("js",    numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Signed
    0x79: X64InstructionInfo("jns",   numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Unsigned
    0x7a: X64InstructionInfo("jp",    numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Parity
    0x7b: X64InstructionInfo("jnp",   numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Not parity
    0x7c: X64InstructionInfo("jlt",   numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Less than (signed)
    0x7d: X64InstructionInfo("jge",   numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Greater than or equal (signed)
    0x7e: X64InstructionInfo("jle",   numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Less than or equal (signed)
    0x7f: X64InstructionInfo("jgt",   numOperands=1, relativeJump=True, size_0=REG_SIZE_8), # Greater than (signed)
    0x80: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X64InstructionInfo("add", modRm_0=True, isImmediate_1=True),
                1: X64InstructionInfo("or",  modRm_0=True, isImmediate_1=True),
                2: X64InstructionInfo("adc", modRm_0=True, isImmediate_1=True),
                3: X64InstructionInfo("sbb", modRm_0=True, isImmediate_1=True),
                4: X64InstructionInfo("and", modRm_0=True, isImmediate_1=True),
                5: X64InstructionInfo("sub", modRm_0=True, isImmediate_1=True),
                6: X64InstructionInfo("xor", modRm_0=True, isImmediate_1=True),
                7: X64InstructionInfo("cmp", numOperands=3, value_0=REG_RFLAGS, modRm_1=True, isImmediate_2=True, size_0=REG_SIZE_64, size_1=REG_SIZE_8, size_2=REG_SIZE_8),
            },
        },
    },
    0x81: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X64InstructionInfo("add", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                1: X64InstructionInfo("or",  modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                2: X64InstructionInfo("adc", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                3: X64InstructionInfo("sbb", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                4: X64InstructionInfo("and", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                5: X64InstructionInfo("sub", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                6: X64InstructionInfo("xor", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
                7: X64InstructionInfo("cmp", numOperands=3, value_0=REG_RFLAGS, modRm_1=True, isImmediate_2=True, size_0=REG_SIZE_64, maxSize_2=REG_SIZE_32),
            },
        },
    },
#   0x82: Invalid
    0x83: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X64InstructionInfo("add", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                1: X64InstructionInfo("or",  modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                2: X64InstructionInfo("adc", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                3: X64InstructionInfo("sbb", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                4: X64InstructionInfo("and", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                5: X64InstructionInfo("sub", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                6: X64InstructionInfo("xor", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                7: X64InstructionInfo("cmp", numOperands=3, value_0=REG_RFLAGS, modRm_1=True, isImmediate_2=True, size_0=REG_SIZE_64, size_2=REG_SIZE_8),
            },
        },
    },
    0x84: X64InstructionInfo("test",  numOperands=3, value_0=REG_RFLAGS, modRm_1=True, reg_2=True),
    0x85: X64InstructionInfo("test",  numOperands=3, value_0=REG_RFLAGS, modRm_1=True, reg_2=True),
    0x86: X64InstructionInfo("xchg",  modRm_1=True, reg_0=True, exchange_inst=True),
    0x87: X64InstructionInfo("xchg",  modRm_1=True, reg_0=True, exchange_inst=True),
    0x88: X64InstructionInfo("mov",   modRm_0=True, reg_1=True),
    0x89: X64InstructionInfo("mov",   modRm_0=True, reg_1=True),
    0x8a: X64InstructionInfo("mov",   modRm_1=True, reg_0=True),
    0x8b: X64InstructionInfo("mov",   modRm_1=True, reg_0=True),
#   0x8c: TODO: X64InstructionInfo("mov",   modRm=MODRM_SRC), A lot is strange about this instruction. It refers to a segment register in the Mod R/M byte or a memory location that is always a word long
    0x8d: X64InstructionInfo("lea",   modRm_1=True, reg_0=True),
#   0x8e: TODO: X64InstructionInfo("mov",   modRm=MODRM_SRC), A lot is strange about this instruction. It refers to a segment register in the Mod R/M byte
    0x8f: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X64InstructionInfo("pop", modRm_0=True, value_1=REG_STACK, size_op=REG_SIZE_64),
            },
        },
    },
    0x90: {
        None: { # There are no secondary opcodes
            None: X64InstructionInfo("nop"), # This is a special case of exchange instructions that would swap EAX with EAX
            0xf3: X64InstructionInfo("pause"),
        },
    },
    0x91: X64InstructionInfo("xchg",  value_0=1, exchange_inst=True, size_op=REG_SIZE_32),
    0x92: X64InstructionInfo("xchg",  value_0=2, exchange_inst=True, size_op=REG_SIZE_32),
    0x93: X64InstructionInfo("xchg",  value_0=3, exchange_inst=True, size_op=REG_SIZE_32),
    0x94: X64InstructionInfo("xchg",  value_0=4, exchange_inst=True, size_op=REG_SIZE_32),
    0x95: X64InstructionInfo("xchg",  value_0=5, exchange_inst=True, size_op=REG_SIZE_32),
    0x96: X64InstructionInfo("xchg",  value_0=6, exchange_inst=True, size_op=REG_SIZE_32),
    0x97: X64InstructionInfo("xchg",  value_0=7, exchange_inst=True, size_op=REG_SIZE_32),
    0x98: {
        None: { # There are no secondary opcodes
            PREFIX_16_BIT_OPERAND: X64InstructionInfo("cbw",  size_0=REG_SIZE_16, size_1=REG_SIZE_8),
            None:                  X64InstructionInfo("cwde", size_0=REG_SIZE_32, size_1=REG_SIZE_16),
            REG_SIZE_64:           X64InstructionInfo("cdqe", size_0=REG_SIZE_64, size_1=REG_SIZE_32),
        },
    },
    0x99: {
        None: { # There are no secondary opcodes
            PREFIX_16_BIT_OPERAND: X64InstructionInfo("cwd", value_0=REG_RDX),
            None:                  X64InstructionInfo("cdq", value_0=REG_RDX),
            REG_SIZE_64:           X64InstructionInfo("cqo", value_0=REG_RDX),
        },
    },
#   0x9a: Invalid
    0x9b: X64InstructionInfo("fwait", numOperands=0),
    0x9c: X64InstructionInfo("pushf", value_0=REG_STACK,  value_1=REG_RFLAGS, size_op=REG_SIZE_64),
    0x9d: X64InstructionInfo("popf",  value_1=REG_STACK,  value_0=REG_RFLAGS, size_op=REG_SIZE_64),
    0x9e: X64InstructionInfo("sahf",  value_0=REG_RFLAGS, value_1=REG_RSP, size_op=REG_SIZE_8, op_maxSize=REG_SIZE_8),  # REG_RSP is the value for %ah at 8 bits
    0x9f: X64InstructionInfo("lahf",  value_1=REG_RFLAGS, value_0=REG_RSP, size_op=REG_SIZE_8, op_maxSize=REG_SIZE_8),  # REG_RSP is the value for %ah at 8 bits
#   0xa0: X64InstructionInfo("mov",   ), TODO: Requires a displacement to place data, maybe use REG_RIP and an immediate?
#   0xa1: X64InstructionInfo("mov",   ), TODO: Requires a displacement to place data, maybe use REG_RIP and an immediate?
#   0xa2: X64InstructionInfo("mov",   ), TODO: Requires a displacement to place data, maybe use REG_RIP and an immediate?
#   0xa3: X64InstructionInfo("mov",   ), TODO: Requires a displacement to place data, maybe use REG_RIP and an immediate?
    0xa4: X64InstructionInfo("movs",  segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI, segmentReg_1=SEGMENT_REG_DS, value_1=REG_RSI),
    0xa5: X64InstructionInfo("movs",  segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI, segmentReg_1=SEGMENT_REG_DS, value_1=REG_RSI),
    0xa6: X64InstructionInfo("cmps",  segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI, segmentReg_1=SEGMENT_REG_DS, value_1=REG_RSI),
    0xa7: X64InstructionInfo("cmps",  segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI, segmentReg_1=SEGMENT_REG_DS, value_1=REG_RSI),
    0xa8: X64InstructionInfo("test",  numOperands=3, value_0=REG_RFLAGS, isImmediate_2=True),
    0xa9: X64InstructionInfo("test",  numOperands=3, value_0=REG_RFLAGS, isImmediate_2=True, maxSize_2=REG_SIZE_32),
    0xaa: X64InstructionInfo("stors", segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI),
    0xab: X64InstructionInfo("stors", segmentReg_0=SEGMENT_REG_ES, value_0=REG_RDI),
    0xac: X64InstructionInfo("loads", segmentReg_1=SEGMENT_REG_DS, value_1=REG_RSI),
    0xad: X64InstructionInfo("loads", segmentReg_1=SEGMENT_REG_DS, value_1=REG_RSI),
    0xae: X64InstructionInfo("scans", numOperands=3, value_0=REG_RFLAGS, segmentReg_1=SEGMENT_REG_ES, value_1=REG_RDI),
    0xaf: X64InstructionInfo("scans", numOperands=3, value_0=REG_RFLAGS, segmentReg_1=SEGMENT_REG_ES, value_1=REG_RDI),
    0xb0: X64InstructionInfo("mov",   value_0=REG_RAX, isImmediate_1=True, size_op=REG_SIZE_8),
    0xb1: X64InstructionInfo("mov",   value_0=REG_RCX, isImmediate_1=True, size_op=REG_SIZE_8),
    0xb2: X64InstructionInfo("mov",   value_0=REG_RDX, isImmediate_1=True, size_op=REG_SIZE_8),
    0xb3: X64InstructionInfo("mov",   value_0=REG_RBX, isImmediate_1=True, size_op=REG_SIZE_8),
    0xb4: X64InstructionInfo("mov",   value_0=REG_RSP, isImmediate_1=True, size_op=REG_SIZE_8),
    0xb5: X64InstructionInfo("mov",   value_0=REG_RBP, isImmediate_1=True, size_op=REG_SIZE_8),
    0xb6: X64InstructionInfo("mov",   value_0=REG_RSI, isImmediate_1=True, size_op=REG_SIZE_8),
    0xb7: X64InstructionInfo("mov",   value_0=REG_RDI, isImmediate_1=True, size_op=REG_SIZE_8),
    0xb8: X64InstructionInfo("mov",   value_0=REG_RAX, isImmediate_1=True, size_op=REG_SIZE_32),
    0xb9: X64InstructionInfo("mov",   value_0=REG_RCX, isImmediate_1=True, size_op=REG_SIZE_32),
    0xba: X64InstructionInfo("mov",   value_0=REG_RDX, isImmediate_1=True, size_op=REG_SIZE_32),
    0xbb: X64InstructionInfo("mov",   value_0=REG_RBX, isImmediate_1=True, size_op=REG_SIZE_32),
    0xbc: X64InstructionInfo("mov",   value_0=REG_RSP, isImmediate_1=True, size_op=REG_SIZE_32),
    0xbd: X64InstructionInfo("mov",   value_0=REG_RBP, isImmediate_1=True, size_op=REG_SIZE_32),
    0xbe: X64InstructionInfo("mov",   value_0=REG_RSI, isImmediate_1=True, size_op=REG_SIZE_32),
    0xbf: X64InstructionInfo("mov",   value_0=REG_RDI, isImmediate_1=True, size_op=REG_SIZE_32),
    0xc0: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X64InstructionInfo("rol", modRm_0=True, isImmediate_1=True),
                1: X64InstructionInfo("ror", modRm_0=True, isImmediate_1=True),
                2: X64InstructionInfo("rcl", modRm_0=True, isImmediate_1=True),
                3: X64InstructionInfo("rcr", modRm_0=True, isImmediate_1=True),
                4: X64InstructionInfo("shl", modRm_0=True, isImmediate_1=True),
                5: X64InstructionInfo("shr", modRm_0=True, isImmediate_1=True),
                6: X64InstructionInfo("sal", modRm_0=True, isImmediate_1=True),
                7: X64InstructionInfo("sar", modRm_0=True, isImmediate_1=True),
            },
        },
    },
    0xc1: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X64InstructionInfo("rol", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                1: X64InstructionInfo("ror", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                2: X64InstructionInfo("rcl", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                3: X64InstructionInfo("rcr", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                4: X64InstructionInfo("shl", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                5: X64InstructionInfo("shr", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                6: X64InstructionInfo("sal", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
                7: X64InstructionInfo("sar", modRm_0=True, isImmediate_1=True, size_1=REG_SIZE_8),
            },
        },
    },
    0xc2: X64InstructionInfo("ret",   numOperands=1, destinations=[], relativeJump=True, size_0=REG_SIZE_16, _maxSize_0=REG_SIZE_16),
    0xc3: X64InstructionInfo("ret",   numOperands=0),
#   0xc4: Invalid
#   0xc5: Invalid
    0xc6: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X64InstructionInfo("mov", modRm_0=True, isImmediate_1=True),
            },
        },
    },
    0xc7: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X64InstructionInfo("mov", modRm_0=True, isImmediate_1=True, maxSize_1=REG_SIZE_32),
            },
        },
    },
    0xc8: X64InstructionInfo("enter", numOperands=3, isImmediate_1=True, isImmediate_2=True, size_0=REG_SIZE_64, size_1=REG_SIZE_16, size_2=REG_SIZE_8),
    0xc9: X64InstructionInfo("leave", numOperands=0),
    0xca: X64InstructionInfo("retf",  numOperands=1, destinations=[], isImmediate_0=True,  size_0=REG_SIZE_16),
    0xcb: X64InstructionInfo("retf",  numOperands=0),
    0xcc: X64InstructionInfo("int",   destinations=[], isImmediate_0=True, value_0=3, value_1=REG_RFLAGS),
    0xcd: X64InstructionInfo("int",   destinations=[], isImmediate_0=True, value_1=REG_RFLAGS),
    0xce: X64InstructionInfo("into",  destinations=[], value_0=REG_RFLAGS),
    0xcf: X64InstructionInfo("iret",  destinations=[], value_0=REG_RFLAGS),
    0xd0: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X64InstructionInfo("rol", modRm_0=True, isImmediate_1=True, value_1=1),
                1: X64InstructionInfo("ror", modRm_0=True, isImmediate_1=True, value_1=1),
                2: X64InstructionInfo("rcl", modRm_0=True, isImmediate_1=True, value_1=1),
                3: X64InstructionInfo("rcr", modRm_0=True, isImmediate_1=True, value_1=1),
                4: X64InstructionInfo("shl", modRm_0=True, isImmediate_1=True, value_1=1),
                5: X64InstructionInfo("shr", modRm_0=True, isImmediate_1=True, value_1=1),
                6: X64InstructionInfo("sal", modRm_0=True, isImmediate_1=True, value_1=1),
                7: X64InstructionInfo("sar", modRm_0=True, isImmediate_1=True, value_1=1),
            },
        },
    },
    0xd1: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X64InstructionInfo("rol", modRm_0=True, isImmediate_1=True, value_1=1),
                1: X64InstructionInfo("ror", modRm_0=True, isImmediate_1=True, value_1=1),
                2: X64InstructionInfo("rcl", modRm_0=True, isImmediate_1=True, value_1=1),
                3: X64InstructionInfo("rcr", modRm_0=True, isImmediate_1=True, value_1=1),
                4: X64InstructionInfo("shl", modRm_0=True, isImmediate_1=True, value_1=1),
                5: X64InstructionInfo("shr", modRm_0=True, isImmediate_1=True, value_1=1),
                6: X64InstructionInfo("sal", modRm_0=True, isImmediate_1=True, value_1=1),
                7: X64InstructionInfo("sar", modRm_0=True, isImmediate_1=True, value_1=1),
            },
        },
    },
    0xd2: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X64InstructionInfo("rol", modRm_0=True, value_1=REG_RCX),
                1: X64InstructionInfo("ror", modRm_0=True, value_1=REG_RCX),
                2: X64InstructionInfo("rcl", modRm_0=True, value_1=REG_RCX),
                3: X64InstructionInfo("rcr", modRm_0=True, value_1=REG_RCX),
                4: X64InstructionInfo("shl", modRm_0=True, value_1=REG_RCX),
                5: X64InstructionInfo("shr", modRm_0=True, value_1=REG_RCX),
                6: X64InstructionInfo("sal", modRm_0=True, value_1=REG_RCX),
                7: X64InstructionInfo("sar", modRm_0=True, value_1=REG_RCX),
            },
        },
    },
    0xd3: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: X64InstructionInfo("rol", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                1: X64InstructionInfo("ror", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                2: X64InstructionInfo("rcl", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                3: X64InstructionInfo("rcr", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                4: X64InstructionInfo("shl", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                5: X64InstructionInfo("shr", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                6: X64InstructionInfo("sal", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
                7: X64InstructionInfo("sar", modRm_0=True, value_1=REG_RCX, size_1=REG_SIZE_8),
            },
        },
    },
#   0xd4: Invalid
#   0xd5: Invalid
#   0xd6: Invalid
    0xd7: X64InstructionInfo("xlat", size_op=REG_SIZE_8, segmentReg_1=SEGMENT_REG_DS),  # TODO: Check this instruction with objdump
    0xd8: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: {
                    None:       X64InstructionInfo("fadd",  value_0=REG_ST0, modRm_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_64),
                    MOD_DIRECT: X64InstructionInfo("fadd",  value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_64),
                },
                1: {
                    None:       X64InstructionInfo("fmul",  value_0=REG_ST0, modRm_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_64),
                    MOD_DIRECT: X64InstructionInfo("fmul",  value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_64),
                },
                2: {
                    MOD_DIRECT: X64InstructionInfo("fcom",  numOperands=3, value_1=REG_ST0, modRm_2=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_64),
                },
                3: {
                    MOD_DIRECT: X64InstructionInfo("fcomp", numOperands=3, value_1=REG_ST0, modRm_2=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_64),
                },
                4: {
                    None:       X64InstructionInfo("fsub",  value_0=REG_ST0, modRm_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                    MOD_DIRECT: X64InstructionInfo("fsub",  value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                },
                5: {
                    None:       X64InstructionInfo("fsubr", value_0=REG_ST0, modRm_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                    MOD_DIRECT: X64InstructionInfo("fsubr", value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                },
                6: {
                    None:       X64InstructionInfo("fdiv",  value_0=REG_ST0, modRm_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                    MOD_DIRECT: X64InstructionInfo("fdiv",  value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                },
                7: {
                    None:       X64InstructionInfo("fdivr", value_0=REG_ST0, modRm_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                    MOD_DIRECT: X64InstructionInfo("fdivr", value_0=REG_ST0, modRm_1=True, floatReg_1=True, size_op=REG_SIZE_32, maxSize_op=REG_SIZE_32),
                },
            },
        },
    },
    0xd9: {
        None: { # Secondary opcodes
            None: { # Prefixes
                0: X64InstructionInfo("fld",  floatReg_op=True, modRm_1=True, size_op=REG_SIZE_32, value_0=REG_ST0),
                1: X64InstructionInfo("fxch", floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_1=REG_ST0, exchange_inst=True),
                2: {
                    # Direct addressing mode is invalid for this instruction
                    MOD_INDIRECT:    X64InstructionInfo("fst", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_32, value_1=REG_ST0),
                    MOD_1_BYTE_DISP: X64InstructionInfo("fst", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_32, value_1=REG_ST0),
                    MOD_4_BYTE_DISP: X64InstructionInfo("fst", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_32, value_1=REG_ST0),
                },
                3: X64InstructionInfo("fstp",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                4: {
                    # Direct addressing mode is invalid for this instruction
                    MOD_INDIRECT:    X64InstructionInfo("fldenv", modRm_1=True, size_op=REG_SIZE_64, value_0=REG_FPENV),
                    MOD_1_BYTE_DISP: X64InstructionInfo("fldenv", modRm_1=True, size_op=REG_SIZE_64, value_0=REG_FPENV),
                    MOD_4_BYTE_DISP: X64InstructionInfo("fldenv", modRm_1=True, size_op=REG_SIZE_64, value_0=REG_FPENV),
                },
                5: {
                    MOD_INDIRECT:    X64InstructionInfo("fldcw",  modRm_1=True, size_op=REG_SIZE_16, value_0=REG_FPENV),
                    MOD_1_BYTE_DISP: X64InstructionInfo("fldcw",  modRm_1=True, size_op=REG_SIZE_16, value_0=REG_FPENV),
                    MOD_4_BYTE_DISP: X64InstructionInfo("fldcw",  modRm_1=True, size_op=REG_SIZE_16, value_0=REG_FPENV),
                },
                6: {
                    MOD_INDIRECT:    X64InstructionInfo("fstenv", modRm_0=True, size_op=REG_SIZE_64, value_1=REG_FPENV),
                    MOD_1_BYTE_DISP: X64InstructionInfo("fstenv", modRm_0=True, size_op=REG_SIZE_64, value_1=REG_FPENV),
                    MOD_4_BYTE_DISP: X64InstructionInfo("fstenv", modRm_0=True, size_op=REG_SIZE_64, value_1=REG_FPENV),
                },
                7: {
                    MOD_INDIRECT:    X64InstructionInfo("fstcw", modRm_0=True, size_op=REG_SIZE_16, value_1=REG_FPENV),
                    MOD_1_BYTE_DISP: X64InstructionInfo("fstcw", modRm_0=True, size_op=REG_SIZE_16, value_1=REG_FPENV),
                    MOD_4_BYTE_DISP: X64InstructionInfo("fstcw", modRm_0=True, size_op=REG_SIZE_16, value_1=REG_FPENV),
                },
            },
        },
        0xd0: X64InstructionInfo("fnop",    numOperands=0),
        0xe0: X64InstructionInfo("fchs",    numOperands=1, value=REG_ST0, size_0=REG_SIZE_64),
        0xe1: X64InstructionInfo("fabs",    numOperands=1, value=REG_ST0, size_0=REG_SIZE_64),
        0xe4: X64InstructionInfo("ftst",    numOperands=3, value_0=REG_RFLAGS, value_1=REG_ST0, value_2=0.0, size_op=REG_SIZE_64),
        0xe5: X64InstructionInfo("fxam",    value_0=REG_RFLAGS, value_1=REG_ST0, size_op=REG_SIZE_64),
        0xe8: X64InstructionInfo("fld1",    numOperands=1, value_0=REG_ST0, value_1=1.0, isImmediate_1=True, size_op=REG_SIZE_64),
        0xe9: X64InstructionInfo("fldl2t",  numOperands=1, value_0=REG_ST0, value_1=math.log(10, 2),      isImmediate_1=True, size_op=REG_SIZE_64),
        0xea: X64InstructionInfo("fldl2e",  numOperands=1, value_0=REG_ST0, value_1=math.log(10, math.e), isImmediate_1=True, size_op=REG_SIZE_64),
        0xeb: X64InstructionInfo("fldpi",   numOperands=1, value_0=REG_ST0, value_1=math.pi,              isImmediate_1=True, size_op=REG_SIZE_64),
        0xec: X64InstructionInfo("fldlg2",  numOperands=1, value_0=REG_ST0, value_1=math.log(2, 10),      isImmediate_1=True, size_op=REG_SIZE_64),
        0xed: X64InstructionInfo("fldln2",  numOperands=1, value_0=REG_ST0, value_1=math.log(math.e, 2),  isImmediate_1=True, size_op=REG_SIZE_64),
        0xee: X64InstructionInfo("fldz",    numOperands=1, value_0=REG_ST0, value_1=0.0, isImmediate_1=True, size_op=REG_SIZE_64),
        0xf0: X64InstructionInfo("f2xm1",   numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xf1: X64InstructionInfo("fyl2x",   numOperands=1, value_0=REG_ST1, value_1=REG_ST0, size_op=REG_SIZE_64),
        0xf2: X64InstructionInfo("fptan",   numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xf3: X64InstructionInfo("fpatan",  value_0=REG_ST1, value_1=REG_ST0, size_op=REG_SIZE_64),
        0xf4: X64InstructionInfo("fxtract", numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xf5: X64InstructionInfo("fprem1",  value_0=REG_ST1, value_1=REG_ST0, size_op=REG_SIZE_64),
        0xf6: X64InstructionInfo("fdecstp", numOperands=0),
        0xf7: X64InstructionInfo("fincstp", numOperands=0),
        0xf8: X64InstructionInfo("fprem",   value_0=REG_ST0, value_1=REG_ST1, size_op=REG_SIZE_64),
        0xf9: X64InstructionInfo("fyl2xp1", value_0=REG_ST1, value_1=REG_ST0, size_op=REG_SIZE_64),
        0xfa: X64InstructionInfo("fsqrt",   numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xfb: X64InstructionInfo("fsincos", numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xfc: X64InstructionInfo("frndint", numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xfd: X64InstructionInfo("fscale",  value_0=REG_ST0, value_1=REG_ST1, size_op=REG_SIZE_64),
        0xfe: X64InstructionInfo("fsin",    numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
        0xff: X64InstructionInfo("fcos",    numOperands=1, value_0=REG_ST0, size_op=REG_SIZE_64),
    },
#   0xda: TODO:
    0xdb: {
        None: { # Secondary opcodes
            None: { # There are no prefixes
                0: {
                    None:       X64InstructionInfo("fild",    floatReg_op=True, modRm_1=True, value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("cmovnb",  floatReg_op=True, modRm_1=True, value_0=REG_ST0),
                },
                1: {
                    None:       X64InstructionInfo("fisttp",   floatReg_op=True, modRm_0=True, value_1=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fcmovne",  floatReg_op=True, modRm_0=True, value_1=REG_ST0),
                },
                2: {
                    None:       X64InstructionInfo("fist",     floatReg_op=True, modRm_0=True, value_1=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fcmovnbe", floatReg_op=True, modRm_0=True, value_1=REG_ST0),
                },
                3: {
                    None:       X64InstructionInfo("fistp",    floatReg_op=True, modRm_0=True, value_1=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fcmovnu",  floatReg_op=True, modRm_0=True, value_1=REG_ST0),
                },
                # 4 handled as secondary opcodes
                5: {
                    None:       X64InstructionInfo("fld",      floatReg_op=True, modRm_1=True, value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fucomi",   numOperands=3, floatReg_op=True, modRm_1=True, value_0=REG_RFLAGS, value_1=REG_ST0),
                },
                6: X64InstructionInfo("fcomi",   numOperands=3, floatReg_op=True, modRm_1=True, value_0=REG_RFLAGS, value_1=REG_ST0),
                7: {
                    MOD_INDIRECT:    X64InstructionInfo("fstp", floatReg_op=True, modRm_0=True, value_1=REG_ST0),
                    MOD_1_BYTE_DISP: X64InstructionInfo("fstp", floatReg_op=True, modRm_0=True, value_1=REG_ST0),
                    MOD_4_BYTE_DISP: X64InstructionInfo("fstp", floatReg_op=True, modRm_0=True, value_1=REG_ST0),
                },
            },
        },
        0xe0: X64InstructionInfo("nop",     numOperands=0),
        0xe1: X64InstructionInfo("nop",     numOperands=0),
        0xe2: X64InstructionInfo("fclex",   numOperands=0),
        0xe3: X64InstructionInfo("finit",   numOperands=0),
        0xe4: X64InstructionInfo("nop",     numOperands=0),
    },
    0xdc: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: {
                    None:       X64InstructionInfo("fadd",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fadd",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                1: {
                    None:       X64InstructionInfo("fmul",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fmul",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                2: X64InstructionInfo("fcom",   floatReg_op=True, numOperands=3, modRm_2=True, size_op=REG_SIZE_64, value_0=REG_RFLAGS, value_1=REG_ST0),
                3: X64InstructionInfo("fcomp",  floatReg_op=True, numOperands=3, modRm_2=True, size_op=REG_SIZE_64, value_0=REG_RFLAGS, value_1=REG_ST0),
                4: {
                    None:       X64InstructionInfo("fsub",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fsubr",  floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                5: {
                    None:       X64InstructionInfo("fsubr",  floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fsub",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                6: {
                    None:       X64InstructionInfo("fdiv",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fdivr",  floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                7: {
                    None:       X64InstructionInfo("fdivr",  floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fdiv",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
            },
        },
    },
    0xdd: {
        None: { # There are no secondary opcodes
            None: { # There are no prefixes
                0: {
                    None:       X64InstructionInfo("fld",    floatReg_op=True, modR_1=True, size=REG_SIZE_64, value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("ffree",  numOperands=1, floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64),
                },
                1: {
                    None:       X64InstructionInfo("fisttp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fxch",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0, exchange_inst=True),
                },
                2: {
                    None:       X64InstructionInfo("fst",    floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fst",    floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                },
                3: {
                    None:       X64InstructionInfo("fstp",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fstp",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                },
                4: {
                    None:       X64InstructionInfo("frstor", numOperands=1, floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64),
                    MOD_DIRECT: X64InstructionInfo("fucom",  floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                },
                5: {
                    MOD_DIRECT: X64InstructionInfo("fucomp", floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),
                },
                6: {
                    MOD_INDIRECT:    X64InstructionInfo("fsave", numOperands=1, floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64),
                    MOD_1_BYTE_DISP: X64InstructionInfo("fsave", numOperands=1, floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64),
                    MOD_4_BYTE_DISP: X64InstructionInfo("fsave", numOperands=1, floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64),
                },
                7: {
                    MOD_INDIRECT:    X64InstructionInfo("fstsw", modRm_0=True, size_op=REG_SIZE_16, value_1=REG_FPENV),
                    MOD_1_BYTE_DISP: X64InstructionInfo("fstsw", modRm_0=True, size_op=REG_SIZE_16, value_1=REG_FPENV),
                    MOD_1_BYTE_DISP: X64InstructionInfo("fstsw", modRm_0=True, size_op=REG_SIZE_16, value_1=REG_FPENV),
                },
            },
        },
    },
    0xde: {
        None: {
            None: {
                0: {
                    None:       X64InstructionInfo("fiadd", floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("faddp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                1: {
                    None:       X64InstructionInfo("fimul", floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fmulp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                2: {
                    None:       X64InstructionInfo("ficom",  numOperands=3, floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fcomp",  numOperands=3, floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                3: {
                    None:       X64InstructionInfo("ficomp", numOperands=3, floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fcompp", numOperands=3, floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                4: {
                    None:       X64InstructionInfo("fisub",  floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fsubrp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                5: {
                    None:       X64InstructionInfo("fisubr", floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fsubp",  floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                6: {
                    None:       X64InstructionInfo("fidiv",  floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fdivrp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                7: {
                    None:       X64InstructionInfo("fidivr", floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fdivp",  floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
            },
        },
    },
    0xdf: {
        None: {
            None: {
                0: {
                    None:       X64InstructionInfo("fild",   floatReg_op=True, modRm_1=True, size_1=REG_SIZE_16,  value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("ffreep", numOperands=1, floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64),
                },
                1: {
                    None:       X64InstructionInfo("fistp",  floatReg_op=True, modRm_0=True, size_1=REG_SIZE_16,  value_1=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fxch",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0, exchange_inst=True),
                },
                2: {
                    None:       X64InstructionInfo("fist",   floatReg_op=True, modRm_0=True, size_1=REG_SIZE_16,  value_1=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fstp",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                3: {
                    None:       X64InstructionInfo("fistp",  floatReg_op=True, modRm_0=True, size_1=REG_SIZE_16,  value_1=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fstp",   floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                },
                4: {
                    None:       X64InstructionInfo("fbld",   floatReg_op=True, modRm_1=True, size_op=REG_SIZE_64, value_0=REG_ST0),    # bcd value
                    MOD_DIRECT: X64InstructionInfo("fstw",   size_op=REG_SIZE_16, value_0=REG_RAX, value_1=REG_FPENV),
                },
                5: {
                    None:       X64InstructionInfo("fild",    floatReg_op=True, modRm_1=True, size_1=REG_SIZE_64,  value_0=REG_ST0),
                    MOD_DIRECT: X64InstructionInfo("fucomip", numOperands=3, floatReg_op=True, modRm_1=True, value_0=REG_RFLAGS, value_1=REG_ST0),
                },
                6: {
                    None:       X64InstructionInfo("fbstp",  floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),    # bcd value
                    MOD_DIRECT: X64InstructionInfo("fcomip", numOperands=3, floatReg_op=True, modRm_1=True, value_0=REG_RFLAGS, value_1=REG_ST0),
                },
                7: {
                    MOD_INDIRECT:    X64InstructionInfo("fistp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                    MOD_1_BYTE_DISP: X64InstructionInfo("fistp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
                    MOD_4_BYTE_DISP: X64InstructionInfo("fistp", floatReg_op=True, modRm_0=True, size_op=REG_SIZE_64, value_1=REG_ST0),
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
    0xe8: X64InstructionInfo("call",  destinations=[], relativeJump=True, size_0=REG_SIZE_32, maxSize_0=REG_SIZE_32),
    0xe9: X64InstructionInfo("jmp",   destinations=[], relativeJump=True, size_0=REG_SIZE_32, maxSize_0=REG_SIZE_32),
#   0xea: Invalid
    0xeb: X64InstructionInfo("jmp",   destinations=[], relativeJump=True, size_0=REG_SIZE_8),
#   0xec: TODO:
#   0xed: TODO:
#   0xee: TODO:
#   0xef: TODO:
#   0xf0: Lock Prefix
#   0xf1: TODO:
#   0xf2: Repeat while not zero prefix
#   0xf3: Repeat while zero prefix
    0xf4: X64InstructionInfo("hlt",   numOperands=0),
    0xf5: X64InstructionInfo("cmc",   numOperands=0),
    0xf6: X64InstructionInfo("",      modRm=MODRM_SRC, extOpcode=True),
    0xf7: X64InstructionInfo("",      modRm=MODRM_SRC, extOpcode=True),
    0xf8: X64InstructionInfo("clc",   numOperands=0),
    0xf9: X64InstructionInfo("stc",   numOperands=0),
    0xfa: X64InstructionInfo("cli",   numOperands=0),
    0xfb: X64InstructionInfo("sti",   numOperands=0),
    0xfc: X64InstructionInfo("cld",   numOperands=0),
    0xfd: X64InstructionInfo("std",   numOperands=0),
    0xfe: {
        None: {
            None: {
                0: X64InstructionInfo("inc", numOperands=1, modRm_0=True),
                1: X64InstructionInfo("dec", numOperands=1, modRm_0=True),
            },
        },
    },
    0xff: {
        None: {
            None: {
                0: X64InstructionInfo("inc",   numOperands=1, modRm_0=True),
                1: X64InstructionInfo("dec",   numOperands=1, modRm_0=True),
                2: X64InstructionInfo("call",  numOperands=1, destinations=[], modRm_0=True, size_0=REG_SIZE_64),
                3: X64InstructionInfo("callf", numOperands=1, destinations=[], modRm_0=True, size_0=REG_SIZE_64), #TODO: Needs to be done correctly. See Intel documentation.
                4: X64InstructionInfo("jmp",   numOperands=1, destinations=[], modRm_0=True, size_0=REG_SIZE_64),
                5: X64InstructionInfo("jmpf",  numOperands=1, destinations=[], modRm_0=True, size_0=REG_SIZE_64), #TODO: Needs to be done correctly. See Intel documentation.
                6: X64InstructionInfo("push",  modRm_1=True, value_0=REG_STACK, size_op=REG_SIZE_64),
            },
        },
    },
}

twoByteOpcodes = {
    0x10: {
        None: {
            None: X64InstructionInfo("movups", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("movupd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf2: X64InstructionInfo("movsd",  modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf3: X64InstructionInfo("movss",  modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x11: {
        None: {
            None: X64InstructionInfo("movups", modRm=MODRM_DST, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("movupd", modRm=MODRM_DST, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf2: X64InstructionInfo("movsd",  modRm=MODRM_DST, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf3: X64InstructionInfo("movss",  modRm=MODRM_DST, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },

    0x1f: X64InstructionInfo("nop",   modRm=MODRM_SRC),

    0x28: {
        None: {
            None: X64InstructionInfo("movaps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("movapd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x29: {
        None: {
            None: X64InstructionInfo("movaps", modRm=MODRM_DST, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("movapd", modRm=MODRM_DST, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x2a: {
        None: {
            None: X64InstructionInfo("cvtpi2ps", modRm=MODRM_SRC, op_mmRegister=True,  src_size=REG_SIZE_64, dst_size=REG_SIZE_128),
            0x66: X64InstructionInfo("cvtpi2pd", modRm=MODRM_SRC, op_mmRegister=True,  src_size=REG_SIZE_64, dst_size=REG_SIZE_128),
            0xf2: X64InstructionInfo("cvtsi2sd", modRm=MODRM_SRC, dst_mmRegister=True, src_size=REG_SIZE_32, dst_size=REG_SIZE_128),
            0xf3: X64InstructionInfo("cvtsi2ss", modRm=MODRM_SRC, dst_mmRegister=True, src_size=REG_SIZE_32, dst_size=REG_SIZE_128),
        },
    },

    0x2c: {
        None: {
            None: X64InstructionInfo("cvttps2pi", modRm=MODRM_SRC, op_mmRegister=True,  size_op=REG_SIZE_64),
            0x66: X64InstructionInfo("cvttpd2pi", modRm=MODRM_SRC, op_mmRegister=True,  src_size=REG_SIZE_128, dst_size=REG_SIZE_64),
            0xf2: X64InstructionInfo("cvttsd2si", modRm=MODRM_SRC, src_mmRegister=True, src_size=REG_SIZE_128, dst_size=REG_SIZE_32),
            0xf3: X64InstructionInfo("cvttss2si", modRm=MODRM_SRC, src_mmRegister=True, src_size=REG_SIZE_128, dst_size=REG_SIZE_32),
        },
    },

    0x2e: {
        None: {
            None: X64InstructionInfo("ucomiss", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("ucomisd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },

    0x40: X64InstructionInfo("cmovo",  modRm=MODRM_SRC, size_op=REG_SIZE_32), # Overflow
    0x41: X64InstructionInfo("cmovno", modRm=MODRM_SRC, size_op=REG_SIZE_32), # Not overflow
    0x42: X64InstructionInfo("cmovb",  modRm=MODRM_SRC, size_op=REG_SIZE_32), # Less than (unsigned)
    0x43: X64InstructionInfo("cmovae", modRm=MODRM_SRC, size_op=REG_SIZE_32), # Greater than or equal (unsigned)
    0x44: X64InstructionInfo("cmove",  modRm=MODRM_SRC, size_op=REG_SIZE_32), # Equal
    0x45: X64InstructionInfo("cmovne", modRm=MODRM_SRC, size_op=REG_SIZE_32), # Not equal
    0x46: X64InstructionInfo("cmovbe", modRm=MODRM_SRC, size_op=REG_SIZE_32), # Less than or equal (unsigned)
    0x47: X64InstructionInfo("cmova",  modRm=MODRM_SRC, size_op=REG_SIZE_32), # Greater than (unsigned)
    0x48: X64InstructionInfo("cmovs",  modRm=MODRM_SRC, size_op=REG_SIZE_32), # Signed
    0x49: X64InstructionInfo("cmovns", modRm=MODRM_SRC, size_op=REG_SIZE_32), # Unsigned
    0x4a: X64InstructionInfo("cmovp",  modRm=MODRM_SRC, size_op=REG_SIZE_32), # Parity
    0x4b: X64InstructionInfo("cmovnp", modRm=MODRM_SRC, size_op=REG_SIZE_32), # Not parity
    0x4c: X64InstructionInfo("cmovlt", modRm=MODRM_SRC, size_op=REG_SIZE_32), # Less than (signed)
    0x4d: X64InstructionInfo("cmovge", modRm=MODRM_SRC, size_op=REG_SIZE_32), # Greater than or equal (signed)
    0x4e: X64InstructionInfo("cmovle", modRm=MODRM_SRC, size_op=REG_SIZE_32), # Less than or equal (signed)
    0x4f: X64InstructionInfo("cmovgt", modRm=MODRM_SRC, size_op=REG_SIZE_32), # Greater than (signed)

    0x51: {
        None: {
            None: X64InstructionInfo("sqrtps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("sqrtpd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf2: X64InstructionInfo("sqrtsd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf3: X64InstructionInfo("sqrtss", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x52: {
        None: {
            None: X64InstructionInfo("rsqrtps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf3: X64InstructionInfo("rsqrtss", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x53: {
        None: {
            None: X64InstructionInfo("rcpps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf3: X64InstructionInfo("rcpss", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x54: {
        None: {
            None: X64InstructionInfo("andps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("andpd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x55: {
        None: {
            None: X64InstructionInfo("addps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("addpd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x56: {
        None: {
            None: X64InstructionInfo("orps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("orpd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x57: {
        None: {
            None: X64InstructionInfo("xorps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("xorpd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x58: {
        None: {
            None: X64InstructionInfo("addps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("addpd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf2: X64InstructionInfo("addsd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf3: X64InstructionInfo("addss", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x59: {
        None: {
            None: X64InstructionInfo("mulps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("mulpd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf2: X64InstructionInfo("mulsd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf3: X64InstructionInfo("mulss", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },

    0x5c: {
        None: {
            None: X64InstructionInfo("subps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("subpd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf2: X64InstructionInfo("subsd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf3: X64InstructionInfo("subss", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x5d: {
        None: {
            None: X64InstructionInfo("minps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("minpd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf2: X64InstructionInfo("minsd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf3: X64InstructionInfo("minss", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x5e: {
        None: {
            None: X64InstructionInfo("divps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("divpd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf2: X64InstructionInfo("divsd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf3: X64InstructionInfo("divss", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
    0x5f: {
        None: {
            None: X64InstructionInfo("maxps", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0x66: X64InstructionInfo("maxpd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf2: X64InstructionInfo("maxsd", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf3: X64InstructionInfo("maxss", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },

    0x6f: {
        None: {
            None: X64InstructionInfo("movq",   modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_64),
            0x66: X64InstructionInfo("movdqa", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
            0xf3: X64InstructionInfo("movdqu", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },

    0x80: X64InstructionInfo("jo",    relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Overflow
    0x81: X64InstructionInfo("jno",   relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Not overflow
    0x82: X64InstructionInfo("jb",    relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Less than (unsigned)
    0x83: X64InstructionInfo("jae",   relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Greater than or equal (unsigned)
    0x84: X64InstructionInfo("je",    relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Equal
    0x85: X64InstructionInfo("jne",   relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Not equal
    0x86: X64InstructionInfo("jbe",   relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Less than or equal (unsigned)
    0x87: X64InstructionInfo("ja",    relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Greater than (unsigned)
    0x88: X64InstructionInfo("js",    relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Signed
    0x89: X64InstructionInfo("jns",   relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Unsigned
    0x8a: X64InstructionInfo("jp",    relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Parity
    0x8b: X64InstructionInfo("jnp",   relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Not parity
    0x8c: X64InstructionInfo("jlt",   relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Less than (signed)
    0x8d: X64InstructionInfo("jge",   relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Greater than or equal (signed)
    0x8e: X64InstructionInfo("jle",   relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Less than or equal (signed)
    0x8f: X64InstructionInfo("jgt",   relativeJump=True, signExtension=True, src_size=REG_SIZE_32), # Greater than (signed)
    0x90: X64InstructionInfo("seto",  modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Overflow
    0x91: X64InstructionInfo("setno", modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Not Overflow
    0x92: X64InstructionInfo("setb",  modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Less than (unsigned)
    0x93: X64InstructionInfo("setae", modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Greater than or equal (unsigned)
    0x94: X64InstructionInfo("sete",  modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Equal
    0x95: X64InstructionInfo("setne", modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Not equal
    0x96: X64InstructionInfo("setbe", modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Less than or equal (unsigned)
    0x97: X64InstructionInfo("seta",  modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Greater than (unsigned)
    0x98: X64InstructionInfo("sets",  modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Signed
    0x99: X64InstructionInfo("setns", modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Not signed
    0x9a: X64InstructionInfo("setp",  modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Parity
    0x9b: X64InstructionInfo("setnp", modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Not parity
    0x9c: X64InstructionInfo("setl",  modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Less than (signed)
    0x9d: X64InstructionInfo("setge", modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Greater than or equal (signed)
    0x9e: X64InstructionInfo("setle", modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Less than or equal (signed)
    0x9f: X64InstructionInfo("setg",  modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Greater than (signed)

    0xa3: X64InstructionInfo("bt",    modRm=MODRM_DST, size_op=REG_SIZE_32),

    0xaf: X64InstructionInfo("imul",  modRm=MODRM_SRC, size_op=REG_SIZE_32),

    0xb6: X64InstructionInfo("movzx", modRm=MODRM_SRC, src_size=REG_SIZE_8,  dst_size=REG_SIZE_32),
    0xb7: X64InstructionInfo("movzx", modRm=MODRM_SRC, src_size=REG_SIZE_16, dst_size=REG_SIZE_32, src_maxSize=REG_SIZE_16),
    0xbe: X64InstructionInfo("movsx", modRm=MODRM_SRC, signExtension=True,   src_size=REG_SIZE_8,  dst_size=REG_SIZE_32),
    0xbf: X64InstructionInfo("movsx", modRm=MODRM_SRC, signExtension=True,   src_size=REG_SIZE_16, dst_size=REG_SIZE_32, src_maxSize=REG_SIZE_16),

    0xef: {
        None: {
            None: X64InstructionInfo("pxor", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_64),
            0x66: X64InstructionInfo("pxor", modRm=MODRM_SRC, op_mmRegister=True, size_op=REG_SIZE_128),
        },
    },
}
