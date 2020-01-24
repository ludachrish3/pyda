from pyda.disassemblers.disassembler import Instruction, Operand
from pyda.disassemblers.x64.definitions import *

import copy
import logging

logger = logging.getLogger(__name__)

class X64Instruction( Instruction ):

    def __init__( self, mnemonic="byte", addr=0, source=None, dest=None, extraOperands=[] ):
        super().__init__(mnemonic, addr, source, dest, extraOperands)

        self.prefixSize    = None   # The size operands should be based on the prefix
        self.segmentPrefix = 0      # Opcode of the segment
        self.legacyPrefix  = None   # Lock, repeat, or operand size prefix
        self.addressSize   = REG_SIZE_64
        self.extendBase    = False
        self.extendIndex   = False
        self.extendReg     = False

    def setAttributes( self, opcode, info ):

        applyLegacyPrefix = True

        # The info entry can be a dictionary if the instruction changes meaning
        # based on the legacy prefix. The dictionary is of the form
        # {
        #   None: X64InstructionInfo(...),
        #   0x66: X64InstructionInfo(...),
        #   0xf0: X64InstructionInfo(...),
        #   0xf2: X64InstructionInfo(...),
        #   0xf3: X64InstructionInfo(...),
        # }
        # where each key is a possible prefix. None is the value to use when
        # the legacy prefix does not change the opcodes's meaning.
        if type(info) == dict:
            if self.legacyPrefix in info:
                info = info[self.legacyPrefix]
                applyLegacyPrefix = False

            else:
                info = info[None]


        # Create deep copies so that the dictionary of infos remains unchanged
        # and this specific instruction's info can be updated as needed.
        self.info = copy.deepcopy(info)
        self.mnemonic = copy.deepcopy(info.mnemonic)

        logger.debug(f"src:  {self.info.srcKwargs}")
        logger.debug(f"dst:  {self.info.dstKwargs}")
        logger.debug(f"inst: {self.info.instKwargs}")

        info = self.info
        srcKwargs  = info.srcKwargs
        dstKwargs  = info.dstKwargs

        # Update instruction attributes based on the instruction kwargs
        self.__dict__.update(info.instKwargs)

        # If the legacy prefix has no bearing on the opcode's meaning now is
        # the appropriate time to apply its effects.
        if applyLegacyPrefix:
            if self.legacyPrefix == PREFIX_16_BIT_OPERAND:
                self.prefixSize = REG_SIZE_16

            # Handle renaming the mnemonic for Group 1 prefixes
            # TODO: There are special cases for some of these, so that will need to
            # be handled in the future.
            elif self.legacyPrefix == PREFIX_LOCK:
                self.mnemonic = "lock " + self.mnemonic

            elif self.legacyPrefix == PREFIX_REPEAT_NZERO:
                self.mnemonic = "repnz " + self.mnemonic

            elif self.legacyPrefix == PREFIX_REPEAT_ZERO:
                self.mnemonic = "repz " + self.mnemonic

        #############################
        #  DETERMINE OPERAND SIZES  #
        #############################

        srcSize    = srcKwargs.get("size",    None)
        srcMaxSize = srcKwargs.get("maxSize", REG_SIZE_64)

        dstSize    = dstKwargs.get("size",    None)
        dstMaxSize = dstKwargs.get("maxSize", REG_SIZE_64)

        srcKwargs["size"] = self.getOperandSize(opcode, self.prefixSize, srcSize, srcMaxSize)
        dstKwargs["size"] = self.getOperandSize(opcode, self.prefixSize, dstSize, dstMaxSize)

        # Handle conversion opcodes that sign extends the value in EAX
        if info.isConversion:
            if opcode == CONVERT_TO_RAX:
                if dstKwargs["size"] == REG_SIZE_16:
                    self.mnemonic = "cbw"

                if dstKwargs["size"] == REG_SIZE_32:
                    self.mnemonic = "cwde"

                if dstKwargs["size"] == REG_SIZE_64:
                    self.mnemonic = "cdqe"

            elif opcode == CONVERT_TO_RDX:
                if dstKwargs["size"] == REG_SIZE_16:
                    self.mnemonic = "cwd"

                if dstKwargs["size"] == REG_SIZE_32:
                    self.mnemonic = "cdq"

                if dstKwargs["size"] == REG_SIZE_64:
                    self.mnemonic = "cqo"

            # Do not continue on to create operands because conversions have
            # implicit operands based on the opcode. They all use some form of
            # EAX, so leaving them with a value of zero is good enough for it
            # to be disassembled corretly.
            return

        logger.debug(f"source size: {srcKwargs['size']}, dest size: {dstKwargs['size']}")

        #####################
        #  CREATE OPERANDS  #
        #####################

        register = 0

        # Handle sign extension if the bit it meaningful
        if opcode & OP_SIGN_MASK:
            info.signExtension = True

        # Handle setup if there is a register code in the opcode
        if info.registerCode:
            register = opcode & REG_MASK

            if self.extendBase:
                register |= REG_EXTEND

        # Create a destination operand as long as the size isn't 0 and the
        # instruction is not a jump, which would not have a destination.
        if self.dest is None and not info.relativeJump and dstKwargs["size"] != REG_SIZE_0:
            if "value" not in dstKwargs:
                dstKwargs["value"] = register

            self.dest = X64Operand(**dstKwargs)

            # Set the register to 0 now because the destination is always the
            # one to get the register value unless there is no destination.
            # This keeps the source from also getting the value if there is a
            # destination.
            register = 0

        # Create a source operand as long as the size isn't 0 and it has not
        # already been created
        if self.source is None and srcKwargs["size"] != REG_SIZE_0:
            if "value" not in srcKwargs:
                srcKwargs["value"] = register

            self.source = X64Operand(**srcKwargs)

        ################################
        #  SET MOD R/M OPERAND STATUS  #
        ################################

        if info.modRm == MODRM_SOURCE:
            logger.debug("Source gets the mod r/m byte")
            self.source.modRm = True

        elif info.modRm == MODRM_DEST:
            logger.debug("Dest gets the mod r/m byte")
            self.dest.modRm = True


    @classmethod
    def getOperandSize( cls, opcode, prefixSize, infoSize, maxSize ):
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
                        prefixSize - The size based on a prefix byte
                        infoSize   - The size from the table of opcodes
                        maxSize    - The maximum allowed size for the operand

        Return:         The size that should be used for the operand.
        """

        sizeBit = opcode & OP_SIZE_MASK

        logger.debug(f"prefixSize: {prefixSize}, infoSize: {infoSize}, maxSize: {maxSize}, sizeBit: {sizeBit}")

        # If a register size is 0, that means it should not exist and the size
        # should remain 0 no matter what.
        if infoSize == REG_SIZE_0:
            return infoSize

        # If the REX 8-bit prefix is not there, then the size remains the normal
        # 8-bit register. Also, if there is no infoSize and the size bit is 0, the
        # operand is 8 bits. The REX 8-bit prefix only applies in these cases.
        if infoSize == REG_SIZE_8 or (infoSize is None and sizeBit == 0):
            if prefixSize == REG_SIZE_8_REX:
                return REG_SIZE_8_REX

            return REG_SIZE_8

        # The REX 8-bit prefix has no effect if the operand isn't originally 8 bits
        if prefixSize == REG_SIZE_8_REX:
            prefixSize = None

        # If there is a prefix size within the allowed range and there is no info
        # size override, trust the size bit to determine the default size of the
        # operand. If the bit is 0, then the operand is 8 bits and cannot be changed
        # Or if an info size is specified because then the size bit doesn't matter.
        if prefixSize is not None and prefixSize <= maxSize:
            logger.debug("Using prefix size")
            size = prefixSize

        elif infoSize is not None and infoSize <= maxSize:
            logger.debug("Using info size")
            size = infoSize

        elif infoSize is not None and infoSize > maxSize:
            logger.debug("Using max size")
            size = maxSize

        elif infoSize is None and sizeBit == 0:
            logger.debug("Using bit size 8")
            return REG_SIZE_8

        elif infoSize is None and sizeBit == 1:
            logger.debug("Using bit size 32")
            size = REG_SIZE_32

        # If the info size somehow exceeds the maximum, use the maximum instead
        # because the size bit shold not be used if an info size was specified.
        if size > maxSize:
            logger.debug("Capping to max size")
            size = maxSize

        return size


class X64Operand( Operand ):

    def __init__( self, size=REG_SIZE_32, maxSize=REG_SIZE_64, value=0, segmentReg=0, isImmediate=False, indirect=False ):

        super().__init__(size, value)
        self.maxSize = maxSize          # The maximum size allowed for the operand
        self.isImmediate = isImmediate  # Whether the operand is an immediate
        self.segmentReg = segmentReg    # The segment register to use as a base value
        self.indirect = indirect        # Whether the addressing is indirect
        self.displacement = 0           # Value of the displacement from the register value
        self.modRm = False              # Whether the Mod R/M byte applies
        self.scale = 0                  # Factor to multiply the index by if SIB byte is present
        self.index = None               # Index register if SIB byte is present

    def __repr__( self ):

        value    = self.value
        scale    = self.scale
        index    = self.index
        displace = self.displacement

        if self.isImmediate and value is not None:
            return f"{hex(value)}"

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

        # There is only an index if the scale was set to be nonzero, and RSP is
        # not a valid index register.
        if scale > 0 and index is not None and index != REG_RSP:
            indexName  = REG_NAMES[index][REG_SIZE_64]

        # Handle the scale and index values. They should only be there if
        # scale is greater than 0 and the index has a valid name. It will not
        # have a valid name if it is RSP because that is not a valid index.
        if scale > 0 and indexName != "":

            # Only print the scale value if it is not 1 to make it more clean
            if scale > 1:
                scaleStr = f"{scale} * "

        # Handle combining the base and index values. If at least one value is
        # not an empty string, then the values need to go in brackets. If both
        # are set, then they need to be separated by a plus sign. If only one is
        # set, then just putting them all next to each other in brackets is okay
        # because one will be nothing and the other will be the only value.
        if regName != "" or indexName != "":
            if regName != "" and indexName != "":
                baseIndexStr = f"[{regName} + {scaleStr}{indexName}]"

            else:
                baseIndexStr = f"[{regName}{scaleStr}{indexName}]"

        # Handle the displacement value
        if displace != 0:
            signStr = ""
            if baseIndexStr != "" and displace > 0:
                signStr = " + "
            elif baseIndexStr != "" and displace < 0:
                signStr = " - "
            displaceStr = f"{signStr}{hex(abs(displace))}"

        return f"{segmentStr}{baseIndexStr}{displaceStr}"


class X64InstructionInfo():

    def __init__( self, mnemonic, registerCode=False, modRm=MODRM_NONE, extOpcode=False,
                  relativeJump=False, signExtension=False, isConversion=False, **kwargs):

        # Opcode info
        self.mnemonic      = mnemonic       # The name of the instruction
        self.registerCode  = registerCode   # Whether the least 3 significant bits of the opcode represent a register
        self.modRm         = modRm          # How the Mod R/M byte must be handled
        self.extOpcode     = extOpcode      # Whether the opcode is extended into the ModR/M
        self.signExtension = signExtension  # Whether the sign should be extended
        self.isConversion  = isConversion   # Whether the instruction is size conversion
        self.relativeJump  = relativeJump   # Whether the instruction is a relative jump and expects an immediate to follow the opcode

        self.srcKwargs  = { key.split("_")[1]: value for (key, value) in kwargs.items() if key.startswith(("src_", "op_")) }
        self.dstKwargs  = { key.split("_")[1]: value for (key, value) in kwargs.items() if key.startswith(("dst_", "op_")) }
        self.instKwargs = { key.split("_")[1]: value for (key, value) in kwargs.items() if key.startswith("inst_")         }

        # Set properties that are always true if the instruction is a relative jump
        if self.relativeJump:
            self.signExtension  = True
            self.srcKwargs["isImmediate"] = True


# The structure for opcodes and their info is a dictionary keyed on the primary
# opcode. If there are any prefixes that change the opcode's meaning or
# secondary opcodes, there are nested dictionaries to handle these cases. The
# structure is the following if there are secondary opcodes:
#   primaryOpcode: {
#       secondaryOpcode1: {
#           None:    X64InstructionInfo(...),
#           prefix1: X64InstructionInfo(...),
#           prefix2: X64InstructionInfo(...),
#           prefix3: X64InstructionInfo(...),
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

    0x00: X64InstructionInfo("add",   modRm=MODRM_DEST),
    0x01: X64InstructionInfo("add",   modRm=MODRM_DEST),
    0x02: X64InstructionInfo("add",   modRm=MODRM_SOURCE),
    0x03: X64InstructionInfo("add",   modRm=MODRM_SOURCE),
    0x04: X64InstructionInfo("add",   src_isImmediate=True),
    0x05: X64InstructionInfo("add",   signExtension=True, src_isImmediate=True, src_maxSize=REG_SIZE_32),
#   0x06: Invalid
#   0x07: Invalid
    0x08: X64InstructionInfo("or",    modRm=MODRM_DEST),
    0x09: X64InstructionInfo("or",    modRm=MODRM_DEST),
    0x0a: X64InstructionInfo("or",    modRm=MODRM_SOURCE),
    0x0b: X64InstructionInfo("or",    modRm=MODRM_SOURCE),
    0x0c: X64InstructionInfo("or",    src_isImmediate=True),
    0x0d: X64InstructionInfo("or",    signExtension=True, src_isImmediate=True, src_maxSize=REG_SIZE_32),
#   0x0e: Invalid
#   0x0f: 2 byte operand prefix
    0x10: X64InstructionInfo("adc",   modRm=MODRM_DEST),
    0x11: X64InstructionInfo("adc",   modRm=MODRM_DEST),
    0x12: X64InstructionInfo("adc",   modRm=MODRM_SOURCE),
    0x13: X64InstructionInfo("adc",   modRm=MODRM_SOURCE),
    0x14: X64InstructionInfo("adc",   src_isImmediate=True),
    0x15: X64InstructionInfo("adc",   signExtension=True, src_isImmediate=True, src_maxSize=REG_SIZE_32),
#   0x16: Invalid
#   0x17: Invalid
    0x18: X64InstructionInfo("sbb",   modRm=MODRM_DEST),
    0x19: X64InstructionInfo("sbb",   modRm=MODRM_DEST),
    0x1a: X64InstructionInfo("sbb",   modRm=MODRM_SOURCE),
    0x1b: X64InstructionInfo("sbb",   modRm=MODRM_SOURCE),
    0x1c: X64InstructionInfo("sbb",   src_isImmediate=True),
    0x1d: X64InstructionInfo("sbb",   signExtension=True, src_isImmediate=True, src_maxSize=REG_SIZE_32),
#   0x1e: Invalid
#   0x1f: Invalid
    0x20: X64InstructionInfo("and",   modRm=MODRM_DEST),
    0x21: X64InstructionInfo("and",   modRm=MODRM_DEST),
    0x22: X64InstructionInfo("and",   modRm=MODRM_SOURCE),
    0x23: X64InstructionInfo("and",   modRm=MODRM_SOURCE),
    0x24: X64InstructionInfo("and",   src_isImmediate=True),
    0x25: X64InstructionInfo("and",   signExtension=True, src_isImmediate=True, src_maxSize=REG_SIZE_32),
#   0x26: ES Segment Register Prefix
#   0x27: Invalid
    0x28: X64InstructionInfo("sub",   modRm=MODRM_DEST),
    0x29: X64InstructionInfo("sub",   modRm=MODRM_DEST),
    0x2a: X64InstructionInfo("sub",   modRm=MODRM_SOURCE),
    0x2b: X64InstructionInfo("sub",   modRm=MODRM_SOURCE),
    0x2c: X64InstructionInfo("sub",   src_isImmediate=True),
    0x2d: X64InstructionInfo("sub",   signExtension=True, src_isImmediate=True, src_maxSize=REG_SIZE_32),
#   0x2e: CS Segment Register Prefix
#   0x2f: Invalid
    0x30: X64InstructionInfo("xor",   modRm=MODRM_DEST),
    0x31: X64InstructionInfo("xor",   modRm=MODRM_DEST),
    0x32: X64InstructionInfo("xor",   modRm=MODRM_SOURCE),
    0x33: X64InstructionInfo("xor",   modRm=MODRM_SOURCE),
    0x34: X64InstructionInfo("xor",   src_isImmediate=True),
    0x35: X64InstructionInfo("xor",   signExtension=True, src_isImmediate=True, src_maxSize=REG_SIZE_32),
#   0x36: SS Segment Register Prefix
#   0x37: Invalid
    0x38: X64InstructionInfo("cmp",   modRm=MODRM_DEST),
    0x39: X64InstructionInfo("cmp",   modRm=MODRM_DEST),
    0x3a: X64InstructionInfo("cmp",   modRm=MODRM_SOURCE),
    0x3b: X64InstructionInfo("cmp",   modRm=MODRM_SOURCE),
    0x3c: X64InstructionInfo("cmp",   src_isImmediate=True),
    0x3d: X64InstructionInfo("cmp",   signExtension=True, src_isImmediate=True, src_maxSize=REG_SIZE_32),
#   0x3e: DS Segment Register Prefix
#   0x3f: Invalid
#   0x40: REX Prefix (does nothing)
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
    0x50: X64InstructionInfo("push",  registerCode=True, src_size=REG_SIZE_64, dst_size=REG_SIZE_0),
    0x51: X64InstructionInfo("push",  registerCode=True, src_size=REG_SIZE_64, dst_size=REG_SIZE_0),
    0x52: X64InstructionInfo("push",  registerCode=True, src_size=REG_SIZE_64, dst_size=REG_SIZE_0),
    0x53: X64InstructionInfo("push",  registerCode=True, src_size=REG_SIZE_64, dst_size=REG_SIZE_0),
    0x54: X64InstructionInfo("push",  registerCode=True, src_size=REG_SIZE_64, dst_size=REG_SIZE_0),
    0x55: X64InstructionInfo("push",  registerCode=True, src_size=REG_SIZE_64, dst_size=REG_SIZE_0),
    0x56: X64InstructionInfo("push",  registerCode=True, src_size=REG_SIZE_64, dst_size=REG_SIZE_0),
    0x57: X64InstructionInfo("push",  registerCode=True, src_size=REG_SIZE_64, dst_size=REG_SIZE_0),
    0x59: X64InstructionInfo("pop",   registerCode=True, dst_size=REG_SIZE_64, src_size=REG_SIZE_0),
    0x5a: X64InstructionInfo("pop",   registerCode=True, dst_size=REG_SIZE_64, src_size=REG_SIZE_0),
    0x5b: X64InstructionInfo("pop",   registerCode=True, dst_size=REG_SIZE_64, src_size=REG_SIZE_0),
    0x5c: X64InstructionInfo("pop",   registerCode=True, dst_size=REG_SIZE_64, src_size=REG_SIZE_0),
    0x5d: X64InstructionInfo("pop",   registerCode=True, dst_size=REG_SIZE_64, src_size=REG_SIZE_0),
    0x5e: X64InstructionInfo("pop",   registerCode=True, dst_size=REG_SIZE_64, src_size=REG_SIZE_0),
    0x5f: X64InstructionInfo("pop",   registerCode=True, dst_size=REG_SIZE_64, src_size=REG_SIZE_0),
    0x58: X64InstructionInfo("pop",   registerCode=True, dst_size=REG_SIZE_64, src_size=REG_SIZE_0),
#   0x60: Invalid
#   0x61: Invalid
#   0x62: Invalid
    0x63: X64InstructionInfo("movsxd", modRm=MODRM_SOURCE, signExtension=True, src_size=REG_SIZE_16, dst_size=REG_SIZE_32, src_maxSize=REG_SIZE_16),
#   0x64: FS Segment Register Prefix
#   0x65: GS Segment Register Prefix
#   0x66: 16-bit Operand Size Prefix or access to Double Quadword Registers
#   0x67: TODO: 32-bit Address Size Prefix
    0x68: X64InstructionInfo("push",  signExtension=True, src_isImmediate=True, src_size=REG_SIZE_32, dst_size=REG_SIZE_0),
    0x69: X64InstructionInfo("imul",  modRm=MODRM_SOURCE, src_size=REG_SIZE_32, signExtension=True, inst_extraOperands=[X64Operand(isImmediate=True, size=REG_SIZE_32, maxSize=REG_SIZE_32)]),
    0x6a: X64InstructionInfo("push",  signExtension=True, src_isImmediate=True, src_size=REG_SIZE_8, dst_size=REG_SIZE_0),
    0x6b: X64InstructionInfo("imul",  modRm=MODRM_SOURCE, src_size=REG_SIZE_32, signExtension=True, inst_extraOperands=[X64Operand(isImmediate=True, size=REG_SIZE_8)]),
#   0x6c: Debug input port to string
#   0x6d: Debug input port to string
#   0x6e: Debug output string to port
#   0x6f: Debug output string to port
    0x70: X64InstructionInfo("jo",    relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Overflow
    0x71: X64InstructionInfo("jno",   relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Not overflow
    0x72: X64InstructionInfo("jb",    relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Less than (unsigned)
    0x73: X64InstructionInfo("jae",   relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Greater than or equal (unsigned)
    0x74: X64InstructionInfo("je",    relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Equal
    0x75: X64InstructionInfo("jne",   relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Not equal
    0x76: X64InstructionInfo("jbe",   relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Less than or equal (unsigned)
    0x77: X64InstructionInfo("ja",    relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Greater than (unsigned)
    0x78: X64InstructionInfo("js",    relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Signed
    0x79: X64InstructionInfo("jns",   relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Unsigned
    0x7a: X64InstructionInfo("jp",    relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Parity
    0x7b: X64InstructionInfo("jnp",   relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Not parity
    0x7c: X64InstructionInfo("jlt",   relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Less than (signed)
    0x7d: X64InstructionInfo("jge",   relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Greater than or equal (signed)
    0x7e: X64InstructionInfo("jle",   relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Less than or equal (signed)
    0x7f: X64InstructionInfo("jgt",   relativeJump=True, signExtension=True, src_size=REG_SIZE_8), # Greater than (signed)
    0x80: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, src_isImmediate=True),
    0x81: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, signExtension=True, src_isImmediate=True, src_maxSize=REG_SIZE_32),
#   0x82: Invalid
    0x83: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, src_isImmediate=True, src_size=REG_SIZE_8),
    0x84: X64InstructionInfo("test",  modRm=MODRM_DEST),
    0x85: X64InstructionInfo("test",  modRm=MODRM_DEST),
    0x86: X64InstructionInfo("xchg",  modRm=MODRM_SOURCE),
    0x87: X64InstructionInfo("xchg",  modRm=MODRM_SOURCE),
    0x88: X64InstructionInfo("mov",   modRm=MODRM_DEST),
    0x89: X64InstructionInfo("mov",   modRm=MODRM_DEST),
    0x8a: X64InstructionInfo("mov",   modRm=MODRM_SOURCE),
    0x8b: X64InstructionInfo("mov",   modRm=MODRM_SOURCE),
#   0x8c: TODO: X64InstructionInfo("mov",   modRm=MODRM_SOURCE), A lot is strange about this instruction. It refers to a segment register in the Mod R/M byte or a memory location that is always a word long
    0x8d: X64InstructionInfo("lea",   modRm=MODRM_SOURCE),
#   0x8e: TODO: X64InstructionInfo("mov",   modRm=MODRM_SOURCE), A lot is strange about this instruction. It refers to a segment register in the Mod R/M byte
    0x8f: X64InstructionInfo("pop",   modRm=MODRM_DEST, extOpcode=True, dst_size=REG_SIZE_64, src_size=REG_SIZE_0),
    0x90: {
        None: {
            None: X64InstructionInfo("nop"), # This is a special case of exchange instructions that would swap EAX with EAX
            0xf3: X64InstructionInfo("pause"),
        },
    },
    0x91: X64InstructionInfo("xchg",  registerCode=True, op_size=REG_SIZE_32),
    0x92: X64InstructionInfo("xchg",  registerCode=True, op_size=REG_SIZE_32),
    0x93: X64InstructionInfo("xchg",  registerCode=True, op_size=REG_SIZE_32),
    0x94: X64InstructionInfo("xchg",  registerCode=True, op_size=REG_SIZE_32),
    0x95: X64InstructionInfo("xchg",  registerCode=True, op_size=REG_SIZE_32),
    0x96: X64InstructionInfo("xchg",  registerCode=True, op_size=REG_SIZE_32),
    0x97: X64InstructionInfo("xchg",  registerCode=True, op_size=REG_SIZE_32),
    0x98: X64InstructionInfo("",      isConversion=True, op_size=REG_SIZE_32),
    0x99: X64InstructionInfo("",      isConversion=True, op_size=REG_SIZE_32),
#   0x9a: Invalid
    0x9b: X64InstructionInfo("fwait", src_size=REG_SIZE_0,  dst_size=REG_SIZE_0),
    0x9c: X64InstructionInfo("pushf", src_size=REG_SIZE_64, src_value=REG_RFLAGS,  dst_size=REG_SIZE_0),
    0x9d: X64InstructionInfo("popf",  dst_size=REG_SIZE_64, dst_value=REG_RFLAGS,  src_size=REG_SIZE_0),
    0x9e: X64InstructionInfo("sahf",  op_size=REG_SIZE_8,   op_maxSize=REG_SIZE_8, dst_value=REG_RFLAGS, src_value=REG_RSP),  # REG_RSP is the value for %ah at 8 bits
    0x9f: X64InstructionInfo("lahf",  op_size=REG_SIZE_8,   op_maxSize=REG_SIZE_8, src_value=REG_RFLAGS, dst_value=REG_RSP),  # REG_RSP is the value for %ah at 8 bits
#   0xa0: X64InstructionInfo("mov",   ), TODO: Requires a displacement to place data
#   0xa1: X64InstructionInfo("mov",   ), TODO: Requires a displacement to place data
#   0xa2: X64InstructionInfo("mov",   ), TODO: Requires a displacement to place data
#   0xa3: X64InstructionInfo("mov",   ), TODO: Requires a displacement to place data
    0xa4: X64InstructionInfo("movs",  src_segmentReg=SEGMENT_REG_DS, src_indirect=True, src_value=REG_RSI, dst_segmentReg=SEGMENT_REG_ES, dst_indirect=True, dst_value=REG_RDI),
    0xa5: X64InstructionInfo("movs",  src_segmentReg=SEGMENT_REG_DS, src_indirect=True, src_value=REG_RSI, dst_segmentReg=SEGMENT_REG_ES, dst_indirect=True, dst_value=REG_RDI),
    0xa6: X64InstructionInfo("cmps",  src_segmentReg=SEGMENT_REG_DS, src_indirect=True, src_value=REG_RSI, dst_segmentReg=SEGMENT_REG_ES, dst_indirect=True, dst_value=REG_RDI),
    0xa7: X64InstructionInfo("cmps",  src_segmentReg=SEGMENT_REG_DS, src_indirect=True, src_value=REG_RSI, dst_segmentReg=SEGMENT_REG_ES, dst_indirect=True, dst_value=REG_RDI),
    0xa8: X64InstructionInfo("test",  src_isImmediate=True),
    0xa9: X64InstructionInfo("test",  signExtension=True, src_isImmediate=True, src_maxSize=REG_SIZE_32),
    0xaa: X64InstructionInfo("stors", dst_segmentReg=SEGMENT_REG_ES, dst_indirect=True, dst_value=REG_RDI),
    0xab: X64InstructionInfo("stors", dst_segmentReg=SEGMENT_REG_ES, dst_indirect=True, dst_value=REG_RDI),
    0xac: X64InstructionInfo("loads", src_segmentReg=SEGMENT_REG_DS, src_indirect=True, src_value=REG_RSI),
    0xad: X64InstructionInfo("loads", src_segmentReg=SEGMENT_REG_DS, src_indirect=True, src_value=REG_RSI),
    0xae: X64InstructionInfo("scans", src_segmentReg=SEGMENT_REG_ES, src_indirect=True, src_value=REG_RDI),
    0xaf: X64InstructionInfo("scans", src_segmentReg=SEGMENT_REG_ES, src_indirect=True, src_value=REG_RDI),
    0xb0: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_8),
    0xb1: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_8),
    0xb2: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_8),
    0xb3: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_8),
    0xb4: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_8),
    0xb5: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_8),
    0xb6: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_8),
    0xb7: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_8),
    0xb8: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_32),
    0xb9: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_32),
    0xba: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_32),
    0xbb: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_32),
    0xbc: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_32),
    0xbd: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_32),
    0xbe: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_32),
    0xbf: X64InstructionInfo("mov",   registerCode=True, src_isImmediate=True, op_size=REG_SIZE_32),
    0xc0: X64InstructionInfo("",      modRm=MODRM_DEST,  extOpcode=True, src_isImmediate=True),
    0xc1: X64InstructionInfo("",      modRm=MODRM_DEST,  extOpcode=True, src_isImmediate=True, src_size=REG_SIZE_8),
    0xc2: X64InstructionInfo("ret",   relativeJump=True, src_size=REG_SIZE_16, src_maxSize=REG_SIZE_16, dst_size=REG_SIZE_0),
    0xc3: X64InstructionInfo("ret",   op_size=REG_SIZE_0),
#   0xc4: Invalid
#   0xc5: Invalid
    0xc6: X64InstructionInfo("mov",   modRm=MODRM_DEST, signExtension=True, src_isImmediate=True),
    0xc7: X64InstructionInfo("mov",   modRm=MODRM_DEST, signExtension=True, src_isImmediate=True, src_maxSize=REG_SIZE_32),
#   0xc8: TODO: Enter, which has 2 sources and 1 destination
    0xc9: X64InstructionInfo("leave", op_size=REG_SIZE_0),
#   0xca: TODO
#   0xcb: TODO
#   0xcc: TODO
#   0xcd: TODO
#   0xce: TODO
#   0xcf: TODO
    0xd0: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, src_isImmediate=True, src_value=1),
    0xd1: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, src_isImmediate=True, src_value=1),
    0xd2: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, src_size=REG_SIZE_8,  src_value=REG_RCX),
    0xd3: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, src_size=REG_SIZE_8,  src_value=REG_RCX),
#   0xd4: Invalid
#   0xd5: Invalid
#   0xd6: Invalid
#   0xd7: TODO: Table translation
#   0xd8: TODO:
#   0xd9: TODO:
#   0xda: TODO:
#   0xdb: TODO:
#   0xdc: TODO:
#   0xdd: TODO:
#   0xde: TODO:
#   0xdf: TODO:
#   0xe0: TODO:
#   0xe1: TODO:
#   0xe2: TODO:
#   0xe3: TODO:
#   0xe4: TODO:
#   0xe5: TODO:
#   0xe6: TODO:
#   0xe7: TODO:
    0xe8: X64InstructionInfo("call",  relativeJump=True, signExtension=True, src_size=REG_SIZE_32, src_maxSize=REG_SIZE_32),
    0xe9: X64InstructionInfo("jmp",   relativeJump=True, signExtension=True, src_size=REG_SIZE_32, src_maxSize=REG_SIZE_32),
#   0xea: Invalid
    0xeb: X64InstructionInfo("jmp",   relativeJump=True, signExtension=True, src_size=REG_SIZE_8),
#   0xec: TODO:
#   0xed: TODO:
#   0xee: TODO:
#   0xef: TODO:
#   0xf0: Lock Prefix
#   0xf1: TODO:
#   0xf2: Repeat while not zero prefix
#   0xf3: Repeat while zero prefix
    0xf4: X64InstructionInfo("hlt",   src_size=REG_SIZE_0, dst_size=REG_SIZE_0),
    0xf5: X64InstructionInfo("cmc",   op_size=REG_SIZE_0),
    0xf6: X64InstructionInfo("",      modRm=MODRM_SOURCE, extOpcode=True),
    0xf7: X64InstructionInfo("",      modRm=MODRM_SOURCE, extOpcode=True),
    0xf8: X64InstructionInfo("clc",   op_size=REG_SIZE_0),
    0xf9: X64InstructionInfo("stc",   op_size=REG_SIZE_0),
    0xfa: X64InstructionInfo("cli",   op_size=REG_SIZE_0),
    0xfb: X64InstructionInfo("sti",   op_size=REG_SIZE_0),
    0xfc: X64InstructionInfo("cld",   op_size=REG_SIZE_0),
    0xfd: X64InstructionInfo("std",   op_size=REG_SIZE_0),
    0xfe: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, src_size=REG_SIZE_0),
    0xff: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, src_size=REG_SIZE_0),
}

twoByteOpcodes = {
    0x1f: X64InstructionInfo("nop",   modRm=MODRM_SOURCE),

    0x40: X64InstructionInfo("cmovo",  modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Overflow
    0x41: X64InstructionInfo("cmovno", modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Not overflow
    0x42: X64InstructionInfo("cmovb",  modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Less than (unsigned)
    0x43: X64InstructionInfo("cmovae", modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Greater than or equal (unsigned)
    0x44: X64InstructionInfo("cmove",  modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Equal
    0x45: X64InstructionInfo("cmovne", modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Not equal
    0x46: X64InstructionInfo("cmovbe", modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Less than or equal (unsigned)
    0x47: X64InstructionInfo("cmova",  modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Greater than (unsigned)
    0x48: X64InstructionInfo("cmovs",  modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Signed
    0x49: X64InstructionInfo("cmovns", modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Unsigned
    0x4a: X64InstructionInfo("cmovp",  modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Parity
    0x4b: X64InstructionInfo("cmovnp", modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Not parity
    0x4c: X64InstructionInfo("cmovlt", modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Less than (signed)
    0x4d: X64InstructionInfo("cmovge", modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Greater than or equal (signed)
    0x4e: X64InstructionInfo("cmovle", modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Less than or equal (signed)
    0x4f: X64InstructionInfo("cmovgt", modRm=MODRM_SOURCE, op_size=REG_SIZE_32), # Greater than (signed)

    0x6f: {
        None: {
            None: X64InstructionInfo("mov",    modRm=MODRM_SOURCE, mmRegisters=True, op_size=REG_SIZE_64),
            0x66: X64InstructionInfo("mov",    modRm=MODRM_SOURCE, mmRegisters=True, op_size=REG_SIZE_64),
            0xf3: X64InstructionInfo("mov",    modRm=MODRM_SOURCE, mmRegisters=True, op_size=REG_SIZE_64),
        },
    },

    0x80: X64InstructionInfo("jo",    relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Overflow
    0x81: X64InstructionInfo("jno",   relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Not overflow
    0x82: X64InstructionInfo("jb",    relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Less than (unsigned)
    0x83: X64InstructionInfo("jae",   relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Greater than or equal (unsigned)
    0x84: X64InstructionInfo("je",    relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Equal
    0x85: X64InstructionInfo("jne",   relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Not equal
    0x86: X64InstructionInfo("jbe",   relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Less than or equal (unsigned)
    0x87: X64InstructionInfo("ja",    relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Greater than (unsigned)
    0x88: X64InstructionInfo("js",    relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Signed
    0x89: X64InstructionInfo("jns",   relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Unsigned
    0x8a: X64InstructionInfo("jp",    relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Parity
    0x8b: X64InstructionInfo("jnp",   relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Not parity
    0x8c: X64InstructionInfo("jlt",   relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Less than (signed)
    0x8d: X64InstructionInfo("jge",   relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Greater than or equal (signed)
    0x8e: X64InstructionInfo("jle",   relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Less than or equal (signed)
    0x8f: X64InstructionInfo("jgt",   relativeJump=True, signExtension=True, op_size=REG_SIZE_32), # Greater than (signed)
    0x90: X64InstructionInfo("seto",  modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Overflow
    0x91: X64InstructionInfo("setno", modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Not Overflow
    0x92: X64InstructionInfo("setb",  modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Less than (unsigned)
    0x93: X64InstructionInfo("setae", modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Greater than or equal (unsigned)
    0x94: X64InstructionInfo("sete",  modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Equal
    0x95: X64InstructionInfo("setne", modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Not equal
    0x96: X64InstructionInfo("setbe", modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Less than or equal (unsigned)
    0x97: X64InstructionInfo("seta",  modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Greater than (unsigned)
    0x98: X64InstructionInfo("sets",  modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Signed
    0x99: X64InstructionInfo("setns", modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Not signed
    0x9a: X64InstructionInfo("setp",  modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Parity
    0x9b: X64InstructionInfo("setnp", modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Not parity
    0x9c: X64InstructionInfo("setl",  modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Less than (signed)
    0x9d: X64InstructionInfo("setge", modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Greater than or equal (signed)
    0x9e: X64InstructionInfo("setle", modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Less than or equal (signed)
    0x9f: X64InstructionInfo("setg",  modRm=MODRM_DEST, src_size=REG_SIZE_0, dst_size=REG_SIZE_8), # Greater than (signed)

    0xb6: X64InstructionInfo("movzx", modRm=MODRM_SOURCE, src_size=REG_SIZE_8,  dst_size=REG_SIZE_32),
    0xb7: X64InstructionInfo("movzx", modRm=MODRM_SOURCE, src_size=REG_SIZE_16, dst_size=REG_SIZE_32, src_maxSize=REG_SIZE_16),
    0xbe: X64InstructionInfo("movsx", modRm=MODRM_SOURCE, signExtension=True,   src_size=REG_SIZE_8,  dst_size=REG_SIZE_32),
    0xbf: X64InstructionInfo("movsx", modRm=MODRM_SOURCE, signExtension=True,   src_size=REG_SIZE_16, dst_size=REG_SIZE_32, src_maxSize=REG_SIZE_16),
}
