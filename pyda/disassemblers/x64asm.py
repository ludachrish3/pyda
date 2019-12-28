from disassemblers.x64defs import *
from disassemblers.disassembler import Instruction, Operand

import copy
import logging

logger = logging.getLogger(__name__)

class X64Instruction( Instruction ):

    def __init__( self, mnemonic="byte", source=None, dest=None, extraOperands=[] ):
        super().__init__(mnemonic, source, dest, extraOperands)

        self.prefixSize = None  # The size operands should be based on the prefix
        self.addressSize = 8

    def setAttributes( self, opcode, info ):

        # Create deep copies so that the dictionary of infos remains unchanged
        # and this specific instruction's info can be updated as needed.
        self.info = copy.deepcopy(info)
        self.mnemonic= copy.deepcopy(info.mnemonic)

        #############################
        #  DETERMINE OPERAND SIZES  #
        #############################

        self.info.srcOperandSize = getOperandSize(opcode, self.prefixSize, self.info.srcOperandSize)
        self.info.dstOperandSize = getOperandSize(opcode, self.prefixSize, self.info.dstOperandSize)

        logger.debug("source size: {}, dest size: {}".format(self.info.srcOperandSize, self.info.dstOperandSize))

        #################################
        #  DETERMINE OPERAND DIRECTION  #
        #################################

        # If direction is already set, the default rules for direction apply
        # This should only be true in cases where an override is necessary
        if self.info.direction is None:

            # The direction is always to the register or memory if there is an immediate
            if self.info.srcIsImmediate:
                self.info.direction = OP_DIR_TO_REG

            # Otherwise, the direction bit, which is the 2nd least significant
            # bit, is the indicator of which direction to use
            else:
                self.info.direction = (opcode & OP_DIR_MASK) >> 1

        logger.debug("direction: {}".format(self.info.direction))

        #####################
        #  CREATE OPERANDS  #
        #####################

        # Handle setup if there is a register code in the opcode
        if self.info.registerCode:
            register = opcode & REG_MASK

            if self.info.direction == OP_DIR_TO_REG:
                logger.debug("The destination is the register")
                self.dest = X64Operand(size=self.info.dstOperandSize, value=register)

            elif self.info.direction == OP_DIR_FROM_REG:
                logger.debug("The source is the register")
                self.source = X64Operand(size=self.info.srcOperandSize, value=register)

            else:
                logger.debug("An invalid direction was specified")

        else:
            self.source = X64Operand(size=self.info.srcOperandSize, isImmediate=self.info.srcIsImmediate)
            self.dest   = X64Operand(size=self.info.dstOperandSize)

        ################################
        #  SET MOD R/M OPERAND STATUS  #
        ################################

        if self.info.modRm == MODRM_SOURCE:
            logger.debug("Source gets the mod r/m byte")
            self.source.modRm = True

        elif self.info.modRm == MODRM_DEST:
            logger.debug("Dest gets the mod r/m byte")
            self.dest.modRm = True


class X64InstructionInfo():

    def __init__( self, mnemonic, registerCode=False, direction=None,
                  modRm=MODRM_NONE, extOpcode=False, srcIsImmediate=False,
                  srcOperandSize=None, dstOperandSize=None,
                  srcCanPromote=True, dstCanPromote=True, signExtBit=False):

        # Opcode info
        self.mnemonic     = mnemonic        # The name of the instruction
        self.registerCode = registerCode    # Whether the least 3 significant bits of the opcode represent a register
        self.direction    = direction       # The direction to move the data if there is a register code (OP_DIR_TO_REG or OP_DIR_FROM_REG)
        self.modRm        = modRm           # How the Mod R/M byte must be handled
        self.extOpcode    = extOpcode       # Whether the opcode is extended into the ModR/M
        self.signExtBit   = signExtBit      # Whether the sign extension bit of the opcode means anything

        # Operand info
        self.srcCanPromote  = srcCanPromote     # Whether the src operand size is allowed to be promoted to 64 bits
        self.srcOperandSize = srcOperandSize    # The default size of the src operands
        self.srcIsImmediate = srcIsImmediate    # Whether the src operand is an immediate

        self.dstCanPromote  = dstCanPromote     # Whether the dst operand size is allowed to be promoted to 64 bits
        self.dstOperandSize = dstOperandSize    # The default size of the dst operands
                                                # The dst operand cannot be an immediate, so there is no option for it

class X64Operand( Operand ):

    def __init__( self, size=REG_SIZE_32, value=0, isImmediate=False ):

        super().__init__(size, value)
        self.isImmediate = isImmediate  # Whether the operand is an immediate
        self.displacement = 0           # Value of the displacement from the register value
        self.indirect = False           # Whether the addressing is indirect
        self.modRm = False              # Whether the Mod R/M byte applies

    def __repr__( self ):

        if self.isImmediate:
            return "0x{:x}".format(self.value)

        else:
            # If this is an indirect value, use the name of the 64 bit register
            if self.indirect:
                regName = REG_NAMES[self.value][REG_SIZE_64]

            else:
                regName = REG_NAMES[self.value][self.size]

            if self.indirect and self.displacement == 0:
                return "[%{}]".format(regName)

            elif self.indirect and self.displacement < 0:
                return "[%{}] - 0x{:x}".format(regName, abs(self.displacement))

            elif self.indirect and self.displacement > 0:
                return "[%{}] + 0x{:x}".format(regName, self.displacement)

            else:
                return "%{}".format(regName)


def getOperandSize( opcode, prefixSize, infoSize ):
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

    Return:         The size that should be used for the operand.
    """

    sizeBit = opcode & OP_SIZE_MASK

    if prefixSize is not None and infoSize != REG_SIZE_8 and sizeBit != 0:
        return prefixSize

    elif infoSize is not None:
        return infoSize

    elif sizeBit == 0:
        return REG_SIZE_8

    elif sizeBit == 1:
        return REG_SIZE_32

    else:
        logger.debug("The size of the operand could not be determined")


def handlePrefix( instruction, binary ):
    """
    Description:    Consumes all prefix bytes and sets the options for the
                    instruction.

    Arguments:      instruction - An x64Instruction object
                    binary      - An array of bytes

    Return:         Number of bytes that are prefix bytes
    """

    numPrefixBytes = 0

    for byte in binary:

        # TODO: Add support for group 1 and 2 prefixes

        # Group 3 prefixes
        if byte == PREFIX_64_BIT_OPERAND:
            logger.debug("Found the 64-bit prefix")
            instruction.prefixSize = REG_SIZE_64
            instruction.bytes.append(byte)

        elif byte == PREFIX_16_BIT_OPERAND:
            logger.debug("Found the 16-bit prefix")
            instruction.prefixSize = REG_SIZE_16
            instruction.bytes.append(byte)

        # Group 4 prefixes
        elif byte == PREFIX_32_BIT_ADDRESS:
            logger.debug("Found the 32-bit address prefix")
            instruction.addressSize = 4
            instruction.bytes.append(byte)

        # If a prefix is not found, proceed to the next step
        else:
            logger.debug("No more instruction prefixes")
            return numPrefixBytes

        # If the else branch is not hit, a prefix byte was found
        numPrefixBytes += 1


def handleOpcode( instruction, binary ):
    """
    Description:    Looks up the opcode and produces the correct instruction

    Arguments:      instruction - X64Instruction object that already has any
                                  options from prefix bytes set
                    binary      - Bytes starting at the opcode of an instruction

    Return:         The number of bytes consumed for the opcode. If there is no
                    valid opcode found, 0 is returned.
    """

    numOpcodeBytes = 0

    # Check for the opcode being a 2 byte opcode
    if binary[0] == PREFIX_2_BYTE_OPCODE and len(binary) > 1 and binary[1] in twoByteOpcodes:
        logger.debug("A 2 byte opcode was found")

        instruction.setAttributes(binary[1], twoByteOpcodes[binary[1]])
        numOpcodeBytes = 2

    # Check for the opcode being a 1 byte opcode
    elif binary[0] in oneByteOpcodes:
        logger.debug("A 1 byte opcode was found: {:02x}".format(binary[0]))
        instruction.setAttributes(binary[0], oneByteOpcodes[binary[0]])
        numOpcodeBytes = 1

    # The opcode is not a valid 1 or 2 byte opcode, so keep the new instruction
    # the same as the one that was passed in.
    else:
        logger.debug("No valid opcode was found")

    # Append the opcode bytes to the instruction's list of bytes
    instruction.bytes += list(binary[0:numOpcodeBytes])

    return numOpcodeBytes


def handleExtendedOpcode( instruction, modRmOpValue ):
    """
    Description:    Handles the extended opcode based on the REG value of the
                    Mod R/M byte

    Arguments:      instruction  - X64Instruction object
                    modRmOpValue - Value of the REG value of the Mod R/M byte

    Return:         True on success
                    False on failure
    """

    if instruction.bytes[-1] == 0x83:

        if modRmOpValue == 0:
            instruction.mnemonic = "add"

        elif modRmOpValue == 1:
            instruction.mnemonic = "or"

        elif modRmOpValue == 2:
            instruction.mnemonic = "adc"

        elif modRmOpValue == 3:
            instruction.mnemonic = "sbb"

        elif modRmOpValue == 4:
            instruction.mnemonic = "and"

        elif modRmOpValue == 5:
            instruction.mnemonic = "sub"

        elif modRmOpValue == 6:
            instruction.mnemonic = "xor"

        elif modRmOpValue == 7:
            instruction.mnemonic = "cmp"

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

    else:
        logger.debug("An unsupported extended opcode was found")
        return False

    return True


def handleSibByte( instruction, binary ):

    sibByte = binary[0]


def handleOperandAddressing( operand, binary ):
    """
    Description:    Figures out addressing mode for an operand based on the
                    Mod R/M byte.

    Arguments:      operand - X64Operand object
                    binary  - Remaining bytes to disassemble, starting with the
                              Mod R/M byte

    Return:         Number of bytes needed for addressing, not including the
                    Mod R/M byte.
    """

    modRmByte = binary[0]
    mod     = modRmByte & ADDR_MOD_MASK
    regOrOp = (modRmByte & ADDR_REG_MASK) >> 3
    regmem  = modRmByte & ADDR_RM_MASK

    logger.debug("mod: {}, reg: {}, r/m: {}".format(mod >> 6, regOrOp, regmem))

    # Process the addressing if the Mod R/M byte applies to this operand
    if operand.modRm:

        if mod == MOD_INDIRECT:

            # TODO: Go to the SIB if the value is ESP
            if regmem == REG_RSP:
                logger.debug("REQUIRES SIB BYTE")

            # TODO: Calculate the absolute address by figuring out what the address
            # of the next instruction is. That is what value should be in RIP.
            elif regmem == REG_RBP:
                logger.debug("Indirect register 4 byte displacement from RIP")
                operand.indirect = True
                operand.displacement = int.from_bytes(binary[1:5], "little", signed=True)
                operand.value = REG_RIP
                return 4

            else:
            # TODO: Do a 4 byte displacement if the value is EBP
                logger.debug("Operand is address in register value")
                operand.indirect = True
                operand.value = regmem
            return 1

        elif mod == MOD_1_BYTE_DISP:
            logger.debug("Operand is a register value with a 1 byte displacement")
            operand.indirect = True
            operand.displacement = int.from_bytes(binary[1:2], "little", signed=True)
            operand.value = regmem
            return 1

        elif mod == MOD_4_BYTE_DISP:
            logger.debug("Operand is a register value with a 4 byte displacement")
            operand.indirect = True
            operand.displacement = int.from_bytes(binary[1:5], "little", signed=True)
            operand.value = regmem
            return 4

        elif mod == MOD_REGISTER:
            logger.debug("Operand is the value in a register")
            operand.value = regmem

        else:
            logger.debug("Something else")

    # Otherwise, set the value as long as this operand is not an immediate
    elif not operand.isImmediate:
        operand.value = regOrOp

    return 0


def handleModRmByte( instruction, binary ):
    """
    Description:    Handles the Mod R/M byte(s) of an instruction

    Arguments:      instruction - X64Instruction object with its info member set
                    binary      - bytes remaining to be processed for an instruction

    Return:         The number of bytes consumed when processing the Mod R/M bytes
                    If an error occurs 0 is returned
    """

    numBytesConsumed = 1
    modRmByte = binary[0]
    mod     = modRmByte & ADDR_MOD_MASK
    regOrOp = (modRmByte & ADDR_REG_MASK) >> 3
    regmem  = modRmByte & ADDR_RM_MASK

    logger.debug("byte: {:02x}".format(modRmByte))
    logger.debug("mod: {}, reg: {}, r/m: {}".format(mod >> 6, regOrOp, regmem))

    # If the instruction has an extended opcode, the REG value is actually
    # part of the opcode.
    if instruction.info.extOpcode:

        logger.debug("Found an opcode that needs to be extended: {:x}".format(instruction.bytes[-1]))
        opcodeSuccess = handleExtendedOpcode(instruction, regOrOp)
        if not opcodeSuccess:
            return 0

    # Set the operand addressing properties
    direction = instruction.info.direction
    logger.debug("Handling source operand")
    numBytesConsumed += handleOperandAddressing(instruction.source, binary)
    logger.debug("Handling dest operand")
    numBytesConsumed += handleOperandAddressing(instruction.dest,   binary)

    instruction.bytes += list(binary[:numBytesConsumed])
    return numBytesConsumed


def disassemble(binary):

    offTheRails = False
    instructions = []

    # TODO: Remove this line when more instructions can be handled
    binary = binary[:29]

    # TODO: Add a good description of what this loop is doing and the stages that are performed
    while len(binary) > 0:

        logger.debug("moving on to the next instruction")
        curInstruction = X64Instruction()

        # If things have gone off the rails, consume each byte and add a
        # default instruction
        if offTheRails:
            logger.warning("Adding an unknown byte: {:02x}".format(binary[0]))
            curInstruction.bytes.append(binary[0])
            instructions.append(curInstruction)
            binary = binary[1:]
            continue

        # Find all prefix bytes and set the appropriate settings in the
        # instruction. Consume all prefix bytes from the binary.
        numPrefixBytes = handlePrefix(curInstruction, binary)
        logger.debug("There were {} prefix bytes".format(numPrefixBytes))
        binary = binary[numPrefixBytes:]

        # Replace the instruction with the one that corresponds to the opcode.
        # Consume all opcodes bytes from the binary.
        numOpcodeBytes = handleOpcode(curInstruction, binary)
        binary = binary[numOpcodeBytes:]
        if numOpcodeBytes == 0 or curInstruction.info is None:

            # If the opcode is invalid, keep track of going off the rails and
            # continue processing the next instructions as default instructions.
            # Also add back the current instructions bytes so that they don't
            # get lost.
            binary += bytes(curInstruction.bytes)
            offTheRails = True
            continue

        # If the instruction has a Mod R/M byte, parse it next
        if curInstruction.info.modRm == MODRM_NONE:
            instructions.append(curInstruction)
            logger.debug(curInstruction)
            continue

        logger.debug("There is an RM mod byte")
        numModRmBytes = handleModRmByte(curInstruction, binary)
        binary = binary[numModRmBytes:]

        # Handle an immediate value if there is one
        if curInstruction.source.isImmediate:
            numBytes = curInstruction.source.size
            curInstruction.source.value = int.from_bytes(binary[:numBytes], "little")
            curInstruction.bytes += list(binary[:numBytes])
            binary = binary[numBytes:]

        logger.debug(curInstruction)
        instructions.append(curInstruction)


    return instructions

"""
    def __init__( self, mnemonic, registerCode=False, direction=None,
                  modRm=None, extOpcode=False, srcIsImmediate=False,
                  srcOperandSize=None, dstOperandSize=None,
                  srcCanPromote=True, dstCanPromote=True, signExtBit=False):
"""

oneByteOpcodes = {

    0x50: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x51: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x52: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x53: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x54: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x55: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x56: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x57: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),

    0x58: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x59: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x5a: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x5b: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x5c: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x5d: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x5e: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x5f: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),

    0x83: X64InstructionInfo("",     modRm=MODRM_DEST, extOpcode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_8),

    0x89: X64InstructionInfo("mov",  modRm=MODRM_DEST),

    0x8b: X64InstructionInfo("mov",  modRm=MODRM_SOURCE),

    0x8d: X64InstructionInfo("lea",  modRm=MODRM_SOURCE),

    0xc7: X64InstructionInfo("mov",  modRm=MODRM_DEST, srcIsImmediate=True, signExtBit= True),
}


twoByteOpcodes = {
    0xbe: X64Instruction("movsx", 2),
}
