from disassemblers.x64defs import *

from disassemblers.disassembler import Instruction, Operand

import logging

logger = logging.getLogger(__name__)

class X64Instruction( Instruction ):
    # TODO: Fill out x64 specific attributes
    def __init__( self, mnemonic="byte", source=None, dest=None, extraOperands=[] ):
        super().__init__(mnemonic, source, dest, extraOperands)

        self.prefixSize = None  # The size operands should be based on the prefix
        self.addressSize = 8

    def setAttributes( self, opcode, info ):

        self.info = info
        self.mnemonic= info.mnemonic

        #############################
        #  DETERMINE OPERAND SIZES  #
        #############################

        self.info.srcOperandSize = getOperandSize( opcode, self.prefixSize, self.info.srcOperandSize )
        self.info.dstOperandSize = getOperandSize( opcode, self.prefixSize, self.info.dstOperandSize )

        logger.debug("source size: {}, dest size: {}".format(self.info.srcOperandSize, self.info.dstOperandSize))

        #################################
        #  DETERMINE OPERAND DIRECTION  #
        #################################

        # If direction is already set, the default rules for direction apply
        # This should only be true in cases where an override is necessary
        if self.info.direction is not None:

            # The direction is always to the register or memory if there is an immediate
            if self.info.srcIsImmediate:
                self.info.direction = OP_DIR_TO_REG

            # Otherwise, the direction bit, which is the 2nd least significant
            # bit, is the indicator of which direction to use
            else:
                self.info.direction = (opcode & OP_DIR_MASK) > 1

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


class X64InstructionInfo():

    def __init__( self, mnemonic, registerCode=False, direction=None,
                  hasModRM=True, extOpcode=False, srcIsImmediate=False,
                  srcOperandSize=None, dstOperandSize=None,
                  srcCanPromote=True, dstCanPromote=True, signExtBit=False):

        # Opcode info
        self.mnemonic     = mnemonic        # The name of the instruction
        self.registerCode = registerCode    # Whether the least 3 significant bits of the opcode represent a register
        self.direction    = direction       # The direction to move the data if there is a register code (OP_DIR_TO_REG or OP_DIR_FROM_REG)
        self.hasModRM     = hasModRM        # Whether an ModR/M byte follows the opcode
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
        self.isImmediate = isImmediate
        self.displacement = 0
        self.indirect = False

    # Make the size 64 bits because it must hold an address
    # TODO: Make this also be able to hold other values in case the address
    # size has changed based on a prefix byte.
    def makeIndirect(self):

        self.indirect = True
        self.size = REG_SIZE_64

    def __repr__(self):

        if self.isImmediate:
            return "0x{:x}".format(self.value)

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

class X64OperandInfo():

    def __init__( self, size=REG_SIZE_32, isImmediate=False, sizeCanChange=True):
        self.size = size
        self.isImmediate = isImmediate
        self.sizeCanChange = sizeCanChange

def getOperandSize( opcode, prefixSize, infoSize ):
    """
    Description:    Figures out what the operand size should be based on the
                    opcode, the size of the instruction if one was set by a
                    prefix byte, and the info from the opcode dictionary.

                    The value in the info dictionary should be used if given
                    because it is an override of the normal behavior.

                    Next, the size of the operands because of a prefix are
                    used if one was found.

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

    if infoSize is not None:
        return infoSize

    elif prefixSize is not None and sizeBit != 0:
        return prefixSize

    elif sizeBit == 0:
        return REG_SIZE_8L

    elif sizeBit == 1:
        return REG_SIZE_32

    else:
        logger.debug("The size for the operand could not be determined")

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
        logger.debug("A 1 byte opcode was found")
        instruction.setAttributes(binary[0], oneByteOpcodes[binary[0]])
        numOpcodeBytes = 1

    # The opcode is not a valid 1 or 2 byte opcode, so keep the new instruction
    # the same as the one that was passed in.
    else:
        logger.debug("No valid opcode was found")

    # Append the opcode bytes to the instruction's list of bytes
    instruction.bytes += list(binary[0:numOpcodeBytes])

    return numOpcodeBytes


def handleModRMByte( instruction, binary ):
    """
    Description:    Handles the Mod R/M byte(s) of an instruction

    Arguments:      instruction - X64Instruction object with its info member set
                    binary      - bytes remaining to be processed for an instruction

    Return:         The number of bytes consumed when processing the Mod R/M bytes
    """

    numBytesConsumed = 1
    modRmByte = binary[0]
    mod     = modRmByte & ADDR_MOD_MASK
    regOrOp = (modRmByte & ADDR_REG_MASK) >> 3
    regmem  = modRmByte & ADDR_RM_MASK

    logger.debug("byte: {:02x}".format(modRmByte))
    logger.debug("mod: {}, reg: {}, r/m: {}".format(mod, regOrOp, regmem))
    logger.debug("Extended opcode? {}".format(instruction.info.extOpcode))

    if instruction.info.extOpcode:
        logger.debug("Found an opcode that needs to be extended: {:x}".format(curInstruction.bytes[-1]))


    # TODO: Append consumed bytes to the end of instruction.bytes

def disassemble(binary):

    offTheRails = False
    instructions = []

    # TODO: Add a good description of what this loop is doing and the stages that are performed
    while len(binary) > 0:

        logger.debug("moving on to the next instruction")
        curInstruction = X64Instruction()

        # If things have gone off the rails, consume each byte and add a
        # default instruction
        if offTheRails:
            logger.warning("Adding an unknown byte: {:02x}".format(byte))
            curInstruction.bytes.append(binary[0])
            binary = binary[1:]
            continue

        displaceBytes = 0
        displaceBytesLeft = 0
        immediateBytes = 0
        immediateBytesLeft = 0

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
        if curInstruction.info.hasModRM:
            logger.debug("There is an RM mod byte")
            numModRMBytes = handleModRMByte(curInstruction, binary)

        else:
            instructions.append(curInstruction)
            logger.debug(curInstruction)
            continue

        # The size flag indicates either 8-bit or 32-bit operands
        # This is mainly for Mod R/M values
        # The direction determines whether the operands go to a register or
        # from a register.


            # TODO: If the instruction has an extended opcode, the register value is actually part of the opcode. Do the necessary stuff here
            if curInstruction.extOpcode:

                logger.debug("Found an opcode that needs to be extended: {:x}".format(curInstruction.bytes[-1]))
                if curInstruction.bytes[-2] == 0x83:
                    # Make sure that the direction is into the value at R/M
                    # because the source operand is an immediate.
                    direction = OP_DIR_TO_REG_MEM
                    curInstruction.source.value = 0

                    if regOrOp == 0:
                        curInstruction.mnemonic = "add"

                    elif regOrOp == 1:
                        curInstruction.mnemonic = "or"

                    elif regOrOp == 2:
                        curInstruction.mnemonic = "adc"

                    elif regOrOp == 3:
                        curInstruction.mnemonic = "sbb"

                    elif regOrOp == 4:
                        curInstruction.mnemonic = "and"

                    elif regOrOp == 5:
                        curInstruction.mnemonic = "sub"

                    elif regOrOp == 6:
                        curInstruction.mnemonic = "xor"

                    elif regOrOp == 7:
                        curInstruction.mnemonic = "cmp"

                    step = STEP_DISP_IMM_BYTES

            # Set the properties of the source operand now that enough is known about it
            # TODO: Look into refactoring this section. The source and destination setup is very similar
            # Maybe have a function that just sets this info that is called for the source and then the dest
            if curInstruction.source is not None:

                curInstruction.source.setSize(operandSize)
                if curInstruction.source.isImm:
                    logger.debug("Setting number of bytes for the immediate")
                    immediateBytes = REG_NUM_BYTES[curInstruction.source.size]
                    immediateBytesLeft = REG_NUM_BYTES[curInstruction.source.size]

                if direction == OP_DIR_FROM_REG_MEM:
                    curInstruction.source.value = regmem

                else:
                    if mod == MOD_INDIRECT:
                        # TODO: Go to the SIB if the value is ESP
                        # TODO: Do a 4 byte displacement if the value is EBP
                        curInstruction.source.makeIndirect()

                    # Only set the value if it is a register. Immediates are not set with the R/M byte.
                    if not curInstruction.source.isImm:
                        curInstruction.source.value = regOrOp

                    elif mod == MOD_1_BYTE_DISP and not curInstruction.source.isImm:
                        curInstruction.source.makeIndirect()

                    elif mod == MOD_4_BYTE_DISP and not curInstruction.source.isImm:
                        curInstruction.source.makeIndirect()

            # Set the properties of the destination operand now that enough is known about it
            if curInstruction.dest is not None:

                curInstruction.dest.setSize(operandSize)
                if direction == OP_DIR_FROM_REG_MEM:
                    curInstruction.dest.value = regOrOp

                else:
                    if mod == MOD_INDIRECT:
                        # TODO: Go to the SIB if the value is ESP
                        # TODO: Do a 4 byte displacement if the value is EBP
                        curInstruction.dest.makeIndirect()

                    elif mod == MOD_1_BYTE_DISP and not curInstruction.dest.isImm:
                        curInstruction.dest.makeIndirect()

                    elif mod == MOD_4_BYTE_DISP and not curInstruction.dest.isImm:
                        curInstruction.dest.makeIndirect()

                    curInstruction.dest.value = regmem

            if mod == MOD_1_BYTE_DISP:
                logger.debug("1 byte dispalcement")
                displaceBytes = 1
                displaceBytesLeft = 1
                step = STEP_DISP_IMM_BYTES
                continue

            elif mod == MOD_4_BYTE_DISP:
                logger.debug("4 byte dispalcement")
                displaceBytes = 4
                displaceBytesLeft = 4
                step = STEP_DISP_IMM_BYTES
                continue

            elif immediateBytes > 0:
                step = STEP_DISP_IMM_BYTES
                continue

            else:
                step = STEP_BEGIN
                instructions.append(curInstruction)
                continue

        if step <= STEP_DISP_IMM_BYTES:
            logger.debug("Looking for extra bytes, disp: {}, imm: {}".format(displaceBytesLeft, immediateBytesLeft))

            curInstruction.bytes.append(byte)

            if displaceBytesLeft > 0:
                logger.debug("Processing displacement byte")
                # TODO: Assume that displacement bytes can only be for one operand
                if curInstruction.source is not None and curInstruction.source.indirect:
                    logger.debug("adding to source displacement")
                    curInstruction.source.displacement += (byte >> (8 * (displaceBytes - displaceBytesLeft)))
                    if displaceBytesLeft == 1 and byte > 0x80:
                        curInstruction.source.displacement = -1 * (pow(2, 8 * displaceBytes) - curInstruction.source.displacement)

                elif curInstruction.dest is not None and curInstruction.dest.indirect:
                    logger.debug("adding to dest displacement")
                    curInstruction.dest.displacement += (byte >> (8 * (displaceBytes - displaceBytesLeft)))
                    if displaceBytesLeft == 1 and byte > 0x80:
                        curInstruction.dest.displacement = -1 * (pow(2, 8 * displaceBytes) - curInstruction.dest.displacement)

                else:
                    raise binary.AnalysisError("There are displacement bytes left, but no operand that needs any")

                displaceBytesLeft -= 1

            elif immediateBytesLeft > 0:
                logger.debug("adding immediate")
                # x86 is little endian, so as bytes come in, they should be bitshifted over 8 times for every
                # byte that has already been processed for the value.
                curInstruction.source.value += (byte >> (8 * (immediateBytes - immediateBytesLeft)))
                immediateBytesLeft -= 1

            # After processing the displacement or immediate byte, check whether there are
            # any bytes left. If not, add the instruction to the list because this is the
            # last possible step when processing an instruction.
            if displaceBytesLeft == 0 and immediateBytesLeft == 0:
                logger.debug("nothing left")
                instructions.append(curInstruction)
                step = STEP_BEGIN
                continue

    return instructions


"""
x86 is split between modifers and opcodes. There can be 0-4 modifier bytes then followed by an opcode. Parts of the opcode can also say something about how the operands should be used.
For example, the add opcode's lower bits tell which registers to use and which direction to do the addition


"""
prefixes = [

    PREFIX_64_BIT_OPERAND,
    PREFIX_16_BIT_OPERAND,
    PREFIX_32_BIT_ADDRESS,

]

"""
def __init__( self, mnemonic, registerCode=False, direction=None,
              hasModRM=False, canPromote=True, operandSize=REG_SIZE_32,
              sizeBit=False, signExtBit=False, directionBit=False):
"""
oneByteOpcodes = {

    0x50: X64InstructionInfo("push", hasModRM=False, registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x51: X64InstructionInfo("push", hasModRM=False, registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x52: X64InstructionInfo("push", hasModRM=False, registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x53: X64InstructionInfo("push", hasModRM=False, registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x54: X64InstructionInfo("push", hasModRM=False, registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x55: X64InstructionInfo("push", hasModRM=False, registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x56: X64InstructionInfo("push", hasModRM=False, registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x57: X64InstructionInfo("push", hasModRM=False, registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),

    0x58: X64InstructionInfo("pop",  hasModRM=False, registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x59: X64InstructionInfo("pop",  hasModRM=False, registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x5a: X64InstructionInfo("pop",  hasModRM=False, registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x5b: X64InstructionInfo("pop",  hasModRM=False, registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x5c: X64InstructionInfo("pop",  hasModRM=False, registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x5d: X64InstructionInfo("pop",  hasModRM=False, registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x5e: X64InstructionInfo("pop",  hasModRM=False, registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),
    0x5f: X64InstructionInfo("pop",  hasModRM=False, registerCode=True, direction=OP_DIR_TO_REG, dstOperandSize=REG_SIZE_64),

    0x89: X64InstructionInfo("mov", srcOperandSize=REG_SIZE_8L),
}


twoByteOpcodes = {
    0xbe: X64Instruction("movsx", 2),
}
