from disassemblers.x64defs import *

from disassemblers.disassembler import Instruction, Operand

import logging

logger = logging.getLogger(__name__)

class X64Instruction( Instruction ):
    # TODO: Fill out x64 specific attributes
    def __init__( self, mnemonic="byte", source=[], dest=None, extraOperands=[] ):
        super().__init__(mnemonic, source, dest, extraOperands)

        self.operandSize = REG_SIZE_32
        self.addressSize = 8

    def setAttributes( self, opcode, info ):

        self.info = info
        self.mnemonic= info.mnemonic

        operands = []

        # Make sure promotion to 64 bits is allowed if it happened.
        # Use the operand size from info as long as it wasn't already
        # increased from a legal promotion from a prefix byte. If that's the
        # case, the instruction's operand size should remain the same.
        if not (self.operandSize > info.operandSize and info.canPromote):
            self.operandSize = info.operandSize

        else:
            self.operandSize 

        logger.debug("operand size: {}, info size: {}".format(self.operandSize, info.operandSize))

        # Handle setup if there is a register code in the opcode
        if info.registerCode:
            logger.debug("3 least signficant bytes choose a register")
            register = opcode & REG_MASK
            operand = X64Operand(size=self.operandSize, value=register)

            if info.direction == OP_DIR_TO_REG:
                logger.debug("The destination is the register")
                self.dest = operand

            elif info.direction == OP_DIR_FROM_REG:
                logger.debug("The source is the register")
                self.source.append(operand)

            else:
                logger.debug("An invalid direction was specified")


class X64InstructionInfo():

    def __init__( self, mnemonic, registerCode=False, direction=None,
                  hasRMMod=False, canPromote=True, operandSize=REG_SIZE_32,
                  sizeBit=False, signExtBit=False, directionBit=False):

        self.mnemonic     = mnemonic        # The name of the instruction
        self.registerCode = registerCode    # Whether the least 3 significant bits of the opcode represent a register
        self.direction    = direction       # The direction to move the data if there is a register code (OP_DIR_TO_REG or OP_DIR_FROM_REG)
        self.hasRMMod     = hasRMMod        # Whether an R/MMod byte follows the opcode
        self.canPromote   = canPromote      # Whether the operand size is allowed to be promoted to 64 bits
        self.operandSize  = operandSize     # The default size of the operands
        self.sizeBit      = sizeBit         # Whether the size bit of the opcode means anything
        self.signExtBit   = signExtBit      # Whether the sign extension bit of the opcode means anything
        self.directionBit = directionBit    # Whether the direction bit of the opcode means anything


class X64Operand( Operand ):

    def __init__( self, size=REG_SIZE_32, value=0, isImm=False ):

        super().__init__(size, value)
        self.isImm = isImm
        self.displacement = 0
        self.indirect = False

    # Make the size 64 bits because it must hold an address
    # TODO: Make this also be able to hold other values in case the address
    # size has changed based on a prefix byte.
    def makeIndirect(self):

        self.indirect = True
        self.size = REG_SIZE_64

    def __repr__(self):

        if self.isImm:
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
            instruction.operandSize = REG_SIZE_64
            instruction.canChangeSize = False
            instruction.bytes.append(byte)

        elif byte == PREFIX_16_BIT_OPERAND:
            logger.debug("Found the 16-bit prefix")
            instruction.operandSize = REG_SIZE_16
            instruction.canChangeSize = False
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

        # If the instruction has an R/M MOD byte, parse it next
        if curInstruction.info.hasRMMod:
            logger.debug("There is an RM mod byte")
            numRMModBytes = handleRMModByte(curInstruction, binary)

        else:
            instructions.append(curInstruction)
            logger.debug(curInstruction)
            continue

        # The size flag indicates either 8-bit or 32-bit operands
        # This is mainly for R/M Mod values
        # The direction determines whether the operands go to a register or
        # from a register.
        sizeFlag  = byte & OP_SIZE_MASK
        direction = byte & OP_DIR_MASK

        if sizeFlag == 0:
            operandSize = REG_SIZE_8L

        if step <= STEP_RM_MOD:
            curInstruction.bytes.append(byte)
            mod     = byte & MOD_MASK
            regOrOp = (byte & REG_MASK) >> 3
            regmem  = byte & RM_MASK

            logger.debug("mod: {}, reg: {}, r/m: {}".format(mod, regOrOp, regmem))
            logger.debug("Extended opcode? {}".format(curInstruction.extOpcode))

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
              hasRMMod=False, canPromote=True, operandSize=REG_SIZE_32,
              sizeBit=False, signExtBit=False, directionBit=False):
"""
oneByteOpcodes = {

    0x50: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_TO_REG, operandSize=REG_SIZE_64),
    0x51: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_TO_REG, operandSize=REG_SIZE_64),
    0x52: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_TO_REG, operandSize=REG_SIZE_64),
    0x53: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_TO_REG, operandSize=REG_SIZE_64),
    0x54: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_TO_REG, operandSize=REG_SIZE_64),
    0x55: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_TO_REG, operandSize=REG_SIZE_64),
    0x56: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_TO_REG, operandSize=REG_SIZE_64),
    0x57: X64InstructionInfo("push", registerCode=True, direction=OP_DIR_TO_REG, operandSize=REG_SIZE_64),

    0x58: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_FROM_REG, operandSize=REG_SIZE_64),
    0x59: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_FROM_REG, operandSize=REG_SIZE_64),
    0x5a: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_FROM_REG, operandSize=REG_SIZE_64),
    0x5b: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_FROM_REG, operandSize=REG_SIZE_64),
    0x5c: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_FROM_REG, operandSize=REG_SIZE_64),
    0x5d: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_FROM_REG, operandSize=REG_SIZE_64),
    0x5e: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_FROM_REG, operandSize=REG_SIZE_64),
    0x5f: X64InstructionInfo("pop",  registerCode=True, direction=OP_DIR_FROM_REG, operandSize=REG_SIZE_64),


    0x89: X64InstructionInfo("mov", hasRMMod=True, directionBit=True, sizeBit =True),
}


twoByteOpcodes = {
    0xbe: X64Instruction("movsx", 2),
}
