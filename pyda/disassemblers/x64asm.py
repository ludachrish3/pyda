from disassemblers.x64defs import *

from disassemblers.disassembler import Instruction, Operand

import logging

logger = logging.getLogger(__name__)

class X64Instruction(Instruction):
    # TODO: Fill out x64 specific attributes
    def __init__(self, mnemonic, source=None, dest=None, extOpcode=False, extraOperands=[], hasRMMod=True):
        super().__init__(mnemonic, source, dest, extraOperands)

        self.hasRMMod = hasRMMod
        self.extOpcode = extOpcode

class X64Operand(Operand):

    def __init__(self, size=REG_SIZE_32, value=0, isImm=False, defSize=False):

        super().__init__(size, value)
        self.isImm = isImm
        self.displacement = 0
        self.defSize = defSize
        self.indirect = False

    # Make the size 64 bits because it must hold an address
    # TODO: Make this also be able to hold other values in case the address
    # size has changed based on a prefix byte.
    def makeIndirect(self):

        self.indirect = True
        self.size = REG_SIZE_64

    # Only update the size if different sizes are allowed
    def setSize(self, newSize):

        if not self.defSize:
            self.size = newSize

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

STEP_BEGIN = 0
STEP_PREFIX = 1
STEP_2_BYTE_PREFIX = 2
STEP_OPCODE = 3
STEP_RM_MOD = 4
STEP_SIB_BYTE = 5
STEP_DISP_IMM_BYTES = 6

def disassemble(binary):

    step = STEP_BEGIN
    offTheRails = False
    instructions = []
    instructionBytes = []

    # TODO: Add a good description of what this loop is doing and the stages that are performed
    for byte in binary[0:20]:

        logger.debug("byte: {0:0>2x}".format(byte))
        if offTheRails:
            logger.warning("Adding an unknown byte: {:02x}".format(byte))
            curInstruction = X64Instruction("byte")
            curInstruction.bytes = [byte]
            instructions.append(curInstruction)
            continue

        if step <= STEP_BEGIN:
            logger.debug("moving on to the next instruction")
            instructionBytes = []
            curInstruction = None
            is2ByteOpcode = False
            operandSize = REG_SIZE_32
            addressSize = 64
            displaceBytes = 0
            displaceBytesLeft = 0
            immediateBytes = 0
            immediateBytesLeft = 0

        # Handle all possible prefix bytes and reset the state
        if step <= STEP_PREFIX:
            logger.debug("Looking for a prefix")

            if byte == PREFIX_64_BIT_OPERAND:
                logger.debug("Found the 64-bit prefix")
                operandSize = REG_SIZE_64
                instructionBytes.append(byte)
                step = STEP_PREFIX
                continue

            if byte == PREFIX_16_BIT_OPERAND:
                logger.debug("Found the 16-bit prefix")
                operandSize = REG_SIZE_16
                instructionBytes.append(byte)
                step = STEP_PREFIX
                continue

            if byte == PREFIX_32_BIT_ADDRESS:
                logger.debug("Found the 32-bit address prefix")
                addressSize = 32
                instructionBytes.append(byte)
                step = STEP_PREFIX
                continue

            # If a prefix is not found, proceed to the next step
            else:
                logger.debug("Instruction prefix not found")

        # Check for the 2-byte prefix after prefix bytes because this is
        # always immediately before the opcode.
        if step <= STEP_2_BYTE_PREFIX:
            logger.debug("Checking for the 2-byte prefix")
            if byte == PREFIX_2_BYTE_OPCODE:
                is2ByteOpcode = True
                step = STEP_OPCODE
                instructionBytes.append(byte)
                continue

            # If the 2-byte prefix is not found, proceed to the next step
            else:
                logger.debug("2-byte prefix not found")
                step = STEP_OPCODE

        # Get the opcode for the instruction
        if step <= STEP_OPCODE:

            if is2ByteOpcode and byte in twoByteOpcodes:

                curInstruction = twoByteOpcodes[byte]
                logger.debug("Found a 2 byte opcode")

            elif not is2ByteOpcode and byte in oneByteOpcodes:

                logger.debug("Found a 1 byte opcode")
                curInstruction = oneByteOpcodes[byte]

            else:

                logger.warning("Found an unknown instruction")
                curInstruction = X64Instruction("byte")
                offTheRails = True

            # Assign the bytes so far to the instruction
            curInstruction.bytes = instructionBytes
            curInstruction.bytes.append(byte)

            # If an unknown instruction is found, add the instruction and continue
            if offTheRails:
                instructions.append(curInstruction)
                continue

            # The size flag indicates either 8-bit or 32-bit operands
            # This is mainly for R/M Mod values
            # The direction determines whether the operands go to a register or
            # from a register.
            sizeFlag  = byte & OP_SIZE_MASK
            direction = byte & OP_DIR_MASK

            if sizeFlag == 0:
                operandSize = REG_SIZE_8L

            # If the instruction has an R/W MOD byte, parse it next
            if curInstruction.hasRMMod:
                logger.debug("There is an RM mod byte")

                step = STEP_RM_MOD
                continue

            else:
                curInstruction.bytes = instructionBytes
                instructions.append(curInstruction)
                step = STEP_BEGIN
                continue

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
                    # because these source operand is an immediate.
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

oneByteOpcodes = {
    0x00: X64Instruction("add", source=X64Operand(size=REG_SIZE_8L, defSize=True),
                                dest  =X64Operand(size=REG_SIZE_8L, defSize=True)),
    0x01: X64Instruction("add", 2, []),
    0x02: X64Instruction("add", 2),
    0x03: X64Instruction("add", 2),
    0x04: X64Instruction("add", 2),
    0x05: X64Instruction("add", 2),
    0x08: X64Instruction("or",  2),
    0x09: X64Instruction("or",  2),
    0x0a: X64Instruction("or",  2),
    0x0b: X64Instruction("or",  2),
    0x0c: X64Instruction("or",  2),
    0x0d: X64Instruction("or",  2),
    0x10: X64Instruction("adc", 2),
    0x11: X64Instruction("adc", 2),
    0x12: X64Instruction("adc", 2),
    0x13: X64Instruction("adc", 2),
    0x14: X64Instruction("adc", 2),
    0x15: X64Instruction("adc", 2),




    0x50: X64Instruction("push", source=X64Operand(size=REG_SIZE_64, value=REG_RAX, defSize=True), hasRMMod=False),

    0x51: X64Instruction("push", source=X64Operand(size=REG_SIZE_64, value=REG_RCX, defSize=True), hasRMMod=False),

    0x52: X64Instruction("push", source=X64Operand(size=REG_SIZE_64, value=REG_RDX, defSize=True), hasRMMod=False),

    0x53: X64Instruction("push", source=X64Operand(size=REG_SIZE_64, value=REG_RBX, defSize=True), hasRMMod=False),

    0x54: X64Instruction("push", source=X64Operand(size=REG_SIZE_64, value=REG_RSP, defSize=True), hasRMMod=False),

    0x55: X64Instruction("push", source=X64Operand(size=REG_SIZE_64, value=REG_RBP, defSize=True), hasRMMod=False),


    0x56: X64Instruction("push", source=X64Operand(size=REG_SIZE_64, value=REG_RSI, defSize=True), hasRMMod=False),

    0x57: X64Instruction("push", source=X64Operand(size=REG_SIZE_64, value=REG_RDI, defSize=True), hasRMMod=False),

    0x83: X64Instruction("",     source=X64Operand(size=REG_SIZE_8L, defSize=True, isImm=True), dest=X64Operand(), extOpcode=True),

    0x89: X64Instruction("mov",  source=X64Operand(), dest=X64Operand()),

    0x8b: X64Instruction("mov",  source=X64Operand(), dest=X64Operand()),

    0xc3: X64Instruction("leave", 0),
    0xc7: X64Instruction("mov", source= X64Operand(isImm=True), dest=X64Operand()),
    0xc9: X64Instruction("ret", 0),

}


twoByteOpcodes = {
    0xbe: X64Instruction("movsx", 2),
}

invalid = [
    0x06,
    0x07,
    0x0e,
    0x17,
    0x18,
    0x60,
    0x61,
    0x62,
]


