from x64defs import *

from disassembler import Instruction, Operand

class X64Instruction(Instruction):
    # TODO: Fill out x64 specific attributes
    def __init__(self, mnemonic, source=None, dest=None, extOpcode=False, extraOperands=[], hasRMMod=True):
        super().__init__(mnemonic, source, dest, extraOperands)

        self.hasRMMod = hasRMMod
        self.extOpcode = extOpcode

class X64Operand(Operand):

    def __init__(self, size=REG_SIZE_32, value=0, isReg=True, defSize=False):

        super().__init__(size, value)
        self.isReg = isReg
        self.defSize = defSize
        self.indirect = False

    # Only update the size if different sizes are allowed
    def setSize(self, newSize):

        if not self.defSize:
            self.size = newSize

    def __repr__(self):

        if self.isReg:
            regName = REG_NAMES[self.value][self.size]
            if self.indirect:
                return "[{}]".format(regName)
            else:
                return regName

        else:
            return "0x{:x}".format(self.value)
            
STEP_BEGIN = 0
STEP_PREFIX = 1
STEP_2_BYTE_PREFIX = 2
STEP_OPCODE = 3
STEP_RM_MOD = 4
STEP_SIB_BYTE = 5
STEP_DISP_IMM_BYTES = 6

def disassemble(binary):

    step = STEP_BEGIN
    instructions = []
    instBytes = []

    for byte in binary[0:8]:

        print("byte: {0:0>2x}".format(byte))

        if step <= STEP_BEGIN:
            print("moving on to the next instruction")
            instBytes = []
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
            print("Looking for a prefix")

            if byte == PREFIX_64_BIT_OPERAND:
                print("Found the 64-bit prefix")
                operandSize = REG_SIZE_64
                instBytes.append(byte)
                step = STEP_PREFIX
                continue

            if byte == PREFIX_32_BIT_ADDRESS:
                print("Found the 32-bit address prefix")
                addressSize = 32
                instBytes.append(byte)
                step = STEP_PREFIX
                continue

            # If a prefix is not found, proceed to the next step
            else:
                print("Instruction prefix not found")

        # Check for the 2-byte prefix
        if step <= STEP_2_BYTE_PREFIX:
            print("Checking for the 2-byte prefix")
            if byte == PREFIX_2_BYTE_OPCODE:
                is2ByteOpcode = True
                step = STEP_OPCODE
                instBytes.append(byte)
                continue

            # If the 2-byte prefix is not found, proceed to the next step
            else:
                print("2-byte prefix not found")
                step = STEP_OPCODE


        # Get the opcode for the instruction
        if step <= STEP_OPCODE:

            if is2ByteOpcode and byte in twoByteOpcodes:

                curInst = twoByteOpcodes[byte]
                print("Found a 2 byte opcode")

            elif not is2ByteOpcode and byte in oneByteOpcodes:

                print("Found a 1 byte opcode")
                curInst = oneByteOpcodes[byte]

            else:
                print("no opcode was found :(")
                instructions.append(X64Instruction("byte"))
                step = STEP_BEGIN
                continue

            # Assign the bytes so far to the instruction
            curInst.bytes = instBytes
            curInst.bytes.append(byte)

            # The size flag indicates either 8-bit or 32-bit operands
            # This is mainly for R/M Mod values
            sizeFlag   = byte & OP_SIZE_MASK
            direction = byte & OP_DIR_MASK

            if sizeFlag == 0:
                operandSize = REG_SIZE_8L

            # If the instruction has an R/W MOD byte, parse it next
            if curInst.hasRMMod:
                print("There is an RM mod byte")

                step = STEP_RM_MOD
                continue

            else:
                curInst.bytes = instBytes
                instructions.append(curInst)
                step = STEP_BEGIN
                continue

        if step <= STEP_RM_MOD:
            curInst.bytes.append(byte)
            mod     = byte & MOD_MASK
            regOrOp = (byte & REG_MASK) >> 3
            regmem  = byte & RM_MASK

            print("mod: {}, reg: {}, r/m: {}".format(mod, regOrOp, regmem))
            print("Extended opcode? {}".format(curInst.extOpcode))

            # TODO: If the instruction has an extended opcode, the register value is actually part of the opcode. Do the necessary stuff here
            if curInst.extOpcode:
                
                print("Found an opcode that needs to be extended: {:x}".format(curInst.bytes[-1]))
                if curInst.bytes[-2] == 0x83:
                    # Make sure that the direction is into the value at R/M
                    # because these source operand is an immediate.
                    direction = OP_DIR_TO_REG_MEM
                    curInst.source.value = 0

                    if regOrOp == 0:
                        curInst.mnemonic = "add"

                    elif regOrOp == 1:
                        curInst.mnemonic = "or"

                    elif regOrOp == 2:
                        curInst.mnemonic = "adc"
                        
                    elif regOrOp == 3:
                        curInst.mnemonic = "sbb"

                    elif regOrOp == 4:
                        curInst.mnemonic = "and"

                    elif regOrOp == 5:
                        curInst.mnemonic = "sub"

                    elif regOrOp == 6:
                        curInst.mnemonic = "xor"

                    elif regOrOp == 7:
                        curInst.mnemonic = "cmp"

                    # TODO: This is true for 0x83. Other opcodes might have different sizes
                    immediateBytes = 1
                    immediateBytesLeft = 1
                    step = STEP_DISP_IMM_BYTES

            # Set the properties of the source operand now that enough is known about it
            if curInst.source is not None:

                curInst.source.setSize(operandSize)
                if direction == OP_DIR_FROM_REG_MEM:
                    curInst.source.value = regmem
                else:
                    if mod == MOD_INDIRECT:
                        # TODO: Go to the SIB if the value is ESP
                        # TODO: Do a 4 byte displacement if the value is EBP
                        curInst.source.indirect = True

                    # Only set the value if it is a register. Immediates are not set with the R/M byte.
                    if curInst.source.isReg:
                        curInst.source.value = regOrOp

            # Set the properties of the destination operand now that enough is known about it
            if curInst.dest is not None:

                curInst.dest.setSize(operandSize)
                if direction == OP_DIR_FROM_REG_MEM:
                    curInst.dest.value = regOrOp
                else:
                    if mod == MOD_INDIRECT:
                        # TODO: Go to the SIB if the value is ESP
                        # TODO: Do a 4 byte displacement if the value is EBP
                        curInst.dest.indirect = True

                    curInst.dest.value = regmem

            if mod == MOD_1_BYTE_DISP:
                print("1 byte dispalcement")
                displaceBytes = 1
                displaceBytesLeft = 1
                step = STEP_DISP_IMM_BYTES
                continue

            elif mod == MOD_4_BYTE_DISP:
                print("4 byte dispalcement")
                displaceBytes = 4
                displaceBytesLeft = 4
                step = STEP_DISP_IMM_BYTES
                continue

            elif immediateBytes > 0:
                step = STEP_DISP_IMM_BYTES
                continue

            else:
                step = STEP_BEGIN
                instructions.append(curInst)
                continue

        if step <= STEP_DISP_IMM_BYTES:
            print("Looking for extra bytes, disp: {}, imm: {}".format(displaceBytesLeft, immediateBytesLeft))

            curInst.bytes.append(byte)

            if displaceBytesLeft > 0:
                # TODO: Process displacement bytes
                displaceBytesLeft -= 1

            elif immediateBytesLeft > 0:
                print("adding immediate")
                # x86 is little endian, so as bytes come in, they should be bitshifted over 8 times for every
                # byte that has already been processed for the value.
                curInst.source.value = curInst.source.value + (byte >> (8 * (immediateBytes - immediateBytesLeft)))
                immediateBytesLeft -= 1

            # After processing the displacement or immediate byte, check whether there are
            # any bytes left. If not, add the instruction to the list because this is the
            # last possible step when processing an instruction.
            if displaceBytesLeft == 0 and immediateBytesLeft == 0:
                print("nothing left")
                instructions.append(curInst)
                step = STEP_BEGIN
                continue

    return instructions



"""
x86 is split between modifers and opcodes. There can be 0-4 modifier bytes then followed by an opcode. Parts of the opcode can also say something about how the operands should be used.
For example, the add opcode's lower bits tell which registers to use and which direction to do the addition


"""
prefixes = [

    PREFIX_64_BIT_OPERAND,
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


    0x83: X64Instruction("", source=X64Operand(size=REG_SIZE_8L, defSize=True, isReg=False), dest=X64Operand(), extOpcode=True),

    0x89: X64Instruction("mov",  source=X64Operand(), dest=X64Operand()),

    0xc3: X64Instruction("leave", 0),
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
]


