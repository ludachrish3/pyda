from x64defs import *

from disassembler import Instruction, Operand

class X64Instruction(Instruction):
    # TODO: Fill out x64 specific attributes
    def __init__(self, mnemonic, source=None, dest=None, extOpcode=False, extraOperands=[], hasRMMod=True):
        super().__init__(mnemonic, source, dest, extraOperands)

        self.hasRMMod = hasRMMod

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
                return "[%{}]".format(regName)
            else:
                return "%{}".format(regName)
            
STEP_BEGIN = 0
STEP_PREFIX = 1
STEP_2_BYTE_PREFIX = 2
STEP_OPCODE = 3
STEP_RM_MOD = 4
STEP_SIB_BYTE = 5
STEP_DISPLACE_BYTE = 6
STEP_IMMEDIATE_BYTE = 7

def disassemble(binary):

    step = STEP_BEGIN
    instructions = []
    instBytes = []

    # TODO: Add a good description of what this loop is doing and the stages that are performed
    for byte in binary[0:8]:

        print("byte: {0:0>2x}".format(byte))

        if step <= STEP_BEGIN:
            print("moving on to the next instruction")
            instBytes = []
            curInstruction = None
            is2ByteOpcode = False
            operandSize = REG_SIZE_32
            addressSize = 64
            displaceBytesLeft = 0
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

        # Check for the 2-byte prefix after prefix bytes because this is
        # always immediately before the opcode.
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
            # The direction determines whether the operands go to a register or
            # from a register.
            sizeFlag  = byte & OP_SIZE_MASK
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
            print("About to parse rm mod byte")
            curInst.bytes.append(byte)
            mod      = byte & MOD_MASK
            register = (byte & REG_MASK) >> 3
            regmem   = byte & RM_MASK

            # TODO: If the instruction has an extended opcode, the register value is actually part of the opcode. Do the necessary stuff here

            print("mod: {}, reg: {}, r/m: {}".format(mod, register, regmem))

            # Set the properties of the source operand now that enough is known about it
            if curInst.source is not None:

                curInst.source.setSize(operandSize)
                if direction == OP_DIR_FROM_REG:
                    curInst.source.value = register
                else:
                    if mod == MOD_INDIRECT:
                        # TODO: Go to the SIB if the value is ESP
                        # TODO: Do a 4 byte displacement if the value is EBP
                        curInst.source.indirect = True

                    curInst.source.value = regmem

            # Set the properties of the destination operand now that enough is known about it
            if curInst.dest is not None:

                curInst.dest.setSize(operandSize)
                if direction == OP_DIR_TO_REG:
                    curInst.dest.value = register
                else:
                    if mod == MOD_INDIRECT:
                        # TODO: Go to the SIB if the value is ESP
                        # TODO: Do a 4 byte displacement if the value is EBP
                        curInst.dest.indirect = True

                    curInst.dest.value = regmem

            if mod == MOD_1_BYTE_DISP:
                print("1 byte dispalcement")
                displaceBytesLeft = 1
                step = STEP_DISPLACE_BYTE
                continue

            elif mod == MOD_4_BYTE_DISP:
                print("4 byte dispalcement")
                displaceBytesLeft = 4
                step = STEP_DISPLACE_BYTE
                continue

            else:
                instructions.append(curInst)
                step = STEP_BEGIN
                continue

            print("almost done: {}".format(curInst))


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


    #0x83: X64Instruction("", extOpcode=True, source=

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


