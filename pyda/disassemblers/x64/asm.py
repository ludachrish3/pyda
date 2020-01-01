from pyda.disassemblers.x64.definitions import *
from pyda.disassemblers.x64.instructions import *
from pyda.disassemblers.disassembler import Instruction, Operand

import copy
import logging

logger = logging.getLogger(__name__)

class X64Instruction( Instruction ):

    def __init__( self, mnemonic="byte", addr=0, source=None, dest=None, extraOperands=[] ):
        super().__init__(mnemonic, addr, source, dest, extraOperands)

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

        self.info.srcOperandSize = getOperandSize(opcode, self.prefixSize, self.info.srcOperandSize, self.info.srcCanPromote)
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

        # Handle sign extension if the bit it meaningful
        if opcode & OP_SIGN_MASK:
            self.info.signExtension = True

        # Handle setup if there is a register code in the opcode
        if self.info.registerCode:
            register = opcode & REG_MASK

            # If the source is an immeidate, it is also assumed that the value
            # is being put into the register specified by the register code.
            if self.info.direction == OP_DIR_TO_REG or self.info.srcIsImmediate:
                logger.debug("The destination is the register")
                self.dest = X64Operand(size=self.info.dstOperandSize, value=register)

                # Only add a source if it is an immediate. Otherwise, there
                # should not be a source if the register code is specified.
                if self.info.srcIsImmediate:
                    self.source = X64Operand(size=self.info.srcOperandSize, isImmediate=True)

            elif self.info.direction == OP_DIR_FROM_REG:
                logger.debug("The source is the register")
                self.source = X64Operand(size=self.info.srcOperandSize, value=register)

            else:
                logger.debug("An invalid direction was specified")

        else:
            # Create a source operand as long as the size isn't 0
            if self.info.srcOperandSize != REG_SIZE_0:
                self.source = X64Operand(size=self.info.srcOperandSize, isImmediate=self.info.srcIsImmediate)

            # Create s destination operand as long as the size isn't 0 and the
            # instruction is a jump, which would not have a destination.
            if not self.info.relativeJump and self.info.dstOperandSize != REG_SIZE_0:
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


class X64Operand( Operand ):

    def __init__( self, size=REG_SIZE_32, value=0, isImmediate=False ):

        super().__init__(size, value)
        self.isImmediate = isImmediate  # Whether the operand is an immediate
        self.displacement = 0           # Value of the displacement from the register value
        self.indirect = False           # Whether the addressing is indirect
        self.modRm = False              # Whether the Mod R/M byte applies
        self.scale = 0                  # Factor to multiply the index by if SIB byte is present
        self.index = None               # Index register if SIB byte is present

    def __repr__( self ):

        if self.isImmediate and self.value < 0:
            return "-0x{:x}".format(abs(self.value))

        elif self.isImmediate:
            return "0x{:x}".format(abs(self.value))

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


def getOperandSize( opcode, prefixSize, infoSize, canPromote=True ):
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
                    canPromote - Whether the size can be promoted

    Return:         The size that should be used for the operand.
    """

    sizeBit = opcode & OP_SIZE_MASK

    logger.debug("prefixSize: {}, infoSize: {}, sizeBit: {}".format(prefixSize, infoSize, sizeBit))

    if prefixSize is not None and infoSize != REG_SIZE_8 and canPromote and sizeBit != 0:
        logger.debug("Using prefix size")
        return prefixSize

    elif infoSize is not None:
        logger.debug("Using info size")
        return infoSize

    elif sizeBit == 0:
        logger.debug("Using bit size 8")
        return REG_SIZE_8

    elif sizeBit == 1:
        logger.debug("Using bit size 32")
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

    if instruction.bytes[-1] in [0x80, 0x81, 0x83]:

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

    elif instruction.bytes[-1] in [0xc0, 0xc1]:

        if modRmOpValue == 0:
            instruction.mnemonic = "rol"

        elif modRmOpValue == 1:
            instruction.mnemonic = "ror"

        elif modRmOpValue == 2:
            instruction.mnemonic = "rcl"

        elif modRmOpValue == 3:
            instruction.mnemonic = "rcr"

        elif modRmOpValue == 4:
            instruction.mnemonic = "shl"

        elif modRmOpValue == 5:
            instruction.mnemonic = "shr"

        elif modRmOpValue == 6:
            instruction.mnemonic = "sal"

        elif modRmOpValue == 7:
            instruction.mnemonic = "sar"

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False
    else:
        logger.debug("An unsupported extended opcode was found")
        return False

    return True


def handleSibByte( operand, sibByte ):

    return 1


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
    mod       = modRmByte & ADDR_MOD_MASK
    regOrOp   = (modRmByte & ADDR_REG_MASK) >> 3
    regmem    = modRmByte & ADDR_RM_MASK
    addrBytes = 0
    displaceBytes = 0

    logger.debug("mod: {}, reg: {}, r/m: {}".format(mod >> 6, regOrOp, regmem))

    # Process the addressing if the Mod R/M byte applies to this operand
    if operand.modRm:

        # The value is always regmem if the Mod R/M refers to this operand.
        operand.value = regmem

        if mod == MOD_REGISTER:
            logger.debug("Operand is the value in a register")
            return addrBytes

        # The address is indirect if it is not MOD_REGISTER mode.
        operand.indirect = True

        # Process a SIB byte if the value is ESP
        if regmem == REG_RSP:
            logger.debug("REQUIRES SIB BYTE")
            sibBytes = handleSibByte(operand, binary[1])
            addrBytes += sibBytes

        if mod == MOD_INDIRECT:

            if regmem == REG_RBP:
                logger.debug("Indirect register 4 byte displacement from RIP")
                operand.value = REG_RIP
                displaceBytes = 4

            else:
                logger.debug("Operand is register value")

        elif mod == MOD_1_BYTE_DISP:
            logger.debug("Operand is a register value with a 1 byte displacement")
            displaceBytes = 1

        elif mod == MOD_4_BYTE_DISP:
            logger.debug("Operand is a register value with a 4 byte displacement")
            displaceBytes = 4

        else:
            logger.warning("Invalid addressing mode")

        # Save the displacement value if there are any displacement bytes
        if displaceBytes > 0:
            operand.displacement = int.from_bytes(binary[addrBytes:addrBytes+displaceBytes], "little", signed=True)

    # Otherwise, set the value as long as this operand is not an immediate
    elif not operand.isImmediate:
        logger.debug("Mod R/M byte is not for this operand")
        operand.value = regOrOp

    return addrBytes + displaceBytes


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

    # Set the operand addressing properties as long as they are not None
    direction = instruction.info.direction
    if instruction.source is not None:
        numBytesConsumed += handleOperandAddressing(instruction.source, binary)
        logger.debug("After handling source: {}".format(numBytesConsumed))

    if instruction.dest is not None:
        numBytesConsumed += handleOperandAddressing(instruction.dest,   binary)
        logger.debug("After handling dest: {}".format(numBytesConsumed))

    if numBytesConsumed <= len(binary):
        instruction.bytes += list(binary[:numBytesConsumed])

    else:
        return 0

    return numBytesConsumed


def handleImmediate( instruction, binary ):
    """
    Description:    Consume all immediate bytes and convert them to an integer

    Arguments:      instruction - X64Instruction object with its info member set
                    binary      - bytes remaining to be processed for an instruction

    Return:         The number of bytes consumed when processing the immediate.
                    -1 is returned if not enough bytes remain to form the value.
    """

    # Check whether there are enough bytes for the instruction
    if len(binary) < instruction.source.size:
        logger.error("There are only {} bytes remaining, but {} are expected".format(len(binary), instruction.source.size))
        return -1

    numBytes = instruction.source.size
    instruction.bytes += list(binary[:numBytes])
    immediate = int.from_bytes(binary[:numBytes], "little", signed=instruction.info.signExtension)

    # If the instruction is a relative jump, mark the source as indirect from
    # the RIP register so that it can be resolved once processing all
    # instruction bytes is done and the length of the instruction is known.
    if instruction.info.relativeJump:
        instruction.source.indirect = True
        instruction.source.value = REG_RIP
        instruction.source.displacement = immediate

    # Otherwise, the source value is just the immediate
    else:
        instruction.source.value = immediate

    return numBytes

def resolveRelativeAddr( instruction ):
    """
    Description:    Resolves any relative memory addresses if there are any.

                    If the instruction is a relative address, the it is:
                    [%rip] + displacement

                    The value in the instruction pointer register is the
                    address of the next instruction, which is the address of
                    the current instruction plus the number of bytes in it.

    Arguments:      instruction - X64Instruction object

    Return:         None
    """

    operand = instruction.source

    if operand.indirect and operand.value == REG_RIP:
        logger.debug("Relative indirect memory reference")
        ripValue = instruction.addr + len(instruction.bytes)
        operand.indirect = False
        operand.isImmediate = True
        operand.value = ripValue + operand.displacement


def disassemble( function ):
    """
    Description:    Disassembles a function and creates its list of instructions.
                    The function object will have its instructions member updated
                    with the list of instructions that are generated.

    Arguments:      function - Function object that has assembly to be disassembled

    Return:         The list of instructions that are created.
    """

    addr         = function.addr
    binary       = function.assembly
    instructions = function.instructions
    offTheRails  = False

    # TODO: Add a good description of what this loop is doing and the stages that are performed
    while len(binary) > 0:

        logger.debug("moving on to the next instruction")
        curInstruction = X64Instruction(addr=addr)

        # If things have gone off the rails, consume each byte and add a
        # default instruction
        if offTheRails:
            logger.warning("Adding an unknown byte: {:02x}".format(binary[0]))

            # Create an instruction with the byte and advance the address
            curInstruction.bytes.append(binary[0])
            binary = binary[1:]

            # Add the instruction and advance the address
            instructions.append(curInstruction)
            addr += len(curInstruction.bytes)
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
        if curInstruction.info.modRm != MODRM_NONE:
            logger.debug("There is an RM mod byte")
            numModRmBytes = handleModRmByte(curInstruction, binary)
            if numModRmBytes > 0:
                binary = binary[numModRmBytes:]

            else:
                binary += bytes(curInstruction.bytes)
                offTheRails = True
                continue

        # Handle an immediate value if there is one
        if curInstruction.source is not None and curInstruction.source.isImmediate:
            logger.debug("Handling the immeidate")
            numImmediateBytes = handleImmediate(curInstruction, binary)
            if numImmediateBytes < 0:
                offTheRails = True
                continue

            binary = binary[numImmediateBytes:]

        logger.debug(curInstruction)

        # Resolve any addresses that are relative now that the value of RIP can
        # be calculated because all bytes of the current isntruction are consumed.
        if curInstruction.source is not None:
            resolveRelativeAddr(curInstruction)

        # Add the instruction and advance the address
        instructions.append(curInstruction)
        addr += len(curInstruction.bytes)

    return instructions
