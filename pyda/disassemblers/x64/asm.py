from pyda.disassemblers.x64.definitions import *
from pyda.disassemblers.x64.instructions import *

import logging

logger = logging.getLogger(__name__)

def handlePrefixes( instruction, binary ):
    """
    Description:    Consumes all prefix bytes and sets the options for the
                    instruction. They are consumed in this order:

                    1. Legacy prefixes. All groups can be in any order.
                        a. Group 1: lock and repeat. The repeat prefixes, 0xf2
                           and 0xf3 can also alter the primary opcode's meaning.

                        b. Group 2: segment override

                        c. Group 3: operand size override. This prefix can also
                          alter the primary opcode's meaning.

                        d. Group 4: address size override

                    2. REX Prefixes

    Arguments:      instruction - An x64Instruction object
                    binary      - An array of bytes

    Return:         Number of bytes that are prefix bytes
    """

    numPrefixBytes = 0

    # Handle legacy prefixes
    for byte in binary:

        # Group 1 prefixes
        if byte in [ PREFIX_LOCK, PREFIX_REPEAT_NZERO, PREFIX_REPEAT_ZERO ]:
            logger.debug(f"Found a lock/repeat prefix: {byte:02x}")
            instruction.legacyPrefix = byte

        # Group 2 prefixes
        elif byte in PREFIX_SEGMENTS:
            logger.debug(f"Found a segment register prefix: {byte:02x}")
            instruction.segmentPrefix = byte

        # Group 3 prefixes
        elif byte == PREFIX_16_BIT_OPERAND:
            logger.debug("Found the 16-bit prefix")
            instruction.legacyPrefix = byte

        # Group 4 prefixes
        elif byte == PREFIX_32_BIT_ADDRESS:
            logger.debug("Found the 32-bit address prefix")
            instruction.addressSize = 4

        # If a prefix is not found, proceed to the next step
        else:
            logger.debug("No more legacy prefixes")
            break

        # If the else branch is not hit, a prefix byte was found
        instruction.bytes.append(byte)
        numPrefixBytes += 1

    # Handle REX prefixes starting from wherever the legacy prefixes left off
    for byte in binary[numPrefixBytes:]:

        if byte & 0xf0 == PREFIX_REX_MASK:

            # If the prefix is just the REX prefix with no other bits set, then
            # access to the extended 8-bit registers is available.
            if byte == PREFIX_REX_MASK:
                logger.debug("8-bit REX operand size prefix")
                instruction.prefixSize = REG_SIZE_8_REX

            # The base value of the register is extended
            if byte & PREFIX_REX_W_MASK == PREFIX_REX_W_MASK:
                logger.debug("64-bit operand size prefix")
                instruction.prefixSize = REG_SIZE_64

            if byte & PREFIX_REX_R_MASK == PREFIX_REX_R_MASK:
                logger.debug("Extended reg field prefix")
                instruction.extendReg = True

            if byte & PREFIX_REX_X_MASK == PREFIX_REX_X_MASK:
                logger.debug("Extended SIB index field prefix")
                instruction.extendIndex = True

            if byte & PREFIX_REX_B_MASK == PREFIX_REX_B_MASK:
                instruction.extendBase = True

        else:
            logger.debug("No more REX prefixes")
            break

        # If the else branch is not hit, a prefix byte was found
        instruction.bytes.append(byte)
        numPrefixBytes += 1

    return numPrefixBytes


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
        numOpcodeBytes = 2

        # If the info object is actually a dictionary, then there is a secondary
        # opcode and the next byte also needs to be consumed.
        info = twoByteOpcodes[binary[1]]
        if type(info) == dict:
            if len(binary) > 2 and binary[2] in info:
                info = info[binary[2]]
                numOpcodeBytes += 1

            elif None in info:
                info = info[None]

            else:
                raise Exception("Could not resolve opcode")

        instruction.setAttributes(binary[1], info)

    # Check for the opcode being a 1 byte opcode
    elif binary[0] in oneByteOpcodes:
        numOpcodeBytes = 1

        # If the info object is actually a dictionary, then there is a secondary
        # opcode and the next byte also needs to be consumed.
        info = oneByteOpcodes[binary[0]]
        if type(info) == dict:
            if len(binary) > 1 and binary[1] in info:
                info = info[binary[1]]
                numOpcodeBytes += 1

            elif None in info:
                logger.debug("THIS SHOULD PRINT")
                info = info[None]

            else:
                raise Exception("Could not resolve opcode")

        instruction.setAttributes(binary[0], info)

    # The opcode is not a valid 1 or 2 byte opcode, so keep the new instruction
    # the same as the one that was passed in.
    else:
        logger.warning(f"An invalid opcode was found: {binary[0]:02x}")

    # Append the opcode bytes to the instruction's list of bytes
    instruction.bytes += list(binary[0:numOpcodeBytes])

    return numOpcodeBytes


def handleExtendedOpcode( instruction, modRmByte ):
    """
    Description:    Handles the extended opcode based on the REG value of the
                    Mod R/M byte.

    Arguments:      instruction - X64Instruction object
                    modRmByte   - Full Mod R/M byte

    Return:         True on success
                    False on failure
    """

    mod = modRmByte & ADDR_MOD_MASK
    op  = (modRmByte & ADDR_REG_MASK) >> 3

    if instruction.bytes[-1] in [ 0x80, 0x81, 0x83 ]:

        if op == 0:
            instruction.mnemonic = "add"

        elif op == 1:
            instruction.mnemonic = "or"

        elif op == 2:
            instruction.mnemonic = "adc"

        elif op == 3:
            instruction.mnemonic = "sbb"

        elif op == 4:
            instruction.mnemonic = "and"

        elif op == 5:
            instruction.mnemonic = "sub"

        elif op == 6:
            instruction.mnemonic = "xor"

        elif op == 7:
            instruction.mnemonic = "cmp"

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

    elif instruction.bytes[-1] in [ 0x8f ]:

        if op != 0:
            logger.debug("An invalid Mod R/M value was received")
            return False

    elif instruction.bytes[-1] in [ 0xc0, 0xc1, 0xd0, 0xd1, 0xd2, 0xd3 ]:

        if op == 0:
            instruction.mnemonic = "rol"

        elif op == 1:
            instruction.mnemonic = "ror"

        elif op == 2:
            instruction.mnemonic = "rcl"

        elif op == 3:
            instruction.mnemonic = "rcr"

        elif op == 4:
            instruction.mnemonic = "shl"

        elif op == 5:
            instruction.mnemonic = "shr"

        elif op == 6:
            instruction.mnemonic = "sal"

        elif op == 7:
            instruction.mnemonic = "sar"

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

    elif instruction.bytes[-1] in [ 0xfe ]:

        if op == 0:
            instruction.mnemonic = "inc"

        elif op == 1:
            instruction.mnemonic = "dec"

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

    elif instruction.bytes[-1] in [ 0xff ]:
        # TODO: Update info about operands in each case

        if op == 0:
            instruction.mnemonic = "inc"

        elif op == 1:
            instruction.mnemonic = "dec"

        elif op == 2:
            instruction.mnemonic = "call"
            instruction.info.relativeJump = True

        elif op == 3:
            instruction.mnemonic = "callf"

        elif op == 4:
            instruction.mnemonic = "jmp"
            instruction.info.relativeJump = True

        elif op == 5:
            instruction.mnemonic = "jmpf"

        elif op == 6:
            instruction.mnemonic = "push"

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

    elif instruction.bytes[-1] in [ 0xf6, 0xf7 ]:

        # Clear out the source and destination operands because they might be
        # removed depending on which value is used.
        instruction.source = None
        instruction.dest   = None

        if op == 0:
            newInfo = X64InstructionInfo("test", modRm=MODRM_DST, src_isImmediate=True)
            instruction.setAttributes(instruction.bytes[-1], newInfo)

        elif op == 1:
            newInfo = X64InstructionInfo("test", modRm=MODRM_DST, src_isImmediate=True)
            instruction.setAttributes(instruction.bytes[-1], newInfo)

        elif op == 2:
            newInfo = X64InstructionInfo("not", modRm=MODRM_DST, src_size=REG_SIZE_0)
            instruction.setAttributes(instruction.bytes[-1], newInfo)

        elif op == 3:
            newInfo = X64InstructionInfo("neg", modRm=MODRM_DST, src_size=REG_SIZE_0)
            instruction.setAttributes(instruction.bytes[-1], newInfo)

        elif op == 4:
            newInfo = X64InstructionInfo("mul", modRm=MODRM_SRC)
            instruction.setAttributes(instruction.bytes[-1], newInfo)
            instruction.dest.value = REG_RDX_RAX_COMBINED

        elif op == 5:
            newInfo = X64InstructionInfo("imul", modRm=MODRM_SRC)
            instruction.setAttributes(instruction.bytes[-1], newInfo)
            instruction.dest.value = REG_RDX_RAX_COMBINED

        elif op == 6:
            newInfo = X64InstructionInfo("div", modRm=MODRM_SRC)
            instruction.setAttributes(instruction.bytes[-1], newInfo)
            instruction.dest.value = REG_RDX_RAX_COMBINED

        elif op == 7:
            newInfo = X64InstructionInfo("idiv", modRm=MODRM_SRC)
            instruction.setAttributes(instruction.bytes[-1], newInfo)
            instruction.dest.value = REG_RDX_RAX_COMBINED

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

    elif instruction.bytes[-1] in [ 0xd9 ]:

        # Clear out the source and destination operands because they might be
        # removed depending on which value is used.
        instruction.source = None
        instruction.dest   = None

        if op == 0:
            newInfo = X64InstructionInfo("fld",    op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 1 and mod == MOD_INDIRECT:
            newInfo = X64InstructionInfo("fxch",   op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 2 and mod != MOD_DIRECT:
            newInfo = X64InstructionInfo("fst",    modRm=MODRM_DST, op_size=REG_SIZE_64, src_value=REG_ST0)

        elif op == 3 and mod != MOD_DIRECT:
            newInfo = X64InstructionInfo("fstp",   modRm=MODRM_DST, op_size=REG_SIZE_64, src_value=REG_ST0)

        elif op == 4:
            newInfo = X64InstructionInfo("fldenv", modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_FPENV)

        elif op == 5:
            newInfo = X64InstructionInfo("fldcw",  modRm=MODRM_SRC, op_size=REG_SIZE_16, dst_value=REG_FPENV)

        elif op == 6:
            newInfo = X64InstructionInfo("fstenv", modRm=MODRM_DST, op_size=REG_SIZE_64, src_value=REG_FPENV)

        elif op == 7:
            newInfo = X64InstructionInfo("fstcw",  modRm=MODRM_DST, op_size=REG_SIZE_16, src_value=REG_FPENV)

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

        instruction.setAttributes(instruction.bytes[-1], newInfo)

    elif instruction.bytes[-1] in [ 0xdb ]:

        # Clear out the source and destination operands because they might be
        # removed depending on which value is used.
        instruction.source = None
        instruction.dest   = None

        if op == 0 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fcmovnb",  op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 0:
            newInfo = X64InstructionInfo("fild",     modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 1 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fcmovne",  op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 1:
            newInfo = X64InstructionInfo("fisttp",   modRm=MODRM_DST, op_size=REG_SIZE_64, src_value=REG_ST0)

        elif op == 2 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fcmovnbe", op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 2:
            newInfo = X64InstructionInfo("fist",     modRm=MODRM_DST, op_size=REG_SIZE_64, src_value=REG_ST0)

        elif op == 3 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fcmovnu",  op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 3:
            newInfo = X64InstructionInfo("fistp",    modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        # op == 4 case is covered by secondary opcodes.

        elif op == 5 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fucomi",  op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 5:
            newInfo = X64InstructionInfo("fld",     modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 6:
            newInfo = X64InstructionInfo("fcomi",   op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 7:
            newInfo = X64InstructionInfo("fstp",    op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, src_value=REG_STO)

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

        instruction.setAttributes(instruction.bytes[-1], newInfo)

    elif instruction.bytes[-1] in [ 0xdd ]:

        # Clear out the source and destination operands because they might be
        # removed depending on which value is used.
        instruction.source = None
        instruction.dest   = None

        if op == 0 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("ffree",  op_floatReg=True, modRm=MODRM_DST, src_size=REG_SIZE_0, dst_size=REG_SIZE_64)

        elif op == 0:
            newInfo = X64InstructionInfo("fld",    modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 1 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fxch4",  op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 1:
            newInfo = X64InstructionInfo("fisttp", modRm=MODRM_DST, op_size=REG_SIZE_64, src_value=REG_ST0)

        elif op == 2 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fst",    op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 2:
            newInfo = X64InstructionInfo("fst",    modRm=MODRM_DST, op_size=REG_SIZE_64, src_value=REG_ST0)

        elif op == 3 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fstp",   op_floatReg=True, modRm=MODRM_DST, op_size=REG_SIZE_64, src_value=REG_ST0)

        elif op == 3:
            newInfo = X64InstructionInfo("fstp",   modRm=MODRM_DST, op_size=REG_SIZE_64, src_value=REG_ST0)

        elif op == 4 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fucom",  op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, src_value=REG_ST0)

        elif op == 4:
            newInfo = X64InstructionInfo("frstor", modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_FPENV)

        elif op == 5 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fucomp", op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 6 and mod != MOD_DIRECT:
            newInfo = X64InstructionInfo("fsave",  modRm=MODRM_DST, op_size=REG_SIZE_64, src_value=REG_FPENV)

        elif op == 7 and mod != MOD_DIRECT:
            newInfo = X64InstructionInfo("fstsw",  modRm=MODRM_DST, op_size=REG_SIZE_16, src_value=REG_FPENV)

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

        instruction.setAttributes(instruction.bytes[-1], newInfo)

    elif instruction.bytes[-1] in [ 0xdf ]:

        # Clear out the source and destination operands because they might be
        # removed depending on which value is used.
        instruction.source = None
        instruction.dest   = None

        if op == 0 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("ffreep", op_floatReg=True, modRm=MODRM_SRC, dst_size=REG_SIZE_0, src_size=REG_SIZE_64)

        elif op == 0:
            newInfo = X64InstructionInfo("fild",   modRm=MODRM_SRC, op_size=REG_SIZE_16, op_maxMax=REG_SIZE_16, dst_value=REG_ST0)

        elif op == 1 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fxch",   op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 1:
            newInfo = X64InstructionInfo("fisttp", modRm=MODRM_DST, op_size=REG_SIZE_16, op_maxMax=REG_SIZE_16, src_value=REG_ST0)

        elif op == 2 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fstp",   op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 2:
            newInfo = X64InstructionInfo("fst",    modRm=MODRM_DST, op_size=REG_SIZE_16, op_maxMax=REG_SIZE_16, src_value=REG_ST0)

        elif op == 3 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fstp",   op_floatReg=True, modRm=MODRM_DST, op_size=REG_SIZE_64, src_value=REG_ST0)

        elif op == 3:
            newInfo = X64InstructionInfo("fstp",   modRm=MODRM_DST, op_size=REG_SIZE_16, op_maxMax=REG_SIZE_16, src_value=REG_ST0)

        elif op == 4 and mod != MOD_DIRECT:
            newInfo = X64InstructionInfo("fbld",   modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 5 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fucomip", op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 5:
            newInfo = X64InstructionInfo("fild",   modRm=MODRM_SRC, op_size=REG_SIZE_64, dst_value=REG_ST0)

        elif op == 6 and mod == MOD_DIRECT:
            newInfo = X64InstructionInfo("fcomip", op_floatReg=True, modRm=MODRM_SRC, op_size=REG_SIZE_64, src_value=REG_ST0)

        elif op == 6:
            newInfo = X64InstructionInfo("fbstp",  modRm=MODRM_SRC, op_size=REG_SIZE_64, src_value=REG_ST0)

        elif op == 7 and mod != MOD_DIRECT:
            newInfo = X64InstructionInfo("fistp",  modRm=MODRM_DST, op_size=REG_SIZE_64, src_value=REG_ST0)

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

        instruction.setAttributes(instruction.bytes[-1], newInfo)

    else:
        logger.debug("An unsupported extended opcode was found")
        return False

    return True


def handleSibByte( operand, addrMode, sibByte ):
    """
    Description:    Parses the Scale Index Base (SIB) byte and determines
                    whether a displacement value will follow.

                    If the addressing mode was indirect from the Mod R/M byte
                    and the base is %ebp, then a 4 byte displacement will follow
                    the SIB byte.

    Arguments:      operand  - X64Operand object
                    addrMode - Address mode from the Mod R/M byte
                    sibByte  - SIB byte to process

    Return:         Whether there will be a 4 byte displacement value.
    """

    scale = 2 ** ((sibByte & SIB_SCALE_MASK) >> 6)
    index = (sibByte & SIB_INDEX_MASK) >> 3
    base  = sibByte & SIB_BASE_MASK

    # RSP is not a valid index
    if index == REG_RSP:
        index = None

    logger.debug(f"scale: {scale}, index: {index}, base: {base}")
    operand.scale = scale
    operand.index = index

    # A mode of indrect and a base of %rbp means that displacement bytes will
    # follow the SIB byte. Set the value to None because there will not be a
    # base value if there is a displacement.
    if addrMode == MOD_INDIRECT and base == REG_RBP:
        operand.value = None
        return True

    operand.value = base
    return False


def handleOperandAddressing( instruction, operand, binary ):
    """
    Description:    Figures out addressing mode for an operand based on the
                    Mod R/M byte.

    Arguments:      instruction - X64Instruction object
                    operand     - X64Operand object
                    binary      - Remaining bytes to disassemble, starting with
                                  the Mod R/M byte

    Return:         Number of bytes needed for addressing, not including the
                    Mod R/M byte.
    """

    modRmByte = binary[0]
    mod       = modRmByte & ADDR_MOD_MASK
    regOrOp   = (modRmByte & ADDR_REG_MASK) >> 3
    regmem    = modRmByte & ADDR_RM_MASK
    addrBytes = 0
    displaceBytes = 0
    isSibDisplace = False

    if instruction.extendReg:
        regOrOp |= REG_EXTEND

    logger.debug(f"mod: {mod >> 6}, reg: {regOrOp}, r/m: {regmem}")

    logger.debug(f"Before doing anything, operand value is {operand.value:02x}")

    # Process the addressing if the Mod R/M byte applies to this operand
    if operand.modRm:

        # Set the segment register if one is specified
        if instruction.segmentPrefix in PREFIX_SEGMENTS:
            operand.segmentReg = instruction.segmentPrefix

        # The value is always regmem if the Mod R/M refers to this operand.
        operand.value = regmem

        # Extend the value if the instruction has a base extension prefix.
        if instruction.extendBase:
            logger.debug("Extending value")
            operand.value |= REG_EXTEND

        if operand.floatReg:
            operand.value |= REG_FLOAT

        if mod == MOD_DIRECT:
            logger.debug("Operand is the value in a register")

            # Change this register to an MM register if this instruction deals
            # with MM registers. Only direct references to MM registers should
            # be converted to use MM names because using an indirect address
            # based on an MM (or XMM) register does not make sense. The values
            # in these registers are usually packed values.
            if operand.mmRegister:
                operand.value |= REG_MM

            return addrBytes

        # The address is indirect if it is not MOD_DIRECT mode.
        operand.indirect = True

        # Process a SIB byte if the value is ESP
        if regmem == REG_RSP:
            isSibDisplace = handleSibByte(operand, mod, binary[1])
            addrBytes += 1

            # Extend the index if the instruction has an index extension prefix.
            if instruction.extendIndex and operand.index is not None:
                operand.index |= REG_EXTEND

            # Extend the value if the instruction has a base extension prefix.
            if instruction.extendBase and operand.value is not None:
                operand.value |= REG_EXTEND

        if mod == MOD_INDIRECT:

            if regmem == REG_RBP:
                logger.debug("Indirect register 4 byte displacement from RIP")
                operand.value = REG_RIP
                displaceBytes = 4

            elif isSibDisplace:
                logger.debug("SIB displacement bytes")
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

        # Save the displacement value if there are any displacement bytes. The
        # Mod R/M byte as well as any additional addressing bytes, like the SIB
        # byte, must be skipped to get to the displacement bytes.
        if displaceBytes > 0:
            operand.displacement = int.from_bytes(binary[1+addrBytes:1+addrBytes+displaceBytes], "little", signed=True)
            logger.debug(f"Adding displacement to the operand: {operand.displacement:x}")

    # Otherwise, set the value as long as this operand is not an immediate and
    # the value has not been set, which would indicate that tne operand has a
    # predetermined value and is already set to the correct value.
    elif not operand.isImmediate and operand.value == 0:
        logger.debug("Mod R/M byte is not for this operand")
        operand.value = regOrOp

        if operand.mmRegister:
            logger.debug("Extending register to use MM registers")
            operand.value |= REG_MM

    return addrBytes + displaceBytes


def handleModRmByte( instruction, binary ):
    """
    Description:    Handles the Mod R/M byte(s) of an instruction

    Arguments:      instruction - X64Instruction object with its info member set
                    binary      - bytes remaining to be processed for an instruction

    Return:         The number of bytes consumed when processing the Mod R/M bytes
                    If an error occurs 0 is returned
    """

    if len(binary) == 0:
        return 0

    numBytesConsumed = 1
    modRmByte = binary[0]
    mod     = modRmByte & ADDR_MOD_MASK
    regOrOp = (modRmByte & ADDR_REG_MASK) >> 3
    regmem  = modRmByte & ADDR_RM_MASK

    # If the instruction has an extended opcode, the REG value is actually
    # part of the opcode.
    if instruction.info.extOpcode:

        logger.debug(f"Found an opcode that needs to be extended: {instruction.bytes[-1]:x}")
        opcodeSuccess = handleExtendedOpcode(instruction, modRmByte)
        if not opcodeSuccess:
            return 0

    # Set the operand addressing properties as long as they are not None and
    # their value is 0, which would mean it does not have a predetermined value.
    if instruction.source is not None and instruction.source.value is 0:
        numBytesConsumed += handleOperandAddressing(instruction, instruction.source, binary)
        logger.debug(f"After handling source: {numBytesConsumed}")

    if instruction.dest is not None and instruction.dest.value is 0:
        numBytesConsumed += handleOperandAddressing(instruction, instruction.dest, binary)
        logger.debug(f"After handling dest: {numBytesConsumed}")

    if numBytesConsumed <= len(binary):
        instruction.bytes += list(binary[:numBytesConsumed])

    else:
        return 0

    return numBytesConsumed


def handleImmediate( instruction, operand, binary ):
    """
    Description:    Consume all immediate bytes and convert them to an integer

    Arguments:      instruction - X64Instruction object
                    operand     - X64Operand object
                    binary      - bytes remaining to be processed for an
                                  instruction

    Return:         The number of bytes consumed when processing the immediate.
                    -1 is returned if not enough bytes remain to form the value.
    """

    # Check whether there are enough bytes for the instruction
    if len(binary) < operand.size:
        logger.error(f"There are only {len(binary)} bytes remaining, but {operand.size} are expected")
        return -1

    # Round the operand size down because there are some register sizes that use
    # decimal values to differentiate them. The actual size is always the
    # truncated value of the register size.
    numBytes = int(operand.size)
    instruction.bytes += list(binary[:numBytes])
    immediate = int.from_bytes(binary[:numBytes], "little", signed=instruction.info.signExtension)

    # If the instruction is a relative jump, mark the source as indirect from
    # the RIP register so that it can be resolved once processing all
    # instruction bytes is done and the length of the instruction is known.
    if instruction.info.relativeJump:
        operand.indirect = True
        operand.value = REG_RIP
        operand.displacement = immediate

    # Otherwise, the source value is just the immediate
    else:
        operand.value = immediate

    return numBytes

def resolveRelativeAddr( instruction, operand ):
    """
    Description:    Resolves the relative memory address if there is one.

                    If the instruction is a relative address, the it is:
                    [%rip] + displacement

                    The value in the instruction pointer register is the
                    address of the next instruction, which is the address of
                    the current instruction plus the number of bytes in it.

    Arguments:      instruction - X64Instruction object
                    operand     - X64Operand object. Can also be None.

    Return:         None
    """

    if operand is not None and operand.indirect and operand.value == REG_RIP:
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
    binary       = function.assembly[:45000]
    instructions = function.instructions
    offTheRails  = False

    # TODO: Add a good description of what this loop is doing and the stages that are performed
    while len(binary) > 0:

        curInstruction = X64Instruction(addr=addr)

        # If things have gone off the rails, consume each byte and add a
        # default instruction
        if offTheRails:
            logger.warning(f"Adding an unknown byte: {binary[0]:02x}")

            # Create an instruction with the byte and advance the address
            curInstruction.bytes.append(binary[0])
            binary = binary[1:]

            # Add the instruction and advance the address
            instructions.append(curInstruction)
            addr += len(curInstruction.bytes)
            continue

        # Find all prefix bytes and set the appropriate settings in the
        # instruction. Consume all prefix bytes from the binary.
        numPrefixBytes = handlePrefixes(curInstruction, binary)
        logger.debug(f"There were {numPrefixBytes} prefix bytes")
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
            binary = bytes(curInstruction.bytes) + binary
            offTheRails = True
            continue

        # If the instruction has a Mod R/M byte, parse it next
        if curInstruction.info.modRm != MODRM_NONE:
            numModRmBytes = handleModRmByte(curInstruction, binary)
            if numModRmBytes > 0:
                binary = binary[numModRmBytes:]

            else:
                logger.error("Failed to process the Mod R/M byte")
                binary = bytes(curInstruction.bytes) + binary
                offTheRails = True
                continue

        # Handle an immediate value if there is one and the value has not
        # already been set by the instruction info object. Use "is" instead of
        # "==" because there is an instruction that loads 0.0 into floating
        # point registers, and this prevents that instruction or others like it
        # from trying to consume bytes for an immediate.
        if curInstruction.source is not None and curInstruction.source.isImmediate and curInstruction.source.value is 0:
            numImmediateBytes = handleImmediate(curInstruction, curInstruction.source, binary)
            if numImmediateBytes < 0:
                offTheRails = True
                continue

            binary = binary[numImmediateBytes:]

        for extraOperand in curInstruction.extraOperands:
            if extraOperand.isImmediate and extraOperand.value is 0:
                logger.debug("Handling the extra immeidate")
                numImmediateBytes = handleImmediate(curInstruction, extraOperand, binary)
                if numImmediateBytes < 0:
                    offTheRails = True
                    continue

                binary = binary[numImmediateBytes:]


        # Resolve any addresses that are relative now that the value of RIP can
        # be calculated because all bytes of the current isntruction are consumed.
        resolveRelativeAddr(curInstruction, curInstruction.source)
        resolveRelativeAddr(curInstruction, curInstruction.dest)

        logger.debug(curInstruction)

        # Add the instruction and advance the address
        instructions.append(curInstruction)
        addr += len(curInstruction.bytes)

    return instructions
