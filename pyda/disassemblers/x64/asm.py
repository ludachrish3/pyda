from pyda.disassemblers.x64.definitions import *
from pyda.disassemblers.x64.instructions import *
from pyda.disassemblers.disassembler import Instruction, Operand

import copy
import logging

logger = logging.getLogger(__name__)

class X64Instruction( Instruction ):

    def __init__( self, mnemonic="byte", addr=0, source=None, dest=None, extraOperands=[] ):
        super().__init__(mnemonic, addr, source, dest, extraOperands)

        self.prefixSize = None      # The size operands should be based on the prefix
        self.segmentPrefix = 0      # Opcode of the segment
        self.lockRepeatPrefix = 0   # Lock or repeat prefix
        self.addressSize   = REG_SIZE_64
        self.extendBase    = False
        self.extendIndex   = False
        self.extendReg     = False

    def setAttributes( self, opcode, info ):

        # Create deep copies so that the dictionary of infos remains unchanged
        # and this specific instruction's info can be updated as needed.
        self.info = copy.deepcopy(info)
        self.mnemonic = copy.deepcopy(info.mnemonic)

        logger.debug(f"src:  {self.info.srcKwargs}")
        logger.debug(f"dst:  {self.info.dstKwargs}")
        logger.debug(f"inst: {self.info.instKwargs}")

        info = self.info
        srcKwargs = self.info.srcKwargs
        dstKwargs = self.info.dstKwargs

        # Handle renaming the mnemonic for Group 1 prefixes
        # TODO: There are special cases for some of these, so that will need to
        # be handled in the future.
        if self.lockRepeatPrefix == PREFIX_LOCK:
            self.mnemonic = "lock " + self.mnemonic

        elif self.lockRepeatPrefix == PREFIX_REPEAT_NZERO:
            self.mnemonic = "repnz " + self.mnemonic

        elif self.lockRepeatPrefix == PREFIX_REPEAT_ZERO:
            self.mnemonic = "repz " + self.mnemonic

        #############################
        #  DETERMINE OPERAND SIZES  #
        #############################

        srcSize    = srcKwargs.get("size",    None)
        srcMaxSize = srcKwargs.get("maxSize", REG_SIZE_64)

        dstSize    = dstKwargs.get("size",    None)
        dstMaxSize = dstKwargs.get("maxSize", REG_SIZE_64)

        srcKwargs["size"] = getOperandSize(opcode, self.prefixSize, srcSize, srcMaxSize)
        dstKwargs["size"] = getOperandSize(opcode, self.prefixSize, dstSize, dstMaxSize)

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


def getOperandSize( opcode, prefixSize, infoSize, maxSize ):
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

        # Group 1 prefixes
        if byte in [ PREFIX_LOCK, PREFIX_REPEAT_NZERO, PREFIX_REPEAT_ZERO ]:
            logger.debug(f"Found a lock/repeat prefix: {byte:02x}")
            instruction.lockRepeatPrefix = byte
            instruction.bytes.append(byte)

        # Group 2 prefixes
        elif byte in PREFIX_SEGMENTS:
            logger.debug(f"Found a segment register prefix: {byte:02x}")
            instruction.segmentPrefix = byte
            instruction.bytes.append(byte)

        # REX prefixes
        elif byte & 0xf0 == PREFIX_REX_MASK:

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
        logger.debug(f"A 1 byte opcode was found: {binary[0]:02x}")
        instruction.setAttributes(binary[0], oneByteOpcodes[binary[0]])
        numOpcodeBytes = 1

    # The opcode is not a valid 1 or 2 byte opcode, so keep the new instruction
    # the same as the one that was passed in.
    else:
        logger.warning(f"An invalid opcode was found: {binary[0]:02x}")

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

    if instruction.bytes[-1] in [ 0x80, 0x81, 0x83 ]:

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

    elif instruction.bytes[-1] in [ 0x8f ]:

        if modRmOpValue != 0:
            logger.debug("An invalid Mod R/M value was received")
            return False

    elif instruction.bytes[-1] in [ 0xc0, 0xc1 ]:

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

    elif instruction.bytes[-1] in [ 0xfe ]:

        if modRmOpValue == 0:
            instruction.mnemonic = "inc"

        elif modRmOpValue == 1:
            instruction.mnemonic = "dec"

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

    elif instruction.bytes[-1] in [ 0xff ]:
        # TODO: Update info about operands in each case

        if modRmOpValue == 0:
            instruction.mnemonic = "inc"

        elif modRmOpValue == 1:
            instruction.mnemonic = "dec"

        elif modRmOpValue == 2:
            instruction.mnemonic = "call"
            instruction.info.relativeJump = True

        elif modRmOpValue == 3:
            instruction.mnemonic = "callf"

        elif modRmOpValue == 4:
            instruction.mnemonic = "jmp"
            instruction.info.relativeJump = True

        elif modRmOpValue == 5:
            instruction.mnemonic = "jmpf"

        elif modRmOpValue == 6:
            instruction.mnemonic = "push"

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

    elif instruction.bytes[-1] in [ 0xf6, 0xf7 ]:

        # Clear out the source and destination operands because they might be
        # removed depending on which value is used.
        instruction.source = None
        instruction.dest   = None

        if modRmOpValue == 0:
            newInfo = X64InstructionInfo("test", modRm=MODRM_DEST)
            instruction.setAttributes(instruction.bytes[-1], newInfo)

        elif modRmOpValue == 1:
            newInfo = X64InstructionInfo("test", modRm=MODRM_DEST)
            instruction.setAttributes(instruction.bytes[-1], newInfo)

        elif modRmOpValue == 2:
            newInfo = X64InstructionInfo("not", modRm=MODRM_DEST, src_size=REG_SIZE_0)
            instruction.setAttributes(instruction.bytes[-1], newInfo)

        elif modRmOpValue == 3:
            newInfo = X64InstructionInfo("neg", modRm=MODRM_DEST, src_size=REG_SIZE_0)
            instruction.setAttributes(instruction.bytes[-1], newInfo)

        elif modRmOpValue == 4:
            newInfo = X64InstructionInfo("mul", modRm=MODRM_SOURCE)
            instruction.setAttributes(instruction.bytes[-1], newInfo)
            instruction.dest.value = REG_RDX_RAX_COMBINED

        elif modRmOpValue == 5:
            newInfo = X64InstructionInfo("imul", modRm=MODRM_SOURCE)
            instruction.setAttributes(instruction.bytes[-1], newInfo)
            instruction.dest.value = REG_RDX_RAX_COMBINED

        elif modRmOpValue == 6:
            newInfo = X64InstructionInfo("div", modRm=MODRM_SOURCE)
            instruction.setAttributes(instruction.bytes[-1], newInfo)
            instruction.dest.value = REG_RDX_RAX_COMBINED

        elif modRmOpValue == 7:
            newInfo = X64InstructionInfo("idiv", modRm=MODRM_SOURCE)
            instruction.setAttributes(instruction.bytes[-1], newInfo)
            instruction.dest.value = REG_RDX_RAX_COMBINED

        else:
            logger.debug("An invalid Mod R/M value was received")
            return False

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

    # Process the addressing if the Mod R/M byte applies to this operand
    if operand.modRm:

        # The value is always regmem if the Mod R/M refers to this operand.
        operand.value = regmem

        # Extend the value if the instruction has a base extension prefix.
        if instruction.extendBase:
            logger.debug("Extending value")
            operand.value |= REG_EXTEND

        if mod == MOD_REGISTER:
            logger.debug("Operand is the value in a register")
            return addrBytes

        # The address is indirect if it is not MOD_REGISTER mode.
        operand.indirect = True

        # Process a SIB byte if the value is ESP
        if regmem == REG_RSP:
            isSibDisplace = handleSibByte(operand, mod, binary[1])
            addrBytes += 1

            if instruction.extendIndex and operand.index is not None:
                operand.index |= REG_EXTEND

            # Extend the value if the instruction has a base extension prefix.
            if instruction.extendBase:
                operand.value |= REG_EXTEND

            # RSP is not a valid index, so there must be a segment register set
            # to be used as the index.
            if operand.index == REG_RSP:
                logger.debug(f"RSP is not a valid index, using {instruction.segmentPrefix}")

                if instruction.segmentPrefix in PREFIX_SEGMENTS:
                    operand.segmentReg = instruction.segmentPrefix

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
        opcodeSuccess = handleExtendedOpcode(instruction, regOrOp)
        if not opcodeSuccess:
            return 0

    # Set the operand addressing properties as long as they are not None and they
    # don't their value is 0, which would mean it does not have a certain value.
    if instruction.source is not None and instruction.source.value == 0:
        numBytesConsumed += handleOperandAddressing(instruction, instruction.source, binary)
        logger.debug(f"After handling source: {numBytesConsumed}")

    if instruction.dest is not None and instruction.dest.value == 0:
        numBytesConsumed += handleOperandAddressing(instruction, instruction.dest, binary)
        logger.debug(f"After handling dest: {numBytesConsumed}")

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
        logger.error(f"There are only {len(binary)} bytes remaining, but {instruction.source.size} are expected")
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
    binary       = function.assembly[:4800]
    instructions = function.instructions
    offTheRails  = False

    # TODO: Add a good description of what this loop is doing and the stages that are performed
    while len(binary) > 0:

        logger.debug("moving on to the next instruction")
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
        numPrefixBytes = handlePrefix(curInstruction, binary)
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
            logger.debug("There is a mod RM byte")
            numModRmBytes = handleModRmByte(curInstruction, binary)
            if numModRmBytes > 0:
                binary = binary[numModRmBytes:]

            else:
                logger.error("Failed to process the Mod R/M byte")
                binary = bytes(curInstruction.bytes) + binary
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

        # Resolve any addresses that are relative now that the value of RIP can
        # be calculated because all bytes of the current isntruction are consumed.
        resolveRelativeAddr(curInstruction, curInstruction.source)
        resolveRelativeAddr(curInstruction, curInstruction.dest)

        logger.debug(curInstruction)

        # Add the instruction and advance the address
        instructions.append(curInstruction)
        addr += len(curInstruction.bytes)

    return instructions
