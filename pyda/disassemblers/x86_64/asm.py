from pyda.disassemblers.disassembler import Disassembler

from pyda.disassemblers.x86_64.definitions import *
from pyda.disassemblers.x86_64.instructions import *

import logging

logger = logging.getLogger(__name__)

class X86_64Disassembler( Disassembler ):

    @classmethod
    def disassemble( cls, byteBuffer, addr ):
        """
        Description:    Disassembles a stream of bytes and creates a list of
                        instructions.

        Arguments:      byteBuffer - bytes object to disassemble into x86_64
                                     instructions
                        addr       - starting address to use when disassembling

        Return:         The list of instructions that are created.
        """

        instructions = []
        offTheRails  = False

        # TODO: Add a good description of what this loop is doing and the stages that are performed
        while len(byteBuffer) > 0:

            curInstruction = X86_64Instruction(addr=addr)

            # If things have gone off the rails, consume each byte and add a
            # default instruction
            if offTheRails:
                logger.warning(f"Adding an unknown byte: {byteBuffer[0]:02x}")

                # Create an instruction with the byte and advance the address
                curInstruction.bytes.append(byteBuffer[0])
                byteBuffer = byteBuffer[1:]

                # Add the instruction and advance the address
                instructions.append(curInstruction)
                addr += len(curInstruction.bytes)
                continue

            # Find all prefix bytes and set the appropriate settings in the
            # instruction. Consume all prefix bytes from the byteBuffer.
            numPrefixBytes = cls.__handlePrefixes(curInstruction, byteBuffer)
            byteBuffer = byteBuffer[numPrefixBytes:]

            # Update the instruction based on the instruction info that
            # corresponds with the opcode.  Consume all opcodes bytes from the
            # byteBuffer.
            # TODO: Add exceptions or IndexError if byteBuffer bytes run out
            numOpcodeBytes = cls.__handleOpcode(curInstruction, byteBuffer)
            byteBuffer = byteBuffer[numOpcodeBytes:]
            if numOpcodeBytes == 0 or curInstruction.info is None:

                # If the opcode is invalid, keep track of going off the rails and
                # continue processing the next instructions as default instructions.
                # Also add back the current instructions bytes so that they don't
                # get lost.
                byteBuffer = bytes(curInstruction.bytes) + byteBuffer
                offTheRails = True
                continue

            # If the instruction has a Mod R/M byte, parse it next
            if curInstruction.hasModRm:
                numModRmBytes = cls.__handleModRmByte(curInstruction, byteBuffer)
                if numModRmBytes > 0:
                    byteBuffer = byteBuffer[numModRmBytes:]

                else:
                    logger.error("Failed to process the Mod R/M byte")
                    byteBuffer = bytes(curInstruction.bytes) + byteBuffer
                    offTheRails = True
                    continue

            # Handle an immediate value if there is one and the value has not
            # already been set by the instruction info object. Use "is" instead of
            # "==" because there is an instruction that loads 0.0 into floating
            # point registers, and this prevents that instruction or others like it
            # from trying to consume bytes for an immediate.
            for operand in curInstruction.operands:

                # Handle operands that get their value from the opcode. They aren't
                # necessarily handled earlier if there isn't a Mod R/M byte, which
                # is often the case for this kind of instruction.
                # Extend the value if the instruction has a base extension prefix.
                if operand.opcodeRegVal and curInstruction.extendBase:

                        logger.debug("Extending opcode reg value")
                        operand.value |= REG_EXTEND

                if operand.isOffset or (operand.isImmediate and operand.value is 0):

                    logger.debug("Handling the extra immeidate")
                    numImmediateBytes = cls.__handleImmediate(curInstruction, operand, byteBuffer)
                    if numImmediateBytes < 0:

                        offTheRails = True
                        continue

                    byteBuffer = byteBuffer[numImmediateBytes:]

                cls.__resolveRelativeAddr(curInstruction, operand)

            instBytes = [ f"{x:02x}" for x in curInstruction.bytes ]
            logger.debug(f"{curInstruction.addr:x}: {instBytes} {curInstruction}")

            # Add the instruction and advance the address
            instructions.append(curInstruction)
            addr += len(curInstruction.bytes)

        return instructions


    @classmethod
    def __handlePrefixes( cls, instruction, byteBuffer ):
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
                        byteBuffer  - An array of bytes

        Return:         Number of bytes that are prefix bytes
        """

        numPrefixBytes = 0

        # Handle legacy prefixes
        for byte in byteBuffer:

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
                instruction.sizePrefix   = REG_SIZE_16

            # Group 4 prefixes
            elif byte == PREFIX_32_BIT_ADDRESS:
                logger.debug("Found the 32-bit address prefix")
                instruction.addressSize = 4

            # If a prefix is not found, proceed to the next step
            else:
                break

            # If the else branch is not hit, a prefix byte was found
            instruction.bytes.append(byte)
            numPrefixBytes += 1

        # Handle REX prefixes starting from wherever the legacy prefixes left off
        for byte in byteBuffer[numPrefixBytes:]:

            if byte & 0xf0 == PREFIX_REX_MASK:

                # If the prefix is just the REX prefix with no other bits set, then
                # access to the extended 8-bit registers is available.
                if byte == PREFIX_REX_MASK:
                    logger.debug("8-bit REX operand size prefix")
                    instruction.sizePrefix = REG_SIZE_8_REX

                # The base value of the register is extended
                if byte & PREFIX_REX_W_MASK == PREFIX_REX_W_MASK:
                    logger.debug("64-bit operand size prefix")
                    instruction.sizePrefix = REG_SIZE_64

                if byte & PREFIX_REX_R_MASK == PREFIX_REX_R_MASK:
                    logger.debug("Extended reg field prefix")
                    instruction.extendReg = True

                if byte & PREFIX_REX_X_MASK == PREFIX_REX_X_MASK:
                    logger.debug("Extended SIB index field prefix")
                    instruction.extendIndex = True

                if byte & PREFIX_REX_B_MASK == PREFIX_REX_B_MASK:
                    logger.debug("Extended r/m, SIB base, or opcode reg field prefix")
                    # TODO: This is not correct. The handling is much more complicated. See Intel documentation on REX prefixes
                    instruction.extendBase = True

            else:
                break

            # If the else branch is not hit, a prefix byte was found
            instruction.bytes.append(byte)
            numPrefixBytes += 1

        return numPrefixBytes


    @classmethod
    def __handleOpcode( cls, instruction, byteBuffer ):
        """
        Description:    Looks up the opcode and produces the correct instruction

        Arguments:      instruction - X86_64Instruction object that already has any
                                      options from prefix bytes set
                        byteBuffer  - Bytes starting at the opcode of an instruction

        Return:         The number of bytes consumed for the opcode. If there is no
                        valid opcode found, 0 is returned.
        """

        numOpcodeBytes = 0

        try:
            # Check for the opcode being a 2 byte opcode
            if byteBuffer[0] == PREFIX_2_BYTE_OPCODE:

                numOpcodeBytes = 2
                primaryOpcode = byteBuffer[1]
                info = twoByteOpcodes[primaryOpcode]

            else:

                numOpcodeBytes = 1
                primaryOpcode = byteBuffer[0]
                info = oneByteOpcodes[primaryOpcode]

        except NameError as e:

            # The opcode is not a valid 1 or 2 byte opcode
            raise Exception(f"An invalid opcode was found: {primaryOpcode:02x}")

        # If the info object is a dictionary, then there is more work to be done to
        # determine the secondary opcode, prefix, and extended opcode.
        if type(info) == dict:

            # There is a secondary opcode
            if len(byteBuffer) > numOpcodeBytes and byteBuffer[numOpcodeBytes] in info:

                info = info[byteBuffer[numOpcodeBytes]]
                numOpcodeBytes += 1

            # There are no secondary opcodes defined, so get the default
            elif None in info:
                info = info[None]

            # If the info object is a dictionary, then there is a prefix or
            # extended opcode. Remove the prefix value if it is actually used for
            # specifying a different instruction.
            if type(info) == dict:

                legacyPrefix = instruction.legacyPrefix
                sizePrefix   = instruction.sizePrefix
                logger.debug(f"size prefix: {sizePrefix}")

                if legacyPrefix is not None and legacyPrefix in info:
                    info = info[legacyPrefix]
                    instruction.legacyPrefix = None

                elif sizePrefix is not None and sizePrefix in info:
                    info = info[sizePrefix]
                    instruction.sizePrefix = None

                elif None in info:
                    info = info[None]

                else:
                    logger.warning(f"Failed to find the required prefix")
                    raise Exception(f"Failed to find the required prefix")

                # If the info object is a dictionary, then there is an extended
                # opcode.
                if type(info) == dict:

                    # Get the next byte, which is the Mod R/M byte to figure out the
                    # operation and, if needed, the addressing mode.
                    modRmByte = byteBuffer[numOpcodeBytes]
                    mod = modRmByte & ADDR_MOD_MASK
                    op  = (modRmByte & ADDR_REG_MASK) >> 3

                    info = info[op]

                    # One last time...
                    # If the info object is a dictionary, then there is a difference
                    # in extended opcode based on the addressing mode.
                    if type(info) == dict:

                        if mod in info:
                            info = info[mod]

                        else:
                            info = info[None]

        instruction.setAttributes(primaryOpcode, info)

        # Append the opcode bytes to the instruction's list of bytes
        instruction.bytes += list(byteBuffer[0:numOpcodeBytes])

        return numOpcodeBytes


    @classmethod
    def __handleSibByte( cls, operand, addrMode, sibByte ):
        """
        Description:    Parses the Scale Index Base (SIB) byte and determines
                        whether a displacement value will follow.

                        If the addressing mode was indirect from the Mod R/M byte
                        and the base is %ebp, then a 4 byte displacement will follow
                        the SIB byte.

        Arguments:      operand  - X86_64Operand object
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


    @classmethod
    def __handleOperandAddressing( cls, instruction, operand, byteBuffer ):
        """
        Description:    Figures out addressing mode for an operand based on the
                        Mod R/M byte. If the Mod R/M byte does not apply to the
                        operand, the value will be set to the regOrOp value if the
                        operand is not an immediate.

        Arguments:      instruction - X86_64Instruction object
                        operand     - X86_64Operand object
                        byteBuffer  - Remaining bytes to disassemble, starting with
                                      the Mod R/M byte

        Return:         Number of bytes needed for addressing, not including the
                        Mod R/M byte.
        """

        modRmByte = byteBuffer[0]
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

            # Set the segment register if one is specified
            if instruction.segmentPrefix in PREFIX_SEGMENTS:
                operand.segmentReg = instruction.segmentPrefix

            # The value is always regmem if the Mod R/M refers to this operand.
            operand.value = regmem

            # Extend the value if the instruction has a base extension prefix.
            if instruction.extendBase:
                logger.debug("Extending value")
                operand.value |= REG_EXTEND

            if mod == MOD_DIRECT:
                logger.debug("Operand is the value in a register")

                # Make the register a floating point register if the addressing mode is
                # direct. Otherwise, a normal register should be used for addressing.
                if operand.floatReg:
                    operand.value |= REG_FLOAT

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
                isSibDisplace = cls.__handleSibByte(operand, mod, byteBuffer[1])
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
                operand.displacement = int.from_bytes(byteBuffer[1+addrBytes:1+addrBytes+displaceBytes], "little", signed=True)
                logger.debug(f"Adding displacement to the operand: {operand.displacement:x}")

        # Otherwise, set the value to be the reg value from the Mod R/M byte
        elif operand.reg:
            logger.debug("Mod R/M byte is not for this operand")
            operand.value = regOrOp

            if operand.mmRegister:
                logger.debug("Extending register to use MM registers")
                operand.value |= REG_MM

        return addrBytes + displaceBytes


    @classmethod
    def __handleModRmByte( cls, instruction, byteBuffer ):
        """
        Description:    Handles the Mod R/M byte(s) of an instruction

        Arguments:      instruction - X86_64Instruction object with its info member set
                        byteBuffer  - bytes remaining to be processed for an instruction

        Return:         The number of bytes consumed when processing the Mod R/M bytes
                        If an error occurs 0 is returned
        """

        if len(byteBuffer) == 0:
            return 0

        numBytesConsumed = 1

        # Set the addressing properties for each operand
        for operand in instruction.operands:
            numBytesConsumed += cls.__handleOperandAddressing(instruction, operand, byteBuffer)

        if numBytesConsumed <= len(byteBuffer):
            instruction.bytes += list(byteBuffer[:numBytesConsumed])

        else:
            raise IndexError("There were not enough bytes to handle the Mod R/M byte")

        return numBytesConsumed


    @classmethod
    def __handleImmediate( cls, instruction, operand, byteBuffer ):
        """
        Description:    Consume all immediate bytes and convert them to an integer

        Arguments:      instruction - X86_64Instruction object
                        operand     - X86_64Operand object
                        byteBuffer  - bytes remaining to be processed for an
                                      instruction

        Return:         The number of bytes consumed when processing the immediate.
                        -1 is returned if not enough bytes remain to form the value.
        """

        # Check whether there are enough bytes for the instruction
        if len(byteBuffer) < operand.size:
            logger.error(f"There are only {len(byteBuffer)} bytes remaining, but {operand.size} are expected")
            return -1

        # Round the operand size down because there are some register sizes that use
        # decimal values to differentiate them. The actual size is always the
        # truncated value of the register size. RIP offsets are always signed.
        numBytes = int(operand.size)
        instruction.bytes += list(byteBuffer[:numBytes])
        immediate = int.from_bytes(byteBuffer[:numBytes], "little", signed=operand.isOffset)

        # If the instruction is an offset from the RIP, mark the source as
        # indirect from the RIP register so that it can be resolved once
        # processing all instruction bytes is done and the length of the
        # instruction is known.
        if operand.isOffset:
            operand.indirect = True
            operand.value = REG_RIP
            operand.displacement = immediate

        # Otherwise, the operand value is just the immediate
        else:
            operand.value = immediate

        return numBytes


    @classmethod
    def __resolveRelativeAddr( cls, instruction, operand ):
        """
        Description:    Resolves the relative memory address if there is one.

                        If the instruction is a relative address, the it is:
                        [%rip] + displacement

                        The value in the instruction pointer register is the
                        address of the next instruction, which is the address of
                        the current instruction plus the number of bytes in it.

        Arguments:      instruction - X86_64Instruction object
                        operand     - X86_64Operand object. Can also be None.

        Return:         None
        """

        if operand is not None and operand.indirect and operand.value == REG_RIP:
            logger.debug("Relative indirect memory reference")
            ripValue = instruction.addr + len(instruction.bytes)
            operand.indirect = False
            operand.isImmediate = True
            operand.value = ripValue + operand.displacement


    @classmethod
    def __normalize ( cls, instruction ):
        # TODO: Fix up the instruction to have the destination copied to the sources
        # if that applies. Otherwise, separate source and destination operands
        # because the base Instruction class only has source and destination
        # members, not one list of operands.

        return instruction


    @classmethod
    def __findFunctions( cls, instructions ):

        funcAddrsAndSizes = []

        if len(instructions) == 0:
            return []

        currentlyInFunction = True
        highestReachableAddr = instructions[0].addr
        funcStart = instructions[0].addr

        for instruction in instructions:

            # First, consider whether this instruction signals the beginning of a
            # new function. This happens when not currently in a function and an
            # instruction that is not a NOP is found.
            if not currentlyInFunction and instruction.mnemonic != "nop":

                funcStart = instruction.addr
                highestReachableAddr = instruction.addr
                currentlyInFunction = True
                logger.debug(f"found the beginning of another function: {funcStart:x}")

            # Consider it the end of a function if currently at the highest
            # reachable address and the instruction is a return or halt.
            # Also, consider a jump to an address lower than the start of the
            # current function to be the end of a function because there is no way
            # to resume execution after a jump.
            if (instruction.mnemonic in [ "ret", "repz ret", "hlt" ] and instruction.addr >= highestReachableAddr) \
                or (instruction.operands[0].isOffset and instruction.mnemonic not in [ "call" ] and instruction.operands[0].value < funcStart):

                funcAddrsAndSizes.append((funcStart, instruction.addr + len(instruction.bytes) - funcStart))
                currentlyInFunction = False
                logger.debug(f"Found end of function: {instruction}, {funcAddrsAndSizes[-1]}")

            # If a higher address is reachable by a jump, which is a relative jump
            # that is not a call, set the highest address to the jump destination.
            if instruction.operands[0].isOffset        and \
                instruction.mnemonic not in [ "call" ] and \
                instruction.operands[0].value > highestReachableAddr:

                highestReachableAddr = instruction.operands[0].value
                logger.debug(f"relative jump: {instruction}")

            # Set the highest reachable address if the current instruction is at
            # the highest address that has been processed.
            if instruction.addr > highestReachableAddr:

                highestReachableAddr = instruction.addr

        return funcAddrsAndSizes
