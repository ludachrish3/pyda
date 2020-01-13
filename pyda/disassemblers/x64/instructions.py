from pyda.disassemblers.x64.definitions import *

class X64InstructionInfo():

    def __init__( self, mnemonic, registerCode=False, direction=None,
                  modRm=MODRM_NONE, extOpcode=False, srcIsImmediate=False,
                  srcOperandSize=None, dstOperandSize=None, relativeJump=False,
                  signExtension=False, isFlagsReg=False, isConversion=False,
                  srcMaxSize=REG_SIZE_64, dstMaxSize=REG_SIZE_64, signExtBit=False):

        # Opcode info
        self.mnemonic      = mnemonic       # The name of the instruction
        self.registerCode  = registerCode   # Whether the least 3 significant bits of the opcode represent a register
        self.direction     = direction      # The direction to move the data if there is a register code (OP_DIR_TO_REG or OP_DIR_FROM_REG)
        self.modRm         = modRm          # How the Mod R/M byte must be handled
        self.extOpcode     = extOpcode      # Whether the opcode is extended into the ModR/M
        self.signExtBit    = signExtBit     # Whether the sign extension bit of the opcode means anything
        self.signExtension = signExtension  # Whether the sign should be extended
        self.isFlagsReg    = isFlagsReg     # Whether the value of the register if the flags register
        self.isConversion  = isConversion   # Whether the instruction is size conversion
        self.relativeJump  = relativeJump   # Whether the instruction is a relative jump and expects an immediate to follow the opcode

        # Operand info
        self.srcOperandSize = srcOperandSize    # The default size of the src operands
        self.srcIsImmediate = srcIsImmediate    # Whether the src operand is an immediate
        self.dstOperandSize = dstOperandSize    # The default size of the dst operands
                                                # The dst operand cannot be an immediate, so there is no option for it

        # Set properties that are always true if the instruction is a relative jump
        if self.relativeJump:
            self.signExtension  = True
            self.srcIsImmediate = True

        # Assume that the maximum size of the operand is 8 bits if the size is
        # 8 bits because they cannot be promoted.
        if srcOperandSize == REG_SIZE_8:
            self.srcMaxSize = REG_SIZE_8

        else:
            self.srcMaxSize = srcMaxSize

        if dstOperandSize == REG_SIZE_8:
            self.dstMaxSize = REG_SIZE_8

        else:
            self.dstMaxSize = dstMaxSize

oneByteOpcodes = {

    0x00: X64InstructionInfo("add",   modRm=MODRM_DEST),
    0x01: X64InstructionInfo("add",   modRm=MODRM_DEST),
    0x02: X64InstructionInfo("add",   modRm=MODRM_SOURCE),
    0x03: X64InstructionInfo("add",   modRm=MODRM_SOURCE),
    0x04: X64InstructionInfo("add",   srcIsImmediate=True),
    0x05: X64InstructionInfo("add",   srcIsImmediate=True, signExtension=True, srcMaxSize=REG_SIZE_32),
#   0x06: Invalid
#   0x07: Invalid
    0x08: X64InstructionInfo("or",    modRm=MODRM_DEST),
    0x09: X64InstructionInfo("or",    modRm=MODRM_DEST),
    0x0a: X64InstructionInfo("or",    modRm=MODRM_SOURCE),
    0x0b: X64InstructionInfo("or",    modRm=MODRM_SOURCE),
    0x0c: X64InstructionInfo("or",    srcIsImmediate=True),
    0x0d: X64InstructionInfo("or",    srcIsImmediate=True, signExtension=True, srcMaxSize=REG_SIZE_32),
#   0x0e: Invalid
#   0x0f: 2 byte operand prefix
    0x10: X64InstructionInfo("adc",   modRm=MODRM_DEST),
    0x11: X64InstructionInfo("adc",   modRm=MODRM_DEST),
    0x12: X64InstructionInfo("adc",   modRm=MODRM_SOURCE),
    0x13: X64InstructionInfo("adc",   modRm=MODRM_SOURCE),
    0x14: X64InstructionInfo("adc",   srcIsImmediate=True),
    0x15: X64InstructionInfo("adc",   srcIsImmediate=True, signExtension=True, srcMaxSize=REG_SIZE_32),
#   0x16: Invalid
#   0x17: Invalid
    0x18: X64InstructionInfo("sbb",   modRm=MODRM_DEST),
    0x19: X64InstructionInfo("sbb",   modRm=MODRM_DEST),
    0x1a: X64InstructionInfo("sbb",   modRm=MODRM_SOURCE),
    0x1b: X64InstructionInfo("sbb",   modRm=MODRM_SOURCE),
    0x1c: X64InstructionInfo("sbb",   srcIsImmediate=True),
    0x1d: X64InstructionInfo("sbb",   srcIsImmediate=True, signExtension=True, srcMaxSize=REG_SIZE_32),
#   0x1e: Invalid
#   0x1f: Invalid
    0x20: X64InstructionInfo("and",   modRm=MODRM_DEST),
    0x21: X64InstructionInfo("and",   modRm=MODRM_DEST),
    0x22: X64InstructionInfo("and",   modRm=MODRM_SOURCE),
    0x23: X64InstructionInfo("and",   modRm=MODRM_SOURCE),
    0x24: X64InstructionInfo("and",   srcIsImmediate=True),
    0x25: X64InstructionInfo("and",   srcIsImmediate=True, signExtension=True, srcMaxSize=REG_SIZE_32),
#   0x26: ES Segment Register Prefix
#   0x27: Invalid
    0x28: X64InstructionInfo("sub",   modRm=MODRM_DEST),
    0x29: X64InstructionInfo("sub",   modRm=MODRM_DEST),
    0x2a: X64InstructionInfo("sub",   modRm=MODRM_SOURCE),
    0x2b: X64InstructionInfo("sub",   modRm=MODRM_SOURCE),
    0x2c: X64InstructionInfo("sub",   srcIsImmediate=True),
    0x2d: X64InstructionInfo("sub",   srcIsImmediate=True, signExtension=True, srcMaxSize=REG_SIZE_32),
#   0x2e: CS Segment Register Prefix
#   0x2f: Invalid
    0x30: X64InstructionInfo("xor",   modRm=MODRM_DEST),
    0x31: X64InstructionInfo("xor",   modRm=MODRM_DEST),
    0x32: X64InstructionInfo("xor",   modRm=MODRM_SOURCE),
    0x33: X64InstructionInfo("xor",   modRm=MODRM_SOURCE),
    0x34: X64InstructionInfo("xor",   srcIsImmediate=True),
    0x35: X64InstructionInfo("xor",   srcIsImmediate=True, signExtension=True, srcMaxSize=REG_SIZE_32),
#   0x36: SS Segment Register Prefix
#   0x37: Invalid
    0x38: X64InstructionInfo("cmp",   modRm=MODRM_DEST),
    0x39: X64InstructionInfo("cmp",   modRm=MODRM_DEST),
    0x3a: X64InstructionInfo("cmp",   modRm=MODRM_SOURCE),
    0x3b: X64InstructionInfo("cmp",   modRm=MODRM_SOURCE),
    0x3c: X64InstructionInfo("cmp",   srcIsImmediate=True),
    0x3d: X64InstructionInfo("cmp",   srcIsImmediate=True, signExtension=True, srcMaxSize=REG_SIZE_32),
#   0x3e: DS Segment Register Prefix
#   0x3f: Invalid
#   0x40: REX Prefix (does nothing)
#   0x41: REX.B Prefix
#   0x42: REX.X Prefix
#   0x43: REX.XB Prefix
#   0x44: REX.R Prefix
#   0x45: REX.RB Prefix
#   0x46: REX.RX Prefix
#   0x47: REX.RXB Prefix
#   0x48: REX.W Prefix (64-bit operand size prefix)
#   0x49: REX.WB Prefix
#   0x4a: REX.WX Prefix
#   0x4b: REX.WXB Prefix
#   0x4c: REX.WR Prefix
#   0x4d: REX.WRB Prefix
#   0x4e: REX.WRX Prefix
#   0x4f: REX.WRXB Prefix
    0x50: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64, dstOperandSize=REG_SIZE_0),
    0x51: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64, dstOperandSize=REG_SIZE_0),
    0x52: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64, dstOperandSize=REG_SIZE_0),
    0x53: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64, dstOperandSize=REG_SIZE_0),
    0x54: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64, dstOperandSize=REG_SIZE_0),
    0x55: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64, dstOperandSize=REG_SIZE_0),
    0x56: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64, dstOperandSize=REG_SIZE_0),
    0x57: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64, dstOperandSize=REG_SIZE_0),
    0x59: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64, srcOperandSize=REG_SIZE_0),
    0x5a: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64, srcOperandSize=REG_SIZE_0),
    0x5b: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64, srcOperandSize=REG_SIZE_0),
    0x5c: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64, srcOperandSize=REG_SIZE_0),
    0x5d: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64, srcOperandSize=REG_SIZE_0),
    0x5e: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64, srcOperandSize=REG_SIZE_0),
    0x5f: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64, srcOperandSize=REG_SIZE_0),
    0x58: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64, srcOperandSize=REG_SIZE_0),
#   0x60: Invalid
#   0x61: Invalid
#   0x62: Invalid
    0x63: X64InstructionInfo("movsxd", modRm=MODRM_SOURCE, signExtension=True, srcOperandSize=REG_SIZE_16, dstOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_16),
#   0x64: FS Segment Register Prefix
#   0x65: GS Segment Register Prefix
#   0x66: 16-bit Operand Size Prefix
#   0x67: TODO: 32-bit Address Size Prefix
    0x68: X64InstructionInfo("push",  srcIsImmediate=True, signExtension=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_0),
    0x69: X64InstructionInfo("imul",  modRm=MODRM_SOURCE, srcIsImmediate=True, signExtension=True, srcOperandSize=REG_SIZE_32),    # TODO: Figure out a way to handle an instruction with multiple sources
    0x6a: X64InstructionInfo("push",  srcIsImmediate=True, signExtension=True, srcOperandSize=REG_SIZE_8, dstOperandSize=REG_SIZE_0),
    0x6b: X64InstructionInfo("imul",  modRm=MODRM_SOURCE, srcIsImmediate=True, signExtension=True, srcOperandSize=REG_SIZE_8),
#   0x6c: Debug input port to string
#   0x6d: Debug input port to string
#   0x6e: Debug output string to port
#   0x6f: Debug output string to port
    0x70: X64InstructionInfo("jo",    relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Overflow
    0x71: X64InstructionInfo("jno",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Not overflow
    0x72: X64InstructionInfo("jb",    relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Less than (unsigned)
    0x73: X64InstructionInfo("jae",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Greater than or equal (unsigned)
    0x74: X64InstructionInfo("je",    relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Equal
    0x75: X64InstructionInfo("jne",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Not equal
    0x76: X64InstructionInfo("jbe",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Less than or equal (unsigned)
    0x77: X64InstructionInfo("ja",    relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Greater than (unsigned)
    0x78: X64InstructionInfo("js",    relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Signed
    0x79: X64InstructionInfo("jns",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Unsigned
    0x7a: X64InstructionInfo("jp",    relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Parity
    0x7b: X64InstructionInfo("jnp",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Not parity
    0x7c: X64InstructionInfo("jlt",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Less than (signed)
    0x7d: X64InstructionInfo("jge",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Greater than or equal (signed)
    0x7e: X64InstructionInfo("jle",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Less than or equal (signed)
    0x7f: X64InstructionInfo("jgt",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8), # Greater than (signed)
    0x80: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, srcIsImmediate=True),
    0x81: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, srcIsImmediate=True, signExtension=True, srcMaxSize=REG_SIZE_32),
#   0x82: Invalid
    0x83: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_8),
    0x84: X64InstructionInfo("test",  modRm=MODRM_DEST),
    0x85: X64InstructionInfo("test",  modRm=MODRM_DEST),
    0x86: X64InstructionInfo("xchg",  modRm=MODRM_SOURCE),
    0x87: X64InstructionInfo("xchg",  modRm=MODRM_SOURCE),
    0x88: X64InstructionInfo("mov",   modRm=MODRM_DEST),
    0x89: X64InstructionInfo("mov",   modRm=MODRM_DEST),
    0x8a: X64InstructionInfo("mov",   modRm=MODRM_SOURCE),
    0x8b: X64InstructionInfo("mov",   modRm=MODRM_SOURCE),
#   0x8c: TODO: X64InstructionInfo("mov",   modRm=MODRM_SOURCE), A lot is strange about this instruction. It refers to a segment register in the Mod R/M byte or a memory location that is always a word long
    0x8d: X64InstructionInfo("lea",   modRm=MODRM_SOURCE),
#   0x8e: TODO: X64InstructionInfo("mov",   modRm=MODRM_SOURCE), A lot is strange about this instruction. It refers to a segment register in the Mod R/M byte
    0x8f: X64InstructionInfo("pop",   modRm=MODRM_DEST, extOpcode=True, dstOperandSize=REG_SIZE_64, srcOperandSize=REG_SIZE_0),
    0x90: X64InstructionInfo("nop"), # This is a special case of exchange instructions that would swap EAX with EAX
    0x91: X64InstructionInfo("xchg",  registerCode=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0x92: X64InstructionInfo("xchg",  registerCode=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0x93: X64InstructionInfo("xchg",  registerCode=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0x94: X64InstructionInfo("xchg",  registerCode=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0x95: X64InstructionInfo("xchg",  registerCode=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0x96: X64InstructionInfo("xchg",  registerCode=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0x97: X64InstructionInfo("xchg",  registerCode=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0x98: X64InstructionInfo("",      isConversion=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0x99: X64InstructionInfo("",      isConversion=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
#   0x9a: Invalid
    0x9b: X64InstructionInfo("fwait", srcOperandSize=REG_SIZE_0,  dstOperandSize=REG_SIZE_0),
    0x9c: X64InstructionInfo("pushf", isFlagsReg=True, srcOperandSize=REG_SIZE_64, dstOperandSize=REG_SIZE_0),
    0x9d: X64InstructionInfo("popf",  isFlagsReg=True, dstOperandSize=REG_SIZE_64, srcOperandSize=REG_SIZE_0),
    0x9e: X64InstructionInfo("sahf",  srcOperandSize=REG_SIZE_16, dstOperandSize=REG_SIZE_16, srcMaxSize=REG_SIZE_16, dstMaxSize=REG_SIZE_16),
    0x9f: X64InstructionInfo("sahf",  srcOperandSize=REG_SIZE_16, dstOperandSize=REG_SIZE_16, srcMaxSize=REG_SIZE_16, dstMaxSize=REG_SIZE_16),
#   0xa0: X64InstructionInfo("mov",   srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_8), TODO: Requires a segment register prefix
#   0xa1: X64InstructionInfo("mov",   srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), TODO: Requires a segment register prefix
#   0xa2: X64InstructionInfo("mov",   srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_8), TODO: Requires a segment register prefix
#   0xa3: X64InstructionInfo("mov",   srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), TODO: Requires a segment register prefix
#   0xa4: X64InstructionInfo("mov",   srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), TODO: Requires a segment register prefix
    0xa8: X64InstructionInfo("test",  srcIsImmediate=True, srcOperandSize=REG_SIZE_8, dstOperandSize=REG_SIZE_8),
    0xa9: X64InstructionInfo("test",  srcIsImmediate=True, signExtension=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32),
#   TODO: String operations
#   0xaa:
#   0xab:
#   0xac:
#   0xad:
#   0xae:
#   0xaf:
    0xb0: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_8),
    0xb1: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_8),
    0xb2: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_8),
    0xb3: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_8),
    0xb4: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_8),
    0xb5: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_8),
    0xb6: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_8),
    0xb7: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_8),
    0xb8: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0xb9: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0xba: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0xbb: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0xbc: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0xbd: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0xbe: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0xbf: X64InstructionInfo("mov",   registerCode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32),
    0xc0: X64InstructionInfo("",      modRm=MODRM_DEST,  extOpcode=True, srcIsImmediate=True),
    0xc1: X64InstructionInfo("",      modRm=MODRM_DEST,  extOpcode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_8),
    0xc2: X64InstructionInfo("ret",   relativeJump=True, srcOperandSize=REG_SIZE_16),
    0xc3: X64InstructionInfo("ret",   srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_0),
#   0xc4: Invalid
#   0xc5: Invalid
    0xc6: X64InstructionInfo("mov",   modRm=MODRM_DEST, srcIsImmediate=True, signExtension=True),
    0xc7: X64InstructionInfo("mov",   modRm=MODRM_DEST, srcIsImmediate=True, signExtension=True, srcMaxSize=REG_SIZE_32),
#   0xc8: TODO: Enter, which has 2 sources and 1 destination
    0xc9: X64InstructionInfo("leave", srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_0),

#   0xd4: Invalid
#   0xd5: Invalid
#   0xd6: Invalid

    0xe8: X64InstructionInfo("call",  relativeJump=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32),
    0xe9: X64InstructionInfo("jmp",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32),
#   0xea: Invalid
    0xeb: X64InstructionInfo("jmp",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8),

    0xfe: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),
    0xff: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True),
}

twoByteOpcodes = {
    0x1f: X64InstructionInfo("nop",   modRm=MODRM_SOURCE),

    0x40: X64InstructionInfo("cmovo",  modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Overflow
    0x41: X64InstructionInfo("cmovno", modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Not overflow
    0x42: X64InstructionInfo("cmovb",  modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Less than (unsigned)
    0x43: X64InstructionInfo("cmovae", modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Greater than or equal (unsigned)
    0x44: X64InstructionInfo("cmove",  modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Equal
    0x45: X64InstructionInfo("cmovne", modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Not equal
    0x46: X64InstructionInfo("cmovbe", modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Less than or equal (unsigned)
    0x47: X64InstructionInfo("cmova",  modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Greater than (unsigned)
    0x48: X64InstructionInfo("cmovs",  modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Signed
    0x49: X64InstructionInfo("cmovns", modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Unsigned
    0x4a: X64InstructionInfo("cmovp",  modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Parity
    0x4b: X64InstructionInfo("cmovnp", modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Not parity
    0x4c: X64InstructionInfo("cmovlt", modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Less than (signed)
    0x4d: X64InstructionInfo("cmovge", modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Greater than or equal (signed)
    0x4e: X64InstructionInfo("cmovle", modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Less than or equal (signed)
    0x4f: X64InstructionInfo("cmovgt", modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_32, dstOperandSize=REG_SIZE_32), # Greater than (signed)

    0x80: X64InstructionInfo("jo",    relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Overflow
    0x81: X64InstructionInfo("jno",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Not overflow
    0x82: X64InstructionInfo("jb",    relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Less than (unsigned)
    0x83: X64InstructionInfo("jae",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Greater than or equal (unsigned)
    0x84: X64InstructionInfo("je",    relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Equal
    0x85: X64InstructionInfo("jne",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Not equal
    0x86: X64InstructionInfo("jbe",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Less than or equal (unsigned)
    0x87: X64InstructionInfo("ja",    relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Greater than (unsigned)
    0x88: X64InstructionInfo("js",    relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Signed
    0x89: X64InstructionInfo("jns",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Unsigned
    0x8a: X64InstructionInfo("jp",    relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Parity
    0x8b: X64InstructionInfo("jnp",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Not parity
    0x8c: X64InstructionInfo("jlt",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Less than (signed)
    0x8d: X64InstructionInfo("jge",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Greater than or equal (signed)
    0x8e: X64InstructionInfo("jle",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Less than or equal (signed)
    0x8f: X64InstructionInfo("jgt",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_32, srcMaxSize=REG_SIZE_32), # Greater than (signed)

    0x90: X64InstructionInfo("seto",  modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Overflow
    0x91: X64InstructionInfo("setno", modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Not Overflow
    0x92: X64InstructionInfo("setb",  modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Less than (unsigned)
    0x93: X64InstructionInfo("setae", modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Greater than or equal (unsigned)
    0x94: X64InstructionInfo("sete",  modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Equal
    0x95: X64InstructionInfo("setne", modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Not equal
    0x96: X64InstructionInfo("setbe", modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Less than or equal (unsigned)
    0x97: X64InstructionInfo("seta",  modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Greater than (unsigned)
    0x98: X64InstructionInfo("sets",  modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Signed
    0x99: X64InstructionInfo("setns", modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Not signed
    0x9a: X64InstructionInfo("setp",  modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Parity
    0x9b: X64InstructionInfo("setnp", modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Not parity
    0x9c: X64InstructionInfo("setl",  modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Less than (signed)
    0x9d: X64InstructionInfo("setge", modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Greater than or equal (signed)
    0x9e: X64InstructionInfo("setle", modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Less than or equal (signed)
    0x9f: X64InstructionInfo("setg",  modRm=MODRM_DEST, srcOperandSize=REG_SIZE_0, dstOperandSize=REG_SIZE_8),    # Greater than (signed)

    0xb6: X64InstructionInfo("movzx", modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_32),
    0xb7: X64InstructionInfo("movzx", modRm=MODRM_SOURCE, srcOperandSize=REG_SIZE_16, srcMaxSize=REG_SIZE_16, dstOperandSize=REG_SIZE_32),
    0xbe: X64InstructionInfo("movsx", modRm=MODRM_SOURCE, signExtension=True,  srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_32),
    0xbf: X64InstructionInfo("movsx", modRm=MODRM_SOURCE, signExtension=True,  srcOperandSize=REG_SIZE_16, srcMaxSize=REG_SIZE_16, dstOperandSize=REG_SIZE_32),

}
