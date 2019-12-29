from disassemblers.x64defs import *

class X64InstructionInfo():

    def __init__( self, mnemonic, registerCode=False, direction=None,
                  modRm=MODRM_NONE, extOpcode=False, srcIsImmediate=False,
                  srcOperandSize=None, dstOperandSize=None, relativeJump=False,
                  signExtension=False, noOperands=False,
                  srcCanPromote=True, dstCanPromote=True, signExtBit=False):

        # Opcode info
        self.mnemonic      = mnemonic       # The name of the instruction
        self.registerCode  = registerCode   # Whether the least 3 significant bits of the opcode represent a register
        self.direction     = direction      # The direction to move the data if there is a register code (OP_DIR_TO_REG or OP_DIR_FROM_REG)
        self.modRm         = modRm          # How the Mod R/M byte must be handled
        self.extOpcode     = extOpcode      # Whether the opcode is extended into the ModR/M
        self.signExtBit    = signExtBit     # Whether the sign extension bit of the opcode means anything
        self.signExtension = signExtension  # Whether the sign should be extended
        self.relativeJump  = relativeJump   # Whether the instruction is a relative jump and expects an immediate to follow the opcode
        self.noOperands    = noOperands     # Whether the instruction has no operands

        # Operand info
        self.srcCanPromote  = srcCanPromote     # Whether the src operand size is allowed to be promoted to 64 bits
        self.srcOperandSize = srcOperandSize    # The default size of the src operands
        self.srcIsImmediate = srcIsImmediate    # Whether the src operand is an immediate

        self.dstCanPromote  = dstCanPromote     # Whether the dst operand size is allowed to be promoted to 64 bits
        self.dstOperandSize = dstOperandSize    # The default size of the dst operands
                                                # The dst operand cannot be an immediate, so there is no option for it

        # Set properties that are always true if the instruction is a relative jump
        if self.relativeJump:
            self.signExtension  = True
            self.srcIsImmediate = True


oneByteOpcodes = {

    0x00: X64InstructionInfo("add",   modRm=MODRM_DEST),
    0x01: X64InstructionInfo("add",   modRm=MODRM_DEST),
    0x02: X64InstructionInfo("add",   modRm=MODRM_DEST),
    0x03: X64InstructionInfo("add",   modRm=MODRM_DEST),
    0x04: X64InstructionInfo("add",   srcIsImmediate=True),
    0x05: X64InstructionInfo("add",   srcIsImmediate=True),
#   0x06: Invalid
#   0x07: Invalid
    0x08: X64InstructionInfo("or",    modRm=MODRM_DEST),
    0x09: X64InstructionInfo("or",    modRm=MODRM_DEST),
    0x0a: X64InstructionInfo("or",    modRm=MODRM_DEST),
    0x0b: X64InstructionInfo("or",    modRm=MODRM_DEST),
    0x0c: X64InstructionInfo("or",    srcIsImmediate=True),
    0x0d: X64InstructionInfo("or",    srcIsImmediate=True),
#   0x0e: Invalid
#   0x0f: 2 byte operand prefix
    0x10: X64InstructionInfo("adc",   modRm=MODRM_DEST),
    0x11: X64InstructionInfo("adc",   modRm=MODRM_DEST),
    0x12: X64InstructionInfo("adc",   modRm=MODRM_DEST),
    0x13: X64InstructionInfo("adc",   modRm=MODRM_DEST),
    0x14: X64InstructionInfo("adc",   srcIsImmediate=True),
    0x15: X64InstructionInfo("adc",   srcIsImmediate=True),
#   0x16: Invalid
#   0x17: Invalid
    0x18: X64InstructionInfo("sbb",   modRm=MODRM_DEST),
    0x19: X64InstructionInfo("sbb",   modRm=MODRM_DEST),
    0x1a: X64InstructionInfo("sbb",   modRm=MODRM_DEST),
    0x1b: X64InstructionInfo("sbb",   modRm=MODRM_DEST),
    0x1c: X64InstructionInfo("sbb",   srcIsImmediate=True),
    0x1d: X64InstructionInfo("sbb",   srcIsImmediate=True),
#   0x1e: Invalid
#   0x1f: Invalid
    0x20: X64InstructionInfo("and",   modRm=MODRM_DEST),
    0x21: X64InstructionInfo("and",   modRm=MODRM_DEST),
    0x22: X64InstructionInfo("and",   modRm=MODRM_DEST),
    0x23: X64InstructionInfo("and",   modRm=MODRM_DEST),
    0x24: X64InstructionInfo("and",   srcIsImmediate=True),
    0x25: X64InstructionInfo("and",   srcIsImmediate=True),
#   0x26: Something in 64-bit
#   0x27: Invalid
    0x28: X64InstructionInfo("sub",   modRm=MODRM_DEST),
    0x29: X64InstructionInfo("sub",   modRm=MODRM_DEST),
    0x2a: X64InstructionInfo("sub",   modRm=MODRM_DEST),
    0x2b: X64InstructionInfo("sub",   modRm=MODRM_DEST),
    0x2c: X64InstructionInfo("sub",   srcIsImmediate=True),
    0x2d: X64InstructionInfo("sub",   srcIsImmediate=True),
#   0x2e: Something in 64-bit
#   0x2f: Invalid
    0x30: X64InstructionInfo("xor",   modRm=MODRM_DEST),
    0x31: X64InstructionInfo("xor",   modRm=MODRM_DEST),
    0x32: X64InstructionInfo("xor",   modRm=MODRM_DEST),
    0x33: X64InstructionInfo("xor",   modRm=MODRM_DEST),
    0x34: X64InstructionInfo("xor",   srcIsImmediate=True),
    0x35: X64InstructionInfo("xor",   srcIsImmediate=True),
#   0x36: Something in 64-bit
#   0x37: Invalid
    0x38: X64InstructionInfo("cmp",   modRm=MODRM_DEST),
    0x39: X64InstructionInfo("cmp",   modRm=MODRM_DEST),
    0x3a: X64InstructionInfo("cmp",   modRm=MODRM_DEST),
    0x3b: X64InstructionInfo("cmp",   modRm=MODRM_DEST),
    0x3c: X64InstructionInfo("cmp",   srcIsImmediate=True),
    0x3d: X64InstructionInfo("cmp",   srcIsImmediate=True),
#   0x3e: Something in 64-bit
#   0x3f: Invalid

    0x50: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x51: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x52: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x53: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x54: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x55: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x56: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x57: X64InstructionInfo("push",  registerCode=True, direction=OP_DIR_FROM_REG, srcOperandSize=REG_SIZE_64),
    0x58: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64),
    0x59: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64),
    0x5a: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64),
    0x5b: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64),
    0x5c: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64),
    0x5d: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64),
    0x5e: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64),
    0x5f: X64InstructionInfo("pop",   registerCode=True, direction=OP_DIR_TO_REG,   dstOperandSize=REG_SIZE_64),
#   0x60: Invalid
#   0x61: Invalid
#   0x62: Invalid

    0x70: X64InstructionInfo("jo",    relativeJump=True, srcOperandSize=REG_SIZE_8), # Overflow
    0x71: X64InstructionInfo("jno",   relativeJump=True, srcOperandSize=REG_SIZE_8), # Not overflow
    0x72: X64InstructionInfo("jb",    relativeJump=True, srcOperandSize=REG_SIZE_8), # Less than or equal (unsigned)
    0x73: X64InstructionInfo("jae",   relativeJump=True, srcOperandSize=REG_SIZE_8), # Greater than or equal (unsigned)
    0x74: X64InstructionInfo("jz",    relativeJump=True, srcOperandSize=REG_SIZE_8), # Zero
    0x75: X64InstructionInfo("jnz",   relativeJump=True, srcOperandSize=REG_SIZE_8), # Not zero
    0x76: X64InstructionInfo("jbe",   relativeJump=True, srcOperandSize=REG_SIZE_8), # Less than or equal (unsigned)
    0x77: X64InstructionInfo("ja",    relativeJump=True, srcOperandSize=REG_SIZE_8), # Greater than (unsigned)
    0x78: X64InstructionInfo("js",    relativeJump=True, srcOperandSize=REG_SIZE_8), # Signed
    0x79: X64InstructionInfo("jns",   relativeJump=True, srcOperandSize=REG_SIZE_8), # Unsigned
    0x7a: X64InstructionInfo("jp",    relativeJump=True, srcOperandSize=REG_SIZE_8), # Parity
    0x7b: X64InstructionInfo("jnp",   relativeJump=True, srcOperandSize=REG_SIZE_8), # Not parity
    0x7c: X64InstructionInfo("jlt",   relativeJump=True, srcOperandSize=REG_SIZE_8), # Less than (signed)
    0x7d: X64InstructionInfo("jge",   relativeJump=True, srcOperandSize=REG_SIZE_8), # Greater than or equal (signed)
    0x7e: X64InstructionInfo("jle",   relativeJump=True, srcOperandSize=REG_SIZE_8), # Less than or equal (signed)
    0x7f: X64InstructionInfo("jgt",   relativeJump=True, srcOperandSize=REG_SIZE_8), # Greater than (signed)
    0x80: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, srcIsImmediate=True),
    0x81: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, srcIsImmediate=True),
#   0x82: Invalid
    0x83: X64InstructionInfo("",      modRm=MODRM_DEST, extOpcode=True, srcIsImmediate=True, srcOperandSize=REG_SIZE_8),

    0x88: X64InstructionInfo("mov",   modRm=MODRM_DEST),
    0x89: X64InstructionInfo("mov",   modRm=MODRM_DEST),
    0x8a: X64InstructionInfo("mov",   modRm=MODRM_SOURCE),
    0x8b: X64InstructionInfo("mov",   modRm=MODRM_SOURCE),

    0x8d: X64InstructionInfo("lea",   modRm=MODRM_SOURCE),

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
    0xc3: X64InstructionInfo("ret",   noOperands=True),

    0xc6: X64InstructionInfo("mov",   modRm=MODRM_DEST, srcIsImmediate=True, signExtension=True),
    0xc7: X64InstructionInfo("mov",   modRm=MODRM_DEST, srcIsImmediate=True, signExtension=True),

    0xc9: X64InstructionInfo("leave", noOperands=True),

    0xe8: X64InstructionInfo("call",  relativeJump=True, srcOperandSize=REG_SIZE_32),

    0xeb: X64InstructionInfo("jmp",   relativeJump=True, signExtension=True, srcOperandSize=REG_SIZE_8),
}

twoByteOpcodes = {
    0x9f: X64InstructionInfo("setg",  modRm=MODRM_DEST, dstOperandSize=REG_SIZE_8),    # Greater than
    0xbe: X64InstructionInfo("movsx", modRm=MODRM_SOURCE, signExtension=True, srcOperandSize=REG_SIZE_8,  dstOperandSize=REG_SIZE_32),
    0xbf: X64InstructionInfo("movsx", modRm=MODRM_SOURCE, signExtension=True, srcOperandSize=REG_SIZE_16, dstOperandSize=REG_SIZE_32),
}
