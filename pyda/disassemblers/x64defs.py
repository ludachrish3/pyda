
PREFIX_64_BIT_OPERAND = 0x48
PREFIX_16_BIT_OPERAND = 0x66
PREFIX_32_BIT_ADDRESS = 0x67
PREFIX_2_BYTE_OPCODE  = 0x0f

# Opcode masks
OP_SIZE_MASK = 0b00000001
OP_DIR_MASK  = 0b00000010

OP_DIR_FROM_REG = 0b00000000
OP_DIR_TO_REG   = 0b00000001

# R/M MOD byte masks
ADDR_MOD_MASK = 0b11000000
ADDR_REG_MASK = 0b00111000
ADDR_RM_MASK  = 0b00000111

MOD_INDIRECT    = 0b00000000
MOD_1_BYTE_DISP = 0b01000000
MOD_4_BYTE_DISP = 0b10000000
MOD_REGISTER    = 0b11000000

REG_MASK = 0b00000111
REG_RAX  = 0b00000000
REG_RCX  = 0b00000001
REG_RDX  = 0b00000010
REG_RBX  = 0b00000011
REG_RSP  = 0b00000100
REG_RBP  = 0b00000101
REG_RSI  = 0b00000110
REG_RDI  = 0b00000111

REG_SIZE_64 = 8
REG_SIZE_32 = 4
REG_SIZE_16 = 2
REG_SIZE_8  = 1

REG_NAME_UNDEF = "UNDEF REG"

# For the most part this is straight forward for the A, C, D, and B registers,
# but for RSP, RBP, RSI, and RDI, things are a bit different. Their 8 bit
# values actually correspond to the higher 8 bit values for the corresponding
# A, C, D, and B registers. They do not have 8 bit registers of their own.
REG_NAMES = {
    REG_RAX: {
        REG_SIZE_64: "rax",
        REG_SIZE_32: "eax",
        REG_SIZE_16: "ax",
        REG_SIZE_8:  "al",
    },
    REG_RCX: {
        REG_SIZE_64: "rcx",
        REG_SIZE_32: "ecx",
        REG_SIZE_16: "cx",
        REG_SIZE_8:  "cl",
    },
    REG_RDX: {
        REG_SIZE_64: "rdx",
        REG_SIZE_32: "edx",
        REG_SIZE_16: "dx",
        REG_SIZE_8:  "dl",
    },
    REG_RBX: {
        REG_SIZE_64: "rbx",
        REG_SIZE_32: "ebx",
        REG_SIZE_16: "bx",
        REG_SIZE_8:  "bl",
    },
    REG_RSP:{
        REG_SIZE_64: "rsp",
        REG_SIZE_32: "esp",
        REG_SIZE_16: "sp",
        REG_SIZE_8:  "ah",
    },
    REG_RBP: {
        REG_SIZE_64: "rbp",
        REG_SIZE_32: "ebp",
        REG_SIZE_16: "bp",
        REG_SIZE_8:  "ch",
    },
    REG_RSI: {
        REG_SIZE_64: "rsi",
        REG_SIZE_32: "esi",
        REG_SIZE_16: "si",
        REG_SIZE_8:  "dh",
    },
    REG_RDI: {
        REG_SIZE_64: "rdi",
        REG_SIZE_32: "edi",
        REG_SIZE_16: "di",
        REG_SIZE_8:  "bh",
    },
}
