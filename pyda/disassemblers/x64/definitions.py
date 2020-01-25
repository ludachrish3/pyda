
PREFIX_64_BIT_OPERAND = 0x48
PREFIX_16_BIT_OPERAND = 0x66
PREFIX_32_BIT_ADDRESS = 0x67
PREFIX_2_BYTE_OPCODE  = 0x0f
PREFIX_LOCK           = 0xf0
PREFIX_REPEAT_NZERO   = 0xf2
PREFIX_REPEAT_ZERO    = 0xf3

CONVERT_TO_RAX = 0x98
CONVERT_TO_RDX = 0x99

SEGMENT_REG_ES = 0x26
SEGMENT_REG_CS = 0x2e
SEGMENT_REG_SS = 0x36
SEGMENT_REG_DS = 0x3e
SEGMENT_REG_FS = 0x64
SEGMENT_REG_GS = 0x65

PREFIX_SEGMENTS = [
    SEGMENT_REG_ES,
    SEGMENT_REG_CS,
    SEGMENT_REG_SS,
    SEGMENT_REG_DS,
    SEGMENT_REG_FS,
    SEGMENT_REG_GS,
]

SEGMENT_REG_NAMES = {
    SEGMENT_REG_ES: "%es",
    SEGMENT_REG_CS: "%cs",
    SEGMENT_REG_SS: "%ss",
    SEGMENT_REG_DS: "%ds",
    SEGMENT_REG_FS: "%fs",
    SEGMENT_REG_GS: "%gs",
}

PREFIX_REX_MASK       = 0x40 # All REX prefixes start with 0x4
PREFIX_REX_B_MASK     = 0b00000001
PREFIX_REX_X_MASK     = 0b00000010
PREFIX_REX_R_MASK     = 0b00000100
PREFIX_REX_W_MASK     = 0b00001000

# Opcode masks
OP_SIZE_MASK = 0b00000001
OP_DIR_MASK  = 0b00000010
OP_SIGN_MASK = 0b00000100

OP_DIR_FROM_REG = 0b00000000
OP_DIR_TO_REG   = 0b00000001

# SIB byte masks
SIB_SCALE_MASK = 0b11000000
SIB_INDEX_MASK = 0b00111000
SIB_BASE_MASK  = 0b00000111

# R/M MOD byte masks
ADDR_MOD_MASK = 0b11000000
ADDR_REG_MASK = 0b00111000
ADDR_RM_MASK  = 0b00000111

MODRM_NONE      = 0     # There is no Mod R/M byte
MODRM_SRC       = 1     # Mod R/M byte is applied to the source operand
MODRM_DST       = 2     # Mod R/M byte is applied to the dest operand

MOD_INDIRECT    = 0b00000000
MOD_1_BYTE_DISP = 0b01000000
MOD_4_BYTE_DISP = 0b10000000
MOD_DIRECT      = 0b11000000

REG_MASK = 0b00000111
REG_RAX  = 0b00000000
REG_RCX  = 0b00000001
REG_RDX  = 0b00000010
REG_RBX  = 0b00000011
REG_RSP  = 0b00000100
REG_RBP  = 0b00000101
REG_RSI  = 0b00000110
REG_RDI  = 0b00000111

REG_R8   = 0b00001000
REG_R9   = 0b00001001
REG_R10  = 0b00001010
REG_R11  = 0b00001011
REG_R12  = 0b00001100
REG_R13  = 0b00001101
REG_R14  = 0b00001110
REG_R15  = 0b00001111

REG_MM0  = 0b00010000
REG_MM1  = 0b00010001
REG_MM2  = 0b00010010
REG_MM3  = 0b00010011
REG_MM4  = 0b00010100
REG_MM5  = 0b00010101
REG_MM6  = 0b00010110
REG_MM7  = 0b00010111

REG_ST0  = 0b00100000
REG_ST1  = 0b00100001
REG_ST2  = 0b00100010
REG_ST3  = 0b00100011
REG_ST4  = 0b00100100
REG_ST5  = 0b00100101
REG_ST6  = 0b00100110
REG_ST7  = 0b00100111

REG_EXTEND = 0b00001000   # Extension value when extending a register from its base
REG_MM     = 0b00010000   # Extension value when extending a register to use MM registers
REG_FLOAT  = 0b00100000   # Extension value when extending a register to use floating point registers

# Unofficial values for registers that can be used to identify them.
# They will all start with a 1 at the most significant bit to differentiate
# them from the standard, official registers.
REG_RIP              = 0b10000000
REG_RFLAGS           = 0b10000001
REG_RDX_RAX_COMBINED = 0b10000010
REG_FPENV            = 0b10000011

REG_SIZE_128   = 16
REG_SIZE_80    = 10
REG_SIZE_64    = 8
REG_SIZE_32    = 4
REG_SIZE_16    = 2
REG_SIZE_8     = 1
REG_SIZE_8_REX = 1.5
REG_SIZE_0     = 0 # Used for indicating an operand does not exist

REG_NAME_UNDEF = "UNDEF REG"

# For the most part this is straight forward for the A, C, D, and B registers,
# but for RSP, RBP, RSI, and RDI, things are a bit different. Their 8 bit
# values actually correspond to the higher 8 bit values for the corresponding
# A, C, D, and B registers. They do not have 8 bit registers of their own.
REG_NAMES = {
    REG_RAX: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%rax",
        REG_SIZE_32:    "%eax",
        REG_SIZE_16:    "%ax",
        REG_SIZE_8:     "%al",
        REG_SIZE_8_REX: "%al",
    },
    REG_RCX: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%rcx",
        REG_SIZE_32:    "%ecx",
        REG_SIZE_16:    "%cx",
        REG_SIZE_8:     "%cl",
        REG_SIZE_8_REX: "%cl",
    },
    REG_RDX: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%rdx",
        REG_SIZE_32:    "%edx",
        REG_SIZE_16:    "%dx",
        REG_SIZE_8:     "%dl",
        REG_SIZE_8_REX: "%dl",
    },
    REG_RBX: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%rbx",
        REG_SIZE_32:    "%ebx",
        REG_SIZE_16:    "%bx",
        REG_SIZE_8:     "%bl",
        REG_SIZE_8_REX: "%bl",
    },
    REG_RSP:{
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%rsp",
        REG_SIZE_32:    "%esp",
        REG_SIZE_16:    "%sp",
        REG_SIZE_8:     "%ah",
        REG_SIZE_8_REX: "%spl",
    },
    REG_RBP: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%rbp",
        REG_SIZE_32:    "%ebp",
        REG_SIZE_16:    "%bp",
        REG_SIZE_8:     "%ch",
        REG_SIZE_8_REX: "%bpl",
    },
    REG_RSI: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%rsi",
        REG_SIZE_32:    "%esi",
        REG_SIZE_16:    "%si",
        REG_SIZE_8:     "%dh",
        REG_SIZE_8_REX: "%sil",
    },
    REG_RDI: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%rdi",
        REG_SIZE_32:    "%edi",
        REG_SIZE_16:    "%di",
        REG_SIZE_8:     "%bh",
        REG_SIZE_8_REX: "%dil",
    },
    REG_R8: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%r8",
        REG_SIZE_32:    "%r8d",
        REG_SIZE_16:    "%r8w",
        REG_SIZE_8:     "%r8b",
        REG_SIZE_8_REX: "%r8b",
    },
    REG_R9: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%r9",
        REG_SIZE_32:    "%r9d",
        REG_SIZE_16:    "%r9w",
        REG_SIZE_8:     "%r9b",
        REG_SIZE_8_REX: "%r9b",
    },
    REG_R10: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%r10",
        REG_SIZE_32:    "%r10d",
        REG_SIZE_16:    "%r10w",
        REG_SIZE_8:     "%r10b",
        REG_SIZE_8_REX: "%r10b",
    },
    REG_R11: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%r11",
        REG_SIZE_32:    "%r11d",
        REG_SIZE_16:    "%r11w",
        REG_SIZE_8:     "%r11b",
        REG_SIZE_8_REX: "%r11b",
    },
    REG_R12: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%r12",
        REG_SIZE_32:    "%r12d",
        REG_SIZE_16:    "%r12w",
        REG_SIZE_8:     "%r12b",
        REG_SIZE_8_REX: "%r12b",
    },
    REG_R13: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%r13",
        REG_SIZE_32:    "%r13d",
        REG_SIZE_16:    "%r13w",
        REG_SIZE_8:     "%r13b",
        REG_SIZE_8_REX: "%r13b",
    },
    REG_R14: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%r14",
        REG_SIZE_32:    "%r14d",
        REG_SIZE_16:    "%r14w",
        REG_SIZE_8:     "%r14b",
        REG_SIZE_8_REX: "%r14b",
    },
    REG_R15: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%r15",
        REG_SIZE_32:    "%r15d",
        REG_SIZE_16:    "%r15w",
        REG_SIZE_8:     "%r15b",
        REG_SIZE_8_REX: "%r15b",
    },
    REG_MM0: {
        REG_SIZE_128:   "%xmm0",
        REG_SIZE_64:    "%mm0",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_MM1: {
        REG_SIZE_128:   "%xmm1",
        REG_SIZE_64:    "%mm1",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_MM2: {
        REG_SIZE_128:   "%xmm2",
        REG_SIZE_64:    "%mm2",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_MM3: {
        REG_SIZE_128:   "%xmm3",
        REG_SIZE_64:    "%mm3",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_MM4: {
        REG_SIZE_128:   "%xmm4",
        REG_SIZE_64:    "%mm4",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_MM5: {
        REG_SIZE_128:   "%xmm5",
        REG_SIZE_64:    "%mm5",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_MM6: {
        REG_SIZE_128:   "%xmm6",
        REG_SIZE_64:    "%mm6",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_MM7: {
        REG_SIZE_128:   "%xmm7",
        REG_SIZE_64:    "%mm7",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_ST0: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%st0",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_ST1: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%st1",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_ST2: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%st2",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_ST3: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%st3",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_ST4: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%st4",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_ST5: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%st5",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_ST6: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%st6",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_ST7: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%st7",
        REG_SIZE_32:    REG_NAME_UNDEF,
        REG_SIZE_16:    REG_NAME_UNDEF,
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_RIP: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%rip",
        REG_SIZE_32:    "%eip",
        REG_SIZE_16:    "%ip",
        REG_SIZE_8:     REG_NAME_UNDEF,
        REG_SIZE_8_REX: REG_NAME_UNDEF,
    },
    REG_RFLAGS: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%rflags",
        REG_SIZE_32:    "%eflags",
        REG_SIZE_16:    "%flags",
        REG_SIZE_8:     "%flagsb",
        REG_SIZE_8_REX: "%flagsb",
    },
    REG_RDX_RAX_COMBINED: {
        REG_SIZE_128:   REG_NAME_UNDEF,
        REG_SIZE_64:    "%rdx:%rax",
        REG_SIZE_32:    "%edx:%eax",
        REG_SIZE_16:    "%dx:%ax",
        REG_SIZE_8:     "%al:%ah",
        REG_SIZE_8_REX: "%al:%ah",
    },
    REG_FPENV: {
        REG_SIZE_128:   "%fpenv",
        REG_SIZE_64:    "%fpenv",
        REG_SIZE_32:    "%fpenv",
        REG_SIZE_16:    "%fpenv",
        REG_SIZE_8:     "%fpenv",
        REG_SIZE_8_REX: "%fpenv",
    }
}
