import pytest
import re

from pyda.disassemblers.x64.asm import disassemble
from pyda.disassemblers.x64.instructions import X64Instruction
from pyda.disassemblers.x64.definitions import *

class TestX64():

    # TODO: Add a test for an instruction with an immediate and not enough bytes for the immediate
    # TODO: Add tests for 68-6b

    def test_operand_size( self ):

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=None, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_8

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_0, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_0, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_0, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_0, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_0, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_0

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_8

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_16

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_32

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_64

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_128, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_128, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_128, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_128, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_128, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_128

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8_REX

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8_REX

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8_REX

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8_REX

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=None, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_8_REX

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_0, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_0, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_0, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_0, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_0, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_0

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8_REX

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8_REX

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8_REX

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8_REX

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_8, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_8_REX

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_16, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_16

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_32, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_32

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_64, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_64

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_128, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_128, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_128, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_128, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_8_REX, infoSize=REG_SIZE_128, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_128

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_8

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_0, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_0, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_0, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_0, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_0, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_0

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_8

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_16

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_16

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_16

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_128, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_128, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_128, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_128, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_128, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_128

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_8

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_0, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_0, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_0, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_0, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_0, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_0

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_8

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_64

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_64

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_64

        ########################

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_128, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_128, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_128, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_128, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_128, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_128

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=None, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_32

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_0, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_0, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_0, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_0, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_0, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_0

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_8

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_16

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_32

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_64

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_128, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_128, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_128, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_128, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_128, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_128

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_16

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_0, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_0, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_0, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_0, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_0, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_0

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_8

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_16

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_16

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_16

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_128, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_128, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_128, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_128, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_128, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_128

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_64

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_0, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_0, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_0, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_0, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_0

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_0, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_0

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_8

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_64

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_64

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_64

        ########################

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_128, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_128, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_128, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_128, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        size = X64Instruction.getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_128, maxSize=REG_SIZE_128)
        assert size == REG_SIZE_128


    def instruction_helper( self, mnemonic, src, dst, assembly ):

        if dst == "":
            assemblyRe = re.compile(r'^\s*0:\s+{assembly}\s+{mnemonic}\s+{src}$'.format(
                assembly=" ".join(["{:02x}".format(x) for x in list(assembly)]),
                mnemonic=mnemonic, src=re.escape(src)))

        else:
            assemblyRe = re.compile(r'^\s*0:\s+{assembly}\s+{mnemonic}\s+{src},\s+{dst}$'.format(
                assembly=" ".join(["{:02x}".format(x) for x in list(assembly)]),
                mnemonic=mnemonic, src=re.escape(src), dst=re.escape(dst)))

        instructions = disassemble(assembly, 0)

        # Look for the expected output for the assembly instruction string
        assemblyString = "{}".format(instructions[0])
        match = assemblyRe.match(assemblyString)

        assert len(instructions) == 1
        assert match is not None


    def test_rex_prefixes( self ):

        ########################
        #  REX 64-BIT OPERAND  #
        ########################

        #           Address mode | source         | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Base
        sibByte   = (2 << 6)     | (REG_RAX << 3) | REG_RBX
        assembly = bytes([PREFIX_REX_MASK | PREFIX_REX_R_MASK, 0x01, modRmByte, sibByte])
        self.instruction_helper("add", "%r9d", "[%rbx + 4 * %rax]", assembly)

        ##########################
        #  REX EXTEND REG FIELD  #
        ##########################

        #           Address mode | source         | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Base
        sibByte   = (2 << 6)     | (REG_RAX << 3) | REG_RBX
        assembly = bytes([PREFIX_REX_MASK | PREFIX_REX_W_MASK, 0x01, modRmByte, sibByte])
        self.instruction_helper("add", "%rcx", "[%rbx + 4 * %rax]", assembly)

        ################################
        #  REX EXTEND SIB INDEX FIELD  #
        ################################

        #           Address mode | source         | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Base
        sibByte   = (2 << 6)     | (REG_RAX << 3) | REG_RBX
        assembly = bytes([PREFIX_REX_MASK | PREFIX_REX_X_MASK, 0x01, modRmByte, sibByte])
        self.instruction_helper("add", "%ecx", "[%rbx + 4 * %r8]", assembly)

        ###############################
        #  REX EXTEND SIB BASE FIELD  #
        ###############################

        #           Address mode | source         | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Base
        sibByte   = (2 << 6)     | (REG_RAX << 3) | REG_RBX
        assembly = bytes([PREFIX_REX_MASK | PREFIX_REX_B_MASK, 0x01, modRmByte, sibByte])
        self.instruction_helper("add", "%ecx", "[%r11 + 4 * %rax]", assembly)

        ######################################
        #  REX EXTEND OPCODE REGISTER FIELD  #
        ######################################

        assembly = bytes([PREFIX_REX_MASK | PREFIX_REX_B_MASK, 0x55])
        self.instruction_helper("push", "%r13", "", assembly)

        ##########################
        #  REX EXTEND R/M FIELD  #
        ##########################

        #         Address mode | source         | destination
        modRmByte = MOD_DIRECT | (REG_RCX << 3) | REG_RAX

        assembly = bytes([PREFIX_REX_MASK | PREFIX_REX_B_MASK, 0x01, modRmByte])
        self.instruction_helper("add", "%ecx", "%r8d", assembly)


    def test_basic_no_immediate( self ):
        """
        Description:    Tests a basic instruction (add) in the 4 ways that the
                        Mod R/M byte and operand size can be set.
        """

        ##########################################################
        #  OPCODE 00: 1 BYTE OPERANDS, MOD R/M BYTE IS FOR DEST  #
        ##########################################################

        #           Address mode | source         | destination
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x00, modRmByte])
        self.instruction_helper("add", "%cl", "[%rax]", assembly)

        ##########################################################
        #  OPCODE 01: 4 BYTE OPERANDS, MOD R/M BYTE IS FOR DEST  #
        ##########################################################

        #           Address mode | source         | destination
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x01, modRmByte])
        self.instruction_helper("add", "%ecx", "[%rax]", assembly)

        #########################################################
        #  OPCODE 02: 1 BYTE OPERANDS, MOD R/M BYTE IS FOR SRC  #
        #########################################################

        #           Address mode | destination    | source
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x02, modRmByte])
        self.instruction_helper("add", "[%rax]", "%cl", assembly)

        #########################################################
        #  OPCODE 03: 4 BYTE OPERANDS, MOD R/M BYTE IS FOR SRC  #
        #########################################################

        #           Address mode | destination    | source
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x03, modRmByte])
        self.instruction_helper("add", "[%rax]", "%ecx", assembly)


    def test_basic_immediate( self ):

        ##########################################
        #  OPCODE 04: 1 BYTE IMMEDIATE INTO %AL  #
        ##########################################

        immediate = 0x08
        assembly = bytes([0x04, immediate])
        self.instruction_helper("add", "0x8", "%al", assembly)

        ###########################################
        #  OPCODE 05: 1 BYTE IMMEDIATE INTO %EAX  #
        ###########################################

        assembly = bytes([0x05, 0x08, 0x00, 0x00, 0x00])
        self.instruction_helper("add", "0x8", "%eax", assembly)


    def test_basic_operand_size_prefix( self ):

        ############################################
        #  8 BIT OPERANDS WITH 64 BIT PREFIX BYTE  #
        ############################################

        #           Address mode | source         | destination
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([PREFIX_64_BIT_OPERAND, 0x00, modRmByte])
        self.instruction_helper("add", "%cl", "[%rax]", assembly)

        ############################################
        #  8 BIT OPERANDS WITH 16 BIT PREFIX BYTE  #
        ############################################

        #           Address mode | source         | destination
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([PREFIX_16_BIT_OPERAND, 0x00, modRmByte])
        self.instruction_helper("add", "%cl", "[%rax]", assembly)

        #############################################
        #  32 BIT OPERANDS WITH 64 BIT PREFIX BYTE  #
        #############################################

        #           Address mode | source         | destination
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([PREFIX_64_BIT_OPERAND, 0x01, modRmByte])
        self.instruction_helper("add", "%rcx", "[%rax]", assembly)

        #############################################
        #  32 BIT OPERANDS WITH 16 BIT PREFIX BYTE  #
        #############################################

        #           Address mode | source         | destination
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([PREFIX_16_BIT_OPERAND, 0x01, modRmByte])
        self.instruction_helper("add", "%cx", "[%rax]", assembly)

    def test_basic_mod_rm_byte( self ):

        ##################################
        #  1 BYTE POSITIVE DISPLACEMENT  #
        ##################################

        #           Address mode    | source         | destination
        modRmByte = MOD_1_BYTE_DISP | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x01, modRmByte, 0x42])
        self.instruction_helper("add", "%ecx", "[%rax] + 0x42", assembly)


    def test_basic_sib_byte( self ):

        #########################
        #  NO SIB DISPLACEMENT  #
        #########################

        #           Address mode | source         | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Base
        sibByte   = (2 << 6)     | (REG_RAX << 3) | REG_RBX
        assembly = bytes([0x01, modRmByte, sibByte])
        self.instruction_helper("add", "%ecx", "[%rbx + 4 * %rax]", assembly)

        ######################
        #  SIB DISPLACEMENT  #
        ######################

        #           Address mode | source         | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Use Displacement
        sibByte   = (0 << 6)     | (REG_RAX << 3) | REG_RBP
        assembly = bytes([0x01, modRmByte, sibByte, 0x03, 0x00, 0x00, 0x00])
        self.instruction_helper("add", "%ecx", "[%rax] + 0x3", assembly)

        ###################################################
        #  NO SIB DISPLACEMENT WITH MOD R/M DISPLACEMENT  #
        ###################################################

        #           Address mode    | source         | SIB
        modRmByte = MOD_1_BYTE_DISP | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Base
        sibByte   = (3 << 6)     | (REG_RAX << 3) | REG_RBP
        assembly = bytes([0x01, modRmByte, sibByte, 0x03])
        self.instruction_helper("add", "%ecx", "[%rbp + 8 * %rax] + 0x3", assembly)

        ###################
        #  INVALID INDEX  #
        ###################

        #           Address mode | source         | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Base
        sibByte   = (2 << 6)     | (REG_RSP << 3) | REG_RBX
        assembly = bytes([PREFIX_REX_MASK | PREFIX_REX_B_MASK, 0x01, modRmByte, sibByte])
        self.instruction_helper("add", "%ecx", "[%r11]", assembly)


    def test_rex_b_prefix( self ):

        ##########################################
        #  REGISTER IN OPCODE WITH REX.B PREFIX  #
        ##########################################

        rexByte = PREFIX_REX_MASK | PREFIX_REX_B_MASK

        assembly = bytes([rexByte, 0x55])
        self.instruction_helper("push", "%r13", "", assembly)

        ##############################
        #  MOD/RM WITH REX.B PREFIX  #
        ##############################

        rexByte = PREFIX_REX_MASK | PREFIX_REX_B_MASK

        #           Address mode    | source         | destination
        modRmByte = MOD_1_BYTE_DISP | (REG_RCX << 3) | REG_RAX
        assembly = bytes([rexByte, 0x01, modRmByte, 0x42])
        self.instruction_helper("add", "%ecx", "[%r8] + 0x42", assembly)

        #########################
        #  SIB BYTE WITH REX.B  #
        #########################

        rexByte = PREFIX_REX_MASK | PREFIX_REX_B_MASK

        #           Address mode | source         | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Base
        sibByte   = (2 << 6)     | (REG_RAX << 3) | REG_RBX
        assembly = bytes([rexByte, 0x01, modRmByte, sibByte])
        self.instruction_helper("add", "%ecx", "[%r11 + 4 * %rax]", assembly)

    def test_segment_reg_prefix( self ):

        #################
        #  ES REGISTER  #
        #################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Invalid Reg    | Use Displacement
        sibByte   = (0 << 6)     | (REG_RSP << 3) | REG_RBP
        assembly = bytes([SEGMENT_REG_ES, PREFIX_64_BIT_OPERAND, 0x8b, modRmByte, sibByte, 0x28, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "%es:0x28", "%rcx", assembly)

        #######################################
        #  CS REGISTER  AND NO 64-BIT PREFIX  #
        #######################################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Invalid Reg    | Use Displacement
        sibByte   = (0 << 6)     | (REG_RSP << 3) | REG_RBP
        assembly = bytes([SEGMENT_REG_CS, 0x8b, modRmByte, sibByte, 0x28, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "%cs:0x28", "%ecx", assembly)

        #################
        #  SS REGISTER  #
        #################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Invalid Reg    | Use Displacement
        sibByte   = (0 << 6)     | (REG_RSP << 3) | REG_RBP
        assembly = bytes([SEGMENT_REG_SS, PREFIX_64_BIT_OPERAND, 0x8b, modRmByte, sibByte, 0x28, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "%ss:0x28", "%rcx", assembly)

        #################
        #  DS REGISTER  #
        #################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Invalid Reg    | Use Displacement
        sibByte   = (0 << 6)     | (REG_RSP << 3) | REG_RBP
        assembly = bytes([SEGMENT_REG_DS, PREFIX_64_BIT_OPERAND, 0x8b, modRmByte, sibByte, 0x28, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "%ds:0x28", "%rcx", assembly)

        #################
        #  FS REGISTER  #
        #################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Invalid Reg    | Use Displacement
        sibByte   = (0 << 6)     | (REG_RSP << 3) | REG_RBP
        assembly = bytes([SEGMENT_REG_FS, PREFIX_64_BIT_OPERAND, 0x8b, modRmByte, sibByte, 0x28, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "%fs:0x28", "%rcx", assembly)

        #################
        #  GS REGISTER  #
        #################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Invalid Reg    | Use Displacement
        sibByte   = (0 << 6)     | (REG_RSP << 3) | REG_RBP
        assembly = bytes([SEGMENT_REG_GS, PREFIX_64_BIT_OPERAND, 0x8b, modRmByte, sibByte, 0x28, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "%gs:0x28", "%rcx", assembly)

        #########################################
        #  SEGMENT REGISTER WITHOUT A SIB BYTE  #
        #########################################

        #           Address mode | source         | destination
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([SEGMENT_REG_ES, 0x01, modRmByte])
        self.instruction_helper("add", "%ecx", "%es:[%rax]", assembly)


    def test_move_instructions ( self ):

        #############################################
        #  MOVE WITH CONVERSION AND SIGN EXTENSION  #
        #############################################

        #         Address mode | destination    | source
        modRmByte = MOD_DIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x63, modRmByte])
        self.instruction_helper("movsxd", "%eax", "%ecx", assembly)

        #         Address mode | destination    | source
        modRmByte = MOD_DIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([PREFIX_64_BIT_OPERAND, 0x63, modRmByte])
        self.instruction_helper("movsxd", "%eax", "%rcx", assembly)

        ######################################
        #  MOVE BETWEEN REGISTER AND MEMORY  #
        ######################################

        #         Address mode | source         | destination
        modRmByte = MOD_DIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x88, modRmByte])
        self.instruction_helper("mov", "%cl", "%al", assembly)

        #         Address mode | source         | destination
        modRmByte = MOD_DIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x89, modRmByte])
        self.instruction_helper("mov", "%ecx", "%eax", assembly)

        #         Address mode | destination    | source
        modRmByte = MOD_DIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x8a, modRmByte])
        self.instruction_helper("mov", "%al", "%cl", assembly)

        #         Address mode | destination    | source
        modRmByte = MOD_DIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x8b, modRmByte])
        self.instruction_helper("mov", "%eax", "%ecx", assembly)

        ################################
        #  MOVE IMMEDIATE TO REGISTER  #
        ################################

        assembly = bytes([0xb0, 0x42])
        self.instruction_helper("mov", "0x42", "%al", assembly)

        assembly = bytes([0xb1, 0x42])
        self.instruction_helper("mov", "0x42", "%cl", assembly)

        assembly = bytes([0xb2, 0x42])
        self.instruction_helper("mov", "0x42", "%dl", assembly)

        assembly = bytes([0xb3, 0x42])
        self.instruction_helper("mov", "0x42", "%bl", assembly)

        assembly = bytes([0xb4, 0x42])
        self.instruction_helper("mov", "0x42", "%ah", assembly)

        assembly = bytes([0xb5, 0x42])
        self.instruction_helper("mov", "0x42", "%ch", assembly)

        assembly = bytes([0xb6, 0x42])
        self.instruction_helper("mov", "0x42", "%dh", assembly)

        assembly = bytes([0xb7, 0x42])
        self.instruction_helper("mov", "0x42", "%bh", assembly)

        assembly = bytes([0xb8, 0x42, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "0x42", "%eax", assembly)

        assembly = bytes([0xb9, 0x42, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "0x42", "%ecx", assembly)

        assembly = bytes([0xba, 0x42, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "0x42", "%edx", assembly)

        assembly = bytes([0xbb, 0x42, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "0x42", "%ebx", assembly)

        assembly = bytes([0xbc, 0x42, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "0x42", "%esp", assembly)

        assembly = bytes([0xbd, 0x42, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "0x42", "%ebp", assembly)

        assembly = bytes([0xbe, 0x42, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "0x42", "%esi", assembly)

        assembly = bytes([0xbf, 0x42, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "0x42", "%edi", assembly)

        #         Address mode | destination must be 0 | source
        modRmByte = MOD_DIRECT | 0                     | REG_RCX
        assembly = bytes([0xc6, modRmByte, 0x42])
        self.instruction_helper("mov", "0x42", "%cl", assembly)

        #         Address mode | destination must be 0 | source
        modRmByte = MOD_DIRECT | 0                     | REG_RCX
        assembly = bytes([0xc7, modRmByte, 0x42, 0x00, 0x00, 0x00])
        self.instruction_helper("mov", "0x42", "%ecx", assembly)


    def test_push_instructions( self ):

        assembly = bytes([0x50])
        self.instruction_helper("push", "%rax", "", assembly)

        assembly = bytes([0x51])
        self.instruction_helper("push", "%rcx", "", assembly)

        assembly = bytes([0x52])
        self.instruction_helper("push", "%rdx", "", assembly)

        assembly = bytes([0x53])
        self.instruction_helper("push", "%rbx", "", assembly)

        assembly = bytes([0x54])
        self.instruction_helper("push", "%rsp", "", assembly)

        assembly = bytes([0x55])
        self.instruction_helper("push", "%rbp", "", assembly)

        assembly = bytes([0x56])
        self.instruction_helper("push", "%rsi", "", assembly)

        assembly = bytes([0x57])
        self.instruction_helper("push", "%rdi", "", assembly)

        assembly = bytes([0x68, 0xff, 0xff, 0xff, 0xff])
        self.instruction_helper("push", "-0x1", "", assembly)

        assembly = bytes([0x6a, 0xff])
        self.instruction_helper("push", "-0x1", "", assembly)

        assembly = bytes([0x9c])
        self.instruction_helper("pushf", "%rflags", "", assembly)


    def test_pop_instructions( self ):

        assembly = bytes([0x58])
        self.instruction_helper("pop", "%rax", "", assembly)

        assembly = bytes([0x59])
        self.instruction_helper("pop", "%rcx", "", assembly)

        assembly = bytes([0x5a])
        self.instruction_helper("pop", "%rdx", "", assembly)

        assembly = bytes([0x5b])
        self.instruction_helper("pop", "%rbx", "", assembly)

        assembly = bytes([0x5c])
        self.instruction_helper("pop", "%rsp", "", assembly)

        assembly = bytes([0x5d])
        self.instruction_helper("pop", "%rbp", "", assembly)

        assembly = bytes([0x5e])
        self.instruction_helper("pop", "%rsi", "", assembly)

        assembly = bytes([0x5f])
        self.instruction_helper("pop", "%rdi", "", assembly)

        #           Address mode | regOrOpmust be 0 | Destination
        modRmByte = MOD_INDIRECT | 0                | REG_RCX
        assembly = bytes([0x8f, modRmByte])
        self.instruction_helper("pop", "[%rcx]", "", assembly)

        assembly = bytes([0x9d])
        self.instruction_helper("popf", "%rflags", "", assembly)


    def test_exchange_instructions( self ):

        assembly = bytes([0x90])
        self.instruction_helper("nop", "", "", assembly)

        assembly = bytes([0x91])
        self.instruction_helper("xchg", "%eax", "%ecx", assembly)


    def test_xmm_addressing( self ):

        ########################
        #  MM RELATIVE TO RIP  #
        ########################

        #           Address mode | destination    | Use Displacement
        modRmByte = MOD_INDIRECT | (REG_RAX << 3) | REG_RBP

        assembly = bytes([0x0f, 0x6f, modRmByte, 0x4d, 0xa0, 0x21, 00])
        self.instruction_helper("movq", "0x21a054", "%mm0", assembly)

        #########################
        #  XMM RELATIVE TO RIP  #
        #########################

        #           Address mode | destination    | Use Displacement
        modRmByte = MOD_INDIRECT | (REG_RAX << 3) | REG_RBP

        assembly = bytes([0x66, 0x0f, 0x6f, modRmByte, 0x4d, 0xa0, 0x21, 00])
        self.instruction_helper("movdqa", "0x21a055", "%xmm0", assembly)

        ##############################
        #  MM INDIRECT MOD R/M BYTE  #
        ##############################

        #           Address mode | destination    | source
        modRmByte = MOD_INDIRECT | (REG_RAX << 3) | REG_RCX

        assembly = bytes([0x0f, 0x6f, modRmByte])
        self.instruction_helper("movq", "[%rcx]", "%mm0", assembly)

        ############################
        #  MM DIRECT MOD R/M BYTE  #
        ############################

        #         Address mode | destination    | source
        modRmByte = MOD_DIRECT | (REG_RAX << 3) | REG_RCX

        assembly = bytes([0x0f, 0x6f, modRmByte])
        self.instruction_helper("movq", "%mm1", "%mm0", assembly)

        ######################
        #  MM WITH SIB BYTE  #
        ######################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RAX << 3) | REG_RSP

        #           Scale        | Index          | Base
        sibByte   = (2 << 6)     | (REG_RCX << 3) | REG_RBX
        assembly = bytes([0x0f, 0x6f, modRmByte, sibByte])
        self.instruction_helper("movq", "[%rbx + 4 * %rcx]", "%mm0", assembly)

    def test_floating_point_instructions( self ):

        # TODO: Add a LOT more tests because floating point instructions have
        # tons of special cases
        assembly = bytes([0xd9, 0x05, 0xaa, 0xb7, 0x00, 0x00])
        self.instruction_helper("fld", "0xb7b0", "%st0", assembly)

        #         Address mode | fxch     | source
        modRmByte = MOD_DIRECT | (1 << 3) | 3
        assembly = bytes([0xd9, modRmByte])
        self.instruction_helper("fxch", "%st3", "%st0", assembly)

        #           Address mode | fst      | destination
        modRmByte = MOD_INDIRECT | (2 << 3) | REG_RBX
        assembly = bytes([0xdd, modRmByte])
        self.instruction_helper("fst", "%st0", "[%rbx]", assembly)






