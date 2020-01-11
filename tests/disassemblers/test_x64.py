import pytest
import re

from pyda.binaries.binary import Function
from pyda.disassemblers.x64.asm import disassemble, getOperandSize
from pyda.disassemblers.x64.definitions import *

class TestX64():

    # TODO: Add a test for an instruction with an immediate and not enough bytes for the immediate
    # TODO: Add tests for 68-6b

    def test_operand_size( self ):

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        ########################

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        ########################

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        ########################

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_32

        ########################

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = getOperandSize(opcode=0, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        ########################

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        ########################

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        ########################

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        ########################

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        ########################

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        ########################

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        ########################

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        ########################

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        ########################

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        ########################

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = getOperandSize(opcode=0, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        ########################

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_32

        ########################

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_8

        ########################

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        ########################

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_32

        ########################

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = getOperandSize(opcode=1, prefixSize=None, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        ########################

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        ########################

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        ########################

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        ########################

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        ########################

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_16, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_16

        ########################

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=None, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        ########################

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_8, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        ########################

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_16, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        ########################

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_32, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64

        ########################

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_8)
        assert size == REG_SIZE_8

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_16)
        assert size == REG_SIZE_16

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_32)
        assert size == REG_SIZE_32

        size = getOperandSize(opcode=1, prefixSize=REG_SIZE_64, infoSize=REG_SIZE_64, maxSize=REG_SIZE_64)
        assert size == REG_SIZE_64


    def helper( self, mnemonic, src, dst, assembly ):

        # Create a new function with the assembly and disassemble it
        function = Function(name='testFunc', addr=0, size=0, assembly=assembly)

        if dst == "":
            assemblyRe = re.compile(r'^\s*0:\s+{assembly}\s+{mnemonic}\s+{src}$'.format(
                assembly=" ".join(["{:02x}".format(x) for x in list(assembly)]),
                mnemonic=mnemonic, src=re.escape(src)))

        else:
            assemblyRe = re.compile(r'^\s*0:\s+{assembly}\s+{mnemonic}\s+{src},\s+{dst}$'.format(
                assembly=" ".join(["{:02x}".format(x) for x in list(assembly)]),
                mnemonic=mnemonic, src=re.escape(src), dst=re.escape(dst)))

        disassemble(function)

        # Look for the expected output for the assembly instruction string
        assemblyString = "{}".format(function.instructions[0])
        match = assemblyRe.match(assemblyString)

        # Return the function for analysis and the regex match object
        return function, match


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
        function, match = self.helper("add", "%cl", "[%rax]", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        ##########################################################
        #  OPCODE 01: 4 BYTE OPERANDS, MOD R/M BYTE IS FOR DEST  #
        ##########################################################

        #           Address mode | source         | destination
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x01, modRmByte])
        function, match = self.helper("add", "%ecx", "[%rax]", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #########################################################
        #  OPCODE 02: 1 BYTE OPERANDS, MOD R/M BYTE IS FOR SRC  #
        #########################################################

        #           Address mode | destination    | source
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x02, modRmByte])
        function, match = self.helper("add", "[%rax]", "%cl", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #########################################################
        #  OPCODE 03: 4 BYTE OPERANDS, MOD R/M BYTE IS FOR SRC  #
        #########################################################

        #           Address mode | destination    | source
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x03, modRmByte])
        function, match = self.helper("add", "[%rax]", "%ecx", assembly)
        assert len(function.instructions) == 1
        assert match is not None


    def test_basic_immediate( self ):

        ##########################################
        #  OPCODE 04: 1 BYTE IMMEDIATE INTO %AL  #
        ##########################################

        immediate = 0x08
        assembly = bytes([0x04, immediate])
        function, match = self.helper("add", "0x8", "%al", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        ###########################################
        #  OPCODE 05: 1 BYTE IMMEDIATE INTO %EAX  #
        ###########################################

        assembly = bytes([0x05, 0x08, 0x00, 0x00, 0x00])
        function, match = self.helper("add", "0x8", "%eax", assembly)
        assert len(function.instructions) == 1
        assert match is not None


    def test_basic_operand_size_prefix( self ):

        ############################################
        #  8 BIT OPERANDS WITH 64 BIT PREFIX BYTE  #
        ############################################

        #           Address mode | source         | destination
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([PREFIX_64_BIT_OPERAND, 0x00, modRmByte])
        function, match = self.helper("add", "%cl", "[%rax]", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        ############################################
        #  8 BIT OPERANDS WITH 16 BIT PREFIX BYTE  #
        ############################################

        #           Address mode | source         | destination
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([PREFIX_16_BIT_OPERAND, 0x00, modRmByte])
        function, match = self.helper("add", "%cl", "[%rax]", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #############################################
        #  32 BIT OPERANDS WITH 64 BIT PREFIX BYTE  #
        #############################################

        #           Address mode | source         | destination
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([PREFIX_64_BIT_OPERAND, 0x01, modRmByte])
        function, match = self.helper("add", "%rcx", "[%rax]", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #############################################
        #  32 BIT OPERANDS WITH 16 BIT PREFIX BYTE  #
        #############################################

        #           Address mode | source         | destination
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RAX
        assembly = bytes([PREFIX_16_BIT_OPERAND, 0x01, modRmByte])
        function, match = self.helper("add", "%cx", "[%rax]", assembly)
        assert len(function.instructions) == 1
        assert match is not None

    def test_basic_mod_rm_byte( self ):

        ##################################
        #  1 BYTE POSITIVE DISPLACEMENT  #
        ##################################

        #           Address mode    | source         | destination
        modRmByte = MOD_1_BYTE_DISP | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x01, modRmByte, 0x42])
        function, match = self.helper("add", "%ecx", "[%rax] + 0x42", assembly)
        assert len(function.instructions) == 1
        assert match is not None


    def test_basic_sib_byte( self ):

        #########################
        #  NO SIB DISPLACEMENT  #
        #########################

        #           Address mode | source         | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Base
        sibByte   = (2 << 6)     | (REG_RAX << 3) | REG_RBX
        assembly = bytes([0x01, modRmByte, sibByte])
        function, match = self.helper("add", "%ecx", "[%rbx + 4 * %rax]", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        ######################
        #  SIB DISPLACEMENT  #
        ######################

        #           Address mode | source         | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Use Displacement
        sibByte   = (0 << 6)     | (REG_RAX << 3) | REG_RBP
        assembly = bytes([0x01, modRmByte, sibByte, 0x03, 0x00, 0x00, 0x00])
        function, match = self.helper("add", "%ecx", "[%rax] + 0x3", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        ###################################################
        #  NO SIB DISPLACEMENT WITH MOD R/M DISPLACEMENT  #
        ###################################################

        #           Address mode    | source         | SIB
        modRmByte = MOD_1_BYTE_DISP | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Base
        sibByte   = (3 << 6)     | (REG_RAX << 3) | REG_RBP
        assembly = bytes([0x01, modRmByte, sibByte, 0x03])
        function, match = self.helper("add", "%ecx", "[%rbp + 8 * %rax] + 0x3", assembly)
        assert len(function.instructions) == 1
        assert match is not None


    def test_rex_b_prefix( self ):

        ##########################################
        #  REGISTER IN OPCODE WITH REX.B PREFIX  #
        ##########################################

        rexByte = PREFIX_REX_MASK | PREFIX_REX_B_MASK

        assembly = bytes([rexByte, 0x55])
        function, match = self.helper("push", "%r13", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        ##############################
        #  MOD/RM WITH REX.B PREFIX  #
        ##############################

        rexByte = PREFIX_REX_MASK | PREFIX_REX_B_MASK

        #           Address mode    | source         | destination
        modRmByte = MOD_1_BYTE_DISP | (REG_RCX << 3) | REG_RAX
        assembly = bytes([rexByte, 0x01, modRmByte, 0x42])
        function, match = self.helper("add", "%ecx", "[%r8] + 0x42", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #########################
        #  SIB BYTE WITH REX.B  #
        #########################

        rexByte = PREFIX_REX_MASK | PREFIX_REX_B_MASK

        #           Address mode | source         | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Index          | Base
        sibByte   = (2 << 6)     | (REG_RAX << 3) | REG_RBX
        assembly = bytes([rexByte, 0x01, modRmByte, sibByte])
        function, match = self.helper("add", "%ecx", "[%r11 + 4 * %rax]", assembly)
        assert len(function.instructions) == 1
        assert match is not None

    def test_segment_reg_prefix( self ):

        #################
        #  ES REGISTER  #
        #################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Invalid Reg    | Use Displacement
        sibByte   = (0 << 6)     | (REG_RSP << 3) | REG_RBP
        assembly = bytes([PREFIX_REG_ES, PREFIX_64_BIT_OPERAND, 0x8b, modRmByte, sibByte, 0x28, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "%ES:0x28", "%rcx", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #######################################
        #  CS REGISTER  AND NO 64-BIT PREFIX  #
        #######################################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Invalid Reg    | Use Displacement
        sibByte   = (0 << 6)     | (REG_RSP << 3) | REG_RBP
        assembly = bytes([PREFIX_REG_CS, 0x8b, modRmByte, sibByte, 0x28, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "%CS:0x28", "%ecx", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #################
        #  SS REGISTER  #
        #################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Invalid Reg    | Use Displacement
        sibByte   = (0 << 6)     | (REG_RSP << 3) | REG_RBP
        assembly = bytes([PREFIX_REG_SS, PREFIX_64_BIT_OPERAND, 0x8b, modRmByte, sibByte, 0x28, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "%SS:0x28", "%rcx", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #################
        #  DS REGISTER  #
        #################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Invalid Reg    | Use Displacement
        sibByte   = (0 << 6)     | (REG_RSP << 3) | REG_RBP
        assembly = bytes([PREFIX_REG_DS, PREFIX_64_BIT_OPERAND, 0x8b, modRmByte, sibByte, 0x28, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "%DS:0x28", "%rcx", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #################
        #  FS REGISTER  #
        #################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Invalid Reg    | Use Displacement
        sibByte   = (0 << 6)     | (REG_RSP << 3) | REG_RBP
        assembly = bytes([PREFIX_REG_FS, PREFIX_64_BIT_OPERAND, 0x8b, modRmByte, sibByte, 0x28, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "%FS:0x28", "%rcx", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #################
        #  GS REGISTER  #
        #################

        #           Address mode | destination    | SIB
        modRmByte = MOD_INDIRECT | (REG_RCX << 3) | REG_RSP

        #           Scale        | Invalid Reg    | Use Displacement
        sibByte   = (0 << 6)     | (REG_RSP << 3) | REG_RBP
        assembly = bytes([PREFIX_REG_GS, PREFIX_64_BIT_OPERAND, 0x8b, modRmByte, sibByte, 0x28, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "%GS:0x28", "%rcx", assembly)
        assert len(function.instructions) == 1
        assert match is not None


    def test_move_instructions ( self ):

        #############################################
        #  MOVE WITH CONVERSION AND SIGN EXTENSION  #
        #############################################

        #           Address mode | destination    | source
        modRmByte = MOD_REGISTER | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x63, modRmByte])
        function, match = self.helper("movsxd", "%ax", "%ecx", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #           Address mode | destination    | source
        modRmByte = MOD_REGISTER | (REG_RCX << 3) | REG_RAX
        assembly = bytes([PREFIX_64_BIT_OPERAND, 0x63, modRmByte])
        function, match = self.helper("movsxd", "%ax", "%rcx", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        ######################################
        #  MOVE BETWEEN REGISTER AND MEMORY  #
        ######################################

        #           Address mode | source         | destination
        modRmByte = MOD_REGISTER | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x88, modRmByte])
        function, match = self.helper("mov", "%cl", "%al", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #           Address mode | source         | destination
        modRmByte = MOD_REGISTER | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x89, modRmByte])
        function, match = self.helper("mov", "%ecx", "%eax", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #           Address mode | destination    | source
        modRmByte = MOD_REGISTER | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x8a, modRmByte])
        function, match = self.helper("mov", "%al", "%cl", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #           Address mode | destination    | source
        modRmByte = MOD_REGISTER | (REG_RCX << 3) | REG_RAX
        assembly = bytes([0x8b, modRmByte])
        function, match = self.helper("mov", "%eax", "%ecx", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        ################################
        #  MOVE IMMEDIATE TO REGISTER  #
        ################################

        assembly = bytes([0xb0, 0x42])
        function, match = self.helper("mov", "0x42", "%al", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xb1, 0x42])
        function, match = self.helper("mov", "0x42", "%cl", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xb2, 0x42])
        function, match = self.helper("mov", "0x42", "%dl", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xb3, 0x42])
        function, match = self.helper("mov", "0x42", "%bl", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xb4, 0x42])
        function, match = self.helper("mov", "0x42", "%ah", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xb5, 0x42])
        function, match = self.helper("mov", "0x42", "%ch", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xb6, 0x42])
        function, match = self.helper("mov", "0x42", "%dh", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xb7, 0x42])
        function, match = self.helper("mov", "0x42", "%bh", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xb8, 0x42, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "0x42", "%eax", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xb9, 0x42, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "0x42", "%ecx", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xba, 0x42, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "0x42", "%edx", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xbb, 0x42, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "0x42", "%ebx", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xbc, 0x42, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "0x42", "%esp", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xbd, 0x42, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "0x42", "%ebp", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xbe, 0x42, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "0x42", "%esi", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0xbf, 0x42, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "0x42", "%edi", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #           Address mode | destination must be 0 | source
        modRmByte = MOD_REGISTER | 0                     | REG_RCX
        assembly = bytes([0xc6, modRmByte, 0x42])
        function, match = self.helper("mov", "0x42", "%cl", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #           Address mode | destination must be 0 | source
        modRmByte = MOD_REGISTER | 0                     | REG_RCX
        assembly = bytes([0xc7, modRmByte, 0x42, 0x00, 0x00, 0x00])
        function, match = self.helper("mov", "0x42", "%ecx", assembly)
        assert len(function.instructions) == 1
        assert match is not None


    def test_push_instructions( self ):

        assembly = bytes([0x50])
        function, match = self.helper("push", "%rax", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x51])
        function, match = self.helper("push", "%rcx", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x52])
        function, match = self.helper("push", "%rdx", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x53])
        function, match = self.helper("push", "%rbx", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x54])
        function, match = self.helper("push", "%rsp", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x55])
        function, match = self.helper("push", "%rbp", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x56])
        function, match = self.helper("push", "%rsi", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x57])
        function, match = self.helper("push", "%rdi", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x68, 0xff, 0xff, 0xff, 0xff])
        function, match = self.helper("push", "-0x1", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x6a, 0xff])
        function, match = self.helper("push", "-0x1", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x9c])
        function, match = self.helper("pushf", "%rflags", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None


    def test_pop_instructions( self ):

        assembly = bytes([0x58])
        function, match = self.helper("pop", "%rax", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x59])
        function, match = self.helper("pop", "%rcx", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x5a])
        function, match = self.helper("pop", "%rdx", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x5b])
        function, match = self.helper("pop", "%rbx", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x5c])
        function, match = self.helper("pop", "%rsp", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x5d])
        function, match = self.helper("pop", "%rbp", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x5e])
        function, match = self.helper("pop", "%rsi", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x5f])
        function, match = self.helper("pop", "%rdi", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        #           Address mode | regOrOpmust be 0 | Destination
        modRmByte = MOD_INDIRECT | 0                | REG_RCX
        assembly = bytes([0x8f, modRmByte])
        function, match = self.helper("pop", "[%rcx]", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x9d])
        function, match = self.helper("popf", "%rflags", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None


    def test_exchange_instructions( self ):

        assembly = bytes([0x90])
        function, match = self.helper("nop", "", "", assembly)
        assert len(function.instructions) == 1
        assert match is not None

        assembly = bytes([0x91])
        function, match = self.helper("xchg", "%eax", "%ecx", assembly)
        assert len(function.instructions) == 1
        assert match is not None

