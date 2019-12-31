import pytest
import re

from pyda.binaries.binary import Function
from pyda.disassemblers.x64.asm import disassemble
from pyda.disassemblers.x64.definitions import *

class TestX64():

    # TODO: Add a test for an instruction with an immediate and not enough bytes for the immediate

    def helper( self, mnemonic, src, dst, assembly ):

        # Create a new function with the assembly and disassemble it
        function = Function(name='testFunc', addr=0, size=0, assembly=assembly)
        assemblyRe = re.compile(r'0:\s+{assembly}\s+{mnemonic}\s+{src},\s+{dst}'.format(
            assembly=" ".join(["{:02x}".format(x) for x in list(assembly)]),
            mnemonic=mnemonic, src=re.escape(src), dst=re.escape(dst)))

        disassemble(function)

        # Look for the expected output for the assembly instruction string
        assemblyString = "{}".format(function.instructions[0])
        match = assemblyRe.match(assemblyString)

        # Return the function for analysis and the regex match object
        return function, match


    def test_add_no_immediate( self ):

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


    def test_add_immediate( self ):

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


