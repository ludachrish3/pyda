import pytest
import re

from pyda.binaries.binary import Function
from pyda.disassemblers.x64.asm import disassemble
from pyda.disassemblers.x64.definitions import *

class TestX64():

    # TODO: Add a test for an instruction with an immediate and not enough bytes for the immediate
    # TODO: Add tests for 68-6b

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
