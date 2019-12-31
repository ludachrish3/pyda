import pytest

from pyda.disassemblers.x64.asm import disassemble

class TestX64():

    def test_add_no_immediate( self ):

        assert 1 == 2
