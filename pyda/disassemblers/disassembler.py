import copy

OPERAND_TYPE_REG = 1
OPERAND_TYPE_MEM = 2

class Instruction():

    def __init__(self, mnemonic, addr=0, sources=[], dest=None, exchange=False):

        self.addr = addr
        self.bytes = []
        self.mnemonic = mnemonic
        self.sources = copy.deepcopy(sources)
        self.dest = dest
        self.exchange = exchange


    def __repr__(self):

        bytesStr = " ".join([f"{x:02x}" for x in self.bytes])

        # Do not show operands if the instruction is a NOP because sometimes
        # NOP instructions create operands, but they don't mean anything.
        if self.mnemonic == "nop":

            operandString = ""

        else:

            # If the instruction is an exchange of values, make the arrow point
            # in both directions. Otherwise, the sources should point to the
            # destination operand.
            if len(self.sources) > 0 and self.dest is not None:

                if self.exchange:
                    arrow = "<"

                else:
                    arrow = ""

                sourceString  = ",".join([str(source) for source in self.sources])
                operandString = f"{sourceString} {arrow}-> {str(self.dest)}"

            elif len(self.sources) > 0:

                sourceString  = ",".join([str(source) for source in self.sources])
                operandString = f"{sourceString}"

            elif self.dest is not None:

                operandString = f"{str(self.dest)}"

            else:

                operandString = ""

        return f"{self.addr: >6x}:  {bytesStr: <20}  {self.mnemonic: <7} {operandString}"


class Operand():

    def __init__(self, size=8, value=0):

        # defSize determines whether the size of the operand cannot be changed by
        # the operand-size attribute
        self.type = None
        self.size = size
        self.value = value

    def __repr__(self):

        if type(self.value) == str:
            return self.value

        else:
            return str(self.value)

