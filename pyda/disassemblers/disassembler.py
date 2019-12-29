
OPERAND_TYPE_REG = 1
OPERAND_TYPE_MEM = 2

class Instruction():

    def __init__(self, mnemonic, addr=0, source=None, dest=None, extraOperands=[]):

        self.addr = addr
        self.bytes = []
        self.mnemonic = mnemonic
        self.source = source
        self.dest = dest
        self.extraOperands = extraOperands

    def __repr__(self):

        reprStr = self.mnemonic
        operands = []

        # Display the source first, then the destination
        if self.source is not None:
            operands.append(self.source)

        if self.dest is not None:
            operands.append(self.dest)

        operands = operands + self.extraOperands

        return "{addr: <6} {bytes: <20} {mnemonic: <7}{operands}".format(
                addr="{:x}:".format(self.addr),
                bytes=" ".join(["{:02x}".format(x) for x in self.bytes]),
                mnemonic=self.mnemonic,
                operands=", ".join([str(x) for x in operands]))


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

