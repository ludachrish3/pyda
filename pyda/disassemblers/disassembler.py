
OPERAND_TYPE_REG = 1
OPERAND_TYPE_MEM = 2

class Instruction():

    def __init__(self, mnemonic, source=[], dest=None, extraOperands=[]):

        self.bytes = []
        self.mnemonic = mnemonic
        self.source = source
        self.dest = dest
        self.extraOperands = extraOperands

    def __repr__(self):

        reprStr = self.mnemonic
        operands = []

        # Display the source first, then the destination
        for source in self.source:
            if type(source.value) == int:
                operands += self.source

        if type(self.dest.value) == int:
            operands.append(self.dest)

        operands = operands + self.extraOperands

        return "{: <20} {: <6}{}".format(" ".join(["{:0<2x}".format(x) for x in self.bytes]),
                                  self.mnemonic,
                                  ", ".join([str(x) for x in operands]))


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

