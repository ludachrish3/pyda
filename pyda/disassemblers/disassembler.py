import copy

OPERAND_TYPE_REG = 1
OPERAND_TYPE_MEM = 2

class Instruction():

    def __init__(self, mnemonic, addr=0, operands=[], exchange=False):

        # The operands list must be deep copied or else the reference to it
        # remains even after moving onto the next Instruction object. This way
        # every list of operands is a separate copy and they will not interfere
        # with each other.
        self.addr = addr
        self.bytes = []
        self.mnemonic = mnemonic
        self.operands = copy.deepcopy(operands)
        self.exchange = exchange


    def __repr__(self):

        bytesStr = " ".join([f"{x:02x}" for x in self.bytes])

        # Do not show operands if the instruction is a NOP because sometimes
        # NOP instructions create operands, but they don't mean anything.
        if self.mnemonic == "nop":

            operandString = ""

        # If the instruction is an exchange of values, make the arrow point
        # in both directions. Otherwise, the sources should point to the
        # destination operand.
        elif self.exchange:

            operandString = " <-> ".join([str(operand) for operand in self.operands])

        else:

            destinations = []
            sources      = []

            # Sort the operands into sources and destinations
            for operand in self.operands:

                if operand.isDestination:
                    destinations.append(operand)

                else:
                    sources.append(operand)

            # Create a string list for sources and destinations
            sourceString = ", ".join([ str(source) for source in sources      ])
            destString   = ", ".join([ str(dest)   for dest   in destinations ])

            # If there is at least one source and one destination, put an arrow
            # between them to indicate the sources and destinations.
            if len(sources) > 0 and len(destinations) > 0:
                operandString = f"{sourceString} -> {destString}"

            # If either list is empty, then just concatenate the two lists
            # because at least one will be an empty string. This way the list
            # with items will appear, or it will result in an empty string if
            # both lists are empty.
            else:
                operandString = f"{sourceString}{destString}"

        return f"{self.addr: >6x}:  {bytesStr: <20}  {self.mnemonic: <7} {operandString}"


class Operand():

    def __init__(self, size=8, value=0, isDestination=False):

        # defSize determines whether the size of the operand cannot be changed by
        # the operand-size attribute
        self.type = None
        self.size = size
        self.value = value
        self.isDestination = isDestination

    def __repr__(self):

        if type(self.value) == str:
            return self.value

        else:
            return str(self.value)

