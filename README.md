# pyda

The goal of this project is to create a Python program that can disassemble and decompile programs of various types in an extensible way.

## Usage

```
usage: pyda [-l] [-h] file [file ...]

required arguments:
  file               the binary file(s) to analyze

optional arguments:
  -l , --log-level   Log level to use when printing logs
  -h, --help         Show this help message and exit
```

## TODO

* Handle relocations more generically. Possibly use the GOT value found at the relocation address to find the section that it is in. This can be done by walking the list of sections and backing up one section when the virtual address surpasses the relocation address.
* Figure out what to do with other global symbols that aren't related to PLT, like \_libc_start_main
* Use function sizes as more of a hint instead of a definite size. If it is nonzero, it's okay to trust it. If it's 0, then using the logic for finding functions in a stripped binary can be used to determine when the function ends. In this case, keeping the memory mapped file around is needed. This means that keeping the "assembly" field around for function symbols is unnecessary.
* Take alignment into account when looking for functions in a stripped binary. Functions need to start at an offset where address % alignment == 0
* Convert sources or maybe all operands to a list to be acted on together. This can simplify handling immediates and maybe other things if destination is included.
* Change error handling to be try blocks and raising exceptions instead of checking return values. Checking handleOperandAddressing() needs to be done in the case that an invalid segment register is used.
* In order to find functions in a stripped binary, start at beginning of .text section. Start disassembling and consider all jumps that can be taken. If there are no jumps left and a ret instruction is reached, then that is the end of the function. All instructions after it (not including NOPs) are another function.
* Come up with a way to find functions in stripped binaries
* Get 100% code coverage in tests (or close to it)
* Cross compile for the Raspberry Pi
* Create a disassembler for ARM (whatever version is on the Raspberry Pi v4)
* Come up with an abstraction layer for instructions so that decompiling all ISAs is the same. Will possibly need to break instructions up into multiple ones or combine instructions into one
* Support both Intel and AT&T assembly syntax
* Generate a set of known function prototypes and variable types for type inference
* Visual representation of the stack
* Resetting values of strings or arrays to be the value during runtime. The original value is also saved for reference.
* Analyzing DWARF info
* Entropy analysis
* Calling and called functions
* Highlight CALL instructions for when a function pointer is dereferenced and called
* Cross references of addresses (aggressive matching of address throughout whole binary)
* Create a runnable version from the source code that can be used with GDB by adding DWARF debug symbols to the binary
* Allow for manual disassembly starting at a certain offset if disassembly goes off the rails
