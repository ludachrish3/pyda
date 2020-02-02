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

* Memory map the file so that it can be opened once, read, closed, and only work with the buffer after that to avoid I/O costs
* Handle relocations so that all symbols can be resolved.
* Convert sources or maybe all operands to a list to be acted on together. This can simplify handling immediates and maybe other things if destination is included.
* Change error handling to be try blocks and raising exceptions instead of checking return values. Checking handleOperandAddressing() needs to be done in the case that an invalid segment register is used.
* In order to find functions in a stripped binary, start at beginning of .text section. Start disassembling and consider all jumps that can be taken. If there are no jumps left and a ret instruction is reached, then that is the end of the function. All instructions after it (not including NOPs) are another function.
* Come up with a way to find functions in stripped binaries
* Figure out how global variables and functions are linked to values (like how does calling printf() get figured out)
* Resolve addresses of external symbols
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
