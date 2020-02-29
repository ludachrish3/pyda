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

* Create a fixup function that adds values for the stack (and maybe flags), copies destination into source when needed (mainly for just math?) 
* Create a register value that is the stack so that pushes and pops can have both a source and a destination
* Update tests
* Need to work on symbol resolution first so that more information is available for determining when functions end. For example, knowing when exit is called is a good way to indicate a possible end of function, like return would.
* Mark each function symbol when creating them for whether they should be disassembled or not. This is useful in cases where the symbol says the size is 0 bytes when it can actually be disassembled, like \_init()
* Use function sizes as more of a hint instead of a definite size. If it is nonzero, it's okay to trust it. If it's 0, then using the logic for finding functions in a stripped binary can be used to determine when the function ends. In this case, keeping the memory mapped file around is needed. This means that keeping the "assembly" field around for function symbols is unnecessary.
* Figure out which function is main() by figuring out which address is passed to \__libc_start_main()
* Add command line options for getting just some header info like objdump and readelf does. This should be pretty easy, and can be made more user friendly by using human readable strings.
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
* Figure out how to find address of \__cxa_finalize in ELF files. It appears in the .plt.got section, but there seems to be no address to its PLT entry.
