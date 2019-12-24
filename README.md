# pyda

The goal of this project is to create a Python program that can disassemble and decompile programs of various types in an extensible way.

## Usage

```
usage: pyda.py -f FILE [-l] [-h]

required arguments:
  -f FILE, --file FILE  the binary file to analyze

optional arguments:
  -l , --log-level      Log level to use when printing logs
  -h, --help            Show this help message and exit
```

## Goals

* Support both Intel and AT&T assembly syntax
* Visual representation of the stack
* Resetting values of strings or arrays to be the value during runtime. The original value is also saved for reference.
* Analyzing DWARF info
* Entropy analysis
* Calling and called functions
* Highlight CALL instructions for when a functino pointer is dereferenced and called
* Cross references of addresses (aggressive matching of address throughout whole binary)
* Create a runnable version from the source code that can be used with GDB
