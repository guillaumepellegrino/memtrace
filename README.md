
## Overview
memtrace is a debugger allowing to trace memory allocations for debugging memory leaks.

It's main advantages are:
- It can be attached to a process already runninng
- Reliable callstack based on debug symbols
- Cross-debugging (No debug symbols needed on the target process)
- Supported Platforms: x64, arm

## Installation
### Compilation
```
$ cd memtrace
$ make
$ make install
```
### Cross-Compilation
```
$ cd memtrace
$ export CC=arm-linux-gnueabi-gcc
$ make
$ make install
```

## Debugging with MEMTRACE
```
 TARGET   ptrace TARGET
memtrace <-----> process (with debug symbols)
```

- memtrace set breakpoints on malloc, calloc, free, realloc (with ptrace) to follow memory allocations
- memtrace retrieve the callstack of the target process each time it performs a memory allocation
- target process and libraries MUST have debug symbols (.debug_info elf section)

## Cross-debugging with MEMTRACE
```
    HOST       TCP    TARGET   ptrace TARGET
memtrace-fs <------> memtrace <-----> process (without debug symbols)
stagingdir
```

- memtrace can be attached to a process without debug symbols (Example: Embedded systems with limited flash memory)
- memtrace-fs provide the libraries with debug symbols to memtrace through a TCP socket

## TODO
- Improve search performance of FDE in .eh_frame section by using .eh_frame_hdr
- Improve search performance in .debug_info and .debug_line.
- Improve compliance with DWARF standard (.eh_frame)
- Add ARM support
- Add MIPS support
- Add multicast support
- Improve this README
- Remove -ldl library
- Cleanup old references to libunwind and others
