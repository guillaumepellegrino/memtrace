
## 1. Overview
memtrace is a debugger allowing to trace memory allocations for debugging memory leaks targeted for Linux Embedded Systems.

It's main advantages are:

- It can be attached to a process already runninng
- Cross-debugging (No debug symbols needed on the target process)
- gdb support for inspecting memory allocation context
- Supported Platforms: x64, arm

## 2. Local debugging with MEMTRACE
### 2.1 Architecture
```
  HOST    ptrace   HOST
memtrace <------> process (with debug symbols)
addr2line
gdb
```

- memtrace set breakpoints on malloc, calloc, free, realloc (with ptrace) to follow memory allocations
- memtrace retrieve the callstack of the target process each time it performs a memory allocation
- memtrace rely on addr2line and gdb to analyse callstack
- target process and libraries MUST have debug symbols (.debug_info elf section)

### 2.2 Compilation
```
$ cd memtrace
$ make
$ make install
```

### 2.3 Usage
```
memtrace [OPTION]... -p PID
memtrace [OPTION]... PROGRAM [ARG]...
```

## 3. Cross-debugging with MEMTRACE
### 3.1 Architecture

```
    HOST       TCP    TARGET   ptrace  TARGET
memtrace-fs <------> memtrace <------> process (without debug symbols)
stagingdir
gdb
addr2line
```

- memtrace can be attached to a process without debug symbols (Example: Embedded systems with limited flash memory)
- memtrace-fs provide addr2line and gdb tools to memtrace for callstack analysis
- memtrace-fs provide the libraries with debug symbols to memtrace through a TCP socket


### 3.2 Cross-Compilation
```
$ cd memtrace
$ export CC=arm-linux-gnueabi-gcc
$ make
$ make install
```

### 3.3 Local network
```
# Start memtrace-fs on Host.
# The service will listen on port 3002 and annouce itself with multicast.
# The service allow memtrace to retrieve debug symbols from staging directory
guillaume@ubuntu:~$ memtrace-fs output/staging/
Adding directory output/staging/ to search path
Listening on [::0]:3002
Waiting for client to connect


# Attach memtrace to process on Target
# memtrace will start to query memtrace-fs service with multicast and try to connect to it
# Once connected, it set breakpoints on allocation functions to track the memory
/cfg/system/root # /ext/memtrace -p $(pidof dnsmasq)
Query memtrace-fs service on [224.0.0.251]:3002
memtrace-fs announced on 192.168.1.104:3002
Connecting to [192.168.1.104]:3002
Connected
Ataching to pid 16563
Opening /sbin/dnsmasq begin=0xab0b2000 offset=10000
Opening /usr/lib/pcb/libpcb_serialize_odl.so begin=0xf6d58000 offset=0
Opening /usr/lib/pcb/libpcb_serialize_ddw.so begin=0xf6d81000 offset=0
Opening /lib/libnss_files.so.2 begin=0xf6d9c000 offset=0
Opening /lib/librt.so.1 begin=0xf6dbc000 offset=0
Opening /lib/libc.so.6 begin=0xf6dd3000 offset=0
Opening /lib/libsahtrace.so begin=0xf6f14000 offset=0
Opening /lib/libdl.so.2 begin=0xf6f27000 offset=0
Opening /lib/libpthread.so.0 begin=0xf6f3a000 offset=0
Opening /lib/libpcb_utils.so begin=0xf6f63000 offset=0
Opening /lib/libpcb_sl.so begin=0xf6f8c000 offset=0
Opening /lib/libpcb_dm.so begin=0xf6fa9000 offset=0
Opening /lib/libpcb_preload.so begin=0xf6ffb000 offset=0
Opening /lib/ld-2.26.so begin=0xf700d000 offset=0
Set breakpoint on malloc in /lib/libc.so.6:0x70ed8 (0xf6e43ed8)
Set breakpoint on calloc in /lib/libc.so.6:0x71d0c (0xf6e44d0c)
Set breakpoint on realloc in /lib/libc.so.6:0x71784 (0xf6e44784)
Set breakpoint on reallocarray in /lib/libc.so.6:0x74484 (0xf6e47484)
Set breakpoint on free in /lib/libc.so.6:0x7162c (0xf6e4462c)
```

### 3.4 Non local nework
When target is not running on local network, memtrace can not rely on multicast to discover memtrace-fs.
In this case, it is useful to start memtrace as a tcp server and memtrace-fs as a tcp client. Roles can be inverted if needed.

```
# Attach memtrace to process on Target
# memtrace will listen on tcp port 3002 and wait for memtrace-fs to connect
/cfg/system/root # /ext/memtrace -p $(pidof dnsmasq) -l 0.0.0.0
Listening on [0.0.0.0]:3002
Waiting for client to connect

# Ask memtrace-fs on Host to connect to memtrace on Target
guillaume@ubuntu:~$ memtrace-fs -c targethostname.com  workspace/ib3_12.02.12/output/staging/
Adding directory workspace/ib3_12.02.12/output/staging/ to search path
Connect to [targethostname.com]:3002
Connecting to [targethostname.com]:3002
Connected

# You should now have the hand on Target
Client connected
Ataching to pid 16563
Opening /sbin/dnsmasq begin=0xab0b2000 offset=10000
Opening /usr/lib/pcb/libpcb_serialize_odl.so begin=0xf6d58000 offset=0
Opening /usr/lib/pcb/libpcb_serialize_ddw.so begin=0xf6d81000 offset=0
Opening /lib/libnss_files.so.2 begin=0xf6d9c000 offset=0
Opening /lib/librt.so.1 begin=0xf6dbc000 offset=0
Opening /lib/libc.so.6 begin=0xf6dd3000 offset=0
Opening /lib/libsahtrace.so begin=0xf6f14000 offset=0
Opening /lib/libdl.so.2 begin=0xf6f27000 offset=0
Opening /lib/libpthread.so.0 begin=0xf6f3a000 offset=0
Opening /lib/libpcb_utils.so begin=0xf6f63000 offset=0
Opening /lib/libpcb_sl.so begin=0xf6f8c000 offset=0
Opening /lib/libpcb_dm.so begin=0xf6fa9000 offset=0
Opening /lib/libpcb_preload.so begin=0xf6ffb000 offset=0
Opening /lib/ld-2.26.so begin=0xf700d000 offset=0
Set breakpoint on malloc in /lib/libc.so.6:0x70ed8 (0xf6e43ed8)
Set breakpoint on calloc in /lib/libc.so.6:0x71d0c (0xf6e44d0c)
Set breakpoint on realloc in /lib/libc.so.6:0x71784 (0xf6e44784)
Set breakpoint on reallocarray in /lib/libc.so.6:0x74484 (0xf6e47484)
Set breakpoint on free in /lib/libc.so.6:0x7162c (0xf6e4462c)
> 
```

## 4. Console Usage
memtrace provide a console to inspect the HEAP usage. It currently offers the following commands:
```
> help
List of commands:
       help: Display this help
       quit: Quit memtrace and show report
     status: Show memtrace status
    monitor: Monitor memory allocations
     report: Show memtrace report
      clear: Clear memory statistics
   coredump: Inspect memory alllocation with a coredump
        gdb: Inspect memory allocation with gdb
```

### 4.1 Show HEAP summary
This command allow to show the HEAP status.
  
Following the HEAP status evolution may help to detect when a program is leaking meory.
```
> status
HEAP SUMMARY Wed Feb 23 16:31:51 2022

    in use: 0 bytes in 0 blocks
    total heap usage: 205 allocs, 205 frees, 51885 bytes allocated
```

### 4.2 Clear current statistics
```
> clear
Clearing list of allocations
>
> status
HEAP SUMMARY Wed Feb 23 16:32:08 2022

    in use: 0 bytes in 0 blocks
    total heap usage: 0 allocs, 0 frees, 0 bytes allocated
>
```

### 4.3 Monitor the HEAP status
This command allow to monitor every 3x seconds the HEAP status.

It is convenient way to avoid running **status** command in loop.
```
> monitor 3 
Start monitoring
HEAP SUMMARY Wed Feb 23 16:35:43 2022

    in use: 0 bytes in 0 blocks
    total heap usage: 82 allocs, 82 frees, 20754 bytes allocated

HEAP SUMMARY Wed Feb 23 16:35:46 2022

    in use: 0 bytes in 0 blocks
    total heap usage: 123 allocs, 123 frees, 31131 bytes allocated
```

### 4.4 Show complete HEAP report with backtrace of each allocation
Example with selftest:
```
> report
[libraries]
[0x55d5771b6000-0x55d5771cb000] [/home/guillaume/Workspace/memtrace/target/memtrace]
[0x7fada9bc6000-0x7fada9d0e000] [/usr/lib/x86_64-linux-gnu/libc-2.33.so]
[0x7fada9d89000-0x7fada9dad000] [/usr/lib/x86_64-linux-gnu/ld-2.33.so]

[memtrace] report
Memory allocation context n°0
252 bytes in 63 blocks were not free
action_loop() in /home/guillaume/Workspace/memtrace/target/../src/selftest.c:341
selftest_main() in /home/guillaume/Workspace/memtrace/target/../src/selftest.c:510
??:?() in thrd_yield
??:?() in confstr
main() in /home/guillaume/Workspace/memtrace/target/../src/memtrace.c:1280
??:?() in _dl_rtld_di_serinfo
??:?() in _dl_catch_exception
??:?() in _dl_rtld_di_serinfo
??:?() in _dl_exception_free
memtrace_stdin_handler() in /home/guillaume/Workspace/memtrace/target/../src/memtrace.c:1175

Memory allocation context n°1
168 bytes in 21 blocks were not free
action_loop() in /home/guillaume/Workspace/memtrace/target/../src/selftest.c:345
selftest_main() in /home/guillaume/Workspace/memtrace/target/../src/selftest.c:510
??:?() in thrd_yield
??:?() in confstr
main() in /home/guillaume/Workspace/memtrace/target/../src/memtrace.c:1280
??:?() in _dl_rtld_di_serinfo
??:?() in _dl_catch_exception
??:?() in _dl_rtld_di_serinfo
??:?() in _dl_exception_free
memtrace_stdin_handler() in /home/guillaume/Workspace/memtrace/target/../src/memtrace.c:1175

HEAP SUMMARY Sun Mar 20 12:38:54 2022

    in use: 420 bytes in 2 blocks
    total heap usage: 84 allocs, 0 frees, 420 bytes allocated
> 
```

### 4.5 Generate a coredump for post-mortem analysis
Let's generate a coredump for Memory allocation context n°0 from previous chapter.
```
> coredump 0
Marking context number 0 for coredump generation
> Generating coredump for memory allocation context n°0
552 bytes in 139 blocks were not free
Writing coredump to /tmp/core
Coredump written in 5 msec

```

### 4.6 Inspect Memory allocation with GDB
This command generate a coredump for Memory allocation context n°0 from Chapter 4.4 and open it with GDB. It provide an interactive console to GDB. When GDB exist, memtrace resume normal execution.
```
> gdb 0
Marking context number 0 for gdb inspection
> Attaching gdb to memory allocation context n°0
1632 bytes in 409 blocks were not free
Starting process 'gdb'
GNU gdb (Debian 10.1-2) 10.1.90.20210103-git
Copyright (C) 2021 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
(gdb) set sysroot 
(gdb) set solib-search-path .
(gdb) set solib-search-path 
(gdb) directory .
Source directories searched: /home/guillaume/Workspace/memtrace:$cdir:$cwd
(gdb) file /home/guillaume/Workspace/memtrace/target/memtrace
Reading symbols from /home/guillaume/Workspace/memtrace/target/memtrace...
(gdb) core-file /tmp/memtrace-target.core
warning: core file may not match specified executable file.
[New LWP 28190]
Core was generated by `./target/memtrace --selftest --action loop'.
#0  __libc_calloc (n=n@entry=1, elem_size=elem_size@entry=4) at malloc.c:3586
3586	malloc.c: Aucun fichier ou dossier de ce type.
(gdb) backtrace
#0  __libc_calloc (n=n@entry=1, elem_size=elem_size@entry=4) at malloc.c:3586
#1  0x000055d5771bf044 in action_do_alloc_2 (size=4) at ../src/selftest.c:248
#2  action_loop () at ../src/selftest.c:340
#3  0x000055d5771c0049 in run_action (action=<optimized out>) at ../src/selftest.c:370
#4  selftest_main (argc=argc@entry=4, argv=argv@entry=0x7fff17acd5a8) at ../src/selftest.c:510
#5  0x000055d5771b6a87 in main (argc=4, argv=0x7fff17acd5a8) at ../src/memtrace.c:1280
(gdb) 
(gdb) quit

Memtrace resuming execution
> 

```

### 4.7 Memtrace can also be run until program termination
```

# Example with selftest program
guillaume@ubuntu: ~/workspace/memtrace$ ./target/memtrace ./target/memtrace --selftest --action multimalloc
Running memtrace in local mode
Ataching to pid 24102
> Opening /home/guillaume/workspace/memtrace/target/memtrace begin=0x56233764e000 offset=0
Opening /lib/x86_64-linux-gnu/ld-2.27.so begin=0x7f945b02f000 offset=0
Opening /lib/x86_64-linux-gnu/libc-2.27.so begin=0x7f945ac3e000 offset=0
Set breakpoint on malloc in /lib/x86_64-linux-gnu/libc-2.27.so:0x97140 (0x7f945acd5140)
Set breakpoint on calloc in /lib/x86_64-linux-gnu/libc-2.27.so:0x9a170 (0x7f945acd8170)
Set breakpoint on realloc in /lib/x86_64-linux-gnu/libc-2.27.so:0x98d70 (0x7f945acd6d70)
Set breakpoint on reallocarray in /lib/x86_64-linux-gnu/libc-2.27.so:0x9d1d0 (0x7f945acdb1d0)
Set breakpoint on free in /lib/x86_64-linux-gnu/libc-2.27.so:0x97a30 (0x7f945acd5a30)
Opening /lib/x86_64-linux-gnu/libc-2.27.so begin=0x7f945ac3e000 offset=0
Opening /lib/x86_64-linux-gnu/libc-2.27.so begin=0x7f945b02b000 offset=0
[WRN]  process 24102 exited with status:0 in ptrace_wait:45
[libraries]
[0x56233764e000-0x56233766b000] [/home/guillaume/workspace/memtrace/target/memtrace]
[0x7f945b02f000-0x7f945b058000] [/lib/x86_64-linux-gnu/ld-2.27.so]
[0x7f945ac3e000-0x7f945b02f000] [/lib/x86_64-linux-gnu/libc-2.27.so]
[0x7f945ac3e000-0x7f945ae25000] [/lib/x86_64-linux-gnu/libc-2.27.so]
[0x7f945b02b000-0x7f945b02f000] [/lib/x86_64-linux-gnu/libc-2.27.so]

[memtrace] report
150 bytes in 50 blocks were not free
__libc_calloc() in /build/glibc-S9d2JN/glibc-2.27/malloc/malloc.c:3389
action_multimalloc() in /home/guillaume/workspace/memtrace/target/../src/selftest.c:265
run_action() in /home/guillaume/workspace/memtrace/target/../src/selftest.c:354
__GI___sbrk() in /build/glibc-S9d2JN/glibc-2.27/misc/sbrk.c:56
__GI___default_morecore() in /build/glibc-S9d2JN/glibc-2.27/malloc/morecore.c:49
process_long_option() in /build/glibc-S9d2JN/glibc-2.27/posix/getopt.c:213

265 bytes in 5 blocks were not free
__GI___libc_malloc() in /build/glibc-S9d2JN/glibc-2.27/malloc/malloc.c:3038
action_multimalloc() in /home/guillaume/workspace/memtrace/target/../src/selftest.c:256
run_action() in /home/guillaume/workspace/memtrace/target/../src/selftest.c:354
__GI___sbrk() in /build/glibc-S9d2JN/glibc-2.27/misc/sbrk.c:56
__GI___default_morecore() in /build/glibc-S9d2JN/glibc-2.27/malloc/morecore.c:49
process_long_option() in /build/glibc-S9d2JN/glibc-2.27/posix/getopt.c:213

137 bytes in 1 blocks were not free
__GI___libc_malloc() in /build/glibc-S9d2JN/glibc-2.27/malloc/malloc.c:3038
action_multimalloc() in /home/guillaume/workspace/memtrace/target/../src/selftest.c:272
run_action() in /home/guillaume/workspace/memtrace/target/../src/selftest.c:354
__GI___sbrk() in /build/glibc-S9d2JN/glibc-2.27/misc/sbrk.c:56
__GI___default_morecore() in /build/glibc-S9d2JN/glibc-2.27/malloc/morecore.c:49
process_long_option() in /build/glibc-S9d2JN/glibc-2.27/posix/getopt.c:213

10 bytes in 1 blocks were not free
__GI___libc_malloc() in /build/glibc-S9d2JN/glibc-2.27/malloc/malloc.c:3038
__GI___strdup() in /build/glibc-S9d2JN/glibc-2.27/string/strdup.c:44
addr2line_default_command() in /home/guillaume/workspace/memtrace/target/../src/memtrace.c:126

HEAP SUMMARY Wed Feb 23 16:47:11 2022

    in use: 562 bytes in 4 blocks
    total heap usage: 113 allocs, 56 frees, 980 bytes allocated
Detaching from pid 24102
```


## 5. TODO
- Add MIPS support
- Improve this README
- Improve console support (move cursor)
- Improve search performance of FDE by auto-generating .eh_frame_hdr if missing
- Improve compliance with DWARF standard (.eh_frame)