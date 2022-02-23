
## Overview
memtrace is a debugger allowing to trace memory allocations for debugging memory leaks.

It's main advantages are:
- It can be attached to a process already runninng
- Reliable callstack based on debug symbols (implementation in progress)
- Cross-debugging (No debug symbols needed on the target process)
- Supported Platforms: x64, arm

## Debugging with MEMTRACE
```
 TARGET   ptrace TARGET
memtrace <-----> process (with debug symbols)
```

- memtrace set breakpoints on malloc, calloc, free, realloc (with ptrace) to follow memory allocations
- memtrace retrieve the callstack of the target process each time it performs a memory allocation
- target process and libraries MUST have debug symbols (.debug_info elf section)

### Compilation
```
$ cd memtrace
$ make
$ make install
```

### Usage
```
memtrace [OPTION]... -p PID
memtrace [OPTION]... PROGRAM [ARG]...
```

## Cross-debugging with MEMTRACE
```
    HOST       TCP    TARGET   ptrace TARGET
memtrace-fs <------> memtrace <-----> process (without debug symbols)
stagingdir
```

- memtrace can be attached to a process without debug symbols (Example: Embedded systems with limited flash memory)
- memtrace-fs provide the libraries with debug symbols to memtrace through a TCP socket

### Cross-Compilation
```
$ cd memtrace
$ export CC=arm-linux-gnueabi-gcc
$ make
$ make install
```

### Local network
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

### Non local nework
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

### Usage
memtrace provide a console to inspect the HEAP usage. It currently offers the following commands:
```
> help
List of commands:
       help: Display this help
       quit: Quit memtrace
     status: Show memtrace status
    monitor: Monitor memory allocations
     report: Show memtrace report
      clear: Clear memory statistics

# Show HEAP summary
> status
HEAP SUMMARY Wed Feb 23 16:31:51 2022

    in use: 0 bytes in 0 blocks
    total heap usage: 205 allocs, 205 frees, 51885 bytes allocated

# Clear current statistics
> clear
Clearing list of allocations
>
> status
HEAP SUMMARY Wed Feb 23 16:32:08 2022

    in use: 0 bytes in 0 blocks
    total heap usage: 0 allocs, 0 frees, 0 bytes allocated
>

# Monitor every 3x seconds the HEAP status
> monitor 3 
Start monitoring
HEAP SUMMARY Wed Feb 23 16:35:43 2022

    in use: 0 bytes in 0 blocks
    total heap usage: 82 allocs, 82 frees, 20754 bytes allocated
> HEAP SUMMARY Wed Feb 23 16:35:46 2022

    in use: 0 bytes in 0 blocks
    total heap usage: 123 allocs, 123 frees, 31131 bytes allocated

# Show complete HEAP report with backtrace of each allocation
# No memory loss, here
> report
[libraries]
[0xab0b2000-0xab0eb000] [/sbin/dnsmasq]
[0xf6d58000-0xf6d70000] [/usr/lib/pcb/libpcb_serialize_odl.so]
[0xf6d81000-0xf6d8b000] [/usr/lib/pcb/libpcb_serialize_ddw.so]
[0xf6d9c000-0xf6da5000] [/lib/libnss_files.so.2]
[0xf6dbc000-0xf6dc2000] [/lib/librt.so.1]
[0xf6dd3000-0xf6efe000] [/lib/libc.so.6]
[0xf6f14000-0xf6f16000] [/lib/libsahtrace.so]
[0xf6f27000-0xf6f29000] [/lib/libdl.so.2]
[0xf6f3a000-0xf6f50000] [/lib/libpthread.so.0]
[0xf6f63000-0xf6f7b000] [/lib/libpcb_utils.so]
[0xf6f8c000-0xf6f98000] [/lib/libpcb_sl.so]
[0xf6fa9000-0xf6fe9000] [/lib/libpcb_dm.so]
[0xf6ffb000-0xf6ffc000] [/lib/libpcb_preload.so]
[0xf700d000-0xf702e000] [/lib/ld-2.26.so]

[memtrace] report
HEAP SUMMARY:
    in use at exit: 0 bytes in 0 blocks
    total heap usage: 164 allocs, 164 frees, 41508 bytes allocated


# Memtrace can also be run until program termination
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


## TODO
- Improve search performance of FDE by auto-generating .eh_frame_hdr if missing
- Improve compliance with DWARF standard (.eh_frame)
- Add MIPS support
- Improve this README
- Cleanup old references to libunwind and others
- Improve console support (move cursor)

