
## 1. Overview
memtrace is a memory leak cross-debugger for Linux Embedded Systems.

- You can attach to a running process with `memtrace -p $pid` and track in real-time the top memory allocations. Stop the target process to get a report of what's left at exit.
- You can start a new program with memtrace attached: `memtrace PROG [ARGS]..`
- You can start endurance tests with `memtrace-endurance PROCNAME start`, let it run for a few hours/day, collect the results and view(plot) the evolution of the top memory allocations with `memtrace-viewer`.

The tool can run on stripped executables and libraries, without debug symbols on target platform.

You still need to have the debug symbols on your Host to decode the report. You can choose to either:
- Start memtrace without debug symbols support. You will still get 'raw' reports than you can decode afterwards on Host with memtrace-server: `memtrace-server --report /path/to/report` [STAGINGDIR]`
- Start memtrace with `--multicast` option to look for the memtrace-server running on your Host in your LAN network. memtrace will query the server to decode the report. The server can be started with `memtrace-server [STAGINGDIR]`.

It's main advantages are:
- It can be attached to a process already running
- Cross-debugging (No debug symbols needed on the target process)
- gdb support for inspecting memory allocation context
- Supported Platforms are x64, arm, aarch64 (arm64) and MIPS


## 2 Compilation
### 2.1 Compilation for Host Platform
```
$ cd memtrace
$ make -j12
$ sudo make install  # install memtrace-server on Host computer
$ sudo make -f Makefile.target install # install memtrace on Host computer
```

### 2.2 Compilation for Target Platform
```
$ cd memtrace
$ export CC=arm-linux-gnueabi-gcc
$ make -j12
$ sudo make install  # install memtrace-server on Host computer
$ DESTDIR=/path/to/dest make install  # install memtrace on rootfs target
```

### 2.3 Manual installation on target platform
Install memtrace agent and memtrace itself on target in the same folder:
```
$ scp build-XXX/libmemtrace-agent.so $hostname-target:/tmp/
$ scp build-XXX/memtrace $hostname-target:/tmp/
$ scp scripts/memtrace-endurance $hostname-target:/tmp/
```
> [!IMPORTANT]
> On some Embedded Linux, you may not have any writable partition with execution rights.
> So, you may need to give a partition with execution rights:
> ```
> $ mount -o remount,exec /tmp/
> ```

> [!IMPORTANT]
> On some Linux distribution, you may have apparmor protecting your target process
> from the injection of libmemtrace-agent.so (with dlopen()).
> So, you may need to disable apparmor for this purpose:
> ```
> $ echo -n "complain" > /sys/module/apparmor/parameters/mode
> ```


## 3. Endurance tests with Memtrace

memtrace-endurance is a script allowing to perform endurance tests with Memtrace.
The script will gather memory snapshot of the target process at regular interval.
You can let it run for a few hours or a few days and plot the results with memtrace-viewer.

#### Start the service you want to monitor:
![start-dummy](img/start-dummy.png)

#### Start memtrace-endurance:
![start-memtrace-endurance](img/start-memtrace-endurance.png)

> [!IMPORTANT]
> If you installed memtrace manually in /tmp on an Embedded Linux, you may start memtrace-endurance with:
> ```
> $ mount -o remount,exec /tmp/
> $ PATH="/tmp:$PATH" memtrace-endurance dummy start --interval 10
> ```

#### Check memtrace-endurance status:
![check-memtrace-endurance](img/check-memtrace-endurance.png)

#### Collect and view the endurance report:
![start-memtrace-viewer](img/start-memtrace-viewer.png)

![start-memtrace-viewer](img/memtrace-viewer.png)

> [!IMPORTANT]
> memtrace-viewer is a python script. You will need to install the following python dependencies:
> - matplotlib
> - mplcursors

#### Analyse the report:
Here, in this endurance report, we can see than our dummy program is leaking consistently memory in two places:
- `thread_loop()` in dummy.c at line 28
- `main()` in dummy.c at line 71

#### Considerations:
- memtrace-endurance can be started on a process without any debug symbols
- memtrace-viewer can decode the raw address into debug symbols with memtrace-server if the debug rootfs is provided in argument.
- memtrace-viewer can plot callstack with or without debug symbols. Without debug symbols, the global functions are still decoded but without the line numbers.

## 4. Debugging with Memtrace
### 4.1 General usage
```mermaid
sequenceDiagram
    actor User
    participant Memtrace
    participant TargetProcess
    participant MemtraceServer

    User->>MemtraceServer: Start memtrace-server on Host Computer
    User->>Memtrace: Start memtrace on Target
    Memtrace->>MemtraceServer: Connect to Server

    Memtrace->>+TargetProcess: Inject memtrace agent


    TargetProcess->>TargetProcess: memtrace-agent monitoring allocations
    TargetProcess->>TargetProcess: 
    TargetProcess->>TargetProcess: 
    TargetProcess->>TargetProcess: Process running and leaking memory
    TargetProcess->>TargetProcess: 
    TargetProcess->>TargetProcess: 


    User->>Memtrace: report command
    Memtrace->>TargetProcess: Get memory allocation report
    TargetProcess-->>Memtrace: 
    Memtrace->>MemtraceServer: Decode memory allocation report
    MemtraceServer-->>Memtrace: 
    Memtrace-->>User: 
    User->>User: Analyze memory leak report

```

### 4.2 Usage in local network for Cross-debugging.
```
# Start memtrace-server on Host.
# The service will listen on port 3002 and annouce itself with multicast.
# The service allow memtrace to retrieve debug symbols from build directory
guillaume@ubuntu:~$ memtrace-server output/staging/
Adding directory output/staging/ to search path
Listening on [0.0.0.0]:3002

# Attach memtrace to process on Target
# memtrace will:
# - inject the agent in target process to follow memory allocations
# - connect to the agent through ipc socket
# - discover server with a multicast query
# - connect to the server
/cfg/system/root # /tmp/memtrace -p $(pidof dnsmasq) --multicast


# In case multicast is filtered on your network, you can specify directly the IP Address of the server:
/cfg/system/root # /tmp/memtrace -p $(pidof dnsmasq) --connect 192.168.1.101:3002
```

### 4.3 Non local nework
When target is not running on local network, memtrace can not rely on multicast to discover memtrace-server .
In this case, it is useful to start memtrace as a tcp server and memtrace-server as a tcp client. Roles can be inverted if needed.

```
# Attach memtrace to process on Target
# memtrace will listen on tcp port 3002 and wait for memtrace-fs to connect
/cfg/system/root # /tmp/memtrace -p $(pidof dnsmasq) -l 0.0.0.0
Listening on [0.0.0.0]:3002
Waiting for client to connect

# Ask memtrace-server on Host to connect to memtrace on Target
guillaume@ubuntu:~$ memtrace-server -c targethostname.com  workspace/ib3_12.02.12/output/staging/
Adding directory workspace/ib3_12.02.12/output/staging/ to search path
Connect to [targethostname.com]:3002
Connecting to [targethostname.com]:3002
Connected

# You should now have the hand on Target
```

### 4.4 Offline Usage
When memtrace client has no possibility to connect to memtrace server, it is possible to start memtrace 'offline'.
/ # /tmp/memtrace -p $(pidof dummy) 

You can still generate 'report' but you will need to decode it offline with memtrace-server.

```
/ # /tmp/memtrace -p $(pidof dummy) 
Try to find /usr/lib/libmemtrace-agent.so
Try to find /tmp/libmemtrace-agent.so
Memtrace agent is /tmp/libmemtrace-agent.so
Memtrace agent is already injected in target process
Memtrace is connected to target process 14612
Enter 'help' for listing possible commands

> report
memtrace report:
[sysroot]/path/to/sysroot
[toolchain]/path/to/toolchain
Memory allocation context n°0
185 allocs, 1295 bytes were not free
[addr]/lib/libc.so.6+0x70ed8 | __libc_malloc()+0x0
[addr]/lib/libc.so.6+0x753e0 | __strdup()+0x18
[addr]/tmp/dummy+0x1092c
[addr]/tmp/dummy+0x10924
[addr]/tmp/dummy+0x1084c | thread_loop()+0x44
[addr]/lib/libpthread.so.0+0x5f14
[addr]/lib/libc.so.6+0xd0658
[addr]/tmp/dummy+0x10808 | thread_loop()+0x0
[addr]/lib/libc.so.6+0x10e508
[addr]/lib/libc.so.6+0x10eb08
[addr]/lib/libc.so.6+0x10f408

HEAP SUMMARY Sun Jun 11 16:21:36 2023

    in use: 185 allocs, 1295 bytes in 1 contexts
    total heap usage: 370 allocs, 185 frees, 2220 bytes allocated
    memory leaked since last hour: 0 allocs, 0 bytes

memtrace-server --report /path/to/encoded/report build-arm-buildroot-linux-gnueabi/dummy
__libc_malloc() in /opt/arm-buildroot-linux-gnueabi/sysroot//lib/libc.so.6
__strdup() in /opt/arm-buildroot-linux-gnueabi/sysroot//lib/libc.so.6
deregister_tm_clones() in build-arm-buildroot-linux-gnueabi/dummy
deregister_tm_clones() in build-arm-buildroot-linux-gnueabi/dummy
main() in /home/sahphilog2/Workspace/memtrace/src/dummy.c:62
start_thread() in /opt/arm-buildroot-linux-gnueabi/sysroot//lib/libpthread.so.0
clone() in /opt/arm-buildroot-linux-gnueabi/sysroot//lib/libc.so.6
main() in /home/sahphilog2/Workspace/memtrace/src/dummy.c:99
```

## 5. Console Usage
memtrace provide a console to inspect the HEAP usage. It currently offers the following commands:
```
> help
List of commands:
       help: Display this help
       quit: Quit memtrace and show report
     status: Show memtrace status
    monitor: Monitor memory allocations. monitor --help for more details.
     report: Show memtrace report. report --help for more details.
  logreport: Log reports at a regular interval in specified file. log --help for more details.
   coredump: Mark a memory context for coredump generation. coredump --help for more details.
      break: Break on specified function.
      clear: Clear memory statistics

```

### 5.1 Show HEAP summary
This command allow to show the HEAP status.
  
Following the HEAP status evolution may help to detect when a program is leaking meory.
```
> status
HEAP SUMMARY Wed Feb 23 16:31:51 2022

    in use: 0 bytes in 0 blocks
    total heap usage: 205 allocs, 205 frees, 51885 bytes allocated
```

### 5.2 Clear current statistics
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

### 5.3 Monitor the HEAP status
```
> monitor --help
Usage: monitor [OPTION]..
Toggle ON/OFF the monitoring of the process
  -h, --help             Display this help
  -i, --interval=VALUE   Start monitoring at the specified interval value in seconds
  -s, --stop             Stop monitoring
> 
> monitor
> HEAP SUMMARY Sun Jun 11 16:12:42 2023

    in use: 66 allocs, 462 bytes in 1 contexts
    total heap usage: 132 allocs, 66 frees, 792 bytes allocated
    memory leaked since last hour: 0 allocs, 0 bytes
HEAP SUMMARY Sun Jun 11 16:12:45 2023

    in use: 69 allocs, 483 bytes in 1 contexts
    total heap usage: 138 allocs, 69 frees, 828 bytes allocated
    memory leaked since last hour: 0 allocs, 0 bytes
HEAP SUMMARY Sun Jun 11 16:12:48 2023

    in use: 72 allocs, 504 bytes in 1 contexts
    total heap usage: 144 allocs, 72 frees, 864 bytes allocated
    memory leaked since last hour: 0 allocs, 0 bytes
HEAP SUMMARY Sun Jun 11 16:12:51 2023
```

### 5.4 Show complete HEAP report with backtrace of each allocation
```
> report -h
Usage: report [OPTION]..
Generate a memory usage report
  -h, --help             Display this help
  -c, --count=VALUE      Count of memory contexts to display (default:10)
```

### 5.5 Generate a coredump for post-mortem analysis
```
> coredump --help
Usage: coredump [OPTION]..
Mark a memory context for coredump generation
  -h, --help             Display this help
  -c, --context=VALUE    Mark the specified memory context for coredump generation (default:core.20328)
  -n, --now              Generate a breakpoint, now !
  -f, --file=PATH        Write the coredump to the specified path

> coredump -c 0 -f /tmp/core
Attaching to 20328
memtrace attached to pid:20328/tid:20328
memtrace attached to pid:20328/tid:20330
memtrace attached to pid:20328/tid:21299
Setting breakpoint on malloc_hook at 0x55860 (/tmp/libmemtrace-agent.so+0x5860)
Breakpoint was hit !
Writing coredump to /tmp/core
Writing coredump done
Detaching from 20328
```

### 5.6 Log reports periodically
Let's say you have an hard time to track a memory leak which manifests after quite a long time.

In this case, you may want to let run memtrace for few hours or even few days without any active supervision.

For this purpose, you may simply ask memtrace to run reports periodically until you stop it or until OOM killer or kernel panic kicks-in.

```
> logreport -h
Usage: log [OPTION].. [FILE]
Log reports at a regular interval to the specified file. (default is /ext/memtrace-2630.log)
  -h, --help             Display this help
  -i, --interval=VALUE   Start monitoring at the specified interval value in seconds
  -c, --count=VALUE      Count of print memory context in each report
  -f, --foreground       Keep memtrace in foreground

> logreport --interval 600 memtrace-endurance-test.log
memtrace logs report every 600s in memtrace-endurance-test.log

Daemonize memtrace
```

The report logger will run as a background task by default.
You will need to kill it by hand if you want to stop it:
```
/cfg/system/root # ps | grep memt
12232 root      1944 S    /tmp/memtrace -p 2630 
12564 root      2004 S    grep memt 
/cfg/system/root #
/cfg/system/root # killall memtrace
```

### 6. Architecture
```mermaid
sequenceDiagram
    actor User
    participant Memtrace
    participant TargetProcess
    participant MemtraceAgent
    participant MemtraceServer

    User->>MemtraceServer: Start memtrace-server on Host Computer
    User->>Memtrace: Start memtrace on Target


    Memtrace->>+TargetProcess: ptrace(PTRACE_ATTACH, pid)
    Memtrace->>TargetProcess: ptrace(PTRACE_SYSCALL, pid)
    Memtrace->>+TargetProcess: wait(pid)
    TargetProcess->>TargetProcess: syscall
    TargetProcess-->>-Memtrace: wait(pid)
    Memtrace->>TargetProcess: Inject libMemtraceAgent.so
    Memtrace->>TargetProcess: Override malloc() functions
    TargetProcess-->>-Memtrace: ptrace(PTRACE_DETACH, pid)

    TargetProcess->>TargetProcess: malloc()
    TargetProcess->>MemtraceAgent: pthread_create()
    MemtraceAgent->>MemtraceAgent: Create ipc listen socket
    Memtrace->>Memtrace: ipc connect loop
    Memtrace->>MemtraceAgent: ipc connect

    Memtrace->>+MemtraceServer: Query MemtraceServer (udp multicast)
    MemtraceServer-->>-Memtrace: Announce MemtraceServer (udp)
    Memtrace->>MemtraceServer: TCP Connect

    MemtraceAgent->>+TargetProcess: Monitor memory alllocations
    TargetProcess->>TargetProcess: 
    TargetProcess->>TargetProcess: 
    TargetProcess->>TargetProcess: 
    TargetProcess->>TargetProcess: Process running and leaking memory
    TargetProcess->>TargetProcess: 
    TargetProcess->>TargetProcess: 


    User->>Memtrace: report command
    Memtrace->>MemtraceAgent:Forward report command to MemtraceAgent
    TargetProcess-->>-MemtraceAgent: Raw memory alllocations report
    MemtraceAgent-->>Memtrace:Raw memory allocations report
    Memtrace->>MemtraceServer:Forward raw memory allocations report
    MemtraceServer->>MemtraceServer: Decode report with addr2line
    MemtraceServer-->>Memtrace: Decoded memory allocation report
    Memtrace-->>User: Decoded memory allocation report
    User->>User: Analyze memory leak report
```

- memtrace inject an agent in the target process and override all memory allocations functions (malloc, calloc, realloc, free) with ptrace.
- The agent maintains the statistics and the callstack of the memory allocations done by the target process.
- memtrace can be attached to a process without debug symbols (Example: Embedded systems with limited flash memory)
- memtrace query the agent (status, report) through an ipc socket.
- memtrace-server provide addr2line and gdb tools to memtrace for callstack analysis


## 7. TODO
Improvement idea:
- How to handle apparmor properly ?
- memtrace-endurance should append coredump(s) of the context(s) with the highest memory usage to the .tar.gz archive
- Scan for definitely lost memory. Maybe count the number of reference of each pointer in /dev/$pid/mem ? One problem maybe than the libmemtrace-agent itself is referencing such pointers.
