/*
 * Copyright (C) 2022 Guillaume Pellegrino
 * This file is part of memtrace <https://github.com/guillaumepellegrino/memtrace>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include "evlp.h"
#include "bus.h"
#include "inject.h"
#include "threads.h"
#include "breakpoint.h"
#include "libraries.h"
#include "console.h"
#include "coredump.h"
#include "elf_main.h"
#include "elf_sym.h"
#include "memfd.h"
#include "selftest.h"
#include "arch.h"
#include "log.h"

typedef struct {
    evlp_t *evlp;
    evlp_handler_t stdin_handler;
    evlp_handler_t timerfd_handler;
    int timerfd;
    char *logfile;
    int logcount;
    console_t console;
    bus_t server;
    bus_t agent;
    strlist_t commands;
    int pid;
    const char *inject_libname;
} memtrace_t;

static const char *default_lib =  "/usr/lib/libmemtrace-agent.so";
static const struct {
    const char *name;
    const char *inject;
} alloc_functions[] = {
    {"malloc",          "malloc_hook"},
    {"calloc",          "calloc_hook"},
    {"realloc",         "realloc_hook"},
    {"reallocarray",    "reallocarray_hook"},
    {"free",            "free_hook"},
    {"fork",            "fork_hook"},
};

__attribute__((aligned)) char g_buff[G_BUFF_SIZE];

static const char *defaultdir() {
    struct stat stbuf;
    bool ext = stat("/ext", &stbuf) == 0;
    return ext ? "/ext" : "/tmp";
}

static bool connect_to_memtrace_agent(bus_t *bus, int pid) {
    struct sockaddr_un connaddr = {
        .sun_family = AF_UNIX,
    };
    struct stat buf = {0};
    int s = -1;
    bool rt = false;

    snprintf(connaddr.sun_path, sizeof(connaddr.sun_path),
        "/tmp/memtrace-agent-%d", pid);

    // Wait for agent to be ready
    for (int i = 0; true; i++) {
        if (stat(connaddr.sun_path, &buf) == 0) {
            break;
        }
        if (i == 0) {
            CONSOLE("memtrace agent is not yet ready");
            CONSOLE("Waiting for target process to perform at least one memory allocation");
        }
        if (usleep(200*1000) != 0) {
            TRACE_ERROR("usleep(): %m");
            break;
        }
    }

    if ((s = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0)) < 0) {
        printf("Failed to create ipc socket: %m\n");
        goto error;
    }
    if (connect(s, (struct sockaddr *) &connaddr, sizeof(connaddr)) != 0) {
        printf("Failed to connect ipc socket to %s: %m\n", connaddr.sun_path);
        goto error;
    }
    if (!bus_ipc_socket(bus, s)) {
        printf("Failed to add ipc socket to bus\n");
        goto error;
    }
    rt = true;

error:
    if (!rt) {
        close(s);
    }
    return rt;
}

static void memtrace_stop_evlp(memtrace_t *memtrace) {
    //CONSOLE("Stoping EVLP");
    evlp_stop(memtrace->evlp);
}

static bool memtrace_report(memtrace_t *memtrace, int count, FILE *fp) {
    char line[4096];
    strmap_t options = {0};
    bus_connection_t *ipc = NULL;
    bus_connection_t *server = NULL;
    bus_connection_t *in = NULL;

    if (!(ipc = bus_first_connection(&memtrace->agent))) {
        CONSOLE("memtrace is not connected to target process");
        return false;
    }
    if (count) {
        strmap_add_fmt(&options, "count", "%d", count);
    }
    bus_connection_write_request(ipc, "report", &options);

    // Are we connected to memtrace-server ?
    if ((server = bus_first_connection(&memtrace->server))) {
        // Forward report to memtrace-server for decodding addresses to line and functions
        bus_connection_write_request(server, "report", NULL);
        while (bus_connection_readline(ipc, line, sizeof(line))) {
            bus_connection_printf(server, "%s", line);
            if (!strcmp(line, "[cmd_done]\n")) {
                break;
            }
        }
        bus_connection_flush(server);
    }

    // Read report and dump it on console
    in = server ? server : ipc;
    while (bus_connection_readline(in, line, sizeof(line))) {
        if (!strcmp(line, "[cmd_done]\n")) {
            break;
        }
        else {
            fputs(line, fp);
        }
    }

    strmap_cleanup(&options);
    return true;
}

static void memtrace_console_quit(console_t *console, int argc, char *argv[]) {
    memtrace_t *memtrace = container_of(console, memtrace_t, console);
    memtrace_stop_evlp(memtrace);
}

static void memtrace_console_forward(console_t *console, int argc, char *argv[]) {
    char line[4096];
    memtrace_t *memtrace = container_of(console, memtrace_t, console);
    bus_connection_t *ipc = NULL;

    if (!(ipc = bus_first_connection(&memtrace->agent))) {
        CONSOLE("memtrace is not connected to target process");
        return;
    }

    bus_connection_write_request(ipc, argv[0], NULL);
    while (bus_connection_readline(ipc, line, sizeof(line))) {
        if (!strcmp(line, "[cmd_done]\n")) {
            break;
        }
        CONSOLE_RAW("%s", line);
    }
    fflush(stderr);
}

static void memtrace_console_monitor(console_t *console, int argc, char *argv[]) {
    memtrace_t *memtrace = container_of(console, memtrace_t, console);
    const char *short_options = "+i:sh";
    const struct option long_options[] = {
        {"interval",    required_argument,  0, 'i'},
        {"stop",        no_argument,        0, 's'},
        {"help",        no_argument,        0, 'h'},
        {0},
    };
    int opt = -1;
    struct itimerspec itimer = {
        .it_value.tv_sec = 0,
        .it_value.tv_nsec = 1,
        .it_interval.tv_sec = 3,
    };
    static bool is_running = false;

    optind = 1;
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                itimer.it_interval.tv_sec = atoi(optarg);
                itimer.it_value.tv_nsec = itimer.it_interval.tv_sec ? 1 : 0;
                break;
            case 's':
                itimer.it_value.tv_sec = 0;
                itimer.it_value.tv_nsec = 0;
                break;
            case 'h':
            default:
                CONSOLE("Usage: monitor [OPTION]..");
                CONSOLE("Toggle ON/OFF the monitoring of the process");
                CONSOLE("  -h, --help             Display this help");
                CONSOLE("  -i, --interval=VALUE   Start monitoring at the specified interval value in seconds");
                CONSOLE("  -s, --stop             Stop monitoring");
                return;
        }
    }

    if (argc == 1) {
        // Toggle ON/OFF when no argument is provided
        itimer.it_value.tv_nsec = is_running ? 0 : 1;
    }

    timerfd_settime(memtrace->timerfd, 0, &itimer, NULL);
    is_running = itimer.it_value.tv_nsec;
}

static void memtrace_console_logreport(console_t *console, int argc, char *argv[]) {
    const char *short_options = "+i:c:fsh";
    const struct option long_options[] = {
        {"interval",    required_argument,  0, 'i'},
        {"count",       required_argument,  0, 'c'},
        {"foreground",  no_argument,        0, 'f'},
        {"help",        no_argument,        0, 'h'},
        {0},
    };
    int opt = -1;
    memtrace_t *memtrace = container_of(console, memtrace_t, console);
    bool foreground = false;
    struct itimerspec itimer = {
        .it_value.tv_sec = 0,
        .it_value.tv_nsec = 1,
        .it_interval.tv_sec = 600,
    };
    memtrace->logcount = 10;

    optind = 1;
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                itimer.it_interval.tv_sec = atoi(optarg);
                break;
            case 'c':
                memtrace->logcount = atoi(optarg);
                break;
            case 'f':
                foreground = true;
                break;
            case 'h':
            default:
                CONSOLE("Usage: log [OPTION].. [FILE]");
                CONSOLE("Log reports at a regular interval to the specified file. (default is %s/memtrace-%d.log)",
                    defaultdir(), memtrace->pid);
                CONSOLE("  -h, --help             Display this help");
                CONSOLE("  -i, --interval=VALUE   Start monitoring at the specified interval value in seconds");
                CONSOLE("  -c, --count=VALUE      Count of print memory context in each report");
                CONSOLE("  -f, --foreground       Keep memtrace in foreground");
                return;
        }
    }

    free(memtrace->logfile);
    if (optind < argc) {
        memtrace->logfile = strdup(argv[optind]);
    }
    else {
        assert(asprintf(&memtrace->logfile, "%s/memtrace-%d.log",
            defaultdir(), memtrace->pid) > 0);
    }

    FILE *fp = fopen(memtrace->logfile, "w");
    if (!fp) {
        CONSOLE("Failed to create %s: %m", memtrace->logfile);
        return;
    }
    fprintf(fp, "memtrace report logs for pid %d\n", memtrace->pid);
    fclose(fp);

    CONSOLE("memtrace logs report every %ds in %s\n",
        (int)itimer.it_interval.tv_sec,
        memtrace->logfile);


    if (!foreground) {
        CONSOLE("Daemonize memtrace");
        evlp_remove_handler(memtrace->evlp, 0);
        if (daemon(1, 0) != 0) {
            CONSOLE("Failed to daemonize: %m");
        }
    }

    timerfd_settime(memtrace->timerfd, 0, &itimer, NULL);
}


static void monitor_handler(memtrace_t *memtrace, int events) {
    char line[4096];
    bus_connection_t *ipc = NULL;

    if (!(ipc = bus_first_connection(&memtrace->agent))) {
        TRACE_ERROR("not connected to agent");
        return;
    }

    bus_connection_write_request(ipc, "status", NULL);
    while (bus_connection_readline(ipc, line, sizeof(line))) {
        if (!strcmp(line, "[cmd_done]\n")) {
            break;
        }
        CONSOLE_RAW("%s", line);
    }
}

static void logreport_handler(memtrace_t *memtrace, int events) {
    FILE *fp = NULL;

    if (!(fp = fopen(memtrace->logfile, "a"))) {
        TRACE_ERROR("Failed to open %s: %m", memtrace->logfile);
        memtrace_stop_evlp(memtrace);
        goto error;
    }

    if (!memtrace_report(memtrace, memtrace->logcount, fp)) {
        TRACE_ERROR("Exit event loop");
        memtrace_stop_evlp(memtrace);
        goto error;
    }

error:
    if (fp) {
        fclose(fp);
    }
}

static void timerfd_handler(evlp_handler_t *self, int events) {
    memtrace_t *memtrace = container_of(self, memtrace_t, timerfd_handler);

    uint64_t value = 0;
    if (read(memtrace->timerfd, &value, sizeof(value)) < 0) {
        TRACE_ERROR("read timer error: %m");
        sleep(1);
        return;
    }

    if (memtrace->logfile) {
        logreport_handler(memtrace, events);
    }
    else {
        monitor_handler(memtrace, events);
    }
}

static void memtrace_console_report(console_t *console, int argc, char *argv[]) {
    const char *short_options = "+c:h";
    const struct option long_options[] = {
        {"count",       required_argument,  0, 'c'},
        {"help",        no_argument,        0, 'h'},
        {0},
    };
    int opt = -1;
    int count = 10;
    memtrace_t *memtrace = container_of(console, memtrace_t, console);

    optind = 1;
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                count = atoi(optarg);
                break;
            case 'h':
            default:
                CONSOLE("Usage: report [OPTION]..");
                CONSOLE("Generate a memory usage report");
                CONSOLE("  -h, --help             Display this help");
                CONSOLE("  -c, --count=VALUE      Count of memory contexts to display (default:10)");
                return;
        }
    }
    memtrace_report(memtrace, count, stderr);
}

static void memtrace_console_kill(console_t *console, int argc, char *argv[]) {
    memtrace_t *memtrace = container_of(console, memtrace_t, console);
    int signal = SIGTERM;

    if (argc >= 2) {
        signal = atoi(argv[1]);
    }
    kill(memtrace->pid, signal);
}

static void memtrace_console_coredump(console_t *console, int argc, char *argv[]) {
    const char *short_options = "+c:f:hn";
    const struct option long_options[] = {
        {"context",     required_argument,  0, 'c'},
        {"file",        required_argument,  0, 'f'},
        {"now",         no_argument,        0, 'n'},
        {"help",        no_argument,        0, 'h'},
        {0},
    };
    int opt = -1;
    memtrace_t *memtrace = container_of(console, memtrace_t, console);
    bus_connection_t *ipc = NULL;
    strmap_t options = {0};
    int retval = 0;
    const char *descr = NULL;

    const char *filename = NULL;
    bool now = false;
    int pid = memtrace->pid;
    DIR *threads = NULL;
    libraries_t *libraries = NULL;
    int memfd = -1;
    size_t bp_addr = 0;

    optind = 1;
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                strmap_add(&options, "context", optarg);
                break;
            case 'f':
                filename = optarg;
                break;
            case 'n':
                now = true;
                break;
            case 'h':
            default:
                CONSOLE("Usage: coredump [OPTION]..");
                CONSOLE("Mark a memory context for coredump generation");
                CONSOLE("  -h, --help             Display this help");
                CONSOLE("  -c, --context=VALUE    Mark the specified memory context for coredump generation (default:core.%d)", memtrace->pid);
                CONSOLE("  -n, --now              Generate a breakpoint, now !");
                CONSOLE("  -f, --file=PATH        Write the coredump to the specified path");
                goto error;
        }
    }

    if (now) {
        coredump_write_file(filename, pid, NULL);
        goto error;
    }

    if (!arch.breakpoint_set) {
        CONSOLE("breakpoint is not implemented for this platform");
        goto error;
    }

    if (!(ipc = bus_first_connection(&memtrace->agent))) {
        CONSOLE("memtrace is not connected to target process");
        goto error;
    }

    // Write getcontext request and read reply
    bus_connection_write_request(ipc, "getcontext", &options);
    bus_connection_read_reply(ipc, &options);
    strmap_get_fmt(&options, "retval", "%d", &retval);
    if (!(descr = strmap_get(&options, "descr"))) {
        descr = "Unknown error";
    }
    if (!retval) {
        CONSOLE("Coredump error: %s", descr);
        goto error;
    }

    void *callstack[10] = {0};
    size_t i = 0;
    for (i = 0; i < countof(callstack); i++) {
        char key[32];
        snprintf(key, sizeof(key), "%zu", i);
        strmap_get_fmt(&options, key, "%p", &callstack[i]);
    }

    CONSOLE("Attaching to %d", pid);
    if (!(threads = threads_attach(pid))) {
        CONSOLE("Failed to get thread list from pid %d", pid);
        goto error;
    }
    if (!(libraries = libraries_create(pid))) {
        CONSOLE("Failed to open libraries");
        goto error;
    }
    if ((memfd = memfd_open(pid)) < 0) {
        goto error;
    }

    // In order to have an exploitable callstack, we should put the breakpoint
    // on {m,c,re}alloc_hook() insted of {m,c,re}alloc().
    //
    // Determine the breakpoint address fromt there.
    library_symbol_t malloc_sym;
    for (size_t i = 0; i < countof(alloc_functions); i++) {
        library_symbol_t sym = libraries_find_symbol(libraries, alloc_functions[i].name);
        malloc_sym = sym;
        if (sym.name && sym.addr == (size_t) callstack[0]) {
            library_symbol_t sym = libraries_find_symbol(libraries, alloc_functions[i].inject);
            if (!sym.name) {
                CONSOLE("Failed to find %s() in target process", alloc_functions[i].inject);
                goto error;
            }
            CONSOLE("Setting breakpoint on %s at 0x%"PRIx64" (%s+0x%"PRIx64")",
                sym.name, sym.addr, library_name(sym.library), sym.offset);
            bp_addr = sym.addr;
            break;
        }
    }
    if (!bp_addr) {
        CONSOLE("%p is not an allocation function", callstack[0]);
        goto error;
    }
    if (!breakpoint_wait_until_callstack_matched(pid, threads, memfd, bp_addr, callstack, sizeof(callstack))) {
        CONSOLE("Breakpoint was not hit");
        goto error;
    }
    CONSOLE("Breakpoint was hit !");
    cpu_registers_t regs;
    cpu_registers_get(&regs, pid);
    cpu_register_set(&regs, cpu_register_pc, malloc_sym.addr);
    coredump_write_file(filename, pid, &regs);

error:
    if (memfd >= 0) {
        close(memfd);
    }
    if (libraries) {
        libraries_destroy(libraries);
    }
    if (threads) {
        CONSOLE("Detaching from %d", pid);
        threads_detach(threads);
    }

    strmap_cleanup(&options);
}

static void memtrace_console_breakpoint(console_t *console, int argc, char *argv[]) {
    memtrace_t *memtrace = container_of(console, memtrace_t, console);
    DIR *threads = NULL;
    int pid = memtrace->pid;
    int memfd = -1;
    libraries_t *libraries = NULL;
    const char *filename = NULL;
    const char *symname = "calloc_hook";

    int opt = -1;
    const char *short_options = "+cf:lh";
    const struct option long_options[] = {
        {"file",        required_argument,  0, 'f'},
        {"coredump",    required_argument,  0, 'c'},
        {"log",         no_argument,        0, 'l'},
        {"help",        no_argument,        0, 'h'},
        {0},
    };
    bool do_coredump = false;
    bool do_logforever = false;

    optind = 1;
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                do_coredump = true;
                break;
            case 'f':
                filename = optarg;
                break;
            case 'l':
                do_logforever = true;
                break;
            case 'h':
            default:
                CONSOLE("Usage: break [OPTION].. [function]");
                CONSOLE("Set a breakpoint at the specified function");
                CONSOLE("  -c, --coredump    Generate a coredump when breakpoint is hit");
                CONSOLE("  -l, --log         Log breakpoint hits forever until CTRL+C is hit");
                CONSOLE("  -h, --help        Display this help");
                goto error;
        }
    }

    if (optind < argc) {
        symname = argv[optind];
    }

    CONSOLE("Attaching to %d", pid);
    if (!(threads = threads_attach(pid))) {
        CONSOLE("Failed to get thread list from pid %d", pid);
        goto error;
    }
    if ((memfd = memfd_open(pid)) < 0) {
        goto error;
    }
    if (!(libraries = libraries_create(pid))) {
        CONSOLE("Failed to open libraries");
        goto error;
    }
    library_symbol_t sym = libraries_find_symbol(libraries, symname);
    if (!sym.name) {
        CONSOLE("%s not found", symname);
        goto error;
    }

    CONSOLE("Setting breakpoint on %s at 0x%"PRIx64" (%s+0x%"PRIx64")",
        sym.name, sym.addr, library_name(sym.library), sym.offset);
    if (do_logforever) {
        if (!breakpoint_log_forever(pid, threads, memfd, sym.addr)) {
            CONSOLE("Failed to set breakpoint");
            goto error;
        }
    }
    else {
        if (!breakpoint_wait(pid, threads, memfd, sym.addr)) {
            CONSOLE("Failed to wait for breakpoint");
            goto error;
        }
    }
    CONSOLE("Breakpoint encountered");

    cpu_registers_t regs = {0};
    cpu_registers_get(&regs, pid);
    cpu_registers_print(&regs);

    if (do_coredump) {
        coredump_write_file(filename, pid, NULL);
    }

error:
    if (memfd >= 0) {
        close(memfd);
    }
    if (libraries) {
        libraries_destroy(libraries);
    }
    if (threads) {
        CONSOLE("Detaching from %d", pid);
        threads_detach(threads);
    }
}

static void memtrace_console_dataviewer(console_t *console, int argc, char *argv[]) {
    memtrace_t *memtrace = container_of(console, memtrace_t, console);
    int opt = -1;
    const char *short_options = "+:h";
    const struct option long_options[] = {
        {"count",       required_argument,  0, 'c'},
        {"help",        no_argument,        0, 'h'},
        {0},
    };
    char line[4096];
    strmap_t options = {0};
    bus_connection_t *ipc = NULL;
    bus_connection_t *server = NULL;
    size_t count = 10;

    optind = 1;
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                count = atoi(optarg);
                break;
            case 'h':
            default:
                CONSOLE("Usage: dataviewer [OPTION]..");
                CONSOLE("  -h, --help        Display this help");
                CONSOLE("  -c, --count=VALUE Count of memory contexts to display (default:10)");
                goto error;
        }
    }


    if (!(ipc = bus_first_connection(&memtrace->agent))) {
        CONSOLE("memtrace is not connected to target process");
        goto error;
    }
    if (!(server = bus_first_connection(&memtrace->server))) {
        CONSOLE("memtrace-server is not running: dataviewer can not be started");
        goto error;
    }
    if (count) {
        strmap_add_fmt(&options, "count", "%d", count);
    }

    // Ask memtrace-agent to generate a dataviewer report
    bus_connection_write_request(ipc, "dataviewer", &options);

    // Forward dataviewer report to memtrace-server for decodding addresses to line and functions
    // dataviewer itself will be started by memtrace-server
    bus_connection_write_request(server, "report", &options);
    while (bus_connection_readline(ipc, line, sizeof(line))) {
        bus_connection_printf(server, "%s", line);
        if (!strcmp(line, "[cmd_done]\n")) {
            break;
        }
    }
    bus_connection_flush(server);

    // Wait for command done
    while (bus_connection_readline(server, line, sizeof(line))) {
        if (!strcmp(line, "[cmd_done]\n")) {
            break;
        }
    }

error:
    strmap_cleanup(&options);
}

static const console_cmd_t memtrace_console_commands[] = {
    {.name = "help",        .help = "           Display this help", .handler = console_cmd_help},
    {.name = "quit",        .help = "           Quit memtrace and show report", .handler = memtrace_console_quit},
    {.name = "status",      .help = "           Show memtrace status", .handler = memtrace_console_forward},
    {.name = "monitor",     .help = "[OPTION].. Monitor memory allocations. monitor --help for more details.", .handler = memtrace_console_monitor},
    {.name = "report",      .help = "[OPTION].. Show memtrace report. report --help for more details.", .handler = memtrace_console_report},
    {.name = "kill",        .help = "[SIGNAL]   Kill the target process. A report is generated at exit.", .handler = memtrace_console_kill},
    {.name = "logreport",   .help = "[OPTION].. Log reports at a regular interval in specified file. log --help for more details.", .handler = memtrace_console_logreport},
    {.name = "coredump",    .help = "[OPTION].. Mark a memory context for coredump generation. coredump --help for more details.", .handler = memtrace_console_coredump},
    {.name = "dataviewer",  .help = "[OPTION].. Open memtrace report with dataviewer", .handler = memtrace_console_dataviewer},
    {.name = "break",       .help = "[OPTION].. Break on specified function.", .handler = memtrace_console_breakpoint},
    {.name = "clear",       .help = "           Clear memory statistics", .handler = memtrace_console_forward},
    {0},
};

static bool library_is_loaded(int pid, const char *libname) {
    libraries_t *libraries = NULL;
    bool rt = false;

    if (!(libraries = libraries_create(pid))) {
        goto error;
    }

    rt = libraries_find_by_name(libraries, libname);

error:
    if (libraries) {
        libraries_destroy(libraries);
    }
    return rt;
}

static bool memtrace_setup_hooks(int pid, const char *libname) {
    bool rt = false;
    injecter_t *injecter = NULL;

    CONSOLE("Setup memtrace hooks");
    if (!(injecter = injecter_create(pid))) {
        TRACE_ERROR("Failed to create code injecter");
        goto error;
    }
    if (!injecter_set_library(injecter, libname)) {
        TRACE_ERROR("Failed to find %s inside pid %d", libname, pid);
        goto error;
    }
    if (!injecter_setup_memtrace_hooks(injecter)) {
        TRACE_ERROR("Failed to setup memtrace functions hooks inside pid %d", libname, pid);
    }
    CONSOLE("Setup memtrace hooks: done");
    rt = true;

error:
    if (injecter) {
        injecter_destroy(injecter);
    }
    return rt;
}

/**
 * On some platforms (seen on MIPS), we simply don't have a RELOCATION Table in ELF file.
 * We have to rely on the GOT Table to setup hooks.
 * However, this table is filled progressively. We don't have the guarantee to
 * find all the functions on which we want to set hooks the first time memtrace is attached.
 *
 * In this case, the workaround is to periodically update memtrace hooks.
 */
void start_update_memtrace_hooks_task(int pid, const char *libname) {
    int time = 0;
    int duration = 20;

    if (fork() != 0) {
        return;
    }

    if (daemon(1, 0) != 0) {
        TRACE_ERROR("Failed to daemonize task");
        exit(1);
    }

    while (true) {
        sleep(1);
        if (kill(pid, 0) != 0) {
            TRACE_WARNING("Target process %d is no longer running", pid);
            exit(0);
        }
        TRACE_WARNING("target is still running");
        time += 1;
        if (time < duration) {
            continue;
        }

        memtrace_setup_hooks(pid, libname);
        duration *= 2;
        duration = (duration > 3600) ? 3600 : duration;
    }
}

static bool memtrace_inject_agent(int pid, const char *libname) {
    bool rt = false;
    bool no_relocation = false;
    injecter_t *injecter = NULL;

    if (!(injecter = injecter_create(pid))) {
        TRACE_ERROR("Failed to create code injecter");
        goto error;
    }
    if (!injecter_load_library(injecter, libname)) {
        TRACE_ERROR("Failed to load %s inside pid %d", libname, pid);
        goto error;
    }
    if (!injecter_setup_memtrace_hooks(injecter)) {
        TRACE_ERROR("Failed to setup memtrace functions hooks inside pid %d", libname, pid);
        goto error;
    }
    if (injecter_relocation_found(injecter) == 0) {
        no_relocation = true;
        CONSOLE("WARNING: This program has no relocation table");
        CONSOLE("=> The .got section needs to be polled");
        CONSOLE("=> Starting update memtrace hooks background task");
        CONSOLE("");
    }

    rt = true;

error:
    if (injecter) {
        injecter_destroy(injecter);
    }
    if (no_relocation) {
        start_update_memtrace_hooks_task(pid, libname);
    }
    return rt;
}

static int memtrace_call_function(int pid, const char *function, int argc, char *argv[]) {
    int rt = 1;
    injecter_t *injecter = NULL;
    size_t retval = 0;

    if (!(injecter = injecter_create(pid))) {
        TRACE_ERROR("Failed to create code injecter");
        goto error;
    }
    if (!injecter_call(injecter, function, argc, (const char **) argv, &retval)) {
        TRACE_ERROR("Failed to call %s()", function);
        goto error;
    }
    rt = 0;

error:
    if (injecter) {
        injecter_destroy(injecter);
    }
    return rt;
}

static int memtrace_syscall_function(int pid, const char *syscall, int argc, char *argv[]) {
    int rt = 1;
    injecter_t *injecter = NULL;
    size_t retval = 0;

    if (!(injecter = injecter_create(pid))) {
        TRACE_ERROR("Failed to create code injecter");
        goto error;
    }
    if (!injecter_syscall(injecter, syscall, argc, (const char **) argv, &retval)) {
        TRACE_ERROR("syscall %s failed", syscall);
        goto error;
    }
    rt = 0;

error:
    if (injecter) {
        injecter_destroy(injecter);
    }
    return rt;
}

static void stdin_handler(evlp_handler_t *self, int events) {
    memtrace_t *memtrace = container_of(self, memtrace_t, stdin_handler);
    if (!console_poll(&memtrace->console)) {
        CONSOLE("Standard input closed");
        memtrace_stop_evlp(memtrace);
    }
}

static void memtrace_read_exit_report(memtrace_t *memtrace) {
    char line[4096];
    char path[128];
    FILE *fp = NULL;
    bus_connection_t *server = NULL;

    snprintf(path, sizeof(path), "/tmp/memtrace-exit-report-%d.txt", memtrace->pid);
    CONSOLE("Opening exit report at %s\n", path);
    fp = fopen(path, "r");
    if (!fp) {
        CONSOLE("Could not open %s: %m", path);
        CONSOLE("Target process exited without generating an exit report");
        return;
    }

    // Are we connected to memtrace-server ?
    if ((server = bus_first_connection(&memtrace->server))) {
        // Forward report to memtrace-server for decodding addresses to line and functions
        bus_connection_write_request(server, "report", NULL);
        while (fgets(line, sizeof(line), fp)) {
            bus_connection_printf(server, "%s", line);
            if (!strcmp(line, "[cmd_done]\n")) {
                break;
            }
        }
        bus_connection_flush(server);

        // Read decoded report from server and write it to console
        while (bus_connection_readline(server, line, sizeof(line))) {
            if (!strcmp(line, "[cmd_done]\n")) {
                break;
            }
            else {
                fputs(line, stdout);
            }
        }
    }
    else {
        // Read report and dump it on console
        while (fgets(line, sizeof(line), fp)) {
            if (!strcmp(line, "[cmd_done]\n")) {
                break;
            }
            fputs(line, stdout);
        }
    }

    fclose(fp);
}

static void memtrace_on_agent_connection_closed(bus_t *bus, bus_connection_t *connection) {
    memtrace_t *memtrace = container_of(bus, memtrace_t, agent);
    CONSOLE("Target process with pid:%d exited", memtrace->pid);

    memtrace_read_exit_report(memtrace);
    memtrace_stop_evlp(memtrace);
}

// Return true if the specified program is installed locally
static bool has_local_program(const char *search) {
    struct stat st = {0};
    char *path = NULL;
    bool rt = false;

    if (stat(search, &st) == 0) {
        rt = true;
        goto exit;
    }
    const char *_path = getenv("PATH");
    if (!_path) {
        goto exit;
    }
    path = strdup(_path);
    const char *prefix = strtok(path, ":");
    for (; prefix; prefix = strtok(NULL, ":")) {
        char *program = NULL;
        if (asprintf(&program, "%s/%s", prefix, search) <= 0) {
            continue;
        }
        rt = (stat(program, &st) == 0);
        free(program);
        if (rt) {
            break;
        }
    }

exit:
    free(path);
    return rt;
}

// Return true if memtrace-server is installed locally
static bool has_local_memtrace_server() {
    static int tristate = -1;

    if (tristate == -1) {
        tristate = has_local_program("memtrace-server");
    }

    return tristate;
}

static int local_memtrace_server(bus_t *bus) {
    char socketarg[32];
    int pid = -1;
    int sockets[2] = {-1, -1};

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
        TRACE_ERROR("socketpair failed: %m");
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        TRACE_ERROR("fork failed: %m");
        return -1;
    }
    else if (pid > 0) {
        close(sockets[1]);
        bus_ipc_socket(bus, sockets[0]);
        return pid;
    }

    // run memtrace server in a new session
    setsid();
    close(sockets[0]);
    snprintf(socketarg, sizeof(socketarg), "%d", sockets[1]);
    if (execlp("memtrace-server", "memtrace-server", "--socket", socketarg, "/", NULL) != 0) {
        TRACE_ERROR("Failed to exec memtrace-server: %m");
    }

    exit(1);
    return -1;
}

static int elf_dump(const char *name) {
    elf_t *elf = elf_open(name);
    if (!elf) {
        TRACE_ERROR("Failed to open %s", name);
        return 1;
    }
    elf_print(elf);
    elf_close(elf);
    return 0;
}

static int elf_dump_relocation(int pid) {
    libraries_t *libraries = NULL;
    size_t i = 0;

    if (!(libraries = libraries_create(pid))) {
        CONSOLE("Failed to open libraries");
        return 1;
    }

    for (i = 0; i < libraries_count(libraries); i++) {
        library_t *library = libraries_get(libraries, i);
        library_dump_elf_relocation(library, stdout);
    }

    libraries_destroy(libraries);
    return 0;
}

// Find where is located libmemtrace-agent.so
static char *find_libmemtrace_agent() {
    struct stat stbuf;
    char *buff = NULL;

    // Check executable directory
    if (readlink("/proc/self/exe", g_buff, sizeof(g_buff)) > 0) {
        assert(asprintf(&buff, "%s/libmemtrace-agent.so", dirname(g_buff)) > 0);
        CONSOLE("Try to find %s", buff);
        if (stat(buff, &stbuf) == 0) {
            return buff;
        }
    }

    // Check current dir
    if (getcwd(g_buff, sizeof(g_buff))) {
        assert(asprintf(&buff, "%s/libmemtrace-agent.so", g_buff) > 0);
        CONSOLE("Try to find %s", buff);
        if (stat(buff, &stbuf) == 0) {
            return buff;
        }
    }

    // Check default library
    CONSOLE("Try to find %s", default_lib);
    if (stat(default_lib, &stbuf) == 0) {
        return strdup(default_lib);
    }

    return NULL;
}

/** SIGALRM signal handler */
static void memtrace_syscall_timeout(int sig, siginfo_t *info, void *arg) {
    TRACE_LOG("Syscall timeout");
}

/**
 * Start PROGRAM with libmemtrace-agent.so attached to it.
 * Return its PID.
 */
static int startprog_with(char *argv[], const char *libmemtraceagent) {
    int pid = fork();
    if (pid == 0) {
        setenv("LD_PRELOAD", libmemtraceagent, 1);
        setenv("MEMTRACE_WAIT4RESUME", "1", 1);
        execvp(argv[0], argv);
        CONSOLE("Failed to exec %s: %m", argv[0]);
    }

    return pid;
}

/**
 * Send 'resume' execution message to memtrace-agent
 */
bool memtrace_send_resume_execution(memtrace_t *memtrace) {
    bus_connection_t *ipc = NULL;

    if (!(ipc = bus_first_connection(&memtrace->agent))) {
        CONSOLE("memtrace is not connected to target process");
        return false;
    }
    return bus_connection_write_request(ipc, "resume", NULL);
}

static void help() {
    CONSOLE("Usage: memtrace [OPTION].. PROG [ARGS]");
    CONSOLE("A cross-debugging tool to trace memory allocations for debugging memory leaks");
    CONSOLE("Options: ");
    CONSOLE("  -p, --pid=VALUE              PID of the target process");
    CONSOLE("  -L, --library=PATH           Library to inject in the target process (default: libmemtrace-agent.so)");
    if (!has_local_memtrace_server()) {
        CONSOLE("  -m, --multicast              Auto-discover memtrace-server with multicast and connect to it");
        CONSOLE("  -c, --connect=HOST:PORT      TCP connect to memtrace-server on the specified host and port");
        CONSOLE("  -l, --listen=HOST:PORT       TCP listen on the specified host and port and wait for memtrace-server to connect");
    }
    CONSOLE("  -x, --command=CMD            Execute memtrace command and exit");
    CONSOLE("  -C, --coredump=PATH          Generate a coredump and exit");
    CONSOLE("  -e, --elfdump=PATH           Dump ELF file info");
    CONSOLE("  -f, --call=FUNCTION [ARG]..  Call function with specified arguments");
    CONSOLE("  -s, --syscall=NAME [ARG]..   Perform syscall with specified arguments");
    CONSOLE("  -t, --selftest [ARG]..       Run self tests to verify your platform is supported");
    CONSOLE("  -d, --debug                  Enable debug logs");
    CONSOLE("  -h, --help                   Display this help");
    CONSOLE("  -v, --version                Display program version");
}

static void version() {
    CONSOLE("memtrace %s", VERSION);
}

int main(int argc, char *argv[]) {
    const char *short_options = "+p:L:C:mc:l:x:e:f:s:rtudhv";
    const struct option long_options[] = {
        {"pid",         required_argument,  0, 'p'},
        {"library",     required_argument,  0, 'L'},
        {"coredump",    required_argument,  0, 'C'},
        {"multicast",   no_argument,        0, 'm'},
        {"connect",     required_argument,  0, 'c'},
        {"listen",      required_argument,  0, 'l'},
        {"command",     required_argument,  0, 'x'},
        {"elfdump",     required_argument,  0, 'e'},
        {"elfrelocation",no_argument,       0, 'r'},
        {"call",        required_argument,  0, 'f'},
        {"syscall",     required_argument,  0, 's'},
        {"selftest",    no_argument,        0, 't'},
        {"debug",       no_argument,        0, 'd'},
        {"help",        no_argument,        0, 'h'},
        {"version",     no_argument,        0, 'v'},
        {0},
    };
    int rt = 1;
    int opt = -1;
    char *libname = NULL;
    const char *hostname = NULL;
    const char *port = "3002";
    bool client = false;
    bool multicast = false;
    bool update_hooks = false;
    int memtrace_server_pid = -1;
    memtrace_t memtrace = {
        .stdin_handler = {.fn = stdin_handler},
        .timerfd_handler = {.fn = timerfd_handler},
        .pid = -1,
    };
    const char *coredump_path = NULL;
    bool startprog = false;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    struct sigaction action = {
        .sa_sigaction = memtrace_syscall_timeout,
        .sa_flags = SA_SIGINFO,
    };
    assert(sigaction(SIGALRM, &action, NULL) == 0);

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                memtrace.pid = atoi(optarg);
                break;
            case 'L':
                libname = strdup(optarg);
                break;
            case 'C':
                coredump_path = optarg;
                break;
            case 'm':
                multicast = true;
                break;
            case 'c':
                hostname = strtok(optarg, ":");
                port = strtok(NULL, ":");
                client = true;
                break;
            case 'l':
                hostname = strtok(optarg, ":");
                port = strtok(NULL, ":");
                break;
            case 'x':
                strlist_append(&memtrace.commands, optarg);
                break;
            case 'd':
                log_more_verbose();
                break;
            case 'e':
                return elf_dump(optarg);
            case 'r':
                return elf_dump_relocation(memtrace.pid);
            case 'u':
                update_hooks = true;
                break;
            case 'f':
                if (memtrace.pid <= 0) {
                    CONSOLE("PID not provided");
                    help();
                    goto error;
                }
                return memtrace_call_function(memtrace.pid, optarg,
                    (argc - optind),
                    (argv + optind));
            case 's':
                if (memtrace.pid <= 0) {
                    CONSOLE("PID not provided");
                    help();
                    goto error;
                }
                return memtrace_syscall_function(memtrace.pid, optarg,
                    (argc - optind),
                    (argv + optind));
            case 't':
                return selftest_main(
                    (argc - optind + 1),
                    (argv + optind - 1));
            case 'h':
                help();
                goto error;
            case 'v':
                version();
                goto error;
            default:
                help();
                goto error;
        }
    }

    signal(SIGPIPE, SIG_IGN);
    evlp_exit_onsignal();

    if (!libname) {
        libname = find_libmemtrace_agent();
    }
    if (!libname) {
        CONSOLE("Could not find memtrace agent");
        goto error;
    }
    CONSOLE("Memtrace agent is %s", libname);
    memtrace.inject_libname = libname;

    if (optind < argc) {
        if (memtrace.pid > 0) {
            CONSOLE("Unknown arguments");
            help();
            goto error;
        }
        startprog = true;
        memtrace.pid = startprog_with(&argv[optind], libname);

    }
    else if (memtrace.pid <= 0) {
        CONSOLE("PID not provided");
        help();
        goto error;
    }

    if (coredump_path) {
        DIR *threads = NULL;
        if (!(threads = threads_attach(memtrace.pid))) {
            CONSOLE("Failed to get thread list from pid %d", memtrace.pid);
            return false;
        }
        coredump_write_file(coredump_path, memtrace.pid, NULL);
        threads_detach(threads);
        rt = 0;
        goto error;
    }

    // Create event loop
    memtrace.evlp = evlp_create();
    assert((memtrace.timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)) >= 0);
    assert(evlp_add_handler(memtrace.evlp, &memtrace.timerfd_handler, memtrace.timerfd, EPOLLIN));

    bus_initialize(&memtrace.agent, memtrace.evlp, "memtrace", "memtrace.agent");
    bus_set_onclose(&memtrace.agent, memtrace_on_agent_connection_closed);
    if (startprog) {
        // Program was started by us with libmemtrace-agent preloaded.
        // However, hooks are not yet setup and the agent is waiting
        // for resume command.
        if (!connect_to_memtrace_agent(&memtrace.agent, memtrace.pid)) {
            CONSOLE("Failed to connect to memtrace-agent");
            goto error;
        }
        if (!memtrace_setup_hooks(memtrace.pid, libname)) {
            goto error;
        }
        memtrace_send_resume_execution(&memtrace);
    }
    else {
        // Program was already started.
        // Inject libmemtrace-agent library if needed, setup hooks, and connect to bus.
        if (!library_is_loaded(memtrace.pid, libname)) {
            CONSOLE("Injecting %s to target process %d", libname, memtrace.pid);
            if (!memtrace_inject_agent(memtrace.pid, libname)) {
                CONSOLE("Failed to inject memtrace agent in target process");
                goto error;
            }
        }
        else if (update_hooks) {
            if (memtrace_setup_hooks(memtrace.pid, libname)) {
                rt = 0;
            }
            goto error;
        }
        else {
            CONSOLE("Memtrace agent is already loaded in target process");
        }

        // Establish ipc connection to memtrace-agent
        if (!connect_to_memtrace_agent(&memtrace.agent, memtrace.pid)) {
            CONSOLE("Failed to connect to memtrace-agent");
            goto error;
        }
        CONSOLE("Memtrace is connected to target process %d", memtrace.pid);
    }

    // Establish connection to memtrace-server and add socket to event loop
    if (hostname && client) {
        bus_initialize(&memtrace.server, memtrace.evlp, "memtrace", "memtrace-server");
        if (!bus_tcp_connect(&memtrace.server, hostname, port)) {
            TRACE_ERROR("Failed to connect to %s:%s", hostname, port);
            goto error;
        }
        bus_wait4connect(&memtrace.server);
    }
    else if (hostname) {
        bus_initialize(&memtrace.server, memtrace.evlp, "memtrace", "memtrace-server");
        if (!bus_tcp_listen(&memtrace.server, hostname, port)) {
            TRACE_ERROR("Failed to listen on %s:%s", hostname, port);
            goto error;
        }
        bus_wait4connect(&memtrace.server);
    }
    else if (multicast) {
        bus_initialize(&memtrace.server, memtrace.evlp, "memtrace", "memtrace-server");
        if (!bus_tcp_autoconnect(&memtrace.server)) {
            TRACE_ERROR("Failed to discover memtrace-server");
            goto error;
        }
        bus_wait4connect(&memtrace.server);
    }
    else if (has_local_memtrace_server()) {
        CONSOLE("Run memtrace-server locally");
        bus_initialize(&memtrace.server, memtrace.evlp, "memtrace", "memtrace-server");
        memtrace_server_pid = local_memtrace_server(&memtrace.server);
        bus_wait4connect(&memtrace.server);
    }

    // Add standard input to event loop
    if (strlist_first(&memtrace.commands)) {
        // TODO: move this in a dedicated function
        strlist_iterator_t *it = NULL;
        FILE *fp = NULL;
        int fds[2] = {-1, -1};
        assert(pipe(fds) == 0);
        assert(dup2(fds[0], 0) == 0);
        close(fds[0]);
        assert((fp = fdopen(fds[1], "w")));
        strlist_for_each(it, &memtrace.commands) {
            fprintf(fp, "%s\n", strlist_iterator_value(it));
        }
        fflush(fp);
        fclose(fp);
    }
    else {
        CONSOLE("Enter 'help' for listing possible commands");
    }
    console_initiliaze(&memtrace.console, memtrace_console_commands);
    evlp_add_handler(memtrace.evlp, &memtrace.stdin_handler, 0, EPOLLIN);

    // Enter event loop
    evlp_main(memtrace.evlp);
    rt = 0;

    // Program is a Child process and is still running: stop it and show report
    if (startprog && bus_first_connection(&memtrace.agent)) {
        CONSOLE("Stopping program with SIGTERM");
        kill(memtrace.pid, SIGTERM);
        waitpid(memtrace.pid, NULL, 0);
        CONSOLE("Program exited");
        memtrace_read_exit_report(&memtrace);
    }

error:
    free(libname);
    free(memtrace.logfile);
    close(memtrace.timerfd);
    strlist_cleanup(&memtrace.commands);
    console_cleanup(&memtrace.console);
    bus_cleanup(&memtrace.server);
    bus_cleanup(&memtrace.agent);
    if (memtrace.evlp) {
        evlp_destroy(memtrace.evlp);
    }
    if (memtrace_server_pid > 0) {
        kill(memtrace_server_pid, SIGKILL);
        waitpid(memtrace_server_pid, NULL, __WALL);
    }

    return rt;
}
