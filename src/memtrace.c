/*
 * Copyright (C) 2022 Guillaume Pellegrino
 * This file is part of memtrace <https://github.com/guillaumepellegrino/memtrace>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
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
#include "libraries.h"
#include "console.h"
#include "coredump.h"
#include "arch.h"
#include "log.h"

typedef struct {
    evlp_t *evlp;
    evlp_handler_t stdin_handler;
    evlp_handler_t monitor_handler;
    int monitorfd;
    console_t console;
    bus_t server;
    bus_t agent;
    strlist_t commands;
    int pid;
    bus_topic_t notify_do_coredump_topic;
    char *coredump_path;
} memtrace_t;

__attribute__((aligned)) char g_buff[G_BUFF_SIZE];

#define process_for_each_thread(tid, dir) \
    for (tid = process_first_thread(dir); tid > 0; tid = process_next_thread(dir))

static DIR *process_threads(int pid) {
    char task_path[128];
    DIR *threads = NULL;

    if (pid <= 0) {
        TRACE_ERROR("pid was not provided");
        return false;
    }

    snprintf(task_path, sizeof(task_path), "/proc/%d/task/", pid);

    if (!(threads = opendir(task_path))) {
        TRACE_ERROR("Failed to open %s: %m", task_path);
        return NULL;
    }

    return threads;
}

static int process_next_thread(DIR *threads) {
    struct dirent *task_entry = NULL;

    if (!threads) {
        return 0;
    }

    while ((task_entry = readdir(threads))) {
        int tid = atoi(task_entry->d_name);
        if (tid <= 0) {
            continue;
        }
        return tid;
    }

    return 0;
}

static int process_first_thread(DIR *threads) {
    if (!threads) {
        return 0;
    }

    seekdir(threads, 0);

    return process_next_thread(threads);
}

static bool thread_attach(int tid) {
    int status = 0;

    if (tid <= 0) {
        TRACE_ERROR("tid was not provided");
        return false;
    }
    if (ptrace(PTRACE_SEIZE, tid, 0, 0) != 0) {
        TRACE_ERROR("ptrace(SEIZE, %d, 0, 0) failed: %m", tid);
        return false;
    }
    if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0) {
        TRACE_ERROR("ptrace(INTERRUPT, %d, 0, 0) failed: %m", tid);
        return false;
    }
    if (waitpid(tid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", tid);
        return false;
    }
    if (ptrace(PTRACE_SETOPTIONS, tid, 0, PTRACE_O_TRACESYSGOOD) != 0) {
        TRACE_ERROR("ptrace(SETOPTIONS, %d, 0, TRACESYSGOOD) failed: %m", tid);
        return false;
    }
    return true;
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
        printf("Failed to bind ipc socket to %s: %m\n", connaddr.sun_path);
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

static void memtrace_console_quit(console_t *console, int argc, char *argv[]) {
    // gently ask the event loop to exit
    kill(getpid(), SIGINT);
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
                break;
            case 'h':
            default:
                CONSOLE("Usage: monitor [OPTION]..");
                CONSOLE("Toggle ON/OFF the monitoring the memory usage");
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

    timerfd_settime(memtrace->monitorfd, 0, &itimer, NULL);
    is_running = itimer.it_value.tv_nsec;
}

static void monitor_handler(evlp_handler_t *self, int events) {
    char line[4096];
    memtrace_t *memtrace = container_of(self, memtrace_t, monitor_handler);
    bus_connection_t *ipc = NULL;
    uint64_t value = 0;

    if (read(memtrace->monitorfd, &value, sizeof(value)) < 0) {
        TRACE_ERROR("read timer error: %m");
        sleep(1);
        return;
    }

    if (!(ipc = bus_first_connection(&memtrace->agent))) {
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

static void memtrace_console_report(console_t *console, int argc, char *argv[]) {
    char line[4096];
    const char *short_options = "+c:h";
    const struct option long_options[] = {
        {"count",       required_argument,  0, 'c'},
        {"help",        no_argument,        0, 'h'},
        {0},
    };
    int opt = -1;
    strmap_t options = {0};
    memtrace_t *memtrace = container_of(console, memtrace_t, console);
    bus_connection_t *ipc = NULL;
    bus_connection_t *server = NULL;
    bus_connection_t *in = NULL;

    optind = 1;
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                strmap_add(&options, "count", optarg);
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

    if (!(ipc = bus_first_connection(&memtrace->agent))) {
        CONSOLE("memtrace is not connected to target process");
        return;
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
            CONSOLE_RAW("%s", line);
        }
    }

    strmap_cleanup(&options);
}

static void memtrace_coredump(const char *filename, int pid, cpu_registers_t *regs) {
    char memfile[64];
    DIR *threads = NULL;
    int tid = -1;
    int memfd = -1;
    FILE *core = NULL;

    if (!(threads = process_threads(pid))) {
        CONSOLE("Failed to get thread list from pid %d", pid);
        goto error;
    }
    process_for_each_thread(tid, threads) {
        if (!thread_attach(tid)) {
            TRACE_ERROR("Failed to attach to thread %d", tid);
            goto error;
        }
        CONSOLE("memtrace attached to pid:%d/tid:%d", pid, tid);
    }

    if (!filename) {
        filename = "core";
    }
    if (!(core = fopen(filename, "w"))) {
        TRACE_ERROR("Failed to open %s: %m", filename);
        goto error;
    }

    snprintf(memfile, sizeof(memfile), "/proc/%d/mem", pid);
    if ((memfd = open(memfile, O_RDONLY)) < 0) {
        TRACE_ERROR("Failed to open %s: %m", "/proc/self/mem");
        goto error;
    }

    fprintf(stderr, "Writing coredump to %s\n", filename);
    coredump_write(pid, memfd, core, regs);
    fprintf(stderr, "Writing coredump done\n");

error:
    if (memfd >= 0) {
        close(memfd);
    }
    if (core) {
        fclose(core);
    }
    if (threads) {
        process_for_each_thread(tid, threads) {
            if (ptrace(PTRACE_DETACH, tid, NULL, NULL) != 0) {
                TRACE_ERROR("ptrace(DETACH, %d) failed: %m", tid);
            }
        }
        closedir(threads);
    }

}

static void memtrace_console_coredump(console_t *console, int argc, char *argv[]) {
    const char *short_options = "+c:f:h";
    const struct option long_options[] = {
        {"context",     required_argument,  0, 'c'},
        {"file",        required_argument,  0, 'f'},
        {"help",        no_argument,        0, 'h'},
        {0},
    };
    int opt = -1;
    memtrace_t *memtrace = container_of(console, memtrace_t, console);
    bus_connection_t *ipc = NULL;
    strmap_t options = {0};
    int retval = 0;
    const char *descr = NULL;

    optind = 1;
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                strmap_add(&options, "context", optarg);
                break;
            case 'f':
                free(memtrace->coredump_path);
                memtrace->coredump_path = strdup(optarg);
                break;
            case 'h':
            default:
                CONSOLE("Usage: coredump [OPTION]..");
                CONSOLE("Mark a memory context for coredump generation");
                CONSOLE("  -h, --help             Display this help");
                CONSOLE("  -c, --context=VALUE    Mark the specified memory context for coredump generation (default:core.%d)", memtrace->pid);
                CONSOLE("  -f, --file=PATH        Write the coredump to the specified path");
                goto error;
        }
    }

    if (!(ipc = bus_first_connection(&memtrace->agent))) {
        CONSOLE("memtrace is not connected to target process");
        goto error;
    }

    // Write coredump request and read reply
    bus_connection_write_request(ipc, "coredump", &options);
    bus_connection_read_reply(ipc, &options);
    strmap_get_fmt(&options, "retval", "%d", &retval);
    if (!(descr = strmap_get(&options, "descr"))) {
        descr = "Unknown error";
    }
    if (!retval) {
        CONSOLE("Coredump error: %s", descr);
        goto error;
    }
    CONSOLE("Coredump: %s", descr);

error:
    strmap_cleanup(&options);
}

static bool memtrace_notify_do_coredump(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *file) {
    memtrace_t *memtrace = container_of(topic, memtrace_t, notify_do_coredump_topic);
    cpu_registers_t regs = {0};
    size_t tid = 0;
    size_t pc = 0;
    size_t sp = 0;
    size_t fp = 0;
    size_t ra = 0;
    size_t arg1 = 0;
    size_t arg2 = 0;
    size_t arg3 = 0;

    strmap_get_fmt(options, "tid", "%zu", &tid);
    strmap_get_fmt(options, "pc", "%zu", &pc);
    strmap_get_fmt(options, "sp", "%zu", &sp);
    strmap_get_fmt(options, "fp", "%zu", &fp);
    strmap_get_fmt(options, "ra", "%zu", &ra);
    strmap_get_fmt(options, "arg1", "%zu", &arg1);
    strmap_get_fmt(options, "arg2", "%zu", &arg2);
    strmap_get_fmt(options, "arg3", "%zu", &arg3);
    cpu_register_set(&regs, cpu_register_pc, pc);
    cpu_register_set(&regs, cpu_register_sp, sp);
    cpu_register_set(&regs, cpu_register_fp, fp);
    cpu_register_set(&regs, cpu_register_ra, ra);
    cpu_register_set(&regs, cpu_register_arg1, arg1);
    cpu_register_set(&regs, cpu_register_arg2, arg2);
    cpu_register_set(&regs, cpu_register_arg3, arg3);

    CONSOLE("Do coredump for process %zu", tid);
    memtrace_coredump(memtrace->coredump_path, tid, &regs);
    CONSOLE("Do coredump done");

    // Reply to NotifyDoCoredump request
    return bus_connection_write_reply(connection, NULL);
}

static const console_cmd_t memtrace_console_commands[] = {
    {.name = "help",        .help = "Display this help", .handler = console_cmd_help},
    {.name = "quit",        .help = "Quit memtrace and show report", .handler = memtrace_console_quit},
    {.name = "status",      .help = "Show memtrace status", .handler = memtrace_console_forward},
    {.name = "monitor",     .help = "Monitor memory allocations. monitor --help for more details.", .handler = memtrace_console_monitor},
    {.name = "report",      .help = "Show memtrace report. report --help for more details.", .handler = memtrace_console_report},
    {.name = "coredump",    .help = "Generate a coredump. coredump --help for more details.", .handler = memtrace_console_coredump},
    {.name = "clear",       .help = "Clear memory statistics", .handler = memtrace_console_forward},
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

static bool inject_memtrace_agent(int pid, const char *libname) {
    static const struct {
        const char *name;
        const char *inject;
    } replace_functions[] = {
        {"malloc",          "malloc_hook"},
        {"calloc",          "calloc_hook"},
        {"calloc",          "calloc_hook"},
        {"realloc",         "realloc_hook"},
        {"reallocarray",    "reallocarray_hook"},
        {"free",            "free_hook"},
        {"fork",            "fork_hook"},
    };
    bool rt = false;
    DIR *threads = NULL;
    int tid = -1;
    injecter_t *injecter = NULL;

    if (!(threads = process_threads(pid))) {
        CONSOLE("Failed to get thread list from pid %d", pid);
        goto error;
    }
    process_for_each_thread(tid, threads) {
        if (!thread_attach(tid)) {
            TRACE_ERROR("Failed to attach to thread %d", tid);
            goto error;
        }
        CONSOLE("memtrace attached to pid:%d/tid:%d", pid, tid);
    }

    if (!(injecter = injecter_create(pid))) {
        TRACE_ERROR("Failed to create code injecter");
        goto error;
    }
    if (!injecter_load_library(injecter, libname)) {
        TRACE_ERROR("Failed to load %s inside pid %d", libname, pid);
        goto error;
    }

    CONSOLE("[Replacing functions]");
    for (size_t i = 0; i < sizeof(replace_functions)/sizeof(*replace_functions); i++) {
        injecter_replace_function(injecter, replace_functions[i].name, replace_functions[i].inject);
    }

    rt = true;

error:
    if (injecter) {
        injecter_destroy(injecter);
    }
    if (threads) {
        process_for_each_thread(tid, threads) {
            if (ptrace(PTRACE_DETACH, tid, NULL, NULL) != 0) {
                TRACE_ERROR("ptrace(DETACH, %d) failed: %m", tid);
            }
        }
        closedir(threads);
    }
    return rt;
}

static void stdin_handler(evlp_handler_t *self, int events) {
    memtrace_t *memtrace = container_of(self, memtrace_t, stdin_handler);
    if (!console_poll(&memtrace->console)) {
        memtrace_console_quit(NULL, 0, NULL);
    }
}

static bool is_cross_compiled() {
    return strlen(SYSROOT) > 1;
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

    // run memtrace server
    close(sockets[0]);
    snprintf(socketarg, sizeof(socketarg), "%d", sockets[1]);
    if (execlp("memtrace-server", "memtrace-server", "--socket", socketarg, "/", NULL) != 0) {
        TRACE_ERROR("Failed to exec memtrace-server: %m");
    }

    exit(1);
    return -1;
}

static void help() {
    CONSOLE("Usage: memtrace [OPTION]..");
    CONSOLE("A cross-debugging tool to trace memory allocations for debugging memory leaks");
    CONSOLE("Options: ");
    CONSOLE("  -p, --pid=VALUE      PID of the target process. MANDATORY.");
    CONSOLE("  -L, --library=PATH   Library to inject in the target process. By default, memtrace inject itself.");
    if (is_cross_compiled()) {
        CONSOLE("  -m, --multicast      Auto-discover memtrace-server with multicast and connect to it");
        CONSOLE("  -c, --connect=HOST:PORT TCP connect to memtrace-server on the specified host and port");
        CONSOLE("  -l, --listen=HOST:PORT TCP listen on the specified host and port and wait for memtrace-server to connect");
    }
    CONSOLE("  -x, --command        Execute memtrace command and exit");
    CONSOLE("  -d, --debug          Enable debug logs");
    CONSOLE("  -h, --help           Display this help");
    CONSOLE("  -v, --version        Display program version");
}

static void version() {
    CONSOLE("memtrace %s", VERSION);
}

int main(int argc, char *argv[]) {
    const char *short_options = "+p:L:Cmc:l:x:dhv";
    const struct option long_options[] = {
        {"pid",         required_argument,  0, 'p'},
        {"library",     required_argument,  0, 'L'},
        {"coredump",    no_argument,        0, 'C'},
        {"multicast",   no_argument,        0, 'm'},
        {"connect",     required_argument,  0, 'c'},
        {"listen",      required_argument,  0, 'l'},
        {"command",     required_argument,  0, 'x'},
        {"debug",       no_argument,        0, 'd'},
        {"help",        no_argument,        0, 'h'},
        {"version",     no_argument,        0, 'v'},
        {0},
    };
    int rt = 1;
    int opt = -1;
    bool do_coredump = false;
    const char *libname = "/usr/lib/libmemtrace-agent.so";
    const char *hostname = NULL;
    const char *port = "3002";
    bool client = false;
    bool multicast = false;
    int memtrace_server_pid = -1;
    memtrace_t memtrace = {
        .stdin_handler = {.fn = stdin_handler},
        .monitor_handler = {.fn = monitor_handler},
        .pid = -1,
    };

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                memtrace.pid = atoi(optarg);
                break;
            case 'L':
                libname = optarg;
                break;
            case 'C':
                do_coredump = true;
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

    if (memtrace.pid <= 0) {
        CONSOLE("PID not provided");
        help();
        goto error;
    }
    if (!libname) {
        CONSOLE("Library name not provided");
        help();
        goto error;
    }
    assert(asprintf(&memtrace.coredump_path, "core.%d", memtrace.pid) > 0);
    if (do_coredump) {
        memtrace_coredump(memtrace.coredump_path, memtrace.pid, NULL);
        rt = 0;
        goto error;
    }

    // Create event loop
    memtrace.evlp = evlp_create();
    assert((memtrace.monitorfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)) >= 0);
    assert(evlp_add_handler(memtrace.evlp, &memtrace.monitor_handler, memtrace.monitorfd, EPOLLIN));

    // Inject memtrace-agent library in target process
    if (!library_is_loaded(memtrace.pid, libname)) {
        if (!inject_memtrace_agent(memtrace.pid, libname)) {
            CONSOLE("Failed to inject memtrace agent in target process");
            goto error;
        }
        CONSOLE("");
    }
    else {
        CONSOLE("Memtrace agent is already injected in target process");
    }

    // Establish ipc connection to memtrace-agent
    bus_initialize(&memtrace.agent, memtrace.evlp, "memtrace", "memtrace.agent");
    if (!connect_to_memtrace_agent(&memtrace.agent, memtrace.pid)) {
        CONSOLE("Failed to connect to memtrace-agent");
        goto error;
    }
    memtrace.notify_do_coredump_topic.name = "NotifyDoCoredump";
    memtrace.notify_do_coredump_topic.read = memtrace_notify_do_coredump;
    bus_register_topic(&memtrace.agent, &memtrace.notify_do_coredump_topic);
    CONSOLE("Memtrace is connected to target process %d", memtrace.pid);

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
    else if (!is_cross_compiled()) {
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

error:
    free(memtrace.coredump_path);
    close(memtrace.monitorfd);
    strlist_cleanup(&memtrace.commands);
    console_cleanup(&memtrace.console);
    bus_cleanup(&memtrace.server);
    bus_cleanup(&memtrace.agent);
    if (memtrace.evlp) {
        evlp_destroy(memtrace.evlp);
    }
    if (memtrace_server_pid > 0) {
        kill(memtrace_server_pid, SIGKILL);
        waitpid(memtrace_server_pid, NULL, 0);
    }

    return rt;
}
