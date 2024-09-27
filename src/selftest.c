/*
 * Copyright (C) 2021 Guillaume Pellegrino
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

#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <limits.h>
#include <poll.h>
#include "log.h"
#include "selftest.h"
#include "process.h"
#include "agent.h"

#define fatal_error(fmt, ...) selftest_error(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

typedef struct {
    char me[PATH_MAX];
    process_t victim;
    size_t success;
} selftest_t;

static selftest_t st = {0};

/** Print the fatal error and exit selftest application */
static void selftest_error(const char *func, int line, const char *fmt, ...) {
    char buff[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buff, sizeof(buff), fmt, ap);
    va_end(ap);

    CONSOLE("\e[0;31m[selftest][Fatal Error] %s in %s:%d", buff, func, line);
    CONSOLE("\e[m");
    exit(1);
}

void useptr(uint32_t *ptr) {
    (void) ptr;
}

/*
 * Run the main function of the victim process.
 *
 * The victim process will be injected the memtrace agent and
 * simply await for instructions (do a malloc, a calloc, ..)
 * from the selftest process on the standard input.
 */
static bool selftest_victim_main() {
    char line[1024];
    bool rt = false;

    // call alloc functions before memtrace attach:
    // this will help MIPS tests to pass
    // TODO: we probably needs to improve
    // function replacement on MIPS.
    uint32_t *ptr = calloc(4, 1);
    useptr(ptr);
    free(ptr);
    ptr = malloc(8);
    useptr(ptr);
    ptr = realloc(ptr, 16);
    useptr(ptr);
    free(ptr);

    printf("started\n");
    fflush(stdout);

    while (true) {
        void *ptr = NULL;
        size_t arg1 = 0;
        size_t arg2 = 0;
        if (!fgets(line, sizeof(line), stdin)) {
            TRACE_ERROR("Failed to read line from stdin: %m");
            break;
        }

        if (sscanf(line, "malloc %zu", &arg1) == 1) {
            ptr = malloc(arg1);
            printf("malloc->%p\n", ptr);
        }
        else if (sscanf(line, "calloc %zu %zu", &arg1, &arg2) == 2) {
            ptr = calloc(arg1, arg2);
            printf("calloc->%p\n", ptr);
        }
        else if (sscanf(line, "free %p", &ptr) == 1) {
            free(ptr);
            printf("free 1\n");
        }
        else if (sscanf(line, "sleep_and_abort %zu", &arg1) == 1) {
            printf("sleep_and_abort->1\n");
            fflush(stdout);
            sleep(arg1);
            printf("sleep(%zu) done => aborting\n", arg1);
            abort();
        }
        else if (sscanf(line, "poll_and_abort %zu", &arg1) == 1) {
            printf("poll_and_abort->1\n");
            fflush(stdout);
            struct pollfd fds = {
                .fd = 0,
                .events = POLLIN,
            };
            poll(&fds, 1, 10000);
            printf("poll() done => aborting\n");
            abort();
        }
        else if (sscanf(line, "read_and_abort %zu", &arg1) == 1) {
            printf("read_and_abort->1\n");
            fflush(stdout);
            size_t rt = read(0, line, 4);
            (void) rt;
            printf("read(0) done => aborting\n");
            abort();
        }
        else if (sscanf(line, "exit %zu", &arg1) == 1) {
            printf("exit 1\n");
            rt = arg1;
            break;
        }
        else {
            printf("error. line='%s'\n", line);
        }
        fflush(stdout);
    }

    TRACE_WARNING("process_exit");

    return rt;
}

/** Start the victim process: memtrace will attach to it */
static void selftest_victim_start() {
    const char *args[] = {
        st.me,
        "--selftest",
        "--victim",
        NULL
    };
    char line[64];

    alarm(2);
    if (!process_start(&st.victim, args)) {
        fatal_error("Failed to start process");
    }
    if (!fgets(line, sizeof(line), st.victim.output)) {
        fatal_error("Failed to read line from process: %m");
    }
    if (strcmp(line, "started\n") != 0) {
        fatal_error("Unexpected '%s'", line);
    }
}

/** Write a message to the victim process */
static void selftest_victim_write(const char *fmt, ...) {
    char line[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    TRACE_WARNING("target performs '%s'", line);
    if (fprintf(st.victim.input, "%s\n", line) <= 0) {
        fatal_error("Failed to write line: %m");
    }
    if (fflush(st.victim.input) != 0) {
        fatal_error("Failed to write to target process");
    }
}

/** Read a message from the victim process */
static void selftest_victim_read(const char *fmt, ...) {
    char line[512];
    va_list ap;

    va_start(ap, fmt);

    alarm(2);
    while (true) {
        if (!fgets(line, sizeof(line), st.victim.output)) {
            va_end(ap);
            fatal_error("Failed to read line from target process: %m");
        }
        //TRACE_WARNING("read: %s", line);
        if (vsscanf(line, fmt, ap) > 0) {
            break;
        }
    }

    va_end(ap);
}

static void selftest_read(FILE *fp, const char *fmt, ...) {
    char line[512];
    va_list ap;

    va_start(ap, fmt);

    alarm(2);
    while (true) {
        if (!fgets(line, sizeof(line), fp)) {
            va_end(ap);
            fatal_error("Failed to read line from target process: %m");
        }
        CONSOLE_RAW("\e[0;35m[memtrace]\e[m %s", line);
        if (vsscanf(line, fmt, ap) > 0) {
            break;
        }
    }

    va_end(ap);
}

/** Retrieve victim process's pid */
static int selftest_pid() {
    return process_get_pid(&st.victim);
}

static FILE *selftest_memtrace_call(const char *fmt, ...) {
    char cmd[PATH_MAX + 1400];
    char buff[1024];
    va_list ap;
    int pid = process_get_pid(&st.victim);

    va_start(ap, fmt);
    vsnprintf(buff, sizeof(buff), fmt, ap);
    va_end(ap);

    snprintf(cmd, sizeof(cmd), "%s --pid %d %s 2>&1", st.me, pid, buff);

    TRACE_WARNING("Run '%s'", cmd);
    return popen(cmd, "r");
}

static void selftest_memtrace_syscall_getpid() {
    FILE *fp = selftest_memtrace_call("--syscall getpid");
    if (!fp) {
        fatal_error("Failed to start memtrace process: %m");
    }

    int pid = 0;
    selftest_read(fp, "syscall returned 0x%x", &pid);
    pclose(fp);

    if (pid != selftest_pid()) {
        fatal_error("getpid syscall returned unexpected result");
    }
    TRACE_WARNING("getpid syscall returned the expected pid");
}

static void selftest_memtrace_call_getpid() {
    FILE *fp = selftest_memtrace_call("--call getpid");
    if (!fp) {
        fatal_error("Failed to start memtrace process: %m");
    }

    int pid = 0;
    selftest_read(fp, "getpid() returned 0x%x", &pid);
    pclose(fp);

    if (pid != selftest_pid()) {
        fatal_error("Call to getpid() function returned unexpected result");
    }
    TRACE_WARNING("Call to getpid() function returned the expected pid");
}

/**
 * Run memtrace command to retrieve a memory status of the target process.
 *
 * On the first run, memtrace will attach to the target process
 * and load the agent library in the target process.
 */
static void selftest_memtrace_status(stats_t *stats) {
    char line[512];

    // Ensure we are not stuck forever in case memtrace is not responding.
    alarm(10);

    FILE *fp = selftest_memtrace_call("-x status");
    if (!fp) {
        fatal_error("Failed to start memtrace process: %m");
    }

    while (true) {
        long long arg1 = 0;
        long long arg2 = 0;
        long long arg3 = 0;
        if (!fgets(line, sizeof(line), fp)) {
            fatal_error("Failed to read line from stdin: %m");
        }
        CONSOLE_RAW("\e[0;35m[memtrace]\e[m %s", line);

        // status command has the following format:
        //> status
        //HEAP SUMMARY Mon May  6 18:55:48 2024
        //
        //    in use: 2 allocs, 16 bytes in 1 contexts
        //    total heap usage: 4 allocs, 2 frees, 26 bytes allocated
        //    memory leaked since last hour: 0 allocs, 0 bytes
        if (sscanf(line, "    in use: %lld allocs, %lld bytes in %lld contexts", &arg1, &arg2, &arg3) == 3) {
            stats->count_inuse = arg1;
            stats->byte_inuse = arg2;
            //stats->block_inuse = arg3;
        }
        if (sscanf(line, "    total heap usage: %lld allocs, %lld frees, %lld bytes allocated", &arg1, &arg2, &arg3) == 3) {
            stats->alloc_count = arg1;
            stats->free_count = arg2;
            stats->alloc_size = arg3;
            break;
        }
    }

    pclose(fp);
}

/** Verify than memtrace status correspond to what is expected */
static void selftest_status_expect(const stats_t *expected) {
    stats_t stats = {0};
    selftest_memtrace_status(&stats);
    if (memcmp(&stats, expected, sizeof(stats)) != 0) {
        TRACE_ERROR("Unexpected memtrace status");
        TRACE_ERROR("Expected in use: %zu allocs, %zu bytes"/* in %zu contexts*/,
            expected->count_inuse, expected->byte_inuse/*, expected->block_inuse*/);
        TRACE_ERROR("Expected total heap usage: %zu allocs, %zu frees, %zu bytes allocated",
            expected->alloc_count, expected->free_count, expected->alloc_size);
        fatal_error("Unexpected memtrace status");
    }
    TRACE_WARNING("Got expected memtrace status");
}

/** SIGALRM signal handler */
static void selftest_timeout(int sig, siginfo_t *info, void *arg) {
    TRACE_ERROR("Test timeout");
}

/** Cleanup the test suite: called at process exit */
static void selftest_cleanup() {
    // print memtrace last lines and exit memtrace
    char line[1024];
    while (st.victim.output) {
        if (!fgets(line, sizeof(line), st.victim.output)) {
            break;
        }
        CONSOLE_RAW("\e[0;35m[memtrace]\e[m %s", line);
    }
    process_stop(&st.victim);

    CONSOLE("###");
    if (st.success) {
        CONSOLE("\e[0;32m");
        CONSOLE("Self tests successful !");
        CONSOLE("Your platform is supported by memtrace.");
    }
    else {
        CONSOLE("\e[0;31m");
        CONSOLE("Self tests have failed");
        CONSOLE("Your platform is currently not supported by memtrace");
    }
    CONSOLE("\e[m");
}

/** Initialize the test suite. */
void selftest_initialize() {
    log_set_header("\e[0;33m[selftest]\e[m");

    // retrieve memtrace program path
    assert(readlink("/proc/self/exe", st.me, sizeof(st.me)) >= 0);

    // configure SIGALRM for handling syscall timeout
    struct sigaction action = {
        .sa_sigaction = selftest_timeout,
        .sa_flags = SA_SIGINFO,
    };
    assert(sigaction(SIGALRM, &action, NULL) == 0);

    atexit(selftest_cleanup);
}

/**
 * Run self integration tests.
 *
 * The goal of these self tests is to perform basic integration tests:
 * - Attach memtrace to a process succesfully
 * - Retrieve memtrace status from a process
 * - Ensure than allocations are well tracked by memtrace
 *   => memtrace status should show memory increase !
 *
 * If these basics tests are succeful, we can consider than memtrace
 * is supported by the platform on which it is running.
 *
 * syscall injection, function injection, function overide are covered
 * by these tests.
 */
static bool selftest() {
    stats_t stats = {0};
    void *ptr1 = NULL;
    void *ptr2 = NULL;
    void *ptr3 = NULL;
    int rt = 0;

    selftest_initialize();

    TRACE_WARNING("Running self integration tests");

    // start the victim process
    selftest_victim_start();
    TRACE_WARNING("Target process has started with pid %d", selftest_pid());

    // check we can perform a simple SYSCALL in victim process
    selftest_memtrace_syscall_getpid();
    selftest_memtrace_syscall_getpid();
    selftest_memtrace_syscall_getpid();

    // check we can perform a simple function call in victim process
    selftest_memtrace_call_getpid();
    selftest_memtrace_call_getpid();
    selftest_memtrace_call_getpid();

    // attach to the victim process
    TRACE_WARNING("Attaching memtrace to pid %d", selftest_pid());
    selftest_memtrace_status(&stats);
    TRACE_WARNING("memtrace succesfully attached to pid %d", selftest_pid());

    // verify we can retrieve memtrace status from the victim process
    TRACE_WARNING("Retrieving memtrace status");
    {
        const stats_t expected = {
            .count_inuse = 0,
            .byte_inuse = 0,
            //.block_inuse = 0,
            .alloc_count = 0,
            .free_count = 0,
            .alloc_size = 0,
        };
        selftest_status_expect(&expected);
    }
    TRACE_WARNING("memtrace status succesfully retrieved");

    // perform a malloc allocation and retrieve new memtrace status
    selftest_victim_write("malloc 64");
    selftest_victim_read("malloc->%p", &ptr1);
    {
        const stats_t expected = {
            .count_inuse = 1,
            .byte_inuse = 64,
            //.block_inuse = 1,
            .alloc_count = 1,
            .free_count = 0,
            .alloc_size = 64,
        };
        selftest_status_expect(&expected);
    }

    // perform another malloc allocation and retrieve new memtrace status
    selftest_victim_write("malloc 36");
    selftest_victim_read("malloc->%p", &ptr2);
    {
        const stats_t expected = {
            .count_inuse = 2,
            .byte_inuse = 100,
            //.block_inuse = 1,
            .alloc_count = 2,
            .free_count = 0,
            .alloc_size = 100,
        };
        selftest_status_expect(&expected);
    }

    // perform a calloc allocation and retrieve new memtrace status
    selftest_victim_write("calloc 10 4");
    selftest_victim_read("calloc->%p", &ptr3);
    {
        const stats_t expected = {
            .count_inuse = 3,
            .byte_inuse = 140,
            //.block_inuse = 2,
            .alloc_count = 3,
            .free_count = 0,
            .alloc_size = 140,
        };
        selftest_status_expect(&expected);
    }

    // free memory and retrieve new memtrace status
    selftest_victim_write("free %p", ptr3);
    selftest_victim_read("free %d", &rt);
    {
        const stats_t expected = {
            .count_inuse = 2,
            .byte_inuse = 100,
            //.block_inuse = 1,
            .alloc_count = 3,
            .free_count = 1,
            .alloc_size = 140,
        };
        selftest_status_expect(&expected);
    }

    // free all and retrieve new memtrace status
    selftest_victim_write("free %p", ptr2);
    selftest_victim_read("free %d", &rt);
    selftest_victim_write("free %p", ptr1);
    selftest_victim_read("free %d", &rt);
    {
        const stats_t expected = {
            .count_inuse = 0,
            .byte_inuse = 0,
            //.block_inuse = 0,
            .alloc_count = 3,
            .free_count = 3,
            .alloc_size = 140,
        };
        selftest_status_expect(&expected);
    }

    // ask victim process to sleep and abort
    // => this will allow us to check than we don't SKIP
    // the current sleep syscall if we inject another syscall or call a function
    selftest_victim_write("sleep_and_abort 10");
    selftest_victim_read("sleep_and_abort->%p", &ptr1);

    // check we can perform a simple SYSCALL in victim process
    selftest_memtrace_syscall_getpid();
    selftest_memtrace_syscall_getpid();
    usleep(1000);
    selftest_memtrace_syscall_getpid();

    // check we can perform a simple function call in victim process
    selftest_memtrace_call_getpid();
    selftest_memtrace_call_getpid();
    usleep(1000);
    selftest_memtrace_call_getpid();

    TRACE_WARNING("All tests done");
    st.success = true;
    return true;
}

static void help() {
    CONSOLE("Usage: memtrace --selftest [OPTION]...");
    CONSOLE("Run memtrace self integration tests");
    CONSOLE("");
    CONSOLE("Options:");
    CONSOLE("   -d, --debug                 Increase logging verbosity");
    CONSOLE("   -h, --help                  Display this help");
}

/** The main entry point for self tests */
int selftest_main(int argc, char *argv[]) {
    const char *short_options = "+vdh";
    const struct option long_options[] = {
        {"victim",      no_argument,        0, 'v'},
        {"debug",       no_argument,        0, 'd'},
        {"help",        no_argument,        0, 'h'},
        {0}
    };
    int opt = -1;
    bool is_victim = false;

    optind = 0;
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'v':
                is_victim = true;
                break;
            case 'd':
                log_more_verbose();
                break;
            default:
                help();
                return 1;
        }
    }

    if (is_victim) {
        return selftest_victim_main() ? 0 : 1;
    }
    else {
        return selftest() ? 0 : 1;
    }

    return 0;
}
