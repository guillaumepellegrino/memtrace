/*
 * Copyright (C) 2021 Guillaume Pellegrino
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

#define TRACE_ZONE TRACE_ZONE_MAIN
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <getopt.h>
#include <poll.h>
#include <elf.h>
#include "ftrace.h"
#include "hashmap.h"
#include "libraries.h"
#include "arch.h"
#include "net.h"
#include "selftest.h"
#include "log.h"
#include "debug_line.h"
#include "debug_info.h"
#include "debug_frame.h"
#include "elf.h"
#include "elf_file.h"
#include "elf_sym.h"
#include "elf_relocate.h"
#include "fs.h"
#include "console.h"
#include "addr2line.h"
#include "coredump.h"

typedef struct _app app_t;

typedef struct {
    hashmap_iterator_t it;
    ssize_t count;
    ssize_t size;
    size_t *callstack;
    size_t *big_callstack;
    size_t number;
    size_t do_coredump : 1;
    size_t do_gdb : 1;
} block_t;

typedef struct {
    hashmap_iterator_t it;
    size_t ptr_size;
    void *ptr;
    block_t *block;
} allocation_t;

struct _app {
    fs_t fs;
    ftrace_t ftrace;
    int pid;
    bool attachpid;
    int libc_fd;
    libraries_t *libraries;
    hashmap_t allocations;
    hashmap_t blocks;
    size_t callstack_size;
    size_t big_callstack_size;
    ssize_t big_callstack_threshold;
    breakpoint_t *calloc_bp;
    breakpoint_t *malloc_bp;
    breakpoint_t *realloc_bp;
    breakpoint_t *reallocarray_bp;
    breakpoint_t *free_bp;
    bool monitor;
    int monitor_timerfd;
    int worker_timerfd;
    epoll_handler_t monitor_handler;
    epoll_handler_t worker_handler;
    bool (*unwind)(libraries_t *libraries, const ftrace_fcall_t *fcall, size_t *callstack, size_t size);
    void (*print_callstack)(app_t *app, size_t *callstack);
    char *addr2line;
    char *gdb;
    char *program_name;
};

static struct {
    size_t alloc_count;
    size_t alloc_size;
    size_t free_count;
    size_t free_size;
    size_t byte_inuse;
    size_t block_inuse;
} stats;
static bool exit_evlp = false;
__attribute__((aligned)) char g_buff[G_BUFF_SIZE];

void memtrace_status(app_t *app);
void memtrace_report(app_t *app, size_t max);
void memtrace_clear(app_t *app);

/** Deduct the default command from compiler toolchain */
static char *toolchain_default_command(const char *program) {
    char *cmd = NULL;
    char *toolchain = NULL;
    char *sep = NULL;

    assert((toolchain = strdup(COMPILER)));

    if ((sep = strrchr(toolchain, '/'))) {
        if ((sep = strrchr(sep, '-'))) {
            *sep = 0;
            assert(asprintf(&cmd, "%s-%s", toolchain, program) >= 0);
        }
    }

    if (!cmd) {
        cmd = strdup(program);
    }

    free(toolchain);
    return cmd;
}

/** Deduct from compiler command if this program was cross-compiled */
static bool is_cross_compiled() {
    bool rt = false;
    char *sep = NULL;

    if ((sep = strrchr(COMPILER, '/'))) {
        if (strchr(sep, '-')) {
            rt = true;
        }
    }

    return rt;
}

/** Compute the the time elapsed in millisecond since start */
static uint64_t clock_elapsed(struct timespec start) {
    struct timespec stop, diff;
    clock_gettime(CLOCK_MONOTONIC, &stop);

    if ((stop.tv_nsec - start.tv_nsec) < 0) {
        diff.tv_sec = stop.tv_sec - start.tv_sec - 1;
        diff.tv_nsec = stop.tv_nsec - start.tv_nsec + 1000000000ULL;
    } else {
        diff.tv_sec = stop.tv_sec - start.tv_sec;
        diff.tv_nsec = stop.tv_nsec - start.tv_nsec;
    }

    return (1000ULL * diff.tv_sec) + (diff.tv_nsec / 1000000ULL);
}

/** Write coredump to file in local filesystem */
static bool memtrace_write_local_coredump(app_t *app, const char *file) {
    FILE *fp = fopen(file, "w");
    if (!fp) {
        TRACE_ERROR("Failed to open %s: %m", file);
        return false;
    }

    CONSOLE("Writing coredump to %s", file);
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    coredump_write(app->pid, ftrace_memfd(&app->ftrace), fp);
    fclose(fp);

    uint64_t duration = clock_elapsed(start);

    CONSOLE("Coredump written in %"PRIu64" msec", duration);
    return true;
}

/**
 *  Spawn a remote gdb console.
 *
 *  This is done in three steps:
 *  - Write coredump on memtrace-fs socket
 *  - Open coredump with gdb on Host
 *  - Forward user input to gdb on Host
 * */
static bool memtrace_gdb(app_t *app) {
    enum {
        FS_SOCKET,
        USERIN,
    };
    FILE *fp = app->fs.socket;

    if (!fp) {
        TRACE_ERROR("gdb not supported when running memtrace in local mode");
        return false;
    }

    fprintf(fp, GDB_REQUEST " gdb=%s\n", app->gdb);
    fprintf(fp, "%s\n", app->program_name);
    coredump_write(app->pid, ftrace_memfd(&app->ftrace), fp);

    int fs_socket = fileno(app->fs.socket);

    while (true) {
        struct pollfd fds[] = {
            [FS_SOCKET] = {
                .fd = fs_socket,
                .events = POLLIN,
            },
            [USERIN] = {
                .fd = 0,
                .events = POLLIN,
            },
        };

        if (poll(fds, countof(fds), -1) < 0) {
            TRACE_ERROR("poll error: %m");
            return false;
        }

        if (fds[FS_SOCKET].revents & POLLIN) {
            char *end = NULL;
            ssize_t len = read(fs_socket, g_buff, sizeof(g_buff));
            if (len < 0) {
                TRACE_ERROR("read error: %m");
                return false;
            }
            if (len == 0) {
                TRACE_ERROR("read-end closed");
                return false;
            }
            if ((end = strstr(g_buff, GDB_REPLY_END))) {
                *end = 0;
                write(1, g_buff, (end-g_buff));
                return true;
            }
            if (write(1, g_buff, len) < 0) {
                TRACE_ERROR("write error: %m");
                return false;
            }
        }
        if (fds[USERIN].revents & POLLIN) {
            ssize_t len = read(0, g_buff, sizeof(g_buff));
            if (len < 0) {
                TRACE_ERROR("read error: %m");
                return false;
            }
            if (len == 0) {
                TRACE_ERROR("read-end closed");
                return false;
            }
            if (write(1, g_buff, len) < 0) {
                TRACE_ERROR("write error: %m");
                return false;
            }
            if (write(fs_socket, g_buff, len) < 0) {
                TRACE_ERROR("write error: %m");
                return false;
            }
        }
        if (fds[FS_SOCKET].revents & POLLHUP) {
            CONSOLE("fs socket POLLHUP");
            return false;
        }
        if (fds[USERIN].revents & POLLHUP) {
            TRACE_ERROR("user input POLLHUP");
            return false;
        }
    }

    return true;
}

static void allocations_maps_destroy(void *key, hashmap_iterator_t *it) {
    allocation_t *allocation = container_of(it, allocation_t, it);
    block_t *block = allocation->block;
    block->count -= 1;
    block->size -= allocation->ptr_size;

    stats.free_count += 1;
    stats.free_size += allocation->ptr_size;
    stats.byte_inuse -= allocation->ptr_size;

    if (block->count <= 0) {
        hashmap_iterator_destroy(&block->it);
    }

    free(allocation);
}

static uint32_t blocks_maps_hash(hashmap_t *hashmap, void *key) {
    app_t *app = container_of(hashmap, app_t, blocks);
    size_t *callstack = key;
    uint32_t hash = 0;
    size_t i = 0;

    for (i = 0; i < app->callstack_size && callstack[i]; i++) {
        hash ^= callstack[i];
    }

    return hash;
}

static bool blocks_maps_match(hashmap_t *hashmap, void *lkey, void *rkey) {
    app_t *app = container_of(hashmap, app_t, blocks);
    size_t *lcallstack = lkey;
    size_t *rcallstack = rkey;
    size_t i = 0;

    for (i = 0; i < app->callstack_size && lcallstack[i]; i++) {
        if (lcallstack[i] != rcallstack[i]) {
            return false;
        }
    }

    return true;
}

static int blocks_map_compar(const hashmap_iterator_t **lval, const hashmap_iterator_t **rval) {
    block_t *lblock = container_of(*lval, block_t, it);
    block_t *rblock = container_of(*rval, block_t, it);

    return rblock->count - lblock->count;
}

static void blocks_maps_destroy(void *key, hashmap_iterator_t *it) {
    block_t *block = container_of(it, block_t, it);
    stats.block_inuse -= 1;
    free(block->callstack);
    free(block);
}

static bool raw_unwind(libraries_t *libraries, const ftrace_fcall_t *fcall, size_t *callstack, size_t size) {
    if (!libraries || !fcall || !callstack || !size) {
        TRACE_ERROR("NULL");
        return false;
    }

    const library_t *library = NULL;
    ssize_t i = 0;
    size_t j = 0;
    ssize_t len = 0;
    int memfd = ftrace_memfd(fcall->ftrace);

    if ((len = pread64(memfd, g_buff, sizeof(g_buff), fcall->sp)) < 0) {
        TRACE_ERROR("Failed to read SP at 0x%zx: %m", fcall->sp);
        return false;
    }
    len /= sizeof(size_t);

    for (i = 0; i < len && j < size; i++) {
        size_t pc = ((size_t *) g_buff)[i];

        if ((library = libraries_find(libraries, pc))) {
            callstack[j++] = pc;
        }
    }

    return true;
}

static void memtrace_monitor_handler(epoll_handler_t *self, int events) {
    uint64_t value = 0;
    app_t *app = container_of(self, app_t, monitor_handler);
    assert(read(app->monitor_timerfd, &value, sizeof(value)) > 0);
    memtrace_status(app);
}

static void memtrace_worker_handler(epoll_handler_t *self, int events) {
    uint64_t value = 0;
    app_t *app = container_of(self, app_t, worker_handler);
    assert(read(app->worker_timerfd, &value, sizeof(value)) > 0);

    hashmap_qsort(&app->blocks, blocks_map_compar);

    size_t i = 0;
    hashmap_iterator_t *it = NULL;
    hashmap_for_each(it, &app->blocks) {
        block_t *block = container_of(it, block_t, it);

        if (i++ >= 20) {
            app->big_callstack_threshold = block->size;
            break;
        }
    }
}

static void raw_print_callstack(app_t *app, size_t *callstack, size_t size) {
    size_t i;
    for (i = 0; i < size; i++) {
        size_t address = callstack[i];
        if (!address || !app->libraries) {
            break;
        }

        const library_t *library = libraries_find(app->libraries, address);
        if (library) {
            size_t ra = library_relative_address(library, address);
            addr2line_print(library->name, ra, stderr);
        }
        else {
            //CONSOLE("    0x%zx", address);
        }
    }
}

block_t *alloc_unwind(app_t *app, const ftrace_fcall_t *fcall) {
    hashmap_iterator_t *it = NULL;
    size_t *callstack = NULL;
    block_t *block = NULL;

    assert((callstack = calloc(app->callstack_size, sizeof(size_t))));
    app->unwind(app->libraries, fcall, callstack, app->callstack_size);

    if ((it = hashmap_get(&app->blocks, callstack))) {
        block = container_of(it, block_t, it);
        if (app->big_callstack_threshold > 0 && block->size >= app->big_callstack_threshold && !block->big_callstack) {
            assert((block->big_callstack = calloc(app->big_callstack_size, sizeof(size_t))));
            app->unwind(app->libraries, fcall, block->big_callstack, app->big_callstack_size);
        }
        free(callstack);
    }
    else {
        block = calloc(1, sizeof(block_t));
        assert(block);
        block->callstack = callstack;
        hashmap_add(&app->blocks, block->callstack, &block->it);
        stats.block_inuse += 1;
    }
    block->count += 1;

    // check flags
    if (block->do_coredump) {
        CONSOLE("Generating coredump for memory allocation context n°%zu", block->number);
        CONSOLE("%zd bytes in %zd blocks were not free", block->size, block->count);
        memtrace_write_local_coredump(app, "/tmp/core");
        CONSOLE_RAW("\n> ");
        block->do_coredump = false;
    }
    if (block->do_gdb) {
        CONSOLE("Attaching gdb to memory allocation context n°%zu", block->number);
        CONSOLE("%zd bytes in %zd blocks were not free", block->size, block->count);
        memtrace_gdb(app);
        CONSOLE("Memtrace resuming execution");
        CONSOLE_RAW("> ");
        block->do_gdb = false;
        // CTRL+C may be used to interrupt gdb. We should not exit event loop
        exit_evlp = false;
    }

    return block;
}

static void memtrace_alloc(app_t *app, void *ptr, size_t size, block_t *block) {
    allocation_t *allocation = NULL;

    // create allocation
    assert((allocation = calloc(1, sizeof(allocation_t))));
    assert(allocation);
    allocation->ptr_size = size;
    allocation->ptr = ptr;
    allocation->block = block;
    hashmap_add(&app->allocations, ptr, &allocation->it);

    // increment statistics
    block->size += allocation->ptr_size;
    stats.alloc_count += 1;
    stats.alloc_size += size;
    stats.byte_inuse += size;
}

static void memtrace_free(app_t *app, void *ptr) {
    hashmap_iterator_t *it = NULL;

    if (ptr && (it = hashmap_get(&app->allocations, ptr))) {
        allocation_t *allocation = container_of(it, allocation_t, it);
        hashmap_iterator_destroy(&allocation->it);
    }
    else if (!app->attachpid) {
        CONSOLE("[memtrace] free(%p) (not found)", ptr);
    }
}

void libraries_print_debug(int pid) {
    snprintf(g_buff, sizeof(g_buff), "/proc/%d/maps", pid);
    FILE *fp = fopen(g_buff, "r");
    if (!fp) {
        return;
    }

    while (fgets(g_buff, sizeof(g_buff), fp)) {
        printf("%s", g_buff);
    }
    fclose(fp);
}

void memtrace_status(app_t *app) {
    time_t now = time(NULL);
    CONSOLE("HEAP SUMMARY %s", asctime(localtime(&now)));
    CONSOLE("    in use: %zu bytes in %zu blocks", stats.byte_inuse, stats.block_inuse);
    CONSOLE("    total heap usage: %zu allocs, %zu frees, %zu bytes allocated", stats.alloc_count, stats.free_count, stats.alloc_size);
}

void memtrace_client_report(app_t *app, size_t max) {

}

bool memtrace_is_local(app_t *app) {
    return app->fs.cfg.type == fs_type_local;
}

static void memtrace_local_blocks_print(app_t *app, size_t max) {
    size_t i = 0;
    hashmap_iterator_t *it = NULL;

    hashmap_for_each(it, &app->blocks) {
        block_t *block = container_of(it, block_t, it);

        if (max > 0 && i >= max) {
            break;
        }

        CONSOLE("Memory allocation context n°%zu", i);
        CONSOLE("%zd bytes in %zd blocks were not free", block->size, block->count);
        if (block->big_callstack) {
            raw_print_callstack(app, block->big_callstack, app->big_callstack_size);
        }
        else {
            raw_print_callstack(app, block->callstack, app->callstack_size);
        }
        CONSOLE("");

        i++;
    }

}

static void memtrace_client_callstack_print(app_t *app, size_t *callstack, size_t size, FILE *fp) {
    size_t i;
    for (i = 0; i < size; i++) {
        size_t address = callstack[i];
        if (!address || !app->libraries) {
            break;
        }

        const library_t *library = libraries_find(app->libraries, address);
        if (library) {
            size_t ra = library_relative_address(library, address);
            fprintf(fp, "ra=0x%zx:%s\n", ra, library->name);
        }
        else {
            //fprintf(fp, "    0x%zx\n", address);
        }
    }
}

static void memtrace_client_blocks_print(app_t *app, size_t max) {
    size_t i = 0;
    hashmap_iterator_t *it = NULL;

    FILE *fp = app->fs.socket;

    // Send whole report to server
    fprintf(fp, REPORT_REQUEST " addr2line=%s\n", app->addr2line);
    hashmap_for_each(it, &app->blocks) {
        block_t *block = container_of(it, block_t, it);

        if (max > 0 && i >= max) {
            break;
        }


        fprintf(fp, "Memory allocation context n°%zu\n", i);
        fprintf(fp, "%zd bytes in %zd blocks were not free\n", block->size, block->count);
        if (block->big_callstack) {
            memtrace_client_callstack_print(app, block->big_callstack, app->big_callstack_size, fp);
        }
        else {
            memtrace_client_callstack_print(app, block->callstack, app->callstack_size, fp);
        }
        fprintf(fp, "\n");
        i++;
    }
    fprintf(fp, REPORT_REQUEST_END "\n");
    fflush(fp);

    // Read back translated formated report from server
    size_t len = 4096;
    char *line = malloc(len);
    while(fgets(line, len, fp)) {
        if (!strcmp(line, REPORT_REPLY"\n")) {
            break;
        }
    }

    while(fgets(line, len, fp)) {
        if (!strcmp(line, REPORT_REPLY_END"\n")) {
            break;
        }
        CONSOLE_RAW("%s", line);
    }
    free(line);
}

void memtrace_blocks_print(app_t *app, size_t max) {
    if (memtrace_is_local(app)) {
        memtrace_local_blocks_print(app, max);
    }
    else {
        memtrace_client_blocks_print(app, max);
    }
}

void memtrace_report(app_t *app, size_t max) {
    if (app->libraries) {
        libraries_print(app->libraries, stdout);
        //libraries_print_debug(app->pid);
    }
    CONSOLE("[memtrace] report");

    hashmap_qsort(&app->blocks, blocks_map_compar);
    memtrace_blocks_print(app, max);
    memtrace_status(app);
}

void memtrace_clear(app_t *app) {
    CONSOLE("Clearing list of allocations");

    hashmap_clear(&app->allocations);
    stats.alloc_count = 0;
    stats.alloc_size = 0;
    stats.free_count = 0;
    stats.free_size = 0;
    stats.byte_inuse = 0;
    stats.block_inuse = 0;
}

bool malloc_handler(const ftrace_fcall_t *fcall, void *userdata) {
    ftrace_fcall_t rtfcall = {0};
    app_t *app = userdata;

    if (ftrace_depth(fcall->ftrace) > 1) {
        TRACE_DEBUG("nested");
        return true;
    }

    block_t *block = alloc_unwind(app, fcall);

    if (!ftrace_fcall_get_rv(fcall, &rtfcall)) {
        TRACE_ERROR("failed to get fcall return value");

        ftrace_fcall_t here = {0};
        if (ftrace_get_registers(&app->ftrace, &here)) {
            ftrace_fcall_dump(&here);
        }
        return false;
    }

    size_t size = fcall->arg1;
    void *newptr = (void *) rtfcall.retval;
    TRACE_DEBUG("malloc(%zu) -> %p", size, newptr);
    memtrace_alloc(app, newptr, size, block);
    return true;
}

bool calloc_handler(const ftrace_fcall_t *fcall, void *userdata) {
    ftrace_fcall_t rtfcall = {0};
    app_t *app = userdata;

    if (ftrace_depth(fcall->ftrace) > 1) {
        TRACE_DEBUG("nested");
        return true;
    }

    block_t *block = alloc_unwind(app, fcall);

    if (!ftrace_fcall_get_rv(fcall, &rtfcall)) {
        TRACE_ERROR("calloc: Failed to get fcall return value");
        return false;
    }

    size_t size = fcall->arg1 * fcall->arg2;
    void *newptr = (void *) rtfcall.retval;
    TRACE_DEBUG("calloc(%zu) -> %p", size, newptr);
    memtrace_alloc(app, newptr, size, block);

    return true;
}

bool realloc_handler(const ftrace_fcall_t *fcall, void *userdata) {
    ftrace_fcall_t rtfcall = {0};
    app_t *app = userdata;

    if (ftrace_depth(fcall->ftrace) > 1) {
        TRACE_DEBUG("nested");
        return true;
    }

    block_t *block = alloc_unwind(app, fcall);

    if (!ftrace_fcall_get_rv(fcall, &rtfcall)) {
        TRACE_ERROR("failed to get fcall return value");
        return false;
    }

    void *oldptr = (void *) fcall->arg1;
    size_t size = fcall->arg2;
    void *newptr = (void *) rtfcall.retval;

    if (oldptr) {
        TRACE_DEBUG("realloc.free(%p)", oldptr);
        memtrace_free(app, oldptr);
    }
    if (newptr) {
        TRACE_DEBUG("realloc.alloc(%zu) -> %p", size, newptr);
        memtrace_alloc(app, newptr, size, block);
    }

    return true;
}

bool reallocarray_handler(const ftrace_fcall_t *fcall, void *userdata) {
    ftrace_fcall_t rtfcall = {0};
    app_t *app = userdata;

    if (ftrace_depth(fcall->ftrace) > 1) {
        TRACE_DEBUG("nested");
        return true;
    }

    block_t *block = alloc_unwind(app, fcall);

    if (!ftrace_fcall_get_rv(fcall, &rtfcall)) {
        TRACE_ERROR("failed to get fcall return value");
        return false;
    }
    void *oldptr = (void *) fcall->arg1;
    size_t size = fcall->arg2 * fcall->arg3;
    void *newptr = (void *) rtfcall.retval;

    if (oldptr) {
        TRACE_DEBUG("reallocarray.free(%p)", oldptr);
        memtrace_free(app, oldptr);
    }
    if (newptr) {
        TRACE_DEBUG("reallocarray.alloc(%zu) -> %p", size, newptr);
        memtrace_alloc(app, newptr, size, block);
    }

    return true;
}

bool free_handler(const ftrace_fcall_t *fcall, void *userdata) {
    ftrace_fcall_t rtfcall = {0};
    app_t *app = userdata;

    void *ptr = (void *) fcall->arg1;

    if (!ftrace_fcall_get_rv(fcall, &rtfcall)) {
        TRACE_ERROR("failed to get fcall return value");
        return false;
    }

    TRACE_DEBUG("free(%p)", ptr);

    if (ftrace_depth(fcall->ftrace) > 1) {
        TRACE_DEBUG("nested");
        return true;
    }

    if (ptr) {
        memtrace_free(app, ptr);
    }
    return true;
}

breakpoint_t *app_set_breakpoint(app_t *app, const char *func, ftrace_handler_t handler) {
    const char *libname = "/libc(\\.|-)";

    const library_t *library = libraries_find_by_name(app->libraries, libname);
    if (!library) {
        TRACE_LOG("%s not found", libname);
        return NULL;
    }

    elf_file_t *symtab = library->dynsym_file;
    elf_file_t *strtab = library->dynstr_file;
    if (!symtab || !strtab) {
        TRACE_ERROR("symtab(%p) or strtab(%p) not found", symtab, strtab);
        return NULL;
    }

    elf_sym_t sym = elf_sym_from_name(symtab, strtab, func);
    if (!sym.name) {
        TRACE_ERROR("%s not found in %s", func, library->name);
        return NULL;
    }

    uint64_t address = library_absolute_address(library, sym.offset);

    CONSOLE("Set breakpoint on %s in %s:0x%"PRIx64" (0x%"PRIx64")", func, library->name, sym.offset, address);
    return ftrace_set_breakpoint(&app->ftrace, func, address, handler, app);
}

static bool app_set_breakpoints(app_t *app) {
    if (!app->calloc_bp) {
        app->malloc_bp = app_set_breakpoint(app, "malloc", malloc_handler);
        app->calloc_bp = app_set_breakpoint(app, "calloc", calloc_handler);
        app->realloc_bp = app_set_breakpoint(app, "realloc", realloc_handler);
        app->reallocarray_bp = app_set_breakpoint(app, "reallocarray", reallocarray_handler);
        app->free_bp = app_set_breakpoint(app, "free", free_handler);

        if (app->calloc_bp) {
            TRACE_LOG("breakpoints are set");
        }
    }

    return app->calloc_bp;
}

static bool openat_handler(const ftrace_fcall_t *fcall, void *userdata) {
    ftrace_fcall_t rtfcall = {0};
    app_t *app = userdata;
    char path[256] = {0};
    ftrace_read_string(fcall->ftrace, fcall->arg2, path, sizeof(path));

    if (!ftrace_fcall_get_rv(fcall, &rtfcall)) {
        TRACE_ERROR("failed to get fcall return value");
        return false;
    }

    TRACE_LOG("openat(path: %s) -> %zd", path, rtfcall.retval);

    if (strstr(path, "/libc.") || strstr(path, "/libc-")) {
        app->libc_fd = rtfcall.retval;
        TRACE_DEBUG("libc fd = %d", app->libc_fd);
    }

    return true;
}

static bool mmap_handler(const ftrace_fcall_t *fcall, void *userdata) {
    ftrace_fcall_t rtfcall = {0};
    app_t *app = userdata;
    //int prot = fcall->arg3;
    //int fd = fcall->arg5;

    TRACE_WARNING("mmap(0x%zx, %zd, %zd, %zd, %d, %zd) in",
        fcall->arg1, fcall->arg2, fcall->arg3, fcall->arg4, (int)fcall->arg5, fcall->arg6);

    if (!ftrace_fcall_get_rv(fcall, &rtfcall)) {
        TRACE_ERROR("failed to get fcall return value");
        return false;
    }

    TRACE_WARNING("mmap(0x%zx, %zd, %zd, %zd, %d, %zd) -> 0x%zx",
        fcall->arg1, fcall->arg2, fcall->arg3, fcall->arg4, (int)fcall->arg5, fcall->arg6, rtfcall.retval);

    if (!app->libraries) {
        const libraries_cfg_t cfg = {
            .pid = app->pid,
            .fs = &app->fs,
        };
        app->libraries = libraries_create(&cfg);
    }
    else {
        libraries_update(app->libraries);
    }
    app_set_breakpoints(app);
/*
    if (fd >= 0 && fd == app->libc_fd && !app->calloc_bp && (prot & PROT_EXEC)) {
        CONSOLE("libc executable library is mapped");

        if (app_set_breakpoints(app)) {
            // TODO: remove syscall breakpoint
        }
    }
    */
    return true;
}

static void signal_interrupt_handler(int sig) {
    CONSOLE("\nInterrupted");
    exit_evlp = true;
}

static uint32_t allocations_maps_hash(hashmap_t *hashmap, void *key) {
    size_t addr = (size_t) key;
    return addr >> 2;
}

static bool allocations_maps_match(hashmap_t *hashmap, void *lkey, void *rkey) {
    size_t laddr = (size_t) lkey;
    size_t raddr = (size_t) rkey;

    return laddr == raddr;
}

static void help() {
    char cpu_mode_list[128] = "";
    const cpu_mode_t *cpu_mode = NULL;

    for (cpu_mode = arch.cpu_modes; cpu_mode && cpu_mode->str; cpu_mode++) {
        if (cpu_mode != arch.cpu_modes) {
            strcat(cpu_mode_list, ", ");
        }
        strcat(cpu_mode_list, cpu_mode->str);
    }

    CONSOLE("Usage: memtrace [OPTION]... -p PID");
    CONSOLE("       memtrace [OPTION]... PROGRAM [ARG]...");
    CONSOLE("Trace memory allocations and report memory leak.");
    CONSOLE("");
    CONSOLE("Options:");
    CONSOLE("   -p, --pid                   Attach to specified PID");
    CONSOLE("   -a, --autoconnect           Auto connect to file server using multicast discovery");
    CONSOLE("   -c, --connect=HOST[:PORT]   Connect to file server specified by HOST and PORT");
    CONSOLE("   -l, --listen=HOST[:PORT]    Listen for file server on the specified HOST and PORT");
    CONSOLE("   -u, --unwind=MODE           Set UNWIND mode [raw, dwarf]");
    CONSOLE("   -s, --size=VALUE            Set callstack size (default: 10)");
    CONSOLE("   --selftest                  Run self test");
    CONSOLE("   --addr2func=ADDR            Convert address to function");
    CONSOLE("   --func2addr=ADDR            Convert function to address");
    CONSOLE("   --debugframe                Dump debug frame");
    CONSOLE("   --elfdump                   Dump ELF file");
    CONSOLE("   --reladump                  Dump ELF relocation addresses");
    CONSOLE("   --coredump                  Generate coredump from target process");
    CONSOLE("   --gdb                       Inspect target process with gdb");
    CONSOLE("   -v, --verbose               Increase logging verbosity");
    fprintf(stderr,
            "   -z, --zone                  Set logging debug zone (");
    print_trace_zones(stderr);
    fprintf(stderr, ")\n");
    CONSOLE("   -h, --help                  Display this help");
    CONSOLE("   -V, --version               Display the version");
}

static void version() {
    CONSOLE("memtrace " VERSION);
}

static int elfdump(const char *name, fs_t *fs) {
    elf_t *elf = NULL;
    if (!(elf = elf_open(name, fs))) {
        CONSOLE("failed to open %s", name);
        return 1;
    }
    elf_print(elf);
    elf_close(elf);
    return 0;
}

static int reladump(const char *name, fs_t *fs) {
    elf_t *elf = NULL;
    if (!(elf = elf_open(name, fs))) {
        CONSOLE("failed to open %s", name);
        return 1;
    }

    CONSOLE("Dump ELF relocation addresses");

    elf_file_t *rela_dyn = elf_section_open_from_name(elf, ".rela.dyn");
    elf_file_t *rela_plt = elf_section_open_from_name(elf, ".rela.plt");
    elf_file_t *symtab = elf_section_open_from_name(elf, ".dynsym");
    elf_file_t *strtab = elf_section_open_from_name(elf, ".dynstr");

    if (rela_dyn && symtab && strtab) {
        CONSOLE("Dump .rela.dyn");
        elf_relocate_dump(elf, rela_dyn, symtab, strtab);
    }
    if (rela_plt && symtab && strtab) {
        CONSOLE("Dump .rela.plt");
        elf_relocate_dump(elf, rela_plt, symtab, strtab);
    }

    elf_file_close(rela_dyn);
    elf_file_close(rela_plt);
    elf_file_close(symtab);
    elf_file_close(strtab);
    elf_close(elf);
    return 0;
}

/*
static int elfaddr2line(const char *name, uint64_t addr, fs_t *fs) {
    elf_t *elf = NULL;
    debug_line_info_t *info = NULL;
    if (!(elf = elf_open(name, fs))) {
        CONSOLE("Failed to open %s", name);
        return 1;
    }
    if ((info = debug_line(elf, addr))) {
        CONSOLE("%s:%d", info->file, info->line);
        debug_line_info_free(info);
    }
    else {
        CONSOLE("line not found");
    }
    elf_close(elf);

    return info ? 0 : 1;
}
*/
static int elfaddr2func(const char *name, uint64_t addr, fs_t *fs) {
    elf_t *elf = NULL;
    if (!(elf = elf_open(name, fs))) {
        CONSOLE("failed to open %s", name);
        return 1;
    }

    elf_file_t *symtab = elf_section_open_from_name(elf, ".dynsym");
    elf_file_t *strtab = elf_section_open_from_name(elf, ".dynstr");
    elf_sym_t sym = {0};
    if (symtab && strtab) {
        sym = elf_sym(symtab, strtab, addr);
        if (sym.name) {
            CONSOLE("%s()+0x%"PRIx64, sym.name, sym.offset);
        }
        else {
            CONSOLE("symbol not found");
        }
    }
    else {
        CONSOLE("symbol table not found");
    }

    if (symtab) {
        elf_file_close(symtab);
    }
    if (strtab) {
        elf_file_close(strtab);
    }
    elf_close(elf);

    return sym.name ? 0 : 1;
}

static int elfdebugframe(const char *name, uint64_t addr, fs_t *fs) {
    elf_t *elf = NULL;
    debug_frame_rules_t state_machine = {0};

    if (!(elf = elf_open(name, fs))) {
        CONSOLE("failed to open %s", name);
        return 1;
    }
    if (debug_frame(elf, &state_machine, addr)) {
        debug_frame_rules_print(&state_machine);
    }
    elf_close(elf);

    return 0;
}

static int elffunc2addr(const char *name, const char *func, fs_t *fs) {
    elf_t *elf = NULL;
    if (!(elf = elf_open(name, fs))) {
        CONSOLE("Failed to open %s", name);
        return 1;
    }

    elf_file_t *symtab = elf_section_open_from_name(elf, ".dynsym");
    elf_file_t *strtab = elf_section_open_from_name(elf, ".dynstr");
    if (symtab && strtab) {
        elf_sym_t sym = elf_sym_from_name(symtab, strtab, func);
        if (sym.name) {
            CONSOLE("%s() address is 0x%"PRIx64, sym.name, sym.offset);
        }
    }

    elf_close(elf);

    return 0;
}


#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "ptrace.h"

size_t ftrace_get_symaddr(ftrace_t *ftrace, libraries_t *libraries, const char *fname) {
    const char *libname = "/libc(\\.|-)";

    const library_t *library = libraries_find_by_name(libraries, libname);
    if (!library) {
        TRACE_ERROR("%s not found", libname);
        return 0;
    }

    elf_file_t *symtab = library->dynsym_file;
    elf_file_t *strtab = library->dynstr_file;
    if (!symtab || !strtab) {
        TRACE_ERROR("symtab(%p) or strtab(%p) not found", symtab, strtab);
        return 0;
    }

    elf_sym_t sym = elf_sym_from_name(symtab, strtab, fname);
    if (!sym.name) {
        TRACE_ERROR("%s not found in %s", fname, library->name);
        return 0;
    }

    size_t fnaddr = library_absolute_address(library, sym.offset);

    CONSOLE("%s function address is 0x%zx (libc+0x%zx)", fname, fnaddr, sym.offset);

    return fnaddr;
}

bool ftrace_call_function(ftrace_t *ftrace, libraries_t *libraries, const char *fname) {
    CONSOLE("Call function %s", fname);

    struct user_regs_struct regs = {0};
    struct user_regs_struct save_regs = {0};
    int i = 0;
    int pid = 0;
    int status = 0;
    size_t fnaddr = 0;

    pid = ftrace_pid(ftrace);

    if (!(fnaddr = ftrace_get_symaddr(ftrace, libraries, fname))) {
        return false;
    }

    // Save registers
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        TRACE_ERROR("Failed to getregs for process %d", pid);
        return false;
    }
    save_regs = regs;


    TRACE_WARNING("Current PC: 0x%llx", regs.rip);
    TRACE_WARNING("Set PC: 0x%zx", fnaddr);

    // Set registers
    //regs.rip = fnaddr;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0) {
        TRACE_ERROR("Failed to setregs for process %d (%m)", pid);
        return false;
    }

    for (i = 0; i < 2; i++) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0) {
            TRACE_ERROR("ptrace(SYSCALL, %d) failed: %m", pid);
            return false;
        }
        if (waitpid(pid, &status, 0) < 0) {
            TRACE_ERROR("waitpid(%d) failed: %m", pid);
            return false;
        }
        if (!ptrace_stopped_by_syscall(status)) {
            TRACE_ERROR("process(%d) was not stopped by syscall (stautus: %d)", pid, status);
            return false;
        }
    }


    // Restore saved registers
    if (ptrace(PTRACE_SETREGS, pid, NULL, &save_regs) != 0) {
        TRACE_ERROR("Failed to setregs for process %d (%m)", pid);
        return false;
    }


    return true;
}

// Note: This seems to work well !
bool ftrace_hijack_syscall(ftrace_t *ftrace, libraries_t *libraries, size_t syscall, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6, size_t *ret) {
    struct user_regs_struct regs = {0};
    struct user_regs_struct save_regs = {0};
    ftrace_fcall_t fcall = {0};
    int pid = 0;
    int status = 0;

    pid = ftrace_pid(ftrace);

    // Wait for next syscall
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0) {
        TRACE_ERROR("ptrace(SYSCALL, %d) failed: %m", pid);
        return false;
    }
    if (waitpid(pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", pid);
        return false;
    }
    if (!ptrace_stopped_by_syscall(status)) {
        TRACE_ERROR("process(%d) was not stopped by syscall (stautus: %d)", pid, status);
        return false;
    }

    // Save registers
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        TRACE_ERROR("Failed to getregs for process %d", pid);
        return false;
    }
    save_regs = regs;

    // Set registers
    regs.orig_rax = syscall;
    regs.rdi = arg1;
    regs.rsi = arg2;
    regs.rdx = arg3;
    regs.r10 = arg4;
    regs.r8  = arg5;
    regs.r9  = arg6;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0) {
        TRACE_ERROR("Failed to setregs for process %d (%m)", pid);
        return false;
    }

    // Wait for syscall done
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0) {
        TRACE_ERROR("ptrace(SYSCALL, %d) failed: %m", pid);
        return false;
    }
    if (waitpid(pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", pid);
        return false;
    }
    if (!ptrace_stopped_by_syscall(status)) {
        TRACE_ERROR("process(%d) was not stopped by syscall (stautus: %d)", pid, status);
        return false;
    }
    if (!arch.ftrace_fcall_fill(&fcall, pid)) {
        TRACE_ERROR("Failed to get registers");
        return false;
    }
    if (ret) {
        *ret = fcall.retval;
    }

    // Restore saved registers
    if (ptrace(PTRACE_SETREGS, pid, NULL, &save_regs) != 0) {
        TRACE_ERROR("Failed to setregs for process %d (%m)", pid);
        return false;
    }

    return true;
}

size_t ftrace_syscall_open(ftrace_t *ftrace, libraries_t *libraries, void *path, int flags, mode_t mode) {
    size_t ret = 0;

    ftrace_hijack_syscall(ftrace, libraries,
        SYS_open, (size_t) path, flags, mode, 0, 0, 0, &ret);

    return ret;
}

void *ftrace_syscall_mmap(ftrace_t *ftrace, libraries_t *libraries, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    size_t ret = 0;

    ftrace_hijack_syscall(ftrace, libraries,
        SYS_mmap, (size_t) addr, length, prot, flags, fd, offset, &ret);

    return (void *) ret;
}


size_t ftrace_get_rela_offset(ftrace_t *ftrace, const library_t *target, const char *fname) {
    elf_relocate_t rela;
    elf_file_t *rela_plt = elf_section_open_from_name(target->elf, ".rela.plt");
    elf_file_t *dynsym = elf_section_open_from_name(target->elf, ".dynsym");
    elf_file_t *dynstr = elf_section_open_from_name(target->elf, ".dynstr");

    if (!rela_plt || !dynsym || !dynstr) {
        TRACE_ERROR("Failed to open .rela.plt section");
        return false;
    }

    if (!elf_relocate_find_by_name(target->elf, rela_plt, dynsym, dynstr, fname, &rela)) {
        TRACE_ERROR("Failed to find relocation address for %s", fname);
        return false;
    }

    elf_file_close(rela_plt);
    elf_file_close(dynsym);
    elf_file_close(dynstr);

    // FIXME: We are assuming rela type is R_X86_64_JUMP_SLO
    return rela.offset;
}

bool ftrace_replace_function(ftrace_t *ftrace, const library_t *target, const library_t *inject, size_t inject_baseaddr, const char *fname, const char *inject_fname) {
    CONSOLE("Replace %s() function by %s() function", fname, inject_fname);

    size_t startcode = library_absolute_address(target, 0);
    CONSOLE("startcode = 0x%zx", startcode);

    //size_t rela_fn_offset = 0x000000004010;
    size_t rela_fn_offset = ftrace_get_rela_offset(ftrace, target, fname);
    size_t rela_fn_addr = startcode + rela_fn_offset;
    CONSOLE("Relocation function address: 0x%zx (offset: 0x%zx)", rela_fn_addr, rela_fn_offset);

    // Compute inject function offset
    elf_file_t *symtab = inject->symtab_file;
    elf_file_t *strtab = inject->strtab_file;
    if (!symtab || !strtab) {
        TRACE_ERROR(".symtab or .strtab not found");
        return NULL;
    }
    elf_sym_t sym = elf_sym_from_name(symtab, strtab, inject_fname);
    if (!sym.name) {
        TRACE_ERROR("%s not found", inject_fname);
        return NULL;
    }
    CONSOLE("Inject function offset: 0x%zx (section: %u)", sym.offset, sym.section_index);
    size_t fn_addr = inject_baseaddr + sym.offset;
    CONSOLE("function address: 0x%zx", fn_addr);

    CONSOLE("Replace function (*0x%zx = 0x%zx)", rela_fn_addr, fn_addr);
    if (ptrace(PTRACE_POKETEXT, ftrace_pid(ftrace), rela_fn_addr, fn_addr) != 0) {
        TRACE_ERROR("Failed to replace function");
        return false;
    }
/*
    CONSOLE("Dump memory at 0x%zx:", fn_addr);
    char memfile[64];
    snprintf(memfile, sizeof(memfile), "/proc/%d/mem", ftrace_pid(ftrace));
    FILE *mem = fopen(memfile, "r");
    assert(mem);
    fseek(mem, fn_addr, SEEK_SET);
    uint8_t buff[0x100];
    fread(buff, sizeof(buff), 1, mem);
    fclose(mem);
    size_t i = 0;
    for (i = 0; i < sizeof(buff); i++) {
        fprintf(stderr, "%02X", buff[i]);
    }
    CONSOLE("");
    CONSOLE("");
*/
    return true;
}

typedef struct {
    ftrace_t *ftrace;
    const library_t *program;
    const library_t *inject;
    const library_t *libc;
} ftrace_resolve_function_ctx_t;

size_t ftrace_relocate_address(const library_t *program, const library_t *lib, elf_relocate_t *rela) {
    switch (rela->type) {
        case R_X86_64_64:
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            return library_absolute_address(lib, rela->offset);
        case R_X86_64_RELATIVE:
            return library_absolute_address(program, rela->offset);
        case R_X86_64_NONE:
        case R_X86_64_PC32:
        case R_X86_64_GOT32:
        case R_X86_64_PLT32:
        case R_X86_64_COPY:
        case R_X86_64_GOTPCREL:
        case R_X86_64_32:
        case R_X86_64_32S:
        case R_X86_64_16:
        case R_X86_64_PC16:
        case R_X86_64_8:
        case R_X86_64_PC8:
        case R_X86_64_DTPMOD64:
        case R_X86_64_DTPOFF64:
        case R_X86_64_TPOFF64:
        case R_X86_64_TLSGD:
        case R_X86_64_TLSLD:
        case R_X86_64_DTPOFF32:
        case R_X86_64_GOTTPOFF:
        case R_X86_64_TPOFF32:
        case R_X86_64_PC64:
        case R_X86_64_GOTOFF64:
        case R_X86_64_GOTPC32:
        case R_X86_64_GOT64:
        case R_X86_64_GOTPCREL64:
        case R_X86_64_GOTPC64:
        case R_X86_64_GOTPLT64:
        case R_X86_64_PLTOFF64:
        case R_X86_64_SIZE32:
        case R_X86_64_SIZE64:
        case R_X86_64_GOTPC32_TLSDESC:
        case R_X86_64_TLSDESC_CALL:
        case R_X86_64_TLSDESC:
        case R_X86_64_IRELATIVE:
        case R_X86_64_RELATIVE64:
        case R_X86_64_GOTPCRELX:
        case R_X86_64_REX_GOTPCRELX:
        default:
            CONSOLE("%x is not handled", rela->type);
            return 0;
    }
}

size_t ftrace_resolve_function_fromlib(elf_relocate_t *rela, ftrace_resolve_function_ctx_t *ctx, const library_t *lib) {
    // Compute lib function offset
    elf_file_t *symtab = lib->dynsym_file;
    elf_file_t *strtab = lib->dynstr_file;
    if (!symtab || !strtab) {
        TRACE_ERROR(".dynsym or .dynstr not found");
        return 0;
    }
    elf_sym_t sym = elf_sym_from_name(symtab, strtab, rela->sym.name);
    if (!sym.name) {
        //TRACE_ERROR("%s not found (section idx: %d)", rela->sym.name, rela->sym.section_index);
        return 0;
    }

    return library_absolute_address(lib, sym.offset);
}

bool ftrace_resolve_function(elf_relocate_t *rela, void *userdata) {
    ftrace_resolve_function_ctx_t *ctx = userdata;
    size_t rela_addr = 0;
    size_t sym_addr = 0;

    if (!(rela_addr = ftrace_relocate_address(ctx->program, ctx->inject, rela))) {
        TRACE_ERROR("Failed to get %s() relocation adress", rela->sym.name);
        return true;
    }

    if (!(sym_addr = ftrace_resolve_function_fromlib(rela, ctx, ctx->libc))) {
        if (!(sym_addr = ftrace_resolve_function_fromlib(rela, ctx, ctx->inject))) {
            if (!(sym_addr = ftrace_resolve_function_fromlib(rela, ctx, ctx->program))) {
                TRACE_ERROR("Failed to resolve function %s()", rela->sym.name);
                return true;
            }
        }
    }

    /*
    if (!(sym_addr = ftrace_resolve_function_fromlib(rela, ctx, ctx->libc))) {
        TRACE_ERROR("Failed to resolve function %s()", rela->sym.name);
        return true;
    }
    */

    CONSOLE("Resolve %s() (*0x%zx = 0x%zx)", rela->sym.name, rela_addr, sym_addr);
    if (ptrace(PTRACE_POKETEXT, ftrace_pid(ctx->ftrace), rela_addr, sym_addr) != 0) {
        TRACE_ERROR("Failed to replace function");
        return true;
    }

    return true;
}

bool ftrace_resolve_functions(ftrace_t *ftrace, const library_t *program, const library_t *inject, const library_t *libc) {
    ftrace_resolve_function_ctx_t ctx = {
        .ftrace = ftrace,
        .program = program,
        .inject = inject,
        .libc = libc,
    };
    if (!inject->rela_plt_file || !inject->rela_dyn_file || !inject->dynsym_file || !inject->dynstr_file) {
        TRACE_ERROR("Failed to open .rela.plt section");
        return false;
    }

    if (!elf_relocate_read(inject->elf, inject->rela_plt_file, inject->dynsym_file, inject->dynstr_file, ftrace_resolve_function, &ctx)) {
        TRACE_ERROR("Failed to process .rela.plt section");
        return false;
    }

    if (!elf_relocate_read(inject->elf, inject->rela_dyn_file, inject->dynsym_file, inject->dynstr_file, ftrace_resolve_function, &ctx)) {
        TRACE_ERROR("Failed to process .rela.dyn section");
        return false;
    }

    return true;
}

bool memtrace_code_injection(app_t *app) {
    CONSOLE("memtrace_code_injection()");

    const char *libname = "/home/guillaume/Workspace/code_injection/code_injection.so";

    elf_t *elf = NULL;
    const program_header_t *ph = NULL;
    FILE *fp = fopen(libname, "r");

    if (!fp) {
        TRACE_ERROR("fopen %s failed: %m", libname);
        return false;
    }
    if (!(elf = elf_open(libname, &app->fs))) {
        TRACE_ERROR("Failed to open %s", libname);
        return false;
    }

    // Allocate memory for writing string
    void *straddr = ftrace_syscall_mmap(&app->ftrace, app->libraries,
        0, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    // Pre-allocate the memory
    void *baseaddr = ftrace_syscall_mmap(&app->ftrace, app->libraries,
        0, 1000*1000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    if (!straddr || !baseaddr) {
        TRACE_ERROR("mmap failed");
        return false;
    }

    char memfile[64];
    snprintf(memfile, sizeof(memfile), "/proc/%d/mem", ftrace_pid(&app->ftrace));
    FILE *mem = fopen(memfile, "w");
    assert(mem);


    // Write library name in target memory
    fseek(mem, (size_t)straddr, SEEK_SET);
    fprintf(mem, "%s", libname);
    fflush(mem);
    size_t fd = ftrace_syscall_open(&app->ftrace, app->libraries, straddr, O_RDONLY, 0);
    CONSOLE("%s opened in target process with fd:%zu", libname, fd);


    TRACE_WARNING("Memory mapped at %p", baseaddr);

    for (ph = elf_program_header_first(elf); ph; ph = elf_program_header_next(elf, ph)) {
        if (ph->p_type != p_type_load) {
            continue;
        }

        void *ptr = (void *) (((size_t) baseaddr) + ph->p_vaddr);

        int prot = PROT_NONE;
        if (ph->p_flags & p_flags_r) {
            prot |= PROT_READ;
        }
        if (ph->p_flags & p_flags_w) {
            prot |= PROT_WRITE;
        }
        if (ph->p_flags & p_flags_x) {
            prot |= PROT_EXEC;
        }

        CONSOLE("Load program: ptr: %p, offset: %"PRIx64 ", size: %"PRIx64, ptr, ph->p_offset, ph->p_memsz);

        // Map memory on target process
        // Map address must be aligned according ph->p_align
        size_t mapaddr = (((size_t) ptr) / ph->p_align) * ph->p_align;
        size_t mapsize = (((size_t) ptr) % ph->p_align) + ph->p_memsz;
        size_t offset = (ph->p_offset / ph->p_align) * ph->p_align;
        if (ftrace_syscall_mmap(&app->ftrace, app->libraries,
            (void *) mapaddr, mapsize, prot, MAP_PRIVATE|MAP_FIXED, fd, offset) != (void *) mapaddr)
        {
            TRACE_ERROR("Failed to map memory");
            return false;
        }
        CONSOLE("Program mapped at 0x%zx (size=0x%zx)", mapaddr, mapsize);
    }

    libraries_update(app->libraries);
    libraries_print(app->libraries, stdout);

    const library_t *program_lib = libraries_first(app->libraries);
    const library_t *c_lib = libraries_find_by_name(app->libraries, "/libc(\\.|-)");
    const library_t *inject_lib = libraries_find_by_name(app->libraries, libname);
    if (!program_lib) {
        TRACE_ERROR("Failed to find target lib");
        return false;
    }
    if (!c_lib) {
        TRACE_ERROR("Failed to find C lib");
        return false;
    }
    if (!inject_lib) {
        TRACE_ERROR("Failed to find inject lib");
        return false;
    }

    ftrace_replace_function(&app->ftrace, program_lib, inject_lib, (size_t)baseaddr, "getmagicnumber", "mygetmagicnumber");
    ftrace_replace_function(&app->ftrace, program_lib, inject_lib, (size_t)baseaddr, "calloc", "mycalloc");
    ftrace_resolve_functions(&app->ftrace, program_lib, inject_lib, c_lib);


    // Initialize .bss section to zero
    const section_header_t *bss = elf_section_header_get(inject_lib->elf, ".bss");
    if (bss) {
        size_t bss_addr = library_absolute_address(inject_lib, bss->sh_addr);
        CONSOLE("Initalizing BSS section (addr = 0x%zx, size = 0x%zx)", bss_addr, bss->sh_size);
        fseek(mem, bss_addr, SEEK_SET);
        for (size_t i = 0; i < bss->sh_size; i++) {
            fputc(0, mem);
        }
        fflush(mem);
    }


    elf_close(elf);
    fclose(fp);
    fclose(mem);
    return true;
}

int main(int argc, char* argv[]) {
    const char *short_options = "+p:ac:l:m:u:s:tvz:hV";
    const struct option long_options[] = {
        {"pid",         required_argument,  0, 'p'},
        {"autoconnect", no_argument,        0, 'a'},
        {"connect",     required_argument,  0, 'c'},
        {"listen",      required_argument,  0, 'l'},
        {"mode",        required_argument,  0, 'm'},
        {"unwind",      required_argument,  0, 'u'},
        {"size",        required_argument,  0, 's'},
        {"selftest",    no_argument,        0, 't'},
        {"verbose",     no_argument,        0, 'v'},
        {"zone",        required_argument,  0, 'z'},
        {"addr2func",   required_argument,  0, 'F'},
        {"func2addr",   required_argument,  0, 'f'},
        {"debugframe",  required_argument,  0, 'D'},
        {"elfdump",     no_argument,        0, 'E'},
        {"reladump",    no_argument,        0, 'R'},
        {"coredump",    no_argument,        0, 'C'},
        {"gdb",         no_argument,        0, 'G'},
        {"help",        no_argument,        0, 'h'},
        {"version",     no_argument,        0, 'V'},
        {0}
    };

    int opt = -1;
    const cpu_mode_t *cpu_mode = NULL;
    const char *cpu_mode_str = NULL;
    //const char *addr2line = NULL;
    const char *addr2func = NULL;
    const char *addr2frame = NULL;
    const char *func2addr = NULL;
    bool do_elfdump = false;
    bool do_reladump = false;
    bool do_coredump = false;
    bool do_gdb = false;
    app_t app = {
        .libc_fd = -1,
        .callstack_size = 10,
        .big_callstack_size = 200,
        .monitor_handler = {memtrace_monitor_handler},
        .worker_handler = {memtrace_worker_handler},
        .unwind = raw_unwind,
        .addr2line = toolchain_default_command("addr2line"),
        .gdb = toolchain_default_command("gdb"),
    };
    fs_cfg_t fs_cfg = {
        .type = is_cross_compiled() ? fs_type_tcp_client : fs_type_local,
        .me = "memtrace",
        .tgt = "memtrace-fs",
    };

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                app.pid = atoi(optarg);
                app.attachpid = true;
                break;
            case 'a':
                fs_cfg.type = fs_type_tcp_client;
                break;
            case 'c':
                fs_cfg.type = fs_type_tcp_client;
                fs_cfg.hostname = strtok(optarg, ":");
                fs_cfg.port = strtok(NULL, ":");
                break;
            case 'l':
                fs_cfg.type = fs_type_tcp_server;
                fs_cfg.hostname = strtok(optarg, ":");
                fs_cfg.port = strtok(NULL, ":");
                break;
            case 'm':
                cpu_mode_str = optarg;
                break;
            case 's':
                app.callstack_size = atoi(optarg);
                break;
            case 't':
                return selftest_main(argc, argv);
            //case 'L':
            //    addr2line = optarg;
            //    break;
            case 'F':
                addr2func = optarg;
                break;
            case 'f':
                func2addr = optarg;
                break;
            case 'D':
                addr2frame = optarg;
                break;
            case 'E':
                do_elfdump = true;
                break;
            case 'R':
                do_reladump = true;
                break;
            case 'C':
                do_coredump = true;
                break;
            case 'G':
                do_gdb = true;
                break;
            case 'v':
                verbose++;
                break;
            case 'z':
                set_trace_zones(optarg);
                break;
            case 'h':
                help();
                return 0;
            case 'V':
                version();
                return 0;
            default:
                help();
                return 1;
        }
    }

    if (!fs_initialize(&app.fs, &fs_cfg)) {
        TRACE_ERROR("Failed to initialize File System");
        return 1;
    }

    argc -= optind;
    argv += optind;

    if (do_elfdump) {
        if (argc != 1) {
            help();
            return 1;
        }
        return elfdump(argv[0], &app.fs);
    }
    if (do_reladump) {
        if (argc != 1) {
            help();
            return 1;
        }
        return reladump(argv[0], &app.fs);
    }
    /*
    if (addr2line) {
        if (argc != 1) {
            help();
            return 1;
        }
        return elfaddr2line(argv[0], atoll(addr2line), &app.fs);
    }
    */
    if (addr2func) {
        if (argc != 1) {
            help();
            return 1;
        }
        return elfaddr2func(argv[0], atoll(addr2func), &app.fs);
    }
    if (addr2frame) {
        if (argc != 1) {
            help();
            return 1;
        }
        return elfdebugframe(argv[0], atoll(addr2frame), &app.fs);
    }
    if (func2addr) {
        if (argc != 1) {
            help();
            return 1;
        }
        return elffunc2addr(argv[0], func2addr, &app.fs);
    }

    for (cpu_mode = arch.cpu_modes; cpu_mode && cpu_mode->str; cpu_mode++) {
        if (cpu_mode_str && !strcmp(cpu_mode->str, cpu_mode_str)) {
            arch.cpu_mode = cpu_mode->value;
            break;
        }
    }

    if (!app.attachpid) {
        if (argc <= 0) {
            help();
            return 1;
        }
        app.pid = fork();
        if (app.pid == 0) {
            //setpgid(0, 0); //FIXME: setpgid cause issue with processes using terminal
            return execvp(argv[0], &argv[0]);
        }
        else if (app.pid < 0) {
            TRACE_ERROR("fork failed: %m");
            return 1;
        }
    }

    struct sigaction sa = {
        .sa_handler = signal_interrupt_handler,
        .sa_flags = 0,
    };

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        TRACE_ERROR("sigaction error: %m");
        return 1;
    }

    CONSOLE("Ataching to pid %d", app.pid);

    if (!ftrace_attach(&app.ftrace, app.pid)) {
        return 1;
    }

    char name[32];
    snprintf(name, sizeof(name), "/proc/%d/exe", app.pid);
    if (readlink(name, g_buff, sizeof(g_buff)) < 0) {
        TRACE_ERROR("Failed to read program name: %m");
        return 1;
    }
    app.program_name = strdup(g_buff);

    if (do_coredump) {
        return memtrace_write_local_coredump(&app, "/tmp/core") ? 0 : 1;
    }
    if (do_gdb) {
        return memtrace_gdb(&app) ? 0 : 1;
    }

    const hashmap_cfg_t allocations_maps_cfg = {
        .size       = 4000,
        .hash       = allocations_maps_hash,
        .match      = allocations_maps_match,
        .destroy    = allocations_maps_destroy,
    };
    const hashmap_cfg_t blocks_maps_cfg = {
        .size       = allocations_maps_cfg.size,
        .hash       = blocks_maps_hash,
        .match      = blocks_maps_match,
        .destroy    = blocks_maps_destroy,
    };
    hashmap_initialize(&app.allocations, &allocations_maps_cfg);
    hashmap_initialize(&app.blocks, &blocks_maps_cfg);

    // Monitor when libc is loaded
    if (!ftrace_set_syscall_breakpoint(&app.ftrace, SYS_openat, openat_handler, &app)) {
        return 1;
    }

    // Monitor when mmap is called
#ifdef SYS_mmap
    if (!ftrace_set_syscall_breakpoint(&app.ftrace, SYS_mmap, mmap_handler, &app)) {
        return 1;
    }
#else
    if (!ftrace_set_syscall_breakpoint(&app.ftrace, SYS_mmap2, mmap_handler, &app)) {
        return 1;
    }
#endif
    if (!app.attachpid) {
        return 1;
    }

    const libraries_cfg_t cfg = {
        .pid = app.pid,
        .fs = &app.fs,
    };
    app.libraries = libraries_create(&cfg);

    if (!app.libraries) {
        TRACE_ERROR("Failed to open libraries");
        return 1;
    }

    return memtrace_code_injection(&app) ? 0 : 1;
}

