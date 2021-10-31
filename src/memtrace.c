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
#include <getopt.h>
//#include <elfutils/elf-knowledge.h>
//#include <elfutils/known-dwarf.h>
//#include <elfutils/libdwfl.h>
//#include <elfutils/libdwelf.h>
//#include <elfutils/libdw.h>
#include "ftrace.h"
#include "hashmap.h"
#include "libraries.h"
#include "arch.h"
#include "net.h"
#include "selftest.h"
#include "log.h"
//#include "backtrace.h"
#include "debug_line.h"
#include "debug_info.h"
#include "debug_frame.h"
#include "dwarf_unwind.h"
#include "elf.h"
#include "elf_file.h"
#include "elf_sym.h"
#include "fs.h"
#include "console.h"

typedef struct {
    hashmap_iterator_t it;
    size_t ptr_size;
    void *ptr;
    size_t *callstack;
} allocation_t;

typedef struct {
    hashmap_iterator_t it;
    size_t count;
    size_t size;
    size_t *callstack;
} block_t;

typedef struct {
    fs_t fs;
    ftrace_t ftrace;
    int pid;
    int libc_fd;
    libraries_t *libraries;
    hashmap_t allocations;
    hashmap_t blocks;
    size_t callstack_size;
    size_t alloc_count;
    size_t alloc_size;
    size_t free_count;
    size_t free_size;
    breakpoint_t *calloc_bp;
    breakpoint_t *malloc_bp;
    breakpoint_t *realloc_bp;
    breakpoint_t *reallocarray_bp;
    breakpoint_t *free_bp;
    console_t console;
    bool monitor;
    int monitor_timerfd;
    epoll_handler_t stdin_handler;
    epoll_handler_t monitor_handler;
    bool (*unwind)(libraries_t *libraries, const ftrace_fcall_t *fcall, size_t *callstack, size_t size);
} app_t;

void memtrace_status(app_t *app);
void memtrace_report(app_t *app);
void memtrace_clear(app_t *app);

static bool raw_unwind(libraries_t *libraries, const ftrace_fcall_t *fcall, size_t *callstack, size_t size) {
    const library_t *library = NULL;
    size_t i = 0, j = 0;

    if (!libraries || !fcall || !callstack || !size) {
        TRACE_ERROR("NULL");
        return false;
    }

    TRACE_LOG("Unwind callstack at 0x%lx", fcall->pc);

    callstack[j++] = fcall->pc;

    for (i = 0; i < 200 && j < size; i++) {
        size_t pc = 0;
        if (!ftrace_read_word(fcall->ftrace, fcall->sp+i, &pc)) {
            break;
        }

        if (!(library = libraries_find(libraries, pc))) {
            continue;
        }

        callstack[j++] = pc;
    }

    return true;
}

static void memtrace_console_quit(console_t *console, int argc, char *argv[]) {
    // gently ask the event loop to exit
    kill(getpid(), SIGINT);
}

static void memtrace_console_status(console_t *console, int argc, char *argv[]) {
    app_t *app = container_of(console, app_t, console);
    memtrace_status(app);
}

static void memtrace_console_monitor(console_t *console, int argc, char *argv[]) {
    app_t *app = container_of(console, app_t, console);
    app->monitor ^= true;

    struct itimerspec itimer = {0};

    if (app->monitor) {
        CONSOLE("Start monitoring");
        itimer.it_interval.tv_sec = 2;
        itimer.it_value.tv_sec = 2;
    }
    timerfd_settime(app->monitor_timerfd, 0, &itimer, NULL);
    memtrace_status(app);
}

static void memtrace_monitor_handler(epoll_handler_t *self, int events) {
    uint64_t value = 0;
    app_t *app = container_of(self, app_t, monitor_handler);
    assert(read(app->monitor_timerfd, &value, sizeof(value)) > 0);
    memtrace_status(app);
}


static void memtrace_console_report(console_t *console, int argc, char *argv[]) {
    app_t *app = container_of(console, app_t, console);
    memtrace_report(app);
}

static void memtrace_console_clear(console_t *console, int argc, char *argv[]) {
    app_t *app = container_of(console, app_t, console);
    memtrace_clear(app);
}

static void allocations_maps_destroy(void *key, hashmap_iterator_t *it) {
    allocation_t *allocation = container_of(it, allocation_t, it);
    free(allocation->callstack);
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
    free(block);
}

void addr2line_backtrace(app_t *app, size_t *callstack) {
    size_t i;
    for (i = 0; i < app->callstack_size; i++) {
        size_t address = callstack[i];
        if (!address || !app->libraries) {
            break;
        }

        //dwfl_print_symbol(stdout, (void *) address, app->pid);
        const library_t *library = libraries_find(app->libraries, address);
        if (library) {
            size_t ra = library_relative_address(library, address);
            library_print_symbol(library, ra, stderr);
        }
        else {
            CONSOLE("    0x%zx", address);
        }
    }
}



void do_callstack_dummy(const ftrace_fcall_t *fcall, app_t *app, allocation_t *allocation) {
    size_t callstackidx = 0;
    allocation->callstack[callstackidx++] = fcall->pc;
    allocation->callstack[callstackidx++] = fcall->ra;
    size_t i = 0;
    size_t word = 0;
    for (i = 0; i < 1024; i++) {
        size_t addr = fcall->sp + (i * sizeof(word));
        if (!ftrace_read_word(&app->ftrace, addr, &word)) {
            break;
        }

        if (!libraries_find(app->libraries, word)) {
            continue;
        }

        allocation->callstack[callstackidx++] = word;

        if (callstackidx >= app->callstack_size) {
            break;
        }
    }
}

static void memtrace_alloc(const ftrace_fcall_t *fcall, const ftrace_fcall_t *rtfcall, app_t *app, void *ptr, size_t size, size_t *callstack) {
    TRACE_LOG("malloc(%zu) -> %p", size, ptr);

    allocation_t *allocation = calloc(1, sizeof(allocation_t));
    assert(allocation);
    allocation->ptr_size = size;
    allocation->ptr = ptr;
    allocation->callstack = callstack;
    assert(allocation->callstack);
    hashmap_add(&app->allocations, ptr, &allocation->it);

    app->alloc_count += 1;
    app->alloc_size += size;


    //CONSOLE("pc = 0x%lx, ra = 0x%zx", fcall->pc, fcall->ra);

    //CONSOLE("unw backtrace:");
    //backtrace(&app->bt, allocation->callstack, app->alloc_size);
    //CONSOLE("");
    //CONSOLE("addr2line backtrace:");
    //addr2line_backtrace(app, allocation->callstack);
    //CONSOLE("");
}

static void memtrace_free(app_t *app, void *ptr) {
    hashmap_iterator_t *it = NULL;

    if (ptr && (it = hashmap_get(&app->allocations, ptr))) {
        TRACE_LOG("free(%p)", ptr);
        allocation_t *allocation = container_of(it, allocation_t, it);
        app->free_count += 1;
        app->free_size += allocation->ptr_size;
        hashmap_iterator_destroy(&allocation->it);
    }
    else {
        CONSOLE("[memtrace] free(%p) (not found)", ptr);
    }
}

void libraries_print_debug(int pid) {
    char buff[1024];
    snprintf(buff, sizeof(buff), "/proc/%d/maps", pid);
    FILE *fp = fopen(buff, "r");
    if (!fp) {
        return;
    }

    while (fgets(buff, sizeof(buff), fp)) {
        printf("%s", buff);
    }
    fclose(fp);
}

void memtrace_status(app_t *app) {
    size_t count = 0;
    size_t size = 0;
    hashmap_iterator_t *it = NULL;

    hashmap_for_each(it, &app->allocations) {
        allocation_t *allocation = container_of(it, allocation_t, it);
        block_t *block = NULL;
        hashmap_iterator_t *sit = NULL;

        count++;
        size += allocation->ptr_size;

        if (!(sit = hashmap_get(&app->blocks, allocation->callstack))) {
            block = calloc(1, sizeof(block_t));
            assert(block);
            block->callstack = allocation->callstack;
            hashmap_add(&app->blocks, block->callstack, &block->it);
        }
        else {
            block = container_of(sit, block_t, it);
        }

        block->count += 1;
        block->size += allocation->ptr_size;
    }

    CONSOLE("HEAP SUMMARY:");
    CONSOLE("    in use: %zu bytes in %zu blocks", size, count);
    CONSOLE("    total heap usage: %zu allocs, %zu frees, %zu bytes allocated", app->alloc_count, app->free_count, app->alloc_size);

    hashmap_clear(&app->blocks);
}

void memtrace_report(app_t *app) {
    if (app->libraries) {
        libraries_print(app->libraries, stdout);
        //libraries_print_debug(app->pid);
    }
    CONSOLE("[memtrace] report");

    size_t count = 0;
    size_t size = 0;
    hashmap_iterator_t *it = NULL;

    hashmap_for_each(it, &app->allocations) {
        allocation_t *allocation = container_of(it, allocation_t, it);
        block_t *block = NULL;
        hashmap_iterator_t *sit = NULL;

        count++;
        size += allocation->ptr_size;

        if (!(sit = hashmap_get(&app->blocks, allocation->callstack))) {
            block = calloc(1, sizeof(block_t));
            assert(block);
            block->callstack = allocation->callstack;
            hashmap_add(&app->blocks, block->callstack, &block->it);
        }
        else {
            block = container_of(sit, block_t, it);
        }

        block->count += 1;
        block->size += allocation->ptr_size;
    }

    hashmap_qsort(&app->blocks, blocks_map_compar);
    hashmap_for_each(it, &app->blocks) {
        block_t *block = container_of(it, block_t, it);

        CONSOLE("%zu bytes in %zu blocks were not free", block->size, block->count);
        addr2line_backtrace(app, block->callstack);
        CONSOLE("");
    }

    CONSOLE("HEAP SUMMARY:");
    CONSOLE("    in use at exit: %zu bytes in %zu blocks", size, count);
    CONSOLE("    total heap usage: %zu allocs, %zu frees, %zu bytes allocated", app->alloc_count, app->free_count, app->alloc_size);

    hashmap_clear(&app->blocks);
}

void memtrace_clear(app_t *app) {
    CONSOLE("Clearing list of allocations");

    hashmap_clear(&app->allocations);
    app->alloc_count = 0;
    app->free_count = 0;
    app->alloc_size = 0;
}

bool malloc_handler(const ftrace_fcall_t *fcall, void *userdata) {
    ftrace_fcall_t rtfcall = {0};
    app_t *app = userdata;

    if (ftrace_depth(fcall->ftrace) > 1) {
        return true;
    }

    size_t *callstack = calloc(app->callstack_size, sizeof(size_t));
    app->unwind(app->libraries, fcall, callstack, app->callstack_size);

    if (!ftrace_fcall_get_rv(fcall, &rtfcall)) {
        TRACE_ERROR("failed to get fcall return value");

        ftrace_fcall_t here = {0};
        if (ftrace_get_registers(&app->ftrace, &here)) {
            ftrace_fcall_dump(&here);
        }
        free(callstack);
        return false;
    }

    memtrace_alloc(fcall, &rtfcall, app, (void *) rtfcall.retval, fcall->arg1, callstack);
    return true;
}

bool calloc_handler(const ftrace_fcall_t *fcall, void *userdata) {
    ftrace_fcall_t rtfcall = {0};
    app_t *app = userdata;

    if (ftrace_depth(fcall->ftrace) > 1) {
        return true;
    }

    size_t *callstack = calloc(app->callstack_size, sizeof(size_t));
    app->unwind(app->libraries, fcall, callstack, app->callstack_size);

    if (!ftrace_fcall_get_rv(fcall, &rtfcall)) {
        TRACE_ERROR("calloc: Failed to get fcall return value");
        free(callstack);
        return false;
    }

    memtrace_alloc(fcall, &rtfcall, app, (void *) rtfcall.retval, fcall->arg1 * fcall->arg2, callstack);

    return true;
}

bool realloc_handler(const ftrace_fcall_t *fcall, void *userdata) {
    ftrace_fcall_t rtfcall = {0};
    app_t *app = userdata;

    if (ftrace_depth(fcall->ftrace) > 1) {
        return true;
    }

    size_t *callstack = calloc(app->callstack_size, sizeof(size_t));
    app->unwind(app->libraries, fcall, callstack, app->callstack_size);

    if (!ftrace_fcall_get_rv(fcall, &rtfcall)) {
        TRACE_ERROR("failed to get fcall return value");
        free(callstack);
        return false;
    }

    void *oldptr = (void *) fcall->arg1;
    size_t size = fcall->arg2;
    void *newptr = (void *) rtfcall.retval;

    if (oldptr) {
        memtrace_free(app, oldptr);
    }
    if (newptr) {
        memtrace_alloc(fcall, &rtfcall, app, newptr, size, callstack);
    }

    return true;
}

bool reallocarray_handler(const ftrace_fcall_t *fcall, void *userdata) {
    ftrace_fcall_t rtfcall = {0};
    app_t *app = userdata;

    if (ftrace_depth(fcall->ftrace) > 1) {
        return true;
    }

    size_t *callstack = calloc(app->callstack_size, sizeof(size_t));
    app->unwind(app->libraries, fcall, callstack, app->callstack_size);

    if (!ftrace_fcall_get_rv(fcall, &rtfcall)) {
        TRACE_ERROR("failed to get fcall return value");
        free(callstack);
        return false;
    }
    void *oldptr = (void *) fcall->arg1;
    size_t size = fcall->arg2 * fcall->arg3;
    void *newptr = (void *) rtfcall.retval;

    if (oldptr) {
        memtrace_free(app, oldptr);
    }
    if (newptr) {
        memtrace_alloc(fcall, &rtfcall, app, newptr, size, callstack);
    }

    return true;
}

bool free_handler(const ftrace_fcall_t *fcall, void *userdata) {
    app_t *app = userdata;

    if (ftrace_depth(fcall->ftrace) > 1) {
        return true;
    }

    void *ptr = (void *) fcall->arg1;
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

    TRACE_WARNING("Set breakpoint on %s in %s:0x%"PRIx64" (0x%"PRIx64")", func, library->name, sym.offset, address);
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

    if (!ftrace_fcall_get_rv(fcall, &rtfcall)) {
        TRACE_ERROR("failed to get fcall return value");
        return false;
    }

    TRACE_LOG("mmap(0x%zx, %zd, %zd, %zd, %d, %zd) -> 0x%zx",
        fcall->arg1, fcall->arg2, fcall->arg3, fcall->arg4, (int)fcall->arg5, fcall->arg6, rtfcall.retval);

    if (!app->libraries) {
        app->libraries = libraries_create(app->pid, &app->fs);
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

    CONSOLE("Usage: memtrace [OPTION]... PID");
    CONSOLE("       memtrace [OPTION]... PROGRAM [ARG]...");
    CONSOLE("Trace memory allocations and report memory leak");
    CONSOLE("");
    CONSOLE("Options:");
    CONSOLE("   -a, --autoconnect           Auto connect to file server using multicast discovery");
    CONSOLE("   -c, --connect=HOST[:PORT]   Connect to file server specified by HOST and PORT");
    CONSOLE("   -l, --listen=HOST[:PORT]    Listen for file server on the specified HOST and PORT");
    CONSOLE("   -m, --mode=VALUE            Set CPU mode [%s]", cpu_mode_list);
    CONSOLE("   --selftest                  Run self test");
    CONSOLE("   --addr2line=ADDR            Convert address to line");
    CONSOLE("   --addr2func=ADDR            Convert address to function");
    CONSOLE("   --func2addr=ADDR            Convert function to address");
    CONSOLE("   --debugframe                Dump debug frame");
    CONSOLE("   --elfdump                   Dump ELF file");
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

static int elfaddr2func(const char *name, uint64_t addr, fs_t *fs) {
    elf_t *elf = NULL;
    debug_info_t *info = NULL;
    if (!(elf = elf_open(name, fs))) {
        CONSOLE("failed to open %s", name);
        return 1;
    }
    if ((info = debug_info_function(elf, addr))) {
        CONSOLE("0x%"PRIx64" = %s()+0x%"PRIx64, info->address, info->function, info->offset);
        debug_info_free(info);
    }
    else {
        CONSOLE("function not found: fallback to symbol table");
        elf_file_t *symtab = elf_section_open_from_name(elf, ".dynsym");
        elf_file_t *strtab = elf_section_open_from_name(elf, ".dynstr");
        if (symtab && strtab) {
            elf_sym_t sym = elf_sym(symtab, strtab, addr);
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
    }
    elf_close(elf);

    return info ? 0 : 1;
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

static void memtrace_stdin_handler(epoll_handler_t *self, int events) {
    app_t *app = container_of(self, app_t, stdin_handler);
    console_poll(&app->console);
}

static const console_cmd_t memtrace_console_commands[] = {
    {.name = "help",        .help = "Display this help", .handler = console_cmd_help},
    {.name = "quit",        .help = "Quit memtrace and show report", .handler = memtrace_console_quit},
    {.name = "status",      .help = "Show memtrace status", .handler = memtrace_console_status},
    {.name = "monitor",     .help = "Monitor memory allocations", .handler = memtrace_console_monitor},
    {.name = "report",      .help = "Show memtrace report", .handler = memtrace_console_report},
    {.name = "clear",       .help = "Clear memory statistics", .handler = memtrace_console_clear},
    {.name = "continue",    .help = "Continue process execution", .handler = NULL},
    {.name = "backtrace",   .help = "Print process backtrace", .handler = NULL},
    {.name = "breakpoint",  .help = "Set breakpoint", .handler = NULL},
    {0},
};

int main(int argc, char* argv[]) {
    const char *short_options = "+p:ac:l:m:u:tvz:hV";
    const struct option long_options[] = {
        {"pid",         required_argument,  0, 'p'},
        {"autoconnect", no_argument,        0, 'a'},
        {"connect",     required_argument,  0, 'c'},
        {"listen",      required_argument,  0, 'l'},
        {"mode",        required_argument,  0, 'm'},
        {"unwind",      required_argument,  0, 'u'},
        {"selftest",    no_argument,        0, 't'},
        {"verbose",     no_argument,        0, 'v'},
        {"zone",        required_argument,  0, 'z'},
        {"addr2line",   required_argument,  0, 'L'},
        {"addr2func",   required_argument,  0, 'F'},
        {"func2addr",   required_argument,  0, 'f'},
        {"debugframe",  required_argument,  0, 'D'},
        {"elfdump",     no_argument,        0, 'E'},
        {"help",        no_argument,        0, 'h'},
        {"version",     no_argument,        0, 'V'},
        {0}
    };

    int opt = -1;
    const cpu_mode_t *cpu_mode = NULL;
    const char *cpu_mode_str = NULL;
    const char *addr2line = NULL;
    const char *addr2func = NULL;
    const char *addr2frame = NULL;
    const char *func2addr = NULL;
    bool attachpid = false;
    bool do_elfdump = false;
    int s = -1;
    app_t app = {
        .libc_fd = -1,
        .callstack_size = 10,
        .stdin_handler = {memtrace_stdin_handler},
        .monitor_handler = {memtrace_monitor_handler},
        .unwind = dwarf_unwind,
    };
    fs_cfg_t fs_cfg = {
        .type = fs_type_local,
        .me = "memtrace",
        .tgt = "memtrace-fs",
    };

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                app.pid = atoi(optarg);
                attachpid = true;
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
            case 'u':
                if (!strcmp(optarg, "raw")) {
                    app.unwind = raw_unwind;
                }
                else if (!strcmp(optarg, "dwarf")) {
                    app.unwind = dwarf_unwind;
                }
                else {
                    CONSOLE("Unknown unwind mode");
                    return 1;
                }
                break;
            case 't':
                return selftest_main(argc, argv);
            case 'L':
                addr2line = optarg;
                break;
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
    if (addr2line) {
        if (argc != 1) {
            help();
            return 1;
        }
        return elfaddr2line(argv[0], atoll(addr2line), &app.fs);
    }
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

    if (!attachpid) {
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
        perror("sigaction");
        return 1;
    }

    CONSOLE("Ataching to pid %d", app.pid);

    if (!ftrace_attach(&app.ftrace, app.pid)) {
        return 1;
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
    if (attachpid) {
        // Process is already running:
        // Try to set breakpoints now and create process maps
        app.libraries = libraries_create(app.pid, &app.fs);

        if (!app_set_breakpoints(&app)) {
            return 1;
        }
    }

    //backtrace_context_initialize(&app.bt, app.pid);

    console_initiliaze(&app.console, memtrace_console_commands);
    ftrace_set_fd_handler(&app.ftrace, &app.stdin_handler, 0, EPOLLIN);

    app.monitor_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    ftrace_set_fd_handler(&app.ftrace, &app.monitor_handler, app.monitor_timerfd, EPOLLIN);

    while (ftrace_poll(&app.ftrace));

    console_cleanup(&app.console);

    memtrace_report(&app);

    hashmap_cleanup(&app.allocations);
    hashmap_cleanup(&app.blocks);

    if (app.pid > 0) {
        CONSOLE("Detaching from pid %d", app.pid);
        ftrace_detach(&app.ftrace);

        if (!attachpid) {
            kill(app.pid, SIGTERM);
            if (waitpid(app.pid, NULL, 0) != 0) {
                kill(app.pid, SIGKILL);
            }
        }
    }
    if (app.libraries) {
        libraries_destroy(app.libraries);
    }
    if (s >= 0) {
        close(s);
    }

    return 0;
}

