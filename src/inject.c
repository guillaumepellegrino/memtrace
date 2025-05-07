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
#include <fcntl.h>
#include <dirent.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <dlfcn.h>
#include "inject.h"
#include "log.h"
#include "ptrace.h"
#include "memfd.h"
#include "arch.h"
#include "libraries.h"
#include "elf_main.h"
#include "elf_file.h"
#include "elf_sym.h"
#include "elf_relocate.h"
#include "syscall.h"
#include "threads.h"
#include "apparmor.h"

struct _injecter {
    int pid; /** PID of the target process */
    DIR *threads; /** Threads of the target process */
    syscall_ctx_t syscall; /** Context to perform syscall or function call */
    libraries_t *libraries; /** Shared libraries from the target process */
    library_t *libc;
    library_t *inject_lib; /** Injected library */
    int replaced_functions; /** Count of replaced functions */
    int relocation_found; /** Count of relocation found */
};

/**
 * Get Relocation Address (RELA) offset for the specified function
 */
static int64_t library_get_relocation_offset(library_t *lib, const char *symname) {
    elf_relocate_t rela;

    if (!library_get_function_relocation(lib, symname, &rela)) {
        CONSOLE("  - No relocation address for %s() in %s", symname, library_name(lib));
        return -ENOENT;
    }

    return rela.offset;
}

size_t injecter_seek_addr(injecter_t *injecter, void *begin, void *end, size_t addr);

uint64_t library_get_elf_section_addr(library_t *library, elf_t *elf, const section_header_t *sh) {
    const program_header_t *ph = elf_program_header_executable(elf);

    if (ph->p_paddr == (size_t) library_begin(library)) {
        return sh->sh_addr;
    }
    uint64_t baseaddr = library_absolute_address(library, 0);
    //CONSOLE("baseaddr = 0x%"PRIx64, baseaddr);
    return baseaddr + sh->sh_addr;
}

static size_t library_seek_got_addr(injecter_t *injecter, library_t *target, const char *fname) {
    if (!injecter->libc) {
        TRACE_ERROR("libc.so not found");
        return 0;
    }
    library_symbol_t sym = library_find_symbol(injecter->libc, fname);
    if (!sym.name) {
        sym = libraries_find_symbol(injecter->libraries, fname);
    }
    if (!sym.name) {
        TRACE_ERROR("%s() not found in target process", fname);
        return 0;
    }

    elf_t *elf = library_elf(target);
    const section_header_t *got = elf_section_header_get(elf, ".got");
    if (!got) {
        CONSOLE("  - .got section not found in %s", library_name(target));
        return 0;
    }
    CONSOLE(".got section offset: 0x%"PRIx64, got->sh_addr);
    uint64_t got_addr = library_get_elf_section_addr(target, elf, got);
    CONSOLE(".got section : [0x%"PRIx64", 0x%"PRIx64"]", got_addr, got_addr + got->sh_size);

    size_t addr = injecter_seek_addr(injecter, (void *)(size_t) got_addr, (void*)(size_t)(got_addr + got->sh_size), sym.addr);
    if (!addr) {
        CONSOLE("  - %s()=0x%"PRIx64" not found in .got section at [0x%"PRIx64", 0x%"PRIx64"]",
            fname, sym.addr, got_addr, (got_addr + got->sh_size));
    }
    return addr;
}

static bool library_replace_function(injecter_t *injecter, library_t *target, const char *fname, const char *inject_fname) {
    int pid = injecter->pid;
    library_t *inject = injecter->inject_lib;
    CONSOLE("Replace %s():%s by %s():%s", fname, library_name(target), inject_fname, library_name(inject));

    library_symbol_t sym = library_find_symbol(inject, inject_fname);
    if (!sym.name) {
        TRACE_ERROR("%s() not found in %s", inject_fname, library_name(inject));
        return false;
    }

    ssize_t rela_fn_offset = library_get_relocation_offset(target, fname);
    size_t rela_fn_addr = library_absolute_address(target, rela_fn_offset);
    if (rela_fn_offset < 0) {
            rela_fn_addr = library_seek_got_addr(injecter, target, fname);
            if (rela_fn_addr == 0) {
                //TRACE_WARNING("%s() not found in .got section", fname);
                return true;
            }
            CONSOLE("  - GOT Address for %s() is 0x%zx", fname, rela_fn_addr);
    }
    else {
        CONSOLE("  - Relocation Address for %s() is 0x%zx (+0x%zx)", fname, rela_fn_addr, rela_fn_offset);
        injecter->relocation_found++;
    }


    size_t fn_addr = sym.addr;
    CONSOLE("  - %s() address is 0x%"PRIx64" (+0x%"PRIx64")", sym.name, sym.addr, sym.offset);
    CONSOLE("  - Set *0x%zx = 0x%zx", rela_fn_addr, fn_addr);
    if (ptrace(PTRACE_POKETEXT, pid, rela_fn_addr, fn_addr) != 0) {
        TRACE_ERROR("  - Failed to replace function: ptrace(POKETEXT, %d, 0x%zx, 0x%zx) -> %m",
                pid, rela_fn_addr, fn_addr);
        sleep(10);
        return false;
    }

    injecter->replaced_functions++;
    return true;
}

/**
 * Create the injecter context and attach to process
 */
injecter_t *injecter_create(int pid) {
    injecter_t *injecter = NULL;

    assert(pid);
    assert((injecter = calloc(1, sizeof(injecter_t))));
    injecter->pid = pid;

    if (!(injecter->threads = threads_attach(pid))) {
        TRACE_ERROR("Failed to get attach to threads from pid %d", pid);
        goto error;
    }
    if (!(injecter->libraries = libraries_create(injecter->pid))) {
        TRACE_ERROR("Failed to open libraries");
        goto error;
    }
    injecter->libc = libraries_find_by_name(injecter->libraries, "libc.so");
    if (!syscall_initialize(&injecter->syscall, pid, injecter->libraries)) {
        TRACE_ERROR("Failed to init syscall");
        goto error;
    }
    //libraries_print(injecter->libraries, stdout);
    return injecter;

error:
    injecter_destroy(injecter);
    return NULL;
}

/**
 * Destroy the injecter context and detach from process
 */
void injecter_destroy(injecter_t *injecter) {
    if (!injecter) {
        return;
    }
    if (injecter->libraries) {
        libraries_destroy(injecter->libraries);
    }
    syscall_cleanup(&injecter->syscall);
    if (injecter->threads) {
        threads_detach(injecter->threads);
    }
    free(injecter);
}

/**
 * Injecter call function in target process with raw arguments.
 * Function return value is written in retval.
 *
 * Return true on success.
 */
static bool injecter_call_raw(injecter_t *injecter, const char *function, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t *retval) {

    library_symbol_t sym = libraries_find_symbol(injecter->libraries, function);
    if (!sym.name) {
        TRACE_ERROR("Failed to find %s() in target process", function);
        return false;
    }
    CONSOLE("Calling %s(0x%zx, 0x%zx, 0x%zx, 0x%zx) at 0x%"PRIx64,
        sym.name, arg1, arg2, arg3, arg4, sym.addr);

    if (!syscall_function(&injecter->syscall, sym.addr, arg1, arg2, arg3, arg4, retval)) {
        TRACE_ERROR("%s() call failed", sym.name);
        return false;
    }
    CONSOLE("%s() returned 0x%zx (%zd)", sym.name, *retval, *retval);

    return true;
}

/**
 * Injecter duplicate the specified string in target process.
 * Return the address of the allocated string in target process on success..
 *
 * The returned pointer must be freed with injecter_free() after use.
 */
static size_t injecter_strdup(injecter_t *injecter, const char *str) {
    assert(injecter);
    assert(str);

    int memfd = syscall_memfd(&injecter->syscall);
    size_t size = strlen(str) + 1;
    size_t straddr = 0;
    if (!injecter_call_raw(injecter, "calloc", size, 1, 0, 0, &straddr)) {
        TRACE_ERROR("Failed to call calloc(%zu, 1) in target process", size);
        return false;
    }
    if (straddr == 0) {
        TRACE_ERROR("Call to calloc(%zu, 1) returned a NULL pointer", size);
        return false;
    }

    // Write library name in target memory
    if (!memfd_write(memfd, str, strlen(str) + 1, straddr)) {
        TRACE_ERROR("Failed to write library name in target process at 0x%zx", straddr);
        return false;
    }

    CONSOLE("\"%s\" copied at 0x%zx in target process", str, straddr);

    return straddr;
}

/**
 * Injecter call free(addr) in target process.
 * Return true on success.
 */
static bool injecter_free(injecter_t *injecter, size_t addr) {
    size_t retval = 0;
    return injecter_call_raw(injecter, "free", addr, 0, 0, 0, &retval);
}

/**
 * Injecter call function in target process with specified arguments.
 * arguments can be an integer, an hex value or a string.
 * Function return value is written in retval.
 *
 * Return true on success.
 */
bool injecter_call(injecter_t *injecter, const char *function, int argc, const char *argv[], size_t *retval) {
    size_t args_val[4] = {0};
    bool args_is_str[4] = {0};

    assert(injecter);
    assert(function);

    if (argc > 4) {
        TRACE_ERROR("Can not call %s() with more than 4x arguments", function);
        return false;
    }

    CONSOLE_RAW("Preparing to call %s(", function);
    for (int i = 0; i < argc; i++) {
        if (i != 0) {
            CONSOLE_RAW(", ");
        }
        CONSOLE_RAW("%s", argv[i]);
    }
    CONSOLE(")");

    for (int i = 0; i < argc; i++) {
        char *endptr = NULL;
        ssize_t value = strtoll(argv[i], &endptr, 0);

        if (argv[i] == endptr) {
            // argument is not a number but a string
            args_val[i] = injecter_strdup(injecter, argv[i]);
            if (args_val[i] == 0) {
                TRACE_ERROR("Failed to call %s() : Failed to copy %s in target process", function, argv[i]);
                return false;
            }
            args_is_str[i] = true;
        }
        else {
            // argument is a number
            args_val[i] = value;
            args_is_str[i] = false;
        }
    }

    if (getenv("FCALL_CORE")) {
        syscall_do_coredump_at_next_tampering(&injecter->syscall);
    }
    if (!injecter_call_raw(injecter, function, args_val[0], args_val[1], args_val[2], args_val[3], retval)) {
        return false;
    }

    for (int i = 0; i < argc; i++) {
        if (args_is_str[i]) {
            if (!injecter_free(injecter, args_val[i])) {
                TRACE_ERROR("Error calling %s() :Failed to free(%s) in target process", function, argv[i]);
                return false;
            }
        }
    }

    return true;
}

bool injecter_syscall(injecter_t *injecter, const char *syscall, int argc, const char *argv[], size_t *retval) {
    size_t args[6] = {0};
    int number = syscall_number(syscall);

    if (number <= 0) {
        TRACE_ERROR("Unknown syscall %s", syscall);
        return false;
    }
    if (argc > 6) {
        TRACE_ERROR("Can not perform syscall with more than 6x arguments");
        return false;
    }

    for (int i = 0; i < argc; i++) {
        char *endptr = NULL;
        ssize_t value = strtoll(argv[i], &endptr, 0);
        if (argv[i] == endptr) {
            TRACE_ERROR("string arguments are not supported for syscall");
            return false;
        }
        args[i] = value;
    }

    CONSOLE_RAW("Calling syscall %s number %d", syscall, number);
    for (int i = 0; i < argc; i++) {
        if (i == 0) {
            CONSOLE_RAW(" with args ");
        }
        if (i != 0) {
            CONSOLE_RAW(", ");
        }
        CONSOLE_RAW("0x%zx", args[i]);
    }
    CONSOLE("");

    bool rt = syscall_hijack(&injecter->syscall,
        number,
        args[0],
        args[1],
        args[2],
        args[3],
        args[4],
        args[5],
        retval);

    CONSOLE("syscall returned 0x%zx (%zd)", *retval, *retval);

    return rt;
}

void printbuff(size_t *buff, size_t buffsize) {
    for (size_t i = 0; i < buffsize/sizeof(*buff); i++) {
        printf("%08zx ", buff[i]);
        if (i % 8 == 0) {
            printf("\n");
        }
    }

}

size_t injecter_seek_addr(injecter_t *injecter, void *begin, void *end, size_t addr) {
    int memfd = -1;
    const size_t buffsize = 0x1000/sizeof(size_t);
    size_t buff[buffsize];
    size_t location = 0;

    if ((memfd = memfd_open(injecter->pid)) < 0) {
        goto error;
    }

    size_t size = ((size_t) end) - ((size_t) begin);
    // CONSOLE("Seek addr in %p-%p (size:0x%zx)", begin, end, size);
    if (lseek64(memfd, (size_t) begin, SEEK_SET) < 0) {
        TRACE_ERROR("Failed lseek %p: %m", begin);
        goto error;
    }

    for (size_t i = 0; i < size; i += 0x1000) {
        if (read(memfd, buff, sizeof(buff)) <= 0) {
            CONSOLE("[%zx] fread() failed: %m", i);
        }
        for (size_t j = 0; j < sizeof(buff)/sizeof(*buff); j++) {
            if (buff[j] == addr) {
                size_t offset = i + (j * sizeof(*buff));
                location = ((size_t) begin) + offset;
                CONSOLE("0x%zx found at 0x%zx at offset 0x%zx", addr, location, offset);
                goto error;
            }
        }
    }

error:
    close(memfd);
    return location;
}

void injecter_find_function(injecter_t *injecter) {
    const char *fname = "calloc";

    library_symbol_t sym = libraries_find_symbol(injecter->libraries, fname);
    CONSOLE("%s is at 0x%"PRIx64, fname, sym.addr);


    library_t *program = libraries_get(injecter->libraries, 0);
    CONSOLE("Program is %s at [%p, %p]",
            library_name(program), library_begin(program), library_end(program));

    char buff[4096];
    snprintf(buff, sizeof(buff), "/proc/%d/maps", injecter->pid);

    //copy file in buffer
    FILE *fp = fopen(buff, "r");
    if (!fp) {
        TRACE_ERROR("Failed to open %s", buff);
        return;
    }

    while (fgets(buff, sizeof(buff), fp)) {
        void *begin = NULL;
        void *end = NULL;

        if ((sscanf(buff, "%p-%p ", &begin, &end) != 2)) {
            continue;
        }
        injecter_seek_addr(injecter, begin, end, sym.addr);

    }
    fclose(fp);
}

bool injecter_set_library(injecter_t *injecter, const char *libname) {
    assert(injecter);
    assert(libname);

    injecter->inject_lib = libraries_find_by_name(injecter->libraries, libname);

    return injecter->inject_lib;
}

static void injecter_call_dlerror(injecter_t *injecter) {
    char error[512];
    size_t retval = 0;
    if (!injecter_call(injecter, "dlerror", 0, NULL, &retval)) {
        TRACE_ERROR("Could not call dlerror()");
        return;
    }
    int memfd = syscall_memfd(&injecter->syscall);
    memfd_readstr(memfd, error, sizeof(error), retval);
    TRACE_ERROR("dlopen() -> %s", error);
}

// Check if we are able to load this library in the target process
// - Can we open the library in read-only ?
// - Does its mount point have noexec flag ?
// - Can we open the library in read-only in the target process root directory ? (it may fail if process is running in a container)
// - Does its mount point have noexec flag ?
// - Are we able to load the librarary, locally ? (it may fail if library is stored in a read-exec partition or if library has any linking issue)
// - Can the target process, open the library in read-only ?
//
// The goal is to provide comprehensive error messages when the library injection fails.
static bool injecter_check_library(injecter_t *injecter, const char *libname) {
    bool rt = false;
    char *ns_libname = NULL;
    struct statvfs vfs = {0};
    int fd = -1;
    assert(asprintf(&ns_libname, "/proc/%d/root%s", injecter->pid, libname) > 0);

    fd = open(libname, O_RDONLY|O_CLOEXEC);
    if (fd < 0) {
        CONSOLE("Error: Could not open %s: %m", libname);
        goto error;
    }
    if (fstatvfs(fd, &vfs) != 0) {
        TRACE_ERROR("fstatvfs(%s): %m", libname);
        goto error;
    }
    if (vfs.f_flag & ST_NOEXEC) {
        CONSOLE("Error: %s is stored on a mount point with noexec flag", libname);
        CONSOLE("Please remount it with exec rights:");
        CONSOLE("  mount -o remount,exec /path/to/mount/point");
        goto error;
    }
    close(fd);
    fd = open(ns_libname, O_RDONLY|O_CLOEXEC);
    if (fd < 0) {
        CONSOLE("Error: Could not open %s: %m", ns_libname);
        CONSOLE("  but we could open %s", libname);
        CONSOLE("=> The target process seems to be running in a container");
        CONSOLE("=> This usecase is currently not supported");
        goto error;
    }
    if (fstatvfs(fd, &vfs) != 0) {
        TRACE_ERROR("fstatvfs(%s): %m", ns_libname);
        goto error;
    }
    if (vfs.f_flag & ST_NOEXEC) {
        CONSOLE("Error: %s is stored on a mount point with noexec flag", ns_libname);
        CONSOLE("Please remount it with exec rights");
        CONSOLE("  mount -o remount,exec /path/to/mount/point");
    }
    close(fd);

    // Dry run: check if we can load the agent library but without actually starting the agent
    setenv("MEMTRACE_DRYRUN", "1", 1);
    void *dl = dlopen(ns_libname, RTLD_LAZY);
    if (!dl) {
        CONSOLE("ERROR: Can not open %s locally", ns_libname);
        CONSOLE("dlerror() => %s", dlerror());
        goto error;
    }
    dlclose(dl);
    unsetenv("MEMTRACE_DRYRUN");

    // now, check if we can open the file in the target process !
    // we don't have real guarantee than target process have rights for it.
    char flags[16];
    size_t retval = 0;
    snprintf(flags, sizeof(flags), "%d", O_RDONLY|O_CLOEXEC);
    const char *argv[] = {libname, flags};
    if (!injecter_call(injecter, "open", 2, argv, &retval)) {
        TRACE_ERROR("function call injection failed");
        goto error;
    }
    if (((ssize_t) retval) < 0) {
        CONSOLE("ERROR: Target process could not open %s", libname);
        goto error;
    }

    rt = true;
error:
    free(ns_libname);
    return rt;
}

bool injecter_load_library(injecter_t *injecter, const char *libname) {
    bool rt = false;
    char *apparmor = NULL;

    apparmor = apparmor_read_mode();
    if (apparmor && !strcmp(apparmor, "enforce")) {
        TRACE_WARNING("Temporarly disabling apparmor for injecting library");
        apparmor_set_mode("complain");
    }

    if (!injecter_check_library(injecter, libname)) {
        goto error;
    }

    char flags[16];
    snprintf(flags, sizeof(flags), "%d", RTLD_LAZY);
    const char *argv[] = {libname, flags};
    size_t retval = 0;

    // find which function we can use to load library
    bool has_libc_dlopen =  libraries_find_symbol(injecter->libraries, "__libc_dlopen_mode").name;
    bool has_dlopen = libraries_find_symbol(injecter->libraries, "dlopen").name;
    const char *function = NULL;

    if (has_libc_dlopen) {
        function = "__libc_dlopen_mode";
    }
    else if (has_dlopen) {
        function = "dlopen";
    }
    else {
        TRACE_ERROR("Can not load library in target process: target does not have dlopen() nor __libc_dlopen_mode()");
        goto error;
    }

    // load library !
    if (!injecter_call(injecter, function, 2, argv, &retval)) {
        TRACE_ERROR("Failed to inject %s in target process", libname);
        goto error;
    }
    if (retval == 0) {
        TRACE_ERROR("%s(%s, RTLD_LAZY) returned an error", function, libname);
        TRACE_ERROR("Does the target process has the access rights to open %s ?", libname);
        if (has_dlopen) {
            injecter_call_dlerror(injecter);
            goto error;
        }
    }

    // verify library is well loaded
    libraries_update(injecter->libraries);
    injecter->inject_lib = libraries_find_by_name(injecter->libraries, libname);
    injecter->libc = libraries_find_by_name(injecter->libraries, "libc.so");
    if (!injecter->inject_lib) {
        TRACE_ERROR("Failed to find %s in target process mapping", libname);
        libraries_print(injecter->libraries, stdout);
        return false;
    }
    CONSOLE("Library %s injected with success in target process !", libname);
    libraries_print(injecter->libraries, stdout);

    rt = true;
error:
    if (apparmor && !strcmp(apparmor, "enforce")) {
        TRACE_WARNING("Enabling back apparmor");
        apparmor_set_mode(apparmor);
    }
    return rt;
}

bool injecter_replace_function(injecter_t *injecter, const char *program_fname, const char *inject_fname) {
    bool ret = false;
    size_t i = 0;
    for (i = 0; i < libraries_count(injecter->libraries); i++) {
        library_t *lib = libraries_get(injecter->libraries, i);
        if (lib != injecter->inject_lib) {
            ret |= library_replace_function(injecter, lib, program_fname, inject_fname);
        }
    }
    return ret;
}

/**
 * Setup memtrace agent hooks in the target process.
 *
 * The list of functions hooks are retrieved by reading section ".memtrace_hooks" from agent library.
 */
bool injecter_setup_memtrace_hooks(injecter_t *injecter) {
    bool ret = false;
    elf_t *elf = library_elf(injecter->inject_lib);
    elf_file_t *hooks_section = elf_section_open_from_name(elf, ".memtrace_hooks");
    char *hooks = NULL;
    if (!hooks_section) {
        TRACE_ERROR("%s does not contains '.memtrace_hooks' section", library_name(injecter->inject_lib));
        goto error;
    }
    const char *_hooks = elf_file_read_strp(hooks_section);
    if (!_hooks) {
        TRACE_ERROR("'.memtrace_hooks' section does not contain a NULL terminated string");
        goto error;
    }
    hooks = strdup(_hooks);

    CONSOLE("[Replacing functions]");
    injecter->replaced_functions = 0;
    injecter->relocation_found = 0;
    char *saveptr1 = NULL;
    for(char *hook = strtok_r(hooks, ",", &saveptr1); hook; hook = strtok_r(NULL, ",", &saveptr1)) {
        char *saveptr2 = NULL;
        char *program_fname = strtok_r(hook, ":", &saveptr2);
        char *inject_fname = strtok_r(NULL, ":", &saveptr2);
        CONSOLE("[Replacing %s by %s]", program_fname, inject_fname);
        injecter_replace_function(injecter, program_fname, inject_fname);
    }
    ret = injecter->replaced_functions > 0;
    if (ret) {
        CONSOLE("[%d locations were changed]", injecter->replaced_functions);
        CONSOLE("[Functions replaced]");
    }
    else {
        CONSOLE("[Failed to replace any function]");
    }
    ret = true;
error:
    elf_file_close(hooks_section);
    free(hooks);
    return ret;
}

int injecter_relocation_found(injecter_t *injecter) {
    return injecter->relocation_found;
}

