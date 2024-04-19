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

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <dlfcn.h>
#include "inject.h"
#include "log.h"
#include "ptrace.h"
#include "arch.h"
#include "libraries.h"
#include "elf_main.h"
#include "elf_file.h"
#include "elf_sym.h"
#include "elf_relocate.h"
#include "syscall.h"

struct _injecter {
    int pid; /** PID of the target process */
    libraries_t *libraries; /** Shared libraries from the target process */
    char *inject_libname; /** Name of the library to inject */
    void *straddr; /** Memory mapper on target process for writing string */
    library_t *program_lib; /** Program library from target process */
    library_t *inject_lib; /** Injected library */
    library_t *c_lib; /** libc library from target process */
    library_t *pthread_lib; /** optional pthread library from target process */
};

typedef struct {
    int pid;
    library_t *program;
    library_t *inject;
    library_t *c_lib;
    library_t *pthread_lib;
} injecter_resolve_function_ctx_t;

/**
 * Get Relocation Address (RELA) offset for the specified function
 */
static int64_t library_get_rela_offset(library_t *target, const char *fname) {
    elf_relocate_t rela;
    elf_file_t *rela_plt = library_get_elf_section(target, library_section_rela_plt);
    elf_file_t *rela_dyn = library_get_elf_section(target, library_section_rela_dyn);
    elf_file_t *dynsym = library_get_elf_section(target, library_section_dynsym);
    elf_file_t *dynstr = library_get_elf_section(target, library_section_dynstr);

    if (!rela_plt) {
        rela_plt = library_get_elf_section(target, library_section_rel_plt);
        rela_dyn = library_get_elf_section(target, library_section_rel_dyn);
    }
    if (!dynsym || !dynstr) {
        TRACE_ERROR("Failed to open .dynsym and .dynstr sections for %s", library_name(target));
        return -1;
    }

    if (rela_plt && elf_relocate_find_by_name(library_elf(target), rela_plt, dynsym, dynstr, fname, &rela)) {
        return rela.offset;
    }
    if (rela_dyn && elf_relocate_find_by_name(library_elf(target), rela_dyn, dynsym, dynstr, fname, &rela)) {
        return rela.offset;
    }

    CONSOLE("  - No relocation address for %s()", fname);

    // FIXME: We are assuming rela type is R_X86_64_JUMP_SLO
    return -1;
}

static bool library_replace_function(int pid, library_t *target, library_t *inject, const char *fname, const char *inject_fname) {
    CONSOLE("Replace %s():%s by %s():%s", fname, library_name(target), inject_fname, library_name(inject));

    size_t startcode = library_absolute_address(target, 0);
    ssize_t rela_fn_offset = library_get_rela_offset(target, fname);
    if (rela_fn_offset < 0) {
        return true;
    }

    size_t rela_fn_addr = startcode + rela_fn_offset;
    CONSOLE("  - Relocation Address for %s() is 0x%zx (+0x%zx)", fname, rela_fn_addr, rela_fn_offset);

    // Compute inject function offset
    library_symbol_t sym = library_find_symbol(inject, inject_fname);
    if (!sym.name) {
        TRACE_ERROR("%s() not found in %s", inject_fname, library_name(inject));
        return false;
    }
    size_t fn_addr = sym.addr;
    CONSOLE("  - %s() address is 0x%"PRIx64" (+0x%"PRIx64")", sym.name, sym.addr, sym.offset);
    CONSOLE("  - Set *0x%zx = 0x%zx", rela_fn_addr, fn_addr);
    if (ptrace(PTRACE_POKETEXT, pid, rela_fn_addr, fn_addr) != 0) {
        TRACE_ERROR("Failed to replace function: ptrace(POKETEXT, %d, 0x%zx, 0x%zx) -> %m",
            pid, rela_fn_addr, fn_addr);
        sleep(10);
        return false;
    }
    return true;
}

injecter_t *injecter_create(int pid) {
    injecter_t *injecter = NULL;

    assert(pid);
    assert((injecter = calloc(1, sizeof(injecter_t))));
    injecter->pid = pid;

    return injecter;
}

void injecter_destroy(injecter_t *injecter) {
    if (!injecter) {
        return;
    }

    if (injecter->libraries) {
        libraries_destroy(injecter->libraries);
    }

    free(injecter->inject_libname);
    free(injecter);
}

bool injecter_load_library(injecter_t *injecter, const char *libname) {
    char memfile[64];
    int memfd = -1;
    elf_t *elf = NULL;
    FILE *fp = NULL;
    syscall_ctx_t syscall = {0};

    assert(injecter);
    assert(libname);

    injecter->inject_libname = strdup(libname);
    if (!(fp = fopen(injecter->inject_libname, "r"))) {
        TRACE_ERROR("fopen %s failed: %m", injecter->inject_libname);
        return false;
    }
    if (!(elf = elf_open_local(injecter->inject_libname))) {
        TRACE_ERROR("Failed to open %s", injecter->inject_libname);
        return false;
    }

    snprintf(memfile, sizeof(memfile), "/proc/%d/mem", injecter->pid);
    if ((memfd = open(memfile, O_RDWR)) < 0) {
        TRACE_ERROR("Failed to open %s: %m", memfile);
        return false;
    }

    // Sanity check
    if (!syscall_init(&syscall, injecter->pid, memfd)) {
        TRACE_ERROR("Failed to init syscall");
        return false;
    }

    CONSOLE("Performing syscall sanity check on target process");
    int pid = syscall_getpid(&syscall);
    if (pid != injecter->pid) {
        if (pid <= 0) {
            TRACE_ERROR("Failed to inject syscall in target process (pid != %d).", pid);
        }
        else {
            CONSOLE("Target process tell us its pid is %d instead of %d", pid, injecter->pid);
            CONSOLE("Is the target process running in a container ?");
            CONSOLE("");
            CONSOLE("Please ensure than memtrace and target process are running on the same Linux namepaces");
            CONSOLE("");
        }
        return false;
    }
    if (syscall_getpid(&syscall) != injecter->pid) {
        TRACE_ERROR("Failed to inject syscall in target process");
        return false;
    }
    if (syscall_getpid(&syscall) != injecter->pid) {
        TRACE_ERROR("Failed to inject syscall in target process");
        return false;
    }
    CONSOLE("=> Sanity check okay: getpid() returned the correct pid");

/*
Page Size: 0x1000 bytes
Pre-allocate 0x1e000 bytes
mmap() test
ptrace(PTRACE_GETREGS, 10624, {uregs=[0x7, 0xbee9e9d4, 0xbee9ea54, 0, 0, 0xb6ea6ee4, 0xb6f3c6e0, 0x8e, 0x6, 0xbee9e9d4, 0, 0xb6ea6218, 0, 0xbee9e8a0, 0xb6ea1e6b, 0xb6de4550, 0x60000010, 0x7]}) = 0
ptrace(PTRACE_SETREGS, 10624, {uregs=[0, 0x1000, 0x1, 0x802, 0x7, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0x60000010, 0]}) = 0
ptrace(PTRACE_SET_SYSCALL, 10624, NULL, 0xc0) = 0
ptrace(PTRACE_SYSCALL, 10624, NULL, 0)  = 0

b6f38000-b6f39000 r--p b6ea6ee4000 00:14 437     /ext/libmemtrace-agent.so
    */

    if (!(injecter->libraries = libraries_create(injecter->pid))) {
        TRACE_ERROR("Failed to open libraries");
        return false;
    }
    libraries_print(injecter->libraries, stdout);

    injecter->program_lib = libraries_get(injecter->libraries, 0);
    injecter->c_lib = libraries_find_by_name(injecter->libraries, "/libc(\\.|-)");
    injecter->pthread_lib = libraries_find_by_name(injecter->libraries, "/libpthread(\\.|-)");
    if (!injecter->program_lib) {
        TRACE_ERROR("Failed to find target lib");
        return false;
    }
    if (!injecter->c_lib) {
        TRACE_ERROR("Failed to find C lib");
        return false;
    }


    // Allocate memory for writing string
    CONSOLE("Mapping memory in target process");
    injecter->straddr = syscall_mmap(&syscall,
        0, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    if (!injecter->straddr) {
        TRACE_ERROR("mmap failed");
        return false;
    }
    // Write library name in target memory
    if (lseek64(memfd, (size_t)injecter->straddr, SEEK_SET) < 0) {
        TRACE_ERROR("Failed lseek %p: %m", injecter->straddr);
        return false;
    }
    if (write(memfd, injecter->inject_libname, strlen(injecter->inject_libname) + 1) < 0) {
        TRACE_ERROR("Failed write(memfd): %m");
        return false;
    }
    CONSOLE("Library name (%s) is stored at %p in target process", injecter->inject_libname, injecter->straddr);

    library_symbol_t dlopen = libraries_find_symbol(injecter->libraries, "dlopen");
    if (dlopen.name) {
        CONSOLE("dlopen() is at 0x%"PRIx64" in target process", dlopen.addr);
    }
    else {
        dlopen = libraries_find_symbol(injecter->libraries, "__libc_dlopen_mode");
        if (dlopen.name) {
            CONSOLE("__libc_dlopen_mode() is at 0x%"PRIx64" in target process", dlopen.addr);
        }
        else {
            TRACE_ERROR("Failed to find dlopen() or __libc_dlopen_mode()");
            return false;
        }
    }

    CONSOLE("Call %s(%s, RTLD_LAZY) in target process", dlopen.name, injecter->inject_libname);

    size_t rt = 0;
    if (!syscall_function(&syscall, dlopen.addr, (size_t) injecter->straddr, RTLD_LAZY, 0, 0, &rt)) {
        TRACE_ERROR("Failed to run dlopen()");
    }
    if (rt == 0) {
        TRACE_ERROR("dlopen() could not open library");
        return false;
    }
    syscall_munmap(&syscall, injecter->straddr, 4096);

    libraries_update(injecter->libraries);
    injecter->inject_lib = libraries_find_by_name(injecter->libraries, injecter->inject_libname);
    if (!injecter->inject_lib) {
        TRACE_ERROR("Failed to find injected library in target process mapping");
        libraries_print(injecter->libraries, stdout);
        return false;
    }
    CONSOLE("Library injected with success in target process !");
    libraries_print(injecter->libraries, stdout);

    elf_close(elf);
    fclose(fp);
    close(memfd);
    return true;
}

bool injecter_replace_function(injecter_t *injecter, const char *program_fname, const char *inject_fname) {
    bool ret = false;
    size_t i = 0;
    for (i = 0; i < libraries_count(injecter->libraries); i++) {
        library_t *lib = libraries_get(injecter->libraries, i);
        if (lib != injecter->inject_lib) {
            ret |= library_replace_function(injecter->pid, lib, injecter->inject_lib, program_fname, inject_fname);
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
        TRACE_ERROR("%s does not contains '.memtrace_hooks' section", injecter->inject_libname);
        goto error;
    }
    const char *_hooks = elf_file_read_strp(hooks_section);
    if (!_hooks) {
        TRACE_ERROR("'.memtrace_hooks' section does not contain a NULL terminated string");
        goto error;
    }
    hooks = strdup(_hooks);

    CONSOLE("[Replacing functions]");
    char *saveptr1 = NULL;
    for(char *hook = strtok_r(hooks, ",", &saveptr1); hook; hook = strtok_r(NULL, ",", &saveptr1)) {
        char *saveptr2 = NULL;
        char *program_fname = strtok_r(hook, ":", &saveptr2);
        char *inject_fname = strtok_r(NULL, ":", &saveptr2);
        CONSOLE("[Replacing %s by %s]", program_fname, inject_fname);
        injecter_replace_function(injecter, program_fname, inject_fname);
    }
    CONSOLE("[Functions replaced]");
    ret = true;
error:
    elf_file_close(hooks_section);
    free(hooks);
    return ret;
}

