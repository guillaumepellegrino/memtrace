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

#define _LARGEFILE64_SOURCE
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
#include "inject.h"
#include "log.h"
#include "ptrace.h"
#include "arch.h"
#include "libraries.h"
#include "elf_main.h"
#include "elf_file.h"
#include "elf_sym.h"
#include "elf_relocate.h"
#include "syscall_hijack.h"

struct _injecter {
    int pid; /** PID of the target process */
    libraries_t *libraries; /** Shared libraries from the target process */
    char *inject_libname; /** Name of the library to inject */
    void *straddr; /** Memory mapper on target process for writing string */
    void *inject_baseaddr; /** The base address where the library was injected */
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

    TRACE_WARNING("Relocation address not found for %s():%s", fname, library_name(target));

    // FIXME: We are assuming rela type is R_X86_64_JUMP_SLO
    return -1;
}

static bool library_replace_function(int pid, library_t *target, library_t *inject, size_t inject_baseaddr, const char *fname, const char *inject_fname) {
    CONSOLE("Replace %s():%s by %s():%s", fname, library_name(target), inject_fname, library_name(inject));

    size_t startcode = library_absolute_address(target, 0);
    //CONSOLE("startcode = 0x%zx", startcode);

    ssize_t rela_fn_offset = library_get_rela_offset(target, fname);
    if (rela_fn_offset < 0) {
        return false;
    }

    size_t rela_fn_addr = startcode + rela_fn_offset;
    CONSOLE("Relocation function address: 0x%zx (offset: 0x%zx)", rela_fn_addr, rela_fn_offset);

    // Compute inject function offset
    elf_file_t *symtab = library_get_elf_section(inject, library_section_symtab);
    elf_file_t *strtab = library_get_elf_section(inject, library_section_strtab);
    if (!symtab || !strtab) {
        TRACE_ERROR(".symtab or .strtab not found");
        return false;
    }
    elf_sym_t sym = elf_sym_from_name(symtab, strtab, inject_fname);
    if (!sym.name) {
        TRACE_ERROR("%s not found", inject_fname);
        return false;
    }
    CONSOLE("Inject function offset: 0x%"PRIx64" (section: %u)", sym.offset, sym.section_index);
    size_t fn_addr = inject_baseaddr + sym.offset;
    CONSOLE("function address: 0x%zx", fn_addr);

    CONSOLE("Replace function (*0x%zx = 0x%zx)", rela_fn_addr, fn_addr);
    if (ptrace(PTRACE_POKETEXT, pid, rela_fn_addr, fn_addr) != 0) {
        TRACE_ERROR("Failed to replace function: %m");
        return false;
    }
    return true;
}

size_t resolve_function_fromlib(elf_relocate_t *rela, library_t *lib) {
    // Compute lib function offset
    elf_file_t *symtab = library_get_elf_section(lib, library_section_dynsym);
    elf_file_t *strtab = library_get_elf_section(lib, library_section_dynstr);
    if (!symtab || !strtab) {
        TRACE_ERROR(".dynsym or .dynstr not found");
        return 0;
    }
    elf_sym_t sym = elf_sym_from_name(symtab, strtab, rela->sym.name);
    if (!sym.name) {
        //TRACE_ERROR("%s not found (section idx: %d)", rela->sym.name, rela->sym.section_index);
        return 0;
    }
    if (sym.section_index == 0) {
        // Symbol is undefined.
        return 0;
    }

    return library_absolute_address(lib, sym.offset);
}

int injecter_get_machine(injecter_t *injecter) {
    elf_t *elf = NULL;
    const elf_header_t *hdr = NULL;

    if (!(elf = library_elf(injecter->inject_lib))) {
        return EM_NONE;
    }
    if (!(hdr = elf_header(elf))) {
        return EM_NONE;
    }
    return hdr->e_machine;
}

static size_t x86_64_relocate_value(injecter_t *injecter, elf_relocate_t *rela, size_t rela_addr) {
    size_t value = 0;

    switch (rela->type) {
        case R_X86_64_64:
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            if (rela->sym.offset) {
                return library_absolute_address(injecter->inject_lib, rela->sym.offset);
            }
            if ((value = resolve_function_fromlib(rela, injecter->c_lib))) {
                return value;
            }
            if (injecter->pthread_lib && (value = resolve_function_fromlib(rela, injecter->pthread_lib))) {
                return value;
            }
            if ((value = resolve_function_fromlib(rela, injecter->program_lib))) {
                return value;
            }
            TRACE_WARNING("Function %s() was not resolved", rela->sym.name);
            break;
        case R_X86_64_RELATIVE:
            return library_absolute_address(injecter->inject_lib, rela->addend);
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
            break;
    }

    return value;

}

// Refer to glibc/sysdeps/arm/dl-machine.h
static size_t arm_relocate_value(injecter_t *injecter, elf_relocate_t *rela, size_t rela_addr) {
    size_t value = 0;

    switch (rela->type) {
        case R_ARM_ABS32:
        case R_ARM_GLOB_DAT:
        case R_ARM_JUMP_SLOT:
            if (rela->sym.offset) {
                return library_absolute_address(injecter->inject_lib, rela->sym.offset);
            }
            if ((value = resolve_function_fromlib(rela, injecter->c_lib))) {
                return value;
            }
            if (injecter->pthread_lib && (value = resolve_function_fromlib(rela, injecter->pthread_lib))) {
                return value;
            }
            if ((value = resolve_function_fromlib(rela, injecter->program_lib))) {
                return value;
            }
            TRACE_WARNING("Function %s() was not resolved", rela->sym.name);
            break;
        case R_ARM_RELATIVE:
            //ElfW(Addr) l_addr;		/* Difference between the address in the ELF
            //file and the addresses in memory.  */
            //
            // in glibc$ vim sysdeps/arm/dl-machine :
            //	*reloc_addr += map->l_addr;
            value = ptrace(PTRACE_PEEKTEXT, injecter->pid, rela_addr, 0);
            return library_absolute_address(injecter->inject_lib, value);
        case R_ARM_NONE: break;
        case R_ARM_PC24: break;
        case R_ARM_REL32: break;
        case R_ARM_PC13: break;
        case R_ARM_ABS16: break;
        case R_ARM_ABS12: break;
        case R_ARM_THM_ABS5: break;
        case R_ARM_ABS8: break;
        case R_ARM_SBREL32: break;
        case R_ARM_THM_PC22: break;
        case R_ARM_THM_PC8: break;
        case R_ARM_AMP_VCALL9: break;
        case R_ARM_TLS_DESC: break;
        case R_ARM_THM_SWI8: break;
        case R_ARM_XPC25: break;
        case R_ARM_THM_XPC22: break;
        case R_ARM_TLS_DTPMOD32: break;
        case R_ARM_TLS_DTPOFF32: break;
        case R_ARM_TLS_TPOFF32: break;
        case R_ARM_COPY: break;
        case R_ARM_GOTOFF: break;
        case R_ARM_GOTPC: break;
        case R_ARM_GOT32: break;
        case R_ARM_PLT32: break;
        case R_ARM_CALL: break;
        case R_ARM_JUMP24: break;
        case R_ARM_THM_JUMP24: break;
        case R_ARM_BASE_ABS: break;
        case R_ARM_ALU_PCREL_7_0: break;
        case R_ARM_ALU_PCREL_15_8: break;
        case R_ARM_ALU_PCREL_23_15: break;
        case R_ARM_LDR_SBREL_11_0: break;
        case R_ARM_ALU_SBREL_19_12: break;
        case R_ARM_ALU_SBREL_27_20: break;
        case R_ARM_TARGET1: break;
        case R_ARM_SBREL31: break;
        case R_ARM_V4BX: break;
        case R_ARM_TARGET2: break;
        case R_ARM_PREL31: break;
        case R_ARM_MOVW_ABS_NC: break;
        case R_ARM_MOVT_ABS: break;
        case R_ARM_MOVW_PREL_NC: break;
        case R_ARM_MOVT_PREL: break;
        case R_ARM_THM_MOVW_ABS_NC: break;
        case R_ARM_THM_MOVT_ABS: break;
        case R_ARM_THM_MOVW_PREL_NC: break;
        case R_ARM_THM_MOVT_PREL: break;
        case R_ARM_THM_JUMP19: break;
        case R_ARM_THM_JUMP6: break;
        case R_ARM_THM_ALU_PREL_11_0: break;
        case R_ARM_THM_PC12: break;
        case R_ARM_ABS32_NOI: break;
        case R_ARM_REL32_NOI: break;
        case R_ARM_ALU_PC_G0_NC: break;
        case R_ARM_ALU_PC_G0: break;
        case R_ARM_ALU_PC_G1_NC: break;
        case R_ARM_ALU_PC_G1: break;
        case R_ARM_ALU_PC_G2: break;
        case R_ARM_LDR_PC_G1: break;
        case R_ARM_LDR_PC_G2: break;
        case R_ARM_LDRS_PC_G0: break;
        case R_ARM_LDRS_PC_G1: break;
        case R_ARM_LDRS_PC_G2: break;
        case R_ARM_LDC_PC_G0: break;
        case R_ARM_LDC_PC_G1: break;
        case R_ARM_LDC_PC_G2: break;
        case R_ARM_ALU_SB_G0_NC: break;
        case R_ARM_ALU_SB_G0: break;
        case R_ARM_ALU_SB_G1_NC: break;
        case R_ARM_ALU_SB_G1: break;
        case R_ARM_ALU_SB_G2: break;
        case R_ARM_LDR_SB_G0: break;
        case R_ARM_LDR_SB_G1: break;
        case R_ARM_LDR_SB_G2: break;
        case R_ARM_LDRS_SB_G0: break;
        case R_ARM_LDRS_SB_G1: break;
        case R_ARM_LDRS_SB_G2: break;
        case R_ARM_LDC_SB_G0: break;
        case R_ARM_LDC_SB_G1: break;
        case R_ARM_LDC_SB_G2: break;
        case R_ARM_MOVW_BREL_NC: break;
        case R_ARM_MOVT_BREL: break;
        case R_ARM_MOVW_BREL: break;
        case R_ARM_THM_MOVW_BREL_NC: break;
        case R_ARM_THM_MOVT_BREL: break;
        case R_ARM_THM_MOVW_BREL: break;
        case R_ARM_TLS_GOTDESC: break;
        case R_ARM_TLS_CALL: break;
        case R_ARM_TLS_DESCSEQ: break;
        case R_ARM_THM_TLS_CALL: break;
        case R_ARM_PLT32_ABS: break;
        case R_ARM_GOT_ABS: break;
        case R_ARM_GOT_PREL: break;
        case R_ARM_GOT_BREL12: break;
        case R_ARM_GOTOFF12: break;
        case R_ARM_GOTRELAX: break;
        case R_ARM_GNU_VTENTRY: break;
        case R_ARM_GNU_VTINHERIT: break;
        case R_ARM_THM_PC11: break;
        case R_ARM_THM_PC9: break;
        case R_ARM_TLS_GD32: break;
        case R_ARM_TLS_LDM32: break;
        case R_ARM_TLS_LDO32: break;
        case R_ARM_TLS_IE32: break;
        case R_ARM_TLS_LE32: break;
        case R_ARM_TLS_LDO12: break;
        case R_ARM_TLS_LE12: break;
        case R_ARM_TLS_IE12GP: break;
        case R_ARM_ME_TOO: break;
        case R_ARM_THM_TLS_DESCSEQ16: break;
        case R_ARM_THM_TLS_DESCSEQ32: break;
        case R_ARM_THM_GOT_BREL12: break;
        case R_ARM_IRELATIVE: break;
        case R_ARM_RXPC25: break;
        case R_ARM_RSBREL32: break;
        case R_ARM_THM_RPC22: break;
        case R_ARM_RREL32: break;
        case R_ARM_RABS22: break;
        case R_ARM_RPC24: break;
        case R_ARM_RBASE: break;
        case R_ARM_NUM: break;
        default: break;
    }

    CONSOLE("Unsupported relocation type: %d", rela->type);

    return 0;
}



static size_t relocate_value(injecter_t *injecter, elf_relocate_t *rela, size_t rela_addr) {
    switch (injecter_get_machine(injecter)) {
        case EM_X86_64:
            return x86_64_relocate_value(injecter, rela, rela_addr);
        case EM_ARM:
            return arm_relocate_value(injecter, rela, rela_addr);
        case EM_NONE:
        default:
            CONSOLE("Unsupported Architecture");
            return 0;
    }
}

bool resolve_function(elf_relocate_t *rela, void *userdata) {
    injecter_t *injecter = userdata;
    size_t rela_addr = 0;
    size_t rela_value = 0;

    if (!strcmp(rela->sym.name, "_ITM_deregisterTMCloneTable")
        || !strcmp(rela->sym.name, "_ITM_registerTMCloneTable")
        || !strcmp(rela->sym.name, "__gmon_start__")
        || !strcmp(rela->sym.name, "_Jv_RegisterClasses")) {
        // do not resolve these functions
        return true;
    }

    rela_addr = library_absolute_address(injecter->inject_lib, rela->offset);

    if (!(rela_value = relocate_value(injecter, rela, rela_addr))) {
        TRACE_ERROR("Failed to get %s() relocation value", rela->sym.name);
        return true;
    }

    CONSOLE("Resolve %s() (*0x%zx = 0x%zx)", rela->sym.name, rela_addr, rela_value);
    if (ptrace(PTRACE_POKETEXT, injecter->pid, rela_addr, rela_value) != 0) {
        TRACE_ERROR("Failed to replace function: %m");
        return true;
    }

    return true;
}

static bool injecter_resolve_functions(injecter_t *injecter) {
    library_t *inject = injecter->inject_lib;
    elf_file_t *rela_plt_file = library_get_elf_section(inject, library_section_rela_plt);
    elf_file_t *rela_dyn_file = library_get_elf_section(inject, library_section_rela_dyn);
    elf_file_t *dynsym_file = library_get_elf_section(inject, library_section_dynsym);
    elf_file_t *dynstr_file = library_get_elf_section(inject, library_section_dynstr);

    if (!rela_plt_file) {
        rela_plt_file = library_get_elf_section(inject, library_section_rel_plt);
        rela_dyn_file = library_get_elf_section(inject, library_section_rel_dyn);
    }
    if (!rela_plt_file || !rela_dyn_file || !dynsym_file || !dynstr_file) {
        TRACE_ERROR("Failed to open .rela.plt=%p, .rela.dyn=%p, .dynsym=%p, .dynstr=%p sections)",
            rela_plt_file, rela_dyn_file, dynsym_file, dynstr_file);
        return false;
    }

    CONSOLE("[Resolve functions for %s]", library_name(inject));
    if (!elf_relocate_read(library_elf(inject), rela_plt_file, dynsym_file, dynstr_file, resolve_function, injecter)) {
        TRACE_ERROR("Failed to process .rela.plt section");
        return false;
    }

    if (!elf_relocate_read(library_elf(inject), rela_dyn_file, dynsym_file, dynstr_file, resolve_function, injecter)) {
        TRACE_ERROR("Failed to process .rela.dyn section");
        return false;
    }
    CONSOLE("");

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

size_t alignup(size_t value, size_t align) {
    if (value % align == 0) {
        return value;
    }
    else {
        value /= align;
        value += 1;
        value *= align;
        return value;
    }
}

static inline size_t elf_pagestart(size_t value) {
    return value & ~(getpagesize()- 1);
}

static inline size_t elf_pageoffset(size_t value) {
    return value & (getpagesize()- 1);
}

/** Find available memory in /proc/pid/maps */
size_t procmaps_find_available_memory(int pid) {
    size_t bestavailable = 0;
    size_t bestavailable_size = 0;
    size_t available_size = 0;
    size_t prev_end = 0;
    snprintf(g_buff, sizeof(g_buff), "/proc/%d/maps", pid);

    //copy file in buffer
    FILE *fp = fopen(g_buff, "r");
    if (!fp) {
        TRACE_ERROR("Failed to open %s", g_buff);
        return 0;
    }

    while (fgets(g_buff, sizeof(g_buff), fp)) {
        char *sep = NULL;
        void *begin_p = NULL;
        void *end_p = NULL;
        size_t begin = 0;
        size_t end = 0;
        bool stack = false;

        // Strip new line character
        if ((sep = strchr(g_buff, '\n'))) {
            *sep = 0;
        }

        // Scan line
        if ((sscanf(g_buff, "%p-%p", &begin_p, &end_p) != 2)) {
            continue;
        }
        stack = strstr(g_buff, "[stack]");

        begin = (size_t) begin_p;
        end = (size_t) end_p;
        if (stack) {
            // do not map anything after the stack
            break;
        }
        available_size = begin - prev_end;
        if (available_size > bestavailable_size && prev_end != 0) {
            bestavailable_size = available_size;
            bestavailable = prev_end + 1;
        }
        prev_end = end;
    }
    CONSOLE("Memory available at 0x%zx (size: 0x%zx)", bestavailable, bestavailable_size);

    return bestavailable;
}

size_t elf_find_available_memory(int pid, elf_t *elf) {
    size_t base_unaligned_addr = 0;
    size_t align = 0;
    const program_header_t *ph = NULL;

    // lookup for available memory in /proc/$pid/maps
    if (!(base_unaligned_addr = procmaps_find_available_memory(pid))) {
        return 0;
    }

    // lookup for the alignement size of the first elf program to be loaded
    for (ph = elf_program_header_first(elf); ph; ph = elf_program_header_next(elf, ph)) {
        if (ph->p_type != p_type_load) {
            continue;
        }
        align = max(ph->p_align, 0x1000);
        break;
    }

    return alignup(base_unaligned_addr, align);
}

static bool memfd_zerowrite(int memfd, size_t addr, size_t len) {
        char buff[1] = {0};
        size_t i = 0;
        size_t remain = 0;

        if (len <= 0) {
            return true;
        }

        if (lseek64(memfd, addr, SEEK_SET) < 0) {
            TRACE_ERROR("Failed lseek 0x%zx: %m", addr);
            return false;
        }

        for (i = 0; (i + sizeof(buff)) < len; i += sizeof(buff)) {
            if (write(memfd, buff, sizeof(buff)) < 0) {
                TRACE_ERROR("Failed write(0x%zx): %m", addr+i);
                return false;
            }
        }

        remain = len - i;
        if (write(memfd, buff, remain) < 0) {
            TRACE_ERROR("Failed write(0x%zx): %m", addr+i);
            return false;
        }

        return true;
}

bool injecter_load_library(injecter_t *injecter, const char *libname) {
    char memfile[64];
    int memfd = -1;
    elf_t *elf = NULL;
    const program_header_t *ph = NULL;
    FILE *fp = NULL;

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

    // Sanity check
    CONSOLE("Waiting for target process to perform a system call to hijack it");
    if (!syscall_init(injecter->pid)) {
        TRACE_ERROR("Failed to init syscall");
        return false;
    }
    if (syscall_getpid(injecter->pid) != injecter->pid) {
        TRACE_ERROR("Failed to inject syscall in target process");
        return false;
    }
    if (syscall_getpid(injecter->pid) != injecter->pid) {
        TRACE_ERROR("Failed to inject syscall in target process");
        return false;
    }
    if (syscall_getpid(injecter->pid) != injecter->pid) {
        TRACE_ERROR("Failed to inject syscall in target process");
        return false;
    }

    //CONSOLE("DEBUG ERROR");
    //return false;

    // Allocate memory for writing string
    injecter->straddr = syscall_mmap(injecter->pid,
        0, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    if (!injecter->straddr) {
        TRACE_ERROR("mmap failed");
        return false;
    }
    CONSOLE("Memory mapped at %p to store library name", injecter->straddr);

    snprintf(memfile, sizeof(memfile), "/proc/%d/mem", injecter->pid);
    if ((memfd = open(memfile, O_RDWR)) < 0) {
        TRACE_ERROR("Failed to open %s: %m", memfile);
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
    int fd = syscall_open(injecter->pid, injecter->straddr, O_RDONLY, 0);
    if (fd < 0) {
        TRACE_ERROR("Failed to open %s inside pid %d", injecter->inject_libname, injecter->pid);
        return false;
    }

    CONSOLE("%s opened in target process with fd:%d", injecter->inject_libname, fd);

    size_t base_addr = 0;
    if (!(base_addr = elf_find_available_memory(injecter->pid, elf))) {
        CONSOLE("Failed to find available memory to map library");
        return false;
    }
    injecter->inject_baseaddr = (void *) base_addr;
    CONSOLE("Base Addr: 0x%zx", base_addr);

    for (ph = elf_program_header_first(elf); ph; ph = elf_program_header_next(elf, ph)) {
        if (ph->p_type != p_type_load) {
            continue;
        }

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

        // Map memory on target process
        size_t mapaddr = elf_pagestart(base_addr + ph->p_vaddr);
        size_t mapsize = ph->p_memsz + elf_pageoffset(base_addr + ph->p_vaddr);
        size_t mapoffset = ph->p_offset - elf_pageoffset(base_addr + ph->p_vaddr);

        CONSOLE("Load program at 0x%zx, offset: %zx, size: %zx", mapaddr, mapoffset, mapsize);
        if (syscall_mmap(injecter->pid,
            (void *) mapaddr, mapsize, prot, MAP_PRIVATE|MAP_FIXED, fd, mapoffset) != (void *) mapaddr)
        {
            TRACE_ERROR("Failed to map memory");
            return false;
        }

        // Fill unitialized memory with zero
        size_t zeroaddr = base_addr + ph->p_vaddr + ph->p_filesz;
        size_t zerolen = ph->p_memsz - ph->p_filesz;
        if (!memfd_zerowrite(memfd, zeroaddr, zerolen)) {
            TRACE_ERROR("Failed to zeroing memory at 0x%zx (len=0x%zx)", zeroaddr, zerolen);
            //return false;
        }
        CONSOLE("Program mapped at 0x%zx (size=0x%zx)", mapaddr, mapsize);
    }

    if (!(injecter->libraries = libraries_create(injecter->pid))) {
        TRACE_ERROR("Failed to open libraries");
        return false;
    }
    libraries_print(injecter->libraries, stdout);

    injecter->program_lib = libraries_get(injecter->libraries, 0);
    injecter->c_lib = libraries_find_by_name(injecter->libraries, "/libc(\\.|-)");
    injecter->pthread_lib = libraries_find_by_name(injecter->libraries, "/libpthread(\\.|-)");
    injecter->inject_lib = libraries_find_by_name(injecter->libraries, injecter->inject_libname);
    if (!injecter->program_lib) {
        TRACE_ERROR("Failed to find target lib");
        return false;
    }
    if (!injecter->c_lib) {
        TRACE_ERROR("Failed to find C lib");
        return false;
    }
    if (!injecter->inject_lib) {
        TRACE_ERROR("Failed to find inject lib");
        return false;
    }

    // Resolve functions from injected library
    injecter_resolve_functions(injecter);

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
            ret |= library_replace_function(injecter->pid, lib, injecter->inject_lib, (size_t)injecter->inject_baseaddr, program_fname, inject_fname);
        }
    }
    return ret;
}
