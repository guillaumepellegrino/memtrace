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

#ifndef MEMTRACE_ELF_H
#define MEMTRACE_ELF_H

#include "types.h"

typedef enum {
    ei_class_32bit = 1,
    ei_class_64bit = 2,
} ei_class_t;

typedef enum {
    ei_data_le = 1,
    ei_data_be = 2,
} ei_data_t;

typedef enum {
    ei_osabi_systemv = 0x00,
    ei_osabi_hpux,
    ei_osabi_netbsd,
    ei_osabi_linux,
    ei_osabi_gnuhurd,
    ei_osabi_solaris,
    ei_osabi_aix,
    ei_osabi_irix,
    ei_osabi_freebsd,
    ei_osabi_tru64,
    ei_osabi_novell,
    ei_osabi_openbsd,
    ei_osabi_openvms,
    ei_osabi_nonstop,
    ei_osabi_aros,
    ei_osabi_fenix,
    ei_osabi_cloudabi,
    ei_osabi_openvos,
} ei_osabi_t;

typedef enum {
    e_type_none     = 0x00,
    e_type_rel      = 0x01,
    e_type_exec     = 0x02,
    e_type_dyn      = 0x03,
    e_type_core     = 0x04,
    e_type_loos     = 0xFE00,
    e_type_hios     = 0xFEFF,
    e_type_loproc   = 0xFF00,
    e_type_hiproc   = 0xFFFF,
} e_type_t;

typedef enum {
    p_type_null     = 0x00,
    p_type_load     = 0x01,
    p_type_dynamic  = 0x02,
    p_type_interp   = 0x03,
    p_type_note     = 0x04,
    p_type_shlib    = 0x05,
    p_type_phdr     = 0x06,
    p_type_losunw   = 0x6ffffffa,
    p_type_sunwbss  = 0x6ffffffb,
    p_type_sunwstack= 0x6ffffffa,
    p_type_hisunw   = 0x6fffffff,
    p_type_loproc   = 0x70000000,
    p_type_hiproc   = 0x7fffffff,
} p_type_t;

typedef enum {
    p_flags_none= 0x0,
    p_flags_x   = 0x1,
    p_flags_w   = 0x2,
    p_flags_wx  = 0x3,
    p_flags_r   = 0x4,
    p_flags_rx  = 0x5,
    p_flags_rw  = 0x6,
    p_flags_rwx = 0x7,
} p_flags_t;

typedef enum {
    sh_type_null = 0x00,
    sh_type_progbits,
    sh_type_symtab,
    sh_type_strtab,
    sh_type_rela,
    sh_type_hash,
    sh_type_dynamic,
    sh_type_note,
    sh_type_nobits,
    sh_type_rel,
    sh_type_shlib,
    sh_type_dynsym,
    sh_type_init_array,
    sh_type_fini_array,
    sh_type_preinit_array,
    sh_type_group,
    sh_type_symtab_shndx,
    sh_type_num,
    sh_type_loos = 0x60000000,
} sh_type_t;

typedef enum {
    sh_flags_none = 0,
    sh_flags_write = 0x1,
    sh_flags_alloc = 0x2,
    sh_flags_execinstr = 0x4,
    sh_flags_maskproc = 0xf0000000,
} sh_flags_t;

struct _elf_header {
    unsigned char   ei_magic[4];
    ei_class_t      ei_class;
    ei_data_t       ei_data;
    uint8_t         ei_version;
    ei_osabi_t      ei_osabi;
    uint8_t         ei_abiversion;
    e_type_t        e_type;
    uint16_t        e_machine;
    uint32_t        e_version;
    uint64_t        e_entry;
    uint64_t        e_phoff;
    uint64_t        e_shoff;
    uint32_t        e_flags;
    uint16_t        e_ehsize;
    uint16_t        e_phentsize;
    uint16_t        e_phnum;
    uint16_t        e_shentsize;
    uint16_t        e_shnum;
    uint16_t        e_shstrndx;
};

struct _program_header {
    p_type_t        p_type;
    p_flags_t       p_flags;
    uint64_t        p_offset;
    uint64_t        p_vaddr;
    uint64_t        p_paddr;
    uint64_t        p_filesz;
    uint64_t        p_memsz;
    uint64_t        p_align;
};

struct _section_header {
    char           *sh_strname;
    uint32_t        sh_name;
    sh_type_t       sh_type;
    uint64_t        sh_flags;
    uint64_t        sh_addr;
    uint64_t        sh_offset;
    uint64_t        sh_size;
    uint32_t        sh_link;
    uint32_t        sh_info;
    uint64_t        sh_addralign;
    uint64_t        sh_entsize;
};

/** Open/Close ELF file */
elf_t *elf_open_local(const char *name);
elf_t *elf_open(const char *name);
elf_t *elf_parse_header(const char *name);
void elf_close(elf_t *elf);
const char *elf_name(elf_t *elf);

/** Print ELF File*/
void elf_print(elf_t *elf);
void elf_program_header_print(const program_header_t *program);
void elf_section_header_print(const section_header_t *section);

/** Return the ELF Header */
const elf_header_t *elf_header(elf_t *elf);

/** Iterate/Get through ELF Program Headers */
const program_header_t *elf_program_header_first(elf_t *elf);
const program_header_t *elf_program_header_next(elf_t *elf, const program_header_t *program);
const program_header_t *elf_program_header_executable(elf_t *elf);

/** Get ELF Section Header by name */
const section_header_t *elf_section_header_get(elf_t *elf, const char *name);
const section_header_t *elf_section_header_getbyidx(elf_t *elf, uint16_t idx);


#endif
