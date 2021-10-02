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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <endian.h>
#include <inttypes.h>
#include "elf.h"
#include "elf_file.h"
#include "types.h"
#include "fs.h"
#include "log.h"

struct _elf {
    char *name;
    fs_t *fs;
    elf_header_t header;
    program_header_t *programs;
    section_header_t *sections;
    section_header_t *section_shstrtab;
};

static bool elf_program_parse(elf_t *elf, elf_file_t *fp, size_t i) {
    program_header_t *program = &elf->programs[i];

    uint64_t offset = elf->header.e_phentsize * i;
    elf_file_seek(fp, offset);

    program->p_type = elf_file_read_u32(fp);
    if (elf->header.ei_class == ei_class_64bit) {
        program->p_flags = elf_file_read_u32(fp);
    }
    program->p_offset = elf_file_read_addr(fp);
    program->p_vaddr = elf_file_read_addr(fp);
    program->p_paddr = elf_file_read_addr(fp);
    program->p_filesz = elf_file_read_addr(fp);
    program->p_memsz = elf_file_read_addr(fp);
    if (elf->header.ei_class == ei_class_32bit) {
        program->p_flags = elf_file_read_u32(fp);
    }
    program->p_align = elf_file_read_addr(fp);

    return true;
}

static bool elf_section_parse(elf_t *elf, elf_file_t *fp, size_t i) {
    section_header_t *section = &elf->sections[i];

    uint64_t offset = elf->header.e_shentsize * i;
    elf_file_seek(fp, offset);

    section->sh_name = elf_file_read_u32(fp);
    section->sh_type = elf_file_read_u32(fp);
    section->sh_flags = elf_file_read_addr(fp);
    section->sh_addr = elf_file_read_addr(fp);
    section->sh_offset = elf_file_read_addr(fp);
    section->sh_size = elf_file_read_addr(fp);
    section->sh_link = elf_file_read_u32(fp);
    section->sh_info = elf_file_read_u32(fp);
    section->sh_addralign = elf_file_read_addr(fp);
    section->sh_entsize = elf_file_read_addr(fp);

    if (section->sh_type == sh_type_strtab) {
        elf->section_shstrtab = section;
    }

    return true;
}

elf_t *elf_open(const char *name, fs_t *fs) {
    static const unsigned char elf_magic[] = {0x7F, 'E', 'L', 'F'};
    elf_t *elf = NULL;
    elf_file_t *fp = NULL;
    size_t i = 0;

    if (!(elf = calloc(1, sizeof(elf_t)))) {
        goto error;
    }
    if (!name) {
        goto error;
    }
    assert((elf->name = strdup(name)));
    elf->fs = fs;

    if (!(fp = elf_file_open(elf, 0x40, 0))) {
        TRACE_ERROR("Failed to open %s: %m", name);
        goto error;
    }

    // Verify ELF Magic
    if (elf_file_read(fp, &elf->header.ei_magic, sizeof(elf->header.ei_magic)) != sizeof(elf->header.ei_magic)) {
        TRACE_ERROR("Failed to read %s elf header: %m", name);
        goto error;
    }
    if (memcmp(&elf->header.ei_magic, elf_magic, sizeof(elf_magic)) != 0) {
        TRACE_ERROR("%s is not an ELF file", name);
        goto error;
    }

    // Parse ELF Header
    elf->header.ei_class = elf_file_read_u8(fp);
    elf->header.ei_data = elf_file_read_u8(fp);
    elf_file_set64bit(fp, elf->header.ei_class == ei_class_64bit);
    elf_file_setlowendian(fp, elf->header.ei_data == ei_data_le);
    elf->header.ei_version = elf_file_read_u8(fp);
    elf->header.ei_osabi = elf_file_read_u8(fp);
    elf->header.ei_abiversion = elf_file_read_u8(fp);
    elf_file_discard(fp, 7);
    elf->header.e_type = elf_file_read_u16(fp);
    elf->header.e_machine = elf_file_read_u16(fp);
    elf->header.e_version = elf_file_read_u32(fp);
    elf->header.e_entry = elf_file_read_addr(fp);
    elf->header.e_phoff = elf_file_read_addr(fp);
    elf->header.e_shoff = elf_file_read_addr(fp);
    elf->header.e_flags = elf_file_read_u32(fp);
    elf->header.e_ehsize = elf_file_read_u16(fp);
    elf->header.e_phentsize = elf_file_read_u16(fp);
    elf->header.e_phnum = elf_file_read_u16(fp);
    elf->header.e_shentsize = elf_file_read_u16(fp);
    elf->header.e_shnum = elf_file_read_u16(fp);
    elf->header.e_shstrndx = elf_file_read_u16(fp);

    // Basic safety check
    if (elf->header.e_phnum > 256) {
        TRACE_ERROR("%s: Program header num > 256", name);
        goto error;
    }
    if (elf->header.e_shnum > 256) {
        TRACE_ERROR("%s: Section header num > 256", name);
        goto error;
    }

    // Open ELF Program Headers
    elf_file_close(fp);
    if (!(fp = elf_file_open(elf, elf->header.e_phnum * elf->header.e_phentsize, elf->header.e_phoff))) {
        TRACE_ERROR("Failed to open %s: %m", name);
        goto error;
    }

    // Parse ELF Program headers
    if (!(elf->programs = calloc(elf->header.e_phnum, sizeof(program_header_t)))) {
        TRACE_ERROR("%s: calloc failed: %m", name);
        goto error;
    }
    for (i = 0; i < elf->header.e_phnum; i++) {
        if (!elf_program_parse(elf, fp, i)) {
            TRACE_ERROR("%s: Failed to parse Program Header %zu", name, i);
            goto error;
        }
    }

    // Open ELF Section Headers
    elf_file_close(fp);
    if (!(fp = elf_file_open(elf, elf->header.e_shnum * elf->header.e_shentsize, elf->header.e_shoff))) {
        TRACE_ERROR("Failed to open %s: %m", name);
        goto error;
    }
    // Parse ELF Section headers
    if (!(elf->sections = calloc(elf->header.e_shnum, sizeof(section_header_t)))) {
        TRACE_ERROR("%s: calloc failed: %m", name);
        goto error;
    }
    for (i = 0; i < elf->header.e_shnum; i++) {
        if (!elf_section_parse(elf, fp, i)) {
            TRACE_ERROR("%s: Failed to parse Section Header %zu", name, i);
            goto error;
        }
    }

    // Populate ELF Section names
    char section_name[64] = "";

    if (elf->section_shstrtab) {
        elf_file_close(fp);
        if (!(fp = elf_section_open(elf, elf->section_shstrtab))) {
            TRACE_ERROR("Failed to seek to Section header %zu: %m", i);
            goto error;
        }
    }
    for (i = 0; i < elf->header.e_shnum; i++) {
        section_header_t *section = &elf->sections[i];
        if (elf->section_shstrtab) {
            elf_file_seek(fp, section->sh_name);
            elf_file_read_string(fp, section_name, sizeof(section_name));
        }
        section->sh_strname = strdup(section_name);
    }

    elf_file_close(fp);
    return elf;

error:
    elf_file_close(fp);
    elf_close(elf);
    return NULL;
}

const char *elf_name(elf_t *elf) {
    return elf ? elf->name : NULL;
}

fs_t *elf_fs(elf_t *elf) {
    return elf ? elf->fs : NULL;
}

void elf_print(elf_t *elf) {
    size_t i = 0;

    CONSOLE("ei_class       : %s", (elf->header.ei_class == ei_class_64bit ? "ELF64" : "ELF32"));
    CONSOLE("ei_data        : %s", (elf->header.ei_data == ei_data_le? "Little endian" : "Big endian"));
    CONSOLE("ei_version     : %u", elf->header.ei_version);
    CONSOLE("ei_osabi       : %u", elf->header.ei_osabi);
    CONSOLE("ei_abiversion  : %u", elf->header.ei_abiversion);
    CONSOLE("e_type         : %u", elf->header.e_type);
    CONSOLE("e_machine      : %u", elf->header.e_machine);
    CONSOLE("e_version      : %u", elf->header.e_version);
    CONSOLE("e_entry        : 0x%"PRIx64, elf->header.e_entry);
    CONSOLE("e_phoff        : 0x%"PRIx64, elf->header.e_phoff);
    CONSOLE("e_shoff        : 0x%"PRIx64, elf->header.e_shoff);
    CONSOLE("e_flags        : %u", elf->header.e_flags);
    CONSOLE("e_ehsize       : %u", elf->header.e_ehsize);
    CONSOLE("e_phentsize    : %u", elf->header.e_phentsize);
    CONSOLE("e_phnum        : %u", elf->header.e_phnum);
    CONSOLE("e_shentsize    : %u", elf->header.e_shentsize);
    CONSOLE("e_shnum        : %u", elf->header.e_shnum);
    CONSOLE("e_shstrndx     : %u", elf->header.e_shstrndx);
    CONSOLE("");

    for (i = 0; i < elf->header.e_phnum; i++) {
        program_header_t *program = &elf->programs[i];
        CONSOLE("Program Header %zu:", i);
        elf_program_header_print(program);
        CONSOLE("");
    }

    for (i = 0; i < elf->header.e_shnum; i++) {
        section_header_t *section = &elf->sections[i];
        CONSOLE("Section Header %zu:", i);
        elf_section_header_print(section);
        CONSOLE("");
    }
}

void elf_program_header_print(const program_header_t *program) {
    CONSOLE("p_type         : %u", program->p_type);
    CONSOLE("p_flags        : %u", program->p_flags);
    CONSOLE("p_offset       : 0x%"PRIx64, program->p_offset);
    CONSOLE("p_vaddr        : 0x%"PRIx64, program->p_vaddr);
    CONSOLE("p_paddr        : 0x%"PRIx64, program->p_paddr);
    CONSOLE("p_filesz       : 0x%"PRIx64, program->p_filesz);
    CONSOLE("p_memsz        : 0x%"PRIx64, program->p_memsz);
    CONSOLE("p_align        : 0x%"PRIx64, program->p_align);
}

void elf_section_header_print(const section_header_t *section) {
    CONSOLE("sh_name        : %s (%u)", section->sh_strname, section->sh_name);
    CONSOLE("sh_type        : %u", section->sh_type);
    CONSOLE("sh_flags       : 0x%"PRIx64, section->sh_flags);
    CONSOLE("sh_addr        : 0x%"PRIx64, section->sh_addr);
    CONSOLE("sh_offset      : 0x%"PRIx64, section->sh_offset);
    CONSOLE("sh_size        : 0x%"PRIx64, section->sh_size);
    CONSOLE("sh_link        : %u", section->sh_link);
    CONSOLE("sh_info        : %u", section->sh_info);
    CONSOLE("sh_addralign   : 0x%"PRIx64, section->sh_addralign);
    CONSOLE("sh_entsize     : 0x%"PRIx64, section->sh_entsize);
}

void elf_close(elf_t *elf) {
    size_t i = 0;

    if (elf) {
        free(elf->name);
        if (elf->sections) {
            for (i = 0; i < elf->header.e_shnum; i++) {
                section_header_t *section = elf->sections + i;
                free(section->sh_strname);
            }
            free(elf->sections);
        }
        free(elf->programs);
        free(elf);
    }
}

const elf_header_t *elf_header(elf_t *elf) {
    if (!elf) {
        return NULL;
    }

    return &elf->header;
}

const program_header_t *elf_program_header_first(elf_t *elf) {
    if (!elf) {
        return NULL;
    }

    return elf->programs;
}

const program_header_t *elf_program_header_next(elf_t *elf, const program_header_t *program) {
    if (!elf || !program) {
        return NULL;
    }

    program++;

    if (program >= &elf->programs[elf->header.e_phnum]) {
        return NULL;
    }

    return program;
}

const program_header_t *elf_program_header_executable(elf_t *elf) {
    const program_header_t *program = NULL;

    if (!elf) {
        return NULL;
    }

    for (program = elf_program_header_first(elf); program; program = elf_program_header_next(elf, program)) {
        if (program->p_type != p_type_load) {
            continue;
        }
        if (program->p_flags != p_flags_rx) {
            continue;
        }

        return program;
    }

    return NULL;
}

const section_header_t *elf_section_header_get(elf_t *elf, const char *name) {
    size_t i = 0;

    if (!elf || !name) {
        return NULL;
    }

    for (i = 0; i < elf->header.e_shnum; i++) {
        section_header_t *section = &elf->sections[i];
        if (section->sh_strname && !strcmp(section->sh_strname, name)) {
            return section;
        }
    }

    return NULL;
}

