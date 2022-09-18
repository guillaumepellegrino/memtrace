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

#ifndef LIBRARIES_H
#define LIBRARIES_H

#include <stdio.h>
#include "types.h"

typedef enum {
    library_section_dynsym,
    library_section_dynstr,
    library_section_symtab,
    library_section_strtab,
    library_section_rela_dyn,
    library_section_rela_plt,
    library_section_end,
} library_section_t;

typedef struct {
    int pid;
    fs_t *fs;

    /** Load elf sections .debug_frame/.eh_frame
     *  and .debug_frame_hdr/.eh_frame_hdr if set to true */
    size_t debug_frame_section : 1;

    /** Load elf sections .debug_abbrev, .debug_info,
     * .debug_str and .debug_line if set to true*/
    size_t debug_info_section : 1;
} libraries_cfg_t;


struct _library {
    /** A reference on the corresponding ELF file */
    elf_t *elf;
    char *name;

    /** ELF section files */
    elf_file_t *files[library_section_end];

    /** Address where the library mapping begin */
    void *begin;

    /** Address where the library mapping end */
    void *end;

    /** Offset of the ELF executable program */
    size_t offset;
};

/** Create/Destroy/Update the library list by reading /proc/self/maps */
libraries_t *libraries_create(const libraries_cfg_t *cfg);
void libraries_destroy(libraries_t *libraries);
void libraries_update(libraries_t *libraries);

/** Print the libraries to file */
void libraries_print(const libraries_t *libraries, FILE *fp);

/** Print the library's symbol to fp */
void library_print_symbol(const library_t *library, size_t ra, FILE *fp);

/** Return the library to which belongs this address */
library_t *libraries_find(libraries_t *libraries, size_t address);

/** Return the library corresponding to this name */
library_t *libraries_find_by_name(libraries_t *libraries, const char *regex);

/** Return the first library from array */
library_t *libraries_first(libraries_t *libraries);

/** Return the count of libraries */
size_t libraries_count(const libraries_t *libraries);

elf_t *library_elf(const library_t *library);
const char *library_name(const library_t *library);
void *library_begin(const library_t *library);
void *library_end(const library_t *library);
size_t library_offset(const library_t *library);
elf_file_t *library_get_elf_section(library_t *library, library_section_t section);

/** Return the address value relatively to the library */
size_t library_relative_address(const library_t *library, size_t address);

/** Return the absolute address value */
size_t library_absolute_address(const library_t *library, size_t address);


#endif
