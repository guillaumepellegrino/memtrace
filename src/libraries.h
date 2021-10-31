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

struct _library {
    /** A reference on the corresponding ELF file */
    elf_t *elf;
    char *name;

    /** Debug sections of the ELF File */
    elf_file_t *frame_hdr_file;
    elf_file_t *frame_file;
    elf_file_t *abbrev_file;
    elf_file_t *info_file;
    elf_file_t *str_file;
    elf_file_t *line_file;
    elf_file_t *dynsym_file;
    elf_file_t *dynstr_file;

    /** Address where the library mapping begin */
    void *begin;

    /** Address where the library mapping end */
    void *end;

    /** Offset of the ELF executable program */
    size_t offset;
};

/** Create/Destroy/Update the library list by reading /proc/self/maps */
libraries_t *libraries_create(int pid, fs_t *fs);
void libraries_destroy(libraries_t *libraries);
void libraries_update(libraries_t *libraries);

/** Print the libraries to file */
void libraries_print(const libraries_t *libraries, FILE *fp);

/** Print the library's symbol to fp */
void library_print_symbol(const library_t *library, size_t ra, FILE *fp);

/** Return the library to which belongs this address */
const library_t *libraries_find(const libraries_t *libraries, size_t address);

/** Return the library corresponding to this name */
const library_t *libraries_find_by_name(const libraries_t *libraries, const char *regex);

/** Return the address value relatively to the library */
size_t library_relative_address(const library_t *library, size_t address);

/** Return the absolute address value */
size_t library_absolute_address(const library_t *library, size_t address);

#endif
