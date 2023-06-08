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
    library_section_rel_dyn,
    library_section_rel_plt,
    library_section_rela_dyn,
    library_section_rela_plt,
    library_section_bss,
    library_section_end,
} library_section_t;

typedef struct {
    const char *name;
    uint64_t offset;
    uint64_t addr;
    uint16_t section_index;
    library_t *library;
} library_symbol_t;

/** Create/Destroy/Update the library list by reading /proc/self/maps */
libraries_t *libraries_create(int pid);
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

/** Return the library and symbol corresponding to this symbol name */
library_symbol_t libraries_find_symbol(libraries_t *libraries, const char *name);

/** Return the library by index */
library_t *libraries_get(libraries_t *libraries, size_t idx);

/** Return the count of libraries */
size_t libraries_count(const libraries_t *libraries);

void libraries_backtrace(libraries_t *libraries, cpu_registers_t *regs, void **callstack, size_t size);
void libraries_backtrace_print(libraries_t *libraries, void **callstack, size_t size, void *fp);

/** ELF header from the library */
elf_t *library_elf(const library_t *library);

/** Name of the library */
const char *library_name(const library_t *library);

/** Address where the library mapping begin */
void *library_begin(const library_t *library);

/** Address where the library mapping end */
void *library_end(const library_t *library);

/** Offset of the ELF executable program */
size_t library_offset(const library_t *library);

/** Return the required elf section from library */
elf_file_t *library_get_elf_section(library_t *library, library_section_t section);

/** Return the address value relatively to the library */
size_t library_relative_address(const library_t *library, size_t address);

/** Return the absolute address value */
size_t library_absolute_address(const library_t *library, size_t address);


#endif
