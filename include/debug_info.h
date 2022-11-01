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

#ifndef DEBUG_INFO_H
#define DEBUG_INFO_H

#include "types.h"

#if 0
.debug_info:
    vector<CU> (Compilation Unit):
        Length
        Version
        AbbrevOffset (offset in .debug_offset)
        vector<DIEs> (Debug Information Entries):
            DIE_Type (DW_TAG_subprogram)
            DW_AT_NAME (function name)
            DW_AT_low_pc (function start address)
            DW_AT_high_pc (function size)

.debug_abbrev:
#endif

typedef struct {
    uint64_t address;
    uint64_t offset;
    char *function;
    bool resolved;
} debug_info_t;

debug_info_t *debug_info_function(elf_t *elf, uint64_t address);
debug_info_t *debug_info_function_ex(elf_t *elf, elf_file_t *abbrev_file, elf_file_t *info_file, elf_file_t *str_file, uint64_t address);
void debug_info_free(debug_info_t *info);

#endif
