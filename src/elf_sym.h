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

#ifndef ELF_SYM_H
#define ELF_SYM_H

#include "types.h"

typedef struct {
    const char *name;
    uint64_t offset;
    uint16_t section_index;
} elf_sym_t;

elf_sym_t elf_sym(elf_file_t *symtab, elf_file_t *strtab, uint64_t address);
elf_sym_t elf_sym_from_idx(elf_file_t *symtab, elf_file_t *strtab, uint32_t idx);
elf_sym_t elf_sym_from_name(elf_file_t *symtab, elf_file_t *strtab, const char *name);
elf_sym_t elf_sym_from_addr(elf_file_t *symtab, elf_file_t *strtab, size_t addr);

#endif
