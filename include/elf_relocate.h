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

#ifndef ELF_RELOCATE_H
#define ELF_RELOCATE_H

typedef struct {
    uint64_t offset;
    uint64_t info;
    uint64_t addend;
    uint32_t type;
    uint32_t symidx;
    elf_sym_t sym;
} elf_relocate_t;

typedef bool (*elf_relocate_handler_t)(elf_relocate_t *relocate, void *userdata);

bool elf_relocate_read(elf_t *elf, elf_file_t *file, elf_file_t *symtab, elf_file_t *strtab, elf_relocate_handler_t handler, void *userdata);
bool elf_relocate_dump(elf_t *elf, elf_file_t *file, elf_file_t *symtab, elf_file_t *strtab);
bool elf_relocate_find_by_name(elf_t *elf, elf_file_t *file, elf_file_t *symtab, elf_file_t *strtab, const char *name, elf_relocate_t *result);

#endif
