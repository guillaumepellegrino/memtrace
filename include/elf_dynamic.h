/*
 * Copyright (C) 2021 Guillaume Pellegrino
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

#ifndef ELF_DYNAMIC_H
#define ELF_DYNAMIC_H

#include "types.h"

/**
 * Get the corresponding value for the specified tag in
 * the DYNAMIC section ELF file. Return true on success.
 *
 * @dynamic section ELF file
 * @tag to lookup in the DYNAMIC Section (DT_SYMTAB, DT_SYMENT, ...)
 * @val corresponding to the tag
 */
bool elf_dynamic_get_entry(elf_file_t *dynamic, size_t tag, size_t *val);

/** Open the symtab section from the ELF File using DYNAMIC Section info */
elf_file_t *elf_dynamic_open_symtab(elf_t *elf, elf_file_t *dynamic);

/** Open the strtab section from the ELF File using DYNAMIC Section info */
elf_file_t *elf_dynamic_open_strtab(elf_t *elf, elf_file_t *dynamic);

/** Open the rela section from the ELF File using DYNAMIC Section info */
elf_file_t *elf_dynamic_open_rela(elf_t *elf, elf_file_t *dynamic);

/** Open the rel section from the ELF File using DYNAMIC Section info */
elf_file_t *elf_dynamic_open_rel(elf_t *elf, elf_file_t *dynamic);

#endif
