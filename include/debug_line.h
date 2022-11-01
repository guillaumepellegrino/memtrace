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

#ifndef DEBUGLINE_H
#define DEBUGLINE_H

#include "types.h"

typedef struct {
    uint64_t address;
    char *file;
    int line;
} debug_line_info_t;

/**
 * Return debug line informpation about the specified address
 */
debug_line_info_t *debug_line_ex(elf_t *elf, elf_file_t *line_file, uint64_t address);
debug_line_info_t *debug_line(elf_t *elf, uint64_t address);

void debug_line_info_free(debug_line_info_t *info);

#endif
