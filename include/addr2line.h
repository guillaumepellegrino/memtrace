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

#ifndef ADDR2LINE_H
#define ADDR2LINE_H

#ifndef ADDR2LINE_PRIVATE
#define ADDR2LINE_PRIVATE __attribute__((deprecated))
#endif

#include "types.h"
#include "list.h"
#include <stdio.h>

typedef struct {
    char *binary ADDR2LINE_PRIVATE;
    list_t list ADDR2LINE_PRIVATE;
} addr2line_t;

void addr2line_initialize(addr2line_t *ctx, const char *binary);
void addr2line_cleanup(addr2line_t *ctx);
void addr2line_print(addr2line_t *ctx, const char *so, uint64_t address, FILE *out);

#endif
