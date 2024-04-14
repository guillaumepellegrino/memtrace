/*
 * Copyright (C) 2022 Guillaume Pellegrino
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

#ifndef GDB_H
#define GDB_H

#include "types.h"
#include "strlist.h"
#include "process.h"

typedef struct {
    const char *gdb_binary;
    const char *sysroot;
    strlist_t *solib_search_path;
    const char *tgt_binary;
    const char *coredump;
    FILE *userin;
    FILE *userout;
} gdb_cfg_t;

typedef struct {
    FILE *userin;
    FILE *userout;
    process_t process;
} gdb_t;

bool gdb_initialize(gdb_t *gdb, const gdb_cfg_t *cfg);
void gdb_cleanup(gdb_t *gdb);
void gdb_backtrace(gdb_t *gdb);
bool gdb_interact(gdb_t *gdb);


#endif
