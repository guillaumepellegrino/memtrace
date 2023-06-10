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

#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include "types.h"
#include <dirent.h>

struct _breakpoint {
    int memfd;
    size_t addr;
    size_t orig_instr;
};

/** Set a breakpoint at the specified address */
breakpoint_t *breakpoint_set(int memfd, size_t addr);

/** Unset the previously set breakpoint */
bool breakpoint_unset(breakpoint_t *bp);

/**
 * Set a breakpoint at the specified address and
 * wait for it to be hit until it matches the specified callstack.
 */
bool breakpoint_wait_until(int pid, DIR *threads, int memfd, long addr, void **callstack, size_t size);

#endif
