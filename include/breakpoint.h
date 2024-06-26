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

#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include "types.h"
#include <dirent.h>

typedef bool (*breakpoint_handler_t)(int tid, int memfd, cpu_registers_t *regs, void *userdata);

/**
 * Set a breakpoint at the specified address and
 * wait for it to be hit.
 */
bool breakpoint_wait(int pid, DIR *threads, int memfd, long addr);

/*
 * Set a breakpoint at the specified address and
 * log the callstack each time it is matched, forever
 * or until stopped by CTRL+C.
 */
bool breakpoint_log_forever(int pid, DIR *threads, int memfd, long addr);

/**
 * Set a breakpoint at the specified address and
 * wait for it to be hit until it matches the specified callstack.
 */
bool breakpoint_wait_until_callstack_matched(int pid, DIR *threads, int memfd, long addr, void **callstack, size_t size);

/**
 * Set a breakpoint at the specified address and
 * wait for it to be hit until the specified stop condition is met.
 */
bool breakpoint_wait_until(int pid, DIR *threads, int memfd, long addr, breakpoint_handler_t stop_condition, void *userdata);

#endif
