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

#ifndef PTRACE_BACKTRACE_H
#define PTRACE_BACKTRACE_H

#ifndef BACKTRACE_PRIVATE
#define BACKTRACE_PRIVATE __attribute__((deprecated))
#endif

#include "types.h"
#include <libunwind-ptrace.h>

struct _backtrace {
    unw_addr_space_t addr_space        BACKTRACE_PRIVATE;
    void *context                      BACKTRACE_PRIVATE;
};

bool backtrace_context_initialize(backtrace_t *bt, int pid);
void backtrace_context_cleanup(backtrace_t *bt);
bool backtrace(backtrace_t *bt, size_t callstack[], size_t size);


#endif
