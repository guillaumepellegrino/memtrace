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

#ifndef FTRACE_BREAKPOINT_H
#define FTRACE_BREAKPOINT_H

#ifndef BREAKPOINT_PRIVATE
#define BREAKPOINT_PRIVATE __attribute__((deprecated))
#endif

#include <stddef.h>
#include <stdbool.h>
#include "types.h"
#include "list.h"

enum _breakpoint_state {
    breakpoint_state_disabled = 0,
    breakpoint_state_enabled,
};

struct _breakpoint {
    list_iterator_t it          BREAKPOINT_PRIVATE;
    breakpoint_state_t state    BREAKPOINT_PRIVATE;
    ftrace_t *ftrace            BREAKPOINT_PRIVATE;
    int pid                     BREAKPOINT_PRIVATE;
    long addr                   BREAKPOINT_PRIVATE;
    long orig_instr             BREAKPOINT_PRIVATE;
    char *name                  BREAKPOINT_PRIVATE;
    ftrace_handler_t handler    BREAKPOINT_PRIVATE;
    void *userdata              BREAKPOINT_PRIVATE;
};

/**
 * Initialize a breakpoint for the process specified by pid at the specified address
 * The breakpoint is inserted in a list (if parameter is provided)
 */
bool breakpoint_initialize(breakpoint_t *bp, ftrace_t *ftrace, const char *name, size_t addr);

/**
 * Cleanup the breakpoint
 */
void breakpoint_cleanup(breakpoint_t *bp);


bool breakpoint_enable(breakpoint_t *bp);

/**
 * Set breakpoint handler and userdata
 */
void breakpoint_set_handler(breakpoint_t *bp, ftrace_handler_t handler, void *userdata);
bool breakpoint_set_name(breakpoint_t *bp, const char *name);
const char *breakpoint_name(breakpoint_t *bp);

bool breakpoint_stopped(breakpoint_t *bp, const ftrace_fcall_t *fcall);

/**
 * Call function handler
 */
bool breakpoint_call(breakpoint_t *bp, const ftrace_fcall_t *fcall);

/**
 * Handle interrupt triggered by breakpoint
 *
 * Note: this function MUST be called when the program stopped at this breakpoint
 *       otherwise, the program will skip an INSTRUCTION and will have an
 *       unpredictable behavior.
 */
bool breakpoint_handle_interrupt(breakpoint_t *bp);

/**
 * Return a breakpoint from a list iterator
 */
breakpoint_t *breakpoint_from_iterator(list_iterator_t *it);

breakpoint_state_t breakpoint_state(breakpoint_t *bp);

#endif
