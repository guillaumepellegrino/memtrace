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

#define BACKTRACE_PRIVATE
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ptrace.h>
#include "backtrace.h"
#include "log.h"


bool backtrace_context_initialize(backtrace_t *bt, int pid) {
    if (!bt) {
        return false;
    }

    if (!(bt->addr_space = unw_create_addr_space(&_UPT_accessors, 0))) {
        TRACE_ERROR("Failed to create_addr_space with ptrace accessors");
        return false;
    }
    if (!(bt->context = _UPT_create(pid))) {
        TRACE_ERROR("Failed to attach lbunwind to process %d", pid);
        return false;
    }

    return true;
}

void backtrace_context_cleanup(backtrace_t *bt) {
    if (!bt) {
        return;
    }

    if (bt->context) {
        _UPT_destroy(bt->context);
        bt->context = NULL;
    }
    bt->addr_space = NULL;
}

bool backtrace(backtrace_t *bt, size_t callstack[], size_t size) {
    unw_cursor_t cursor;
    size_t i = 0;

    if (!bt || !callstack || size <= 0) {
        return false;
    }

    if (unw_init_remote(&cursor, bt->addr_space, bt->context) != 0) {
        TRACE_ERROR("ERROR: cannot initialize cursor for remote unwinding\n");
        return false;
    }


    for (i = 0; i < size && unw_step(&cursor) > 0; i++) {
        unw_word_t pc;
        if (unw_get_reg(&cursor, UNW_REG_IP, &pc)) {
            TRACE_ERROR("ERROR: cannot read program counter\n");
        }
/*
        static char sym[4096];
        unw_word_t offset;
        if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0) {
            CONSOLE("    (%s+0x%zx)", sym, offset);
        }
        else {
            CONSOLE("    (0x%zx)", pc);
        }
*/
        callstack[i] = pc;
    }

    if (i < size) {
        callstack[i] = 0;
    }

    return true;
}

