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

#define BREAKPOINT_PRIVATE
#define _GNU_SOURCE
#include <errno.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include "breakpoint.h"
#include "ptrace.h"
#include "arch.h"
#include "log.h"


long make_mask(long size) {
    long mask = 0;
    long i;
    for (i = 0; i < size; i++) {
        mask |= 0xFF << (8L * i);
    }
    return mask;
}

bool breakpoint_enable(breakpoint_t *bp) {
    if (bp->state == breakpoint_state_enabled) {
        return true;
    }

    if (!arch.breakpoint_enable(bp)) {
        return false;
    }

    bp->state = breakpoint_state_enabled;

    return true;
}

static bool breakpoint_disable(breakpoint_t *bp) {
    if (bp->state == breakpoint_state_disabled) {
        return true;
    }

    if (ftrace_exited(bp->ftrace)) {
        return true;
    }

    if (!arch.breakpoint_disable(bp)) {
        return false;
    }

    return true;
}

bool breakpoint_handle_interrupt(breakpoint_t *bp) {
    TRACE_LOG("Handle breakpoint %s at 0x%lX", breakpoint_name(bp), bp->addr);

    if (!arch.breakpoint_handle_interrupt(bp)) {
        return false;
    }

    bp->state = breakpoint_state_disabled;

    return true;
}

bool breakpoint_initialize(breakpoint_t *bp, ftrace_t *ftrace, const char *name, size_t addr) {
    list_iterator_initialize(&bp->it);
    bp->state = breakpoint_state_disabled;
    bp->ftrace = ftrace;
    bp->pid = ftrace_pid(ftrace);
    bp->addr = addr;
    bp->orig_instr = 0;

    if (name) {
        assert((bp->name = strdup(name)));
    }
    else {
        assert(asprintf(&bp->name, "0x%lx", bp->addr) > 0);
    }

    list_insert(&ftrace->breakpoints, &bp->it);

    return breakpoint_enable(bp);
}

void breakpoint_cleanup(breakpoint_t *bp) {
    breakpoint_disable(bp);
    free(bp->name);
    list_iterator_take(&bp->it);
}

void breakpoint_set_handler(breakpoint_t *bp, ftrace_handler_t handler, void *userdata) {
    bp->handler = handler;
    bp->userdata = userdata;
}

bool breakpoint_set_name(breakpoint_t *bp, const char *name) {
    if (bp->name) {
        free(bp->name);
    }
    return (bp->name = strdup(name));
}

const char *breakpoint_name(breakpoint_t *bp) {
    if (!bp->name) {
        asprintf(&bp->name, "0x%lx", bp->addr);
    }
    return bp->name ? bp->name : "";
}

bool breakpoint_stopped(breakpoint_t *bp, const ftrace_fcall_t *fcall) {
    return arch.breakpoint_stopped(bp, fcall);
}

bool breakpoint_call(breakpoint_t *bp, const ftrace_fcall_t *fcall) {
    bool rt = true;

    if (bp->handler) {
        rt = bp->handler(fcall, bp->userdata);
    }

    return rt;
}

breakpoint_t *breakpoint_from_iterator(list_iterator_t *it) {
    return container_of(it, breakpoint_t, it);
}

breakpoint_state_t breakpoint_state(breakpoint_t *bp) {
    return bp->state;
}
