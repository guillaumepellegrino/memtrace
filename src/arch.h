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

#ifndef FTRACE_ARCH_H
#define FTRACE_ARCH_H

#include <stddef.h>
#include <stdbool.h>
#include "types.h"
#include "ftrace.h"

typedef struct _cpu_mode cpu_mode_t;
typedef struct _arch arch_t;
typedef struct _breakpoint_instr breakpoint_instr_t;

struct _cpu_mode {
    const char *str;
    int value;
};

struct _breakpoint_instr {
    long opcode;
    long size;
};

struct _arch {
    const cpu_mode_t *cpu_modes;
    int cpu_mode;

    bool (*breakpoint_enable)(breakpoint_t *bp);
    bool (*breakpoint_disable)(breakpoint_t *bp);
    bool (*breakpoint_stopped)(breakpoint_t *bp, const ftrace_fcall_t *fcall);
    bool (*breakpoint_handle_interrupt)(breakpoint_t *bp);
    bool (*ftrace_fcall_fill)(ftrace_fcall_t *fcall, int pid);
};

extern arch_t arch;

#endif
