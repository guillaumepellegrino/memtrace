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
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include "types.h"

typedef struct _arch arch_t;

typedef enum {
    cpu_register_pc,
    cpu_register_sp,
    cpu_register_fp,
    cpu_register_ra,
    cpu_register_syscall,
    cpu_register_arg1,
    cpu_register_arg2,
    cpu_register_arg3,
    cpu_register_arg4,
    cpu_register_arg5,
    cpu_register_arg6,
    cpu_register_arg7,
    cpu_register_retval,
} cpu_register_name_t;

struct _cpu_registers {
#if defined(__x86_64__)
    struct user_regs_struct raw;
#elif defined(__mips__)
    struct user raw;
#else
    struct user_regs raw;
#endif
    size_t extra[1];
};

/** CPU Architecture specific functions */
struct _arch {
    bool (*cpu_registers_get)(cpu_registers_t *regs, int pid);
    bool (*cpu_registers_set)(cpu_registers_t *regs, int pid);
    size_t *(*cpu_register_reference)(cpu_registers_t *regs, cpu_register_name_t name);
    breakpoint_t *(*breakpoint_set)(int memfd, size_t addr);
    const size_t syscall_size;
};
extern arch_t arch;

/** Get all CPU registers from process with specified pid */
static inline bool cpu_registers_get(cpu_registers_t *regs, int pid) {
    return arch.cpu_registers_get(regs, pid);
}

/** Set all CPU registers to process with specified pid */
static inline bool cpu_registers_set(cpu_registers_t *regs, int pid) {
    return arch.cpu_registers_set(regs, pid);
}

/** Get the specified CPU register by name */
static inline size_t cpu_register_get(cpu_registers_t *regs, cpu_register_name_t name) {
    return *arch.cpu_register_reference(regs, name);
}

/** Set the specified CPU register by name */
static inline void cpu_register_set(cpu_registers_t *regs, cpu_register_name_t name, size_t value) {
    *arch.cpu_register_reference(regs, name) = value;
}

#endif
