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
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include "arch.h"
#include "log.h"
#include "ptrace.h"

static bool x86_cpu_registers_get(cpu_registers_t *regs, int pid) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs->raw) != 0) {
        TRACE_ERROR("ptrace(GETREGS, %d) failed: %m", pid);
        return false;
    }

    regs->extra[0] = ptrace(PTRACE_PEEKTEXT, pid, regs->raw.rsp, 0);

    return true;
}

static bool x86_cpu_registers_set(cpu_registers_t *regs, int pid) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs->raw) != 0) {
        TRACE_ERROR("ptrace(SETREGS, %d) failed: %m", pid);
        return false;
    }

    return true;
}


static size_t *x86_cpu_register_reference(cpu_registers_t *registers, cpu_register_name_t name) {
    switch (name) {
        case cpu_register_pc:       return (size_t *) &registers->raw.rip;
        case cpu_register_sp:       return (size_t *) &registers->raw.rsp;
        case cpu_register_fp:       return (size_t *) &registers->raw.rbp;
        case cpu_register_ra:       return (size_t *) &registers->extra[0];
        //case cpu_register_syscall:  return (size_t *) &registers->raw.orig_rax;
        case cpu_register_syscall:  return (size_t *) &registers->raw.rax;
        case cpu_register_arg1:     return (size_t *) &registers->raw.rdi;
        case cpu_register_arg2:     return (size_t *) &registers->raw.rsi;
        case cpu_register_arg3:     return (size_t *) &registers->raw.rdx;
        case cpu_register_arg4:     return (size_t *) &registers->raw.r10;
        case cpu_register_arg5:     return (size_t *) &registers->raw.r8;
        case cpu_register_arg6:     return (size_t *) &registers->raw.r9;
        case cpu_register_retval:   return (size_t *) &registers->raw.rax;
        case cpu_register_syscall_exit_stop: return (size_t *) &registers->extra[0];
        default: return NULL;
    }
}

arch_t arch = {
    .cpu_registers_get = x86_cpu_registers_get,
    .cpu_registers_set = x86_cpu_registers_set,
    .cpu_register_reference = x86_cpu_register_reference,
};
