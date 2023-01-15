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
#include <errno.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/user.h>
#include <stdlib.h>
#include "arch.h"
#include "log.h"

static bool arm_cpu_registers_get(cpu_registers_t *regs, int pid) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs->raw) != 0) {
        TRACE_ERROR("ptrace(GETREGS, %d) failed: %m", pid);
        return false;
    }

    return true;
}

static bool arm_cpu_registers_set(cpu_registers_t *regs, int pid) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs->raw) != 0) {
        TRACE_ERROR("ptrace(SETREGS, %d) failed: %m", pid);
        return false;
    }
//#ifdef PTRACE_SET_SYSCALL
    if (ptrace(PTRACE_SET_SYSCALL, pid, NULL, cpu_register_get(regs, cpu_register_syscall)) != 0) {
        TRACE_ERROR("ptrace(SYSCALL, %d) failed: %m", pid);
        return false;
    }
//#endif

    return true;
}

static size_t *arm_cpu_register_reference(cpu_registers_t *registers, cpu_register_name_t name) {
    switch (name) {
        case cpu_register_pc:       return (size_t *) &registers->raw.uregs[15];
        case cpu_register_sp:       return (size_t *) &registers->raw.uregs[13];
        case cpu_register_fp:       return (size_t *) &registers->raw.uregs[13];
        case cpu_register_ra:       return (size_t *) &registers->raw.uregs[14];
        case cpu_register_syscall:  return (size_t *) &registers->raw.uregs[7];
        case cpu_register_arg1:     return (size_t *) &registers->raw.uregs[0];
        case cpu_register_arg2:     return (size_t *) &registers->raw.uregs[1];
        case cpu_register_arg3:     return (size_t *) &registers->raw.uregs[2];
        case cpu_register_arg4:     return (size_t *) &registers->raw.uregs[3];
        case cpu_register_arg5:     return (size_t *) &registers->raw.uregs[4];
        case cpu_register_arg6:     return (size_t *) &registers->raw.uregs[5];
        case cpu_register_arg7:     return (size_t *) &registers->raw.uregs[6];
        case cpu_register_retval:   return (size_t *) &registers->raw.uregs[0];
        default: return NULL;
    }
}

arch_t arch = {
    .cpu_registers_get = arm_cpu_registers_get,
    .cpu_registers_set = arm_cpu_registers_set,
    .cpu_register_reference = arm_cpu_register_reference,
    .syscall_size = 2,
};
