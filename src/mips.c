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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/user.h>
#include "arch.h"
#include "log.h"

static bool mips_cpu_registers_get(cpu_registers_t *regs, int pid) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs->raw) != 0) {
        TRACE_ERROR("ptrace(GETREGS, %d) failed: %m", pid);
        return false;
    }

    return true;
}

static bool mips_cpu_registers_set(cpu_registers_t *regs, int pid) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs->raw) != 0) {
        TRACE_ERROR("ptrace(SETREGS, %d) failed: %m", pid);
        return false;
    }

    return true;
}

static size_t *mips_cpu_register_reference(cpu_registers_t *registers, cpu_register_name_t name) {
    switch (name) {
        case cpu_register_pc:       return (size_t *) &registers->raw.regs[EF_CP0_EPC];
        case cpu_register_sp:       return (size_t *) &registers->raw.regs[29];
        case cpu_register_fp:       return (size_t *) &registers->raw.regs[30];
        case cpu_register_ra:       return (size_t *) &registers->raw.regs[31];
        case cpu_register_syscall:  return (size_t *) &registers->raw.regs[2];
        case cpu_register_arg1:     return (size_t *) &registers->raw.regs[4];
        case cpu_register_arg2:     return (size_t *) &registers->raw.regs[5];
        case cpu_register_arg3:     return (size_t *) &registers->raw.regs[6];
        case cpu_register_arg4:     return (size_t *) &registers->raw.regs[7];
        case cpu_register_arg5:     return (size_t *) &registers->raw.regs[0];
        case cpu_register_arg6:     return (size_t *) &registers->raw.regs[0];
        case cpu_register_arg7:     return (size_t *) &registers->raw.regs[0];
        case cpu_register_retval:   return (size_t *) &registers->raw.regs[2];
        default: return NULL;
    }

    return NULL;
}

arch_t arch = {
    .cpu_registers_get = mips_cpu_registers_get,
    .cpu_registers_set = mips_cpu_registers_set,
    .cpu_register_reference = mips_cpu_register_reference,
};
