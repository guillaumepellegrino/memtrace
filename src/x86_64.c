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

#define BREAKPOINT_PRIVATE
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include "arch.h"
#include "log.h"
#include "ptrace.h"
#include "memfd.h"

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
    if (ptrace(PTRACE_POKETEXT, pid, regs->raw.rsp, regs->extra[0]) != 0) {
        TRACE_ERROR("ptrace(POKETEXT, %d) failed: %m", pid);
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
        case cpu_register_syscall:  return (size_t *) &registers->raw.orig_rax;
        //case cpu_register_syscall:  return (size_t *) &registers->raw.rax;
        case cpu_register_syscall_arg1:
        case cpu_register_arg1:     return (size_t *) &registers->raw.rdi;
        case cpu_register_syscall_arg2:
        case cpu_register_arg2:     return (size_t *) &registers->raw.rsi;
        case cpu_register_syscall_arg3:
        case cpu_register_arg3:     return (size_t *) &registers->raw.rdx;
        case cpu_register_syscall_arg4:
        case cpu_register_arg4:     return (size_t *) &registers->raw.r10;
        case cpu_register_syscall_arg5:
        case cpu_register_arg5:     return (size_t *) &registers->raw.r8;
        case cpu_register_syscall_arg6:
        case cpu_register_arg6:     return (size_t *) &registers->raw.r9;
        case cpu_register_retval:   return (size_t *) &registers->raw.rax;
        default: return NULL;
    }
}

static void x86_prepare_function_call(cpu_registers_t *regs, int pid) {
    // Ensure Stack Pointer Register is aligned before the function call.
    size_t sp = cpu_register_get(regs, cpu_register_sp);
    sp /= 0x1000;
    sp *= 0x1000;
    sp -= 0x1008;
    cpu_register_set(regs, cpu_register_sp, sp);
}

static bool x86_breakpoint_set(breakpoint_t *bp, int memfd, size_t breakpoint_addr) {
    const uint8_t bp_opcode = 0xCC; // 'INT 3h' opcode for x86_64
    const size_t bp_opcode_size = 1;

    bp->addr = breakpoint_addr;
    bp->memfd = memfd;

    // Read original instruction if not already done
    if (!bp->orig_instr) {
        if (!memfd_read(memfd, &bp->orig_instr, sizeof(bp->orig_instr), bp->addr)) {
            TRACE_ERROR("Failed to read instruction at 0x%zx", bp->addr);
            return false;
        }
    }

    TRACE_LOG("Set breakpoint instr (0x%lX) at 0x%zX (old: 0x%zX)",
        bp_opcode, bp->addr, bp->orig_instr);

    // Write interupt instruction
    if (!memfd_write(memfd, &bp_opcode, bp_opcode_size, bp->addr)) {
        TRACE_ERROR("Failed to write breakpoint at 0x%zx", bp->addr);
        return false;
    }

    bp->is_set = true;

    return true;
}

arch_t arch = {
    .cpu_registers_get = x86_cpu_registers_get,
    .cpu_registers_set = x86_cpu_registers_set,
    .cpu_register_reference = x86_cpu_register_reference,
    .prepare_function_call = x86_prepare_function_call,
    .breakpoint_set = x86_breakpoint_set,
    .syscall_rewind_size = 2,
};
