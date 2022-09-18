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
#include "breakpoint.h"

typedef enum {
    x86_cpu_mode_64bits = 0,
    x86_cpu_mode_32bits,
} x86_cpu_mode_t;

static bool x86_breakpoint_enable(breakpoint_t *bp) {
    long addr = bp->addr;

    // PEEKTEXT and POKETEXT MUST be word aligned
    long offset = addr % sizeof(long);
    addr = (addr / sizeof(long)) * sizeof(long);

    // Read original instruction
    errno = 0;
    if ((bp->orig_instr = ptrace(PTRACE_PEEKTEXT, bp->pid, addr, 0)) == -1 && errno != 0) {
        TRACE_ERROR("ptrace(PEEKTEXT, %d, 0x%lx) failed: %m", bp->pid, bp->addr);
        return false;
    }

    // Write Break instruction with POKETEXT
    long opcode = 0xCCL;
    long mask = 0xFFL << (8L * offset);
    long INT = opcode << (8L * offset);
    long brk_instr = (bp->orig_instr & ~mask) | INT;

    TRACE_LOG("Set breakpoint instr (0x%lX) at 0x%lX (old: 0x%lX, new: 0x%lX)",
        opcode, bp->addr, bp->orig_instr, brk_instr);

    if (ptrace(PTRACE_POKETEXT, bp->pid, addr, brk_instr) == -1) {
        TRACE_ERROR("ptrace(POKETEXT, %d, 0x%lx, 0x%lx) failed: %m", bp->pid, bp->addr, brk_instr);
        return false;
    }

    TRACE_DEBUG("mask: 0x%lx, INT: 0x%lx", mask, INT);
    TRACE_DEBUG("ptrace(PTRACE_PEEKTEXT, %d, 0x%lx, [0x%lx]) = 0", bp->pid, addr, bp->orig_instr);
    TRACE_DEBUG("ptrace(PTRACE_POKETEXT, %d, 0x%lx, [0x%lx]) = 0", bp->pid, addr, brk_instr);

    return true;
}

static bool x86_breakpoint_disable(breakpoint_t *bp) {
    long addr = (bp->addr / sizeof(long)) * sizeof(long);
    if (ptrace(PTRACE_POKETEXT, bp->pid, addr, bp->orig_instr) != 0) {
        TRACE_ERROR("ptrace(POKETEXT, %d) failed: %m", bp->pid);
        return false;
    }
    return true;
}

static bool x86_breakpoint_stopped(breakpoint_t *bp, const ftrace_fcall_t *fcall) {
    return (bp->addr + 1L) == fcall->pc;
}

static bool x86_breakpoint_handle_interrupt(breakpoint_t *bp) {
    struct user_regs_struct regs;

    long addr = (bp->addr / 8) * 8;

    // Set back the original instruction and rewind back to this instruction
    if (ptrace(PTRACE_POKETEXT, bp->pid, addr, bp->orig_instr) != 0) {
        TRACE_ERROR("ptrace(POKETEXT, %d) failed: %m", bp->pid);
        return false;
    }
    if (ptrace(PTRACE_GETREGS, bp->pid, NULL, &regs) != 0) {
        TRACE_ERROR("Failed to getregs for process %d", bp->pid);
        return false;
    }
    regs.rip = bp->addr;
    if (ptrace(PTRACE_SETREGS, bp->pid, NULL, &regs) != 0) {
        TRACE_ERROR("Failed to setregs for process %d", bp->pid);
        return false;
    }

    return true;
}

static bool x86_ftrace_fcall_fill(ftrace_fcall_t *fcall, int pid) {
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        TRACE_ERROR("ptrace(GETREGS, %d) failed: %m", pid);
        return false;
    }

    *fcall = (ftrace_fcall_t) {
        .pc      = regs.rip,
        .sp      = regs.rsp,
        .ra      = ptrace(PTRACE_PEEKTEXT, pid, regs.rsp, 0),
        .syscall = regs.orig_rax,
        .arg1    = regs.rdi,
        .arg2    = regs.rsi,
        .arg3    = regs.rdx,
        .arg4    = regs.r10,
        .arg5    = regs.r8,
        .arg6    = regs.r9,
        .arg7    = 0,
        .retval  = regs.rax,
        .registers = {{
            [0]  = regs.rax,
            [1]  = regs.rbx,
            [2]  = regs.rcx,
            [3]  = regs.rdx,
            [4]  = regs.rsi,
            [5]  = regs.rdi,
            [6]  = regs.rbp,
            [7]  = regs.rsp,
            [8]  = regs.r8,
            [9]  = regs.r9,
            [10] = regs.r10,
            [11] = regs.r11,
            [12] = regs.r12,
            [13] = regs.r13,
            [14] = regs.r14,
            [15] = regs.r15,
            [16] = regs.rip,
            [17] = regs.eflags,
        }}
    };

    return true;
}

static const cpu_mode_t x86_cpu_modes[] = {
    {
        .str = "64bits",
        .value = x86_cpu_mode_64bits,
    },
    {
        .str = "32bits",
        .value = x86_cpu_mode_32bits,
    },
    {NULL}
};

arch_t arch = {
    .cpu_modes = x86_cpu_modes,
    //.step = x86_step,
    .breakpoint_enable = x86_breakpoint_enable,
    .breakpoint_disable = x86_breakpoint_disable,
    .breakpoint_stopped = x86_breakpoint_stopped,
    .breakpoint_handle_interrupt = x86_breakpoint_handle_interrupt,
    .ftrace_fcall_fill = x86_ftrace_fcall_fill,
};


// TODO: replace ftrace_fcall_t by gen_cpu_registers_t implementation
typedef enum {
    register_pc,
    register_sp,
    register_ra,
    register_syscall,
    register_arg1,
    register_arg2,
    register_arg3,
    register_arg4,
    register_arg5,
    register_arg6,
    register_arg7,
    register_retval,
} register_number_t;

typedef struct {
    struct user_regs_struct raw;
    size_t extra[1];
} gen_cpu_registers_t;

size_t *register_get_reference(gen_cpu_registers_t *registers, register_number_t number) {
    switch (number) {
        case register_pc:       return (size_t *) &registers->raw.rip;
        case register_sp:       return (size_t *) &registers->raw.rsp;
        case register_ra:       return (size_t *) &registers->extra[0];
        case register_syscall:  return (size_t *) &registers->raw.orig_rax;
        case register_arg1:     return (size_t *) &registers->raw.rdi;
        case register_arg2:     return (size_t *) &registers->raw.rsi;
        case register_arg3:     return (size_t *) &registers->raw.rdx;
        case register_arg4:     return (size_t *) &registers->raw.r10;
        case register_arg5:     return (size_t *) &registers->raw.r8;
        case register_arg6:     return (size_t *) &registers->raw.r9;
        case register_retval:   return (size_t *) &registers->raw.rax;
        default: return NULL;
    }
}
