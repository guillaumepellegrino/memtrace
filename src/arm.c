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
#include <sys/user.h>
#include <stdlib.h>
#include "breakpoint.h"
#include "arch.h"
#include "ptrace.h"
#include "log.h"

typedef enum {
    arm_cpu_mode_arm = 0,
    arm_cpu_mode_thumb16,
    arm_cpu_mode_thumb32,
} arm_cpu_mode_t;

//gdb implementation
//calloc: 0xb6f338fd (0xb6ede000 + 0x558fd)
//ptrace(PTRACE_PEEKTEXT, 12092, 0xb6f338fc, [0x201ea40]) = 0
//ptrace(PTRACE_POKEDATA, 12092, 0xb6f338fc, 0xa000f7f0) = 0

//cli implementation
//calloc: 0xb6eeb8fd (0xb6e96000 + 0x558fd)
//ptrace(PTRACE_PEEKTEXT, 12036, 0xb6eeb8fc, [0x201ea40]) = 0
//ptrace(PTRACE_POKETEXT, 12036, 0xb6eeb8fc, 0x201de40) = 0
//
//> - two-byte thumb breakpoint: 0xde01
//> - four-byte thumb breakpoint: 0xa000f7f0
//> - arm breakpoint: 0xe7f001f0
breakpoint_instr_t arm_breakpoint_instr() {
    switch (arch.cpu_mode) {
        case arm_cpu_mode_arm:
            return (breakpoint_instr_t) {
                .opcode = 0xe7f001f0,
                .size = 4,
            };
        case arm_cpu_mode_thumb32:
            return (breakpoint_instr_t) {
                .opcode = 0xa000f7f0,
                .size = 4,
            };
        case arm_cpu_mode_thumb16:
            return (breakpoint_instr_t) {
                .opcode = 0xDE01,
                .size = 2,
            };
        default:
            abort();
    }
}

static long make_mask(long size) {
    long mask = 0;
    long i;
    for (i = 0; i < size; i++) {
        mask |= 0xFF << (8L * i);
    }
    return mask;
}

arm_cpu_mode_t arm_get_cpu_mode(long addr, long instr) {
    if (!(addr & 0x01)) {
        return arm_cpu_mode_arm;
    }
    if (addr & 0x02) {
        // Instruction is not aligned on 4xbits => THUM16
        return arm_cpu_mode_thumb16;
    }
    else {
        // 16/32 bit Thumb Instruction Encoding
        // Half Word 1 :
        //      11100.xxxx: 16bits Thumb instruction
        //      111xx.xxxx: 32bits Thumb-2 instruction
        //      xxxxx.xxxx: 16bits Thumb instruction
        long opcode = (instr & 0xF800) >> 11;
        switch (opcode) {
            case 0b11101:
            case 0b11110:
            case 0b11111:
                return arm_cpu_mode_thumb32;
            default:
                return arm_cpu_mode_thumb16;
        }
    }
}

static bool arm_breakpoint_enable(breakpoint_t *bp) {
    long addr = bp->addr & ~1;

    // PEEKTEXT and POKETEXT MUST be word aligned
    long offset = addr % sizeof(long);
    addr = (addr / sizeof(long)) * sizeof(long);

    // Read original instruction
    if ((bp->orig_instr = ptrace(PTRACE_PEEKTEXT, bp->pid, addr, 0)) == -1 && errno != 0) {
        TRACE_ERROR("[%s] ptrace(PEEKTEXT, %d, 0x%lx) failed: %m", breakpoint_name(bp), bp->pid, bp->addr);
        return false;
    }

    // Write Break instruction with POKETEXT
    arch.cpu_mode = arm_get_cpu_mode(bp->addr, bp->orig_instr);
    breakpoint_instr_t instr = arm_breakpoint_instr();
    long mask = make_mask(instr.size) << (8L * offset);
    long INT = instr.opcode << (8L * offset);
    long brk_instr = (bp->orig_instr & ~mask) | INT;

    TRACE_LOG("Set breakpoint instr (0x%lX) at 0x%lX (old: 0x%lX, new: 0x%lX)",
        instr.opcode, bp->addr, bp->orig_instr, brk_instr);

    if (ptrace(PTRACE_POKETEXT, bp->pid, addr, brk_instr) == -1) {
        TRACE_ERROR("ptrace(POKETEXT, %d, 0x%lx, 0x%lx) failed: %m", bp->pid, bp->addr, brk_instr);
        return false;
    }

    TRACE_DEBUG("mask: 0x%lx, INT: 0x%lx", mask, INT);
    TRACE_DEBUG("ptrace(PTRACE_PEEKTEXT, %d, 0x%lx, [0x%lx]) = 0", bp->pid, addr, bp->orig_instr);
    TRACE_DEBUG("ptrace(PTRACE_POKETEXT, %d, 0x%lx, [0x%lx]) = 0", bp->pid, addr, brk_instr);

    return true;
}

static bool arm_breakpoint_disable(breakpoint_t *bp) {
    long addr = (bp->addr / sizeof(long)) * sizeof(long);
    if (ptrace(PTRACE_POKETEXT, bp->pid, addr, bp->orig_instr) != 0) {
        TRACE_ERROR("ptrace(POKETEXT, %d) failed: %m", bp->pid);
        return false;
    }
    return true;
}

static bool arm_breakpoint_stopped(breakpoint_t *bp, const ftrace_fcall_t *fcall) {
    return (bp->addr & ~0x1L) == (fcall->pc & ~0x1L);
}

static bool arm_breakpoint_handle_interrupt(breakpoint_t *bp) {
    struct user_regs regs;
    long addr = (bp->addr / sizeof(long)) * sizeof(long);

    // Set back the original instruction and rewind back to this instruction
    if (ptrace(PTRACE_POKETEXT, bp->pid, addr, bp->orig_instr) != 0) {
        TRACE_ERROR("ptrace(POKETEXT, %d) failed: %m", bp->pid);
        return false;
    }
    if (ptrace(PTRACE_GETREGS, bp->pid, NULL, &regs) != 0) {
        TRACE_ERROR("Failed to getregs for process %d", bp->pid);
        return false;
    }
    regs.uregs[15] = bp->addr;
    if (ptrace(PTRACE_SETREGS, bp->pid, NULL, &regs) != 0) {
        TRACE_ERROR("Failed to setregs for process %d", bp->pid);
        return false;
    }

    return true;
}

static bool arm_ftrace_fcall_fill(ftrace_fcall_t *fcall, int pid) {
    struct user_regs regs;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        TRACE_ERROR("ptrace(GETREGS, %d) failed: %m", pid);
        return false;
    }

    /*
    int i;
    CONSOLE("");
    CONSOLE("registers:");
    for (i = 0; i < 18; i++) {
        CONSOLE("  r%02d: 0x%0lx", i, regs.uregs[i]);
    }
    */

    // ARM/EABI
    *fcall = (ftrace_fcall_t) {
        .pc      = regs.uregs[15],
        .sp      = regs.uregs[13],
        .ra      = regs.uregs[14],
        .syscall = regs.uregs[7],
        .arg1    = regs.uregs[0],
        .arg2    = regs.uregs[1],
        .arg3    = regs.uregs[2],
        .arg4    = regs.uregs[3],
        .arg5    = regs.uregs[4],
        .arg6    = regs.uregs[5],
        .arg7    = regs.uregs[6],
        .retval  = regs.uregs[0],
        .registers = {{
            [0]  = regs.uregs[0],
            [1]  = regs.uregs[1],
            [2]  = regs.uregs[2],
            [3]  = regs.uregs[3],
            [4]  = regs.uregs[4],
            [5]  = regs.uregs[5],
            [6]  = regs.uregs[6],
            [7]  = regs.uregs[7],
            [8]  = regs.uregs[8],
            [9]  = regs.uregs[9],
            [10] = regs.uregs[10],
            [11] = regs.uregs[11],
            [12] = regs.uregs[12],
            [13] = regs.uregs[13],
            [14] = regs.uregs[14],
            [15] = regs.uregs[15],
            [16] = regs.uregs[16],
        }}
    };

    return true;
}

static const cpu_mode_t arm_cpu_modes[] = {
    {
        .str = "arm",
        .value = arm_cpu_mode_arm,
    },
    {
        .str = "thumb16",
        .value = arm_cpu_mode_thumb16,
    },
    {
        .str = "thumb32",
        .value = arm_cpu_mode_thumb32,
    },
    {NULL}
};


// thumb
arch_t arch = {
    .cpu_modes = arm_cpu_modes,
    .ptrace_step_support = false,
    .breakpoint_enable = arm_breakpoint_enable,
    .breakpoint_disable = arm_breakpoint_disable,
    .breakpoint_stopped = arm_breakpoint_stopped,
    .breakpoint_handle_interrupt = arm_breakpoint_handle_interrupt,
    .ftrace_fcall_fill = arm_ftrace_fcall_fill,
};

