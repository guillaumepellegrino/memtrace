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
#include <unistd.h>
#include "arch.h"
#include "breakpoint.h"
#include "log.h"

typedef enum {
    arm_cpu_mode_arm = 0,
    arm_cpu_mode_thumb16,
    arm_cpu_mode_thumb32,
} arm_cpu_mode_t;

typedef struct {
    long opcode;
    long size;
} breakpoint_instr_t;

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

//gdb implementation
//calloc: 0xb6f338fd (0xb6ede000 + 0x558fd)
//ptrace(PTRACE_PEEKTEXT, 12092, 0xb6f338fc, [0x201ea40]) = 0
//ptrace(PTRACE_POKEDATA, 12092, 0xb6f338fc, 0xa000f7f0) = 0
//
//> - two-byte thumb breakpoint: 0xde01
//> - four-byte thumb breakpoint: 0xa000f7f0
//> - arm breakpoint: 0xe7f001f0
static breakpoint_instr_t arm_breakpoint_instr(arm_cpu_mode_t cpu_mode) {
    switch (cpu_mode) {
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

static arm_cpu_mode_t arm_get_cpu_mode(long addr, long instr) {
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

static breakpoint_t *arm_breakpoint_set(int memfd, size_t breakpoint_addr) {
    breakpoint_t *bp = NULL;
    size_t addr = breakpoint_addr & ~1;
    size_t orig_instr = 0;

    // Read original instruction
    if (pread64(memfd, &orig_instr, sizeof(orig_instr), addr) < 0) {
        TRACE_ERROR("pread64(0x%zx) failed: %m", addr);
        return NULL;
    }
    arm_cpu_mode_t cpu_mode = arm_get_cpu_mode(addr, orig_instr);
    breakpoint_instr_t instr = arm_breakpoint_instr(cpu_mode);

    CONSOLE("Set breakpoint instr (0x%lX) at 0x%zX (old: 0x%zX)",
        instr.opcode, addr, orig_instr);

    // Read interuption instruction
    if (pwrite64(memfd, &instr.opcode, instr.size, addr) < 0) {
        TRACE_ERROR("pwrite64(0x%zx) failed: %m", addr);
        return NULL;
    }

    if (!(bp = calloc(1, sizeof(breakpoint_t)))) {
        return NULL;
    }

    bp->memfd = memfd;
    bp->addr = addr;
    bp->orig_instr = orig_instr;

    return bp;
}

arch_t arch = {
    .cpu_registers_get = arm_cpu_registers_get,
    .cpu_registers_set = arm_cpu_registers_set,
    .cpu_register_reference = arm_cpu_register_reference,
    .breakpoint_set = arm_breakpoint_set,
    .syscall_size = 2,
};
