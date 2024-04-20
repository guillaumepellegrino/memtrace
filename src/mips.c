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
#include "memfd.h"
#include "log.h"

/** MIPS General Purpose Registers */
#define zero 0
#define at 1
#define v0 2
#define v1 3
#define a0 4
#define a1 5
#define a2 6
#define a3 7
#define t0 8
#define t1 9
#define t2 10
#define t3 11
#define t4 12
#define t5 13
#define t6 14
#define t7 15
#define s0 16
#define s1 17
#define s2 18
#define s3 19
#define s4 20
#define s5 21
#define s6 22
#define s7 23
#define t8 24
#define t9 25
#define k0 26
#define k1 27
#define gp 28
#define sp 29
#define fp 30
#define ra 31

/** Special Purpose Registers */
#define hi
#define lo

/** Program Counter */
#define pc 34

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
    // for some reasons, kernel is using 64 bits registers for MIPs CPU.
    // thus we must compute the register address as 2*reg+1
    switch (name) {
        case cpu_register_pc:       return (size_t *) &registers->raw.regs[2*pc+1];
        case cpu_register_sp:       return (size_t *) &registers->raw.regs[2*sp+1];
        case cpu_register_fp:       return (size_t *) &registers->raw.regs[2*fp+1];
        case cpu_register_ra:       return (size_t *) &registers->raw.regs[2*ra+1];
        //case cpu_register_syscall:  return (size_t *) &registers->raw.regs[2*4+1];
        case cpu_register_syscall:  return (size_t *) &registers->raw.regs[2*v0+1];
        case cpu_register_syscall_arg1:     return (size_t *) &registers->raw.regs[2*5+1];
        case cpu_register_syscall_arg2:     return (size_t *) &registers->raw.regs[2*6+1];
        case cpu_register_syscall_arg3:     return (size_t *) &registers->raw.regs[2*7+1];
        case cpu_register_syscall_arg4:     return (size_t *) &registers->extra;
        case cpu_register_syscall_arg5:     return (size_t *) &registers->extra;
        case cpu_register_syscall_arg6:     return (size_t *) &registers->extra;
        case cpu_register_syscall_arg7:     return (size_t *) &registers->extra;
        case cpu_register_arg1:     return (size_t *) &registers->raw.regs[2*4+1];
        case cpu_register_arg2:     return (size_t *) &registers->raw.regs[2*5+1];
        case cpu_register_arg3:     return (size_t *) &registers->raw.regs[2*6+1];
        case cpu_register_arg4:     return (size_t *) &registers->raw.regs[2*7+1];
        case cpu_register_arg5:     return (size_t *) &registers->extra;
        case cpu_register_arg6:     return (size_t *) &registers->extra;
        case cpu_register_arg7:     return (size_t *) &registers->extra;
        case cpu_register_retval:   return (size_t *) &registers->raw.regs[2*v0+1];
        default: return NULL;
    }

    return NULL;
}

static void mips_prepare_function_call(cpu_registers_t *regs, int pid) {
    TRACE_WARNING("Prepare to call pc=0x%zx",cpu_register_get(regs, cpu_register_pc));
    regs->raw.regs[2*t9+1] = cpu_register_get(regs, cpu_register_pc);

    /*
    size_t rsp = cpu_register_get(regs, cpu_register_sp);
    rsp /= 0x1000;
    rsp *= 0x1000;
    rsp -= 0x1000;
    cpu_register_set(regs, cpu_register_sp, rsp);

    */
}

/*
static bool mips_breakpoint_set(breakpoint_t *bp, int memfd, size_t breakpoint_addr) {
    const uint32_t bp_opcode = 0x0D << 26;
    const size_t bp_opcode_size = 4;

    bp->addr = breakpoint_addr ;
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
*/

arch_t arch = {
    .cpu_registers_get = mips_cpu_registers_get,
    .cpu_registers_set = mips_cpu_registers_set,
    .cpu_register_reference = mips_cpu_register_reference,
    .prepare_function_call = mips_prepare_function_call,
    //.breakpoint_set = mips_breakpoint_set,
    .syscall_rewind_size = 4,
};
