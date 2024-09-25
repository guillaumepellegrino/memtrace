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

#define _LARGEFILE64_SOURCE
#include <errno.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <linux/ptrace.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "arch.h"
#include "breakpoint.h"
#include "syscall.h"
#include "elf.h"
#include "log.h"

typedef struct {
    long opcode;
    long size;
} breakpoint_instr_t;

// Interrupt the process in a SYSCALL-Exit event
// since we can't directly call a function if we are in a SYSCALL-Enter event
static bool arm_ptrace_interrupt(syscall_ctx_t *ctx) {
    int pid = syscall_pid(ctx);

    // Resume execution until SYSCALL-Enter event
    cpu_registers_t regs = {0};
    cpu_registers_get(&regs, pid);
    syscall_resume_until_syscall(ctx, &regs);

    TRACE_CPUREG(pid, "Entering SYSCALL and saving registers");
    *syscall_save_regs(ctx) = regs;

    // let's not do a blocking syscall: do something non-blocking like SYS_getppid
    cpu_register_set(&regs, cpu_register_syscall, (size_t) SYS_getppid);
    cpu_registers_set(&regs, pid);
    TRACE_CPUREG(pid, "Perform dummy SYSCALL");
    syscall_resume_until_syscall(ctx, &regs);

    TRACE_CPUREG(pid, "Exiting SYSCALL");
    return true;
}

static bool ptrace_resumed_dbg_enabled() {
    static int tristate = -1;
    if (tristate >= 0) {
        return tristate;
    }
    tristate = (getenv("RESUMEDBG") != NULL);

    return tristate;
}

static bool arm_ptrace_resume(syscall_ctx_t *ctx) {
    int pid = syscall_pid(ctx);

    // Rewind to the interrupt SYSCALL instruction
    cpu_registers_t regs = *syscall_save_regs(ctx);
    size_t pc = cpu_register_get(&regs, cpu_register_pc);
    pc -= arch.syscall_rewind_size;
    cpu_register_set(&regs, cpu_register_pc, pc);
    cpu_registers_set(&regs, pid);
    TRACE_CPUREG(pid, "Restoring registers");
    syscall_resume_until_syscall(ctx, &regs);

    // We are entering SYSCALL
    TRACE_CPUREG(pid, "Entering original syscall");
    regs = *syscall_save_regs(ctx);
    cpu_registers_set(&regs, pid);
    TRACE_CPUREG(pid, "Just to be sure..");

    if (ptrace_resumed_dbg_enabled()) {
        int i = 0;
        for (i = 0; i < 10; i++) {
            syscall_resume_until_syscall(ctx, &regs);
            TRACE_CPUREG(pid, "Resume DBG");
        }
    }

    return true;
}

static bool arm_cpu_registers_get(cpu_registers_t *regs, int pid) {
    struct iovec io;
    io.iov_base = &regs->raw;
    io.iov_len = sizeof(regs->raw);

    if (ptrace(PTRACE_GETREGSET, pid, (void *) NT_PRSTATUS, &io) != 0) {
        TRACE_ERROR("ptrace(GETREGSET, %d) failed: %m", pid);
        return false;
    }

    return true;
}

static bool arm_cpu_registers_set(cpu_registers_t *regs, int pid) {
    struct iovec io;
    unsigned long syscall = cpu_register_get(regs, cpu_register_syscall);

    io.iov_base = &regs->raw;
    io.iov_len = sizeof(regs->raw);
    if (ptrace(PTRACE_SETREGSET, pid, (void *) NT_PRSTATUS, &io) != 0) {
        TRACE_ERROR("ptrace(SETREGSET, NT_PRSTATUS, %d) failed: %m", pid);
        return false;
    }

    io.iov_base = &syscall;
    io.iov_len = sizeof(syscall);
    if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_SYSTEM_CALL, &io) != 0) {
        TRACE_ERROR("ptrace(SETREGSET, NT_ARM_SYSTEM_CALL, %d) failed: %m", pid);
        return false;
    }

    return true;
}

static size_t *arm_cpu_register_reference(cpu_registers_t *registers, cpu_register_name_t name) {
    switch (name) {
        case cpu_register_pc:       return (size_t *) &registers->raw.pc;
        case cpu_register_sp:       return (size_t *) &registers->raw.sp;
        case cpu_register_fp:       return (size_t *) &registers->raw.regs[29];
        case cpu_register_ra:       return (size_t *) &registers->raw.regs[30];
        case cpu_register_syscall:  return (size_t *) &registers->raw.regs[8];
        case cpu_register_syscall_arg1:
        case cpu_register_arg1:     return (size_t *) &registers->raw.regs[0];
        case cpu_register_syscall_arg2:
        case cpu_register_arg2:     return (size_t *) &registers->raw.regs[1];
        case cpu_register_syscall_arg3:
        case cpu_register_arg3:     return (size_t *) &registers->raw.regs[2];
        case cpu_register_syscall_arg4:
        case cpu_register_arg4:     return (size_t *) &registers->raw.regs[3];
        case cpu_register_syscall_arg5:
        case cpu_register_arg5:     return (size_t *) &registers->raw.regs[4];
        case cpu_register_syscall_arg6:
        case cpu_register_arg6:     return (size_t *) &registers->raw.regs[5];
        case cpu_register_syscall_arg7:
        case cpu_register_arg7:     return (size_t *) &registers->raw.regs[6];
        case cpu_register_retval:   return (size_t *) &registers->raw.regs[0];
        default: return NULL;
    }
}

static void arm_prepare_function_call(cpu_registers_t *regs, int pid) {
    TRACE_WARNING("Prepare to call pc=0x%zx",cpu_register_get(regs, cpu_register_pc));
    size_t rsp = cpu_register_get(regs, cpu_register_sp);
    rsp /= 0x1000;
    rsp *= 0x1000;
    rsp -= 0x1000;
    cpu_register_set(regs, cpu_register_sp, rsp);
}

static breakpoint_instr_t arm_breakpoint_instr() {
    return (breakpoint_instr_t) {
        .opcode = 0xD43E0000,
        .size = 4,
    };
}

static bool arm_breakpoint_set(breakpoint_t *bp, int memfd, size_t breakpoint_addr) {
    bp->addr = breakpoint_addr & ~1;
    bp->memfd = memfd;

    // Read original instruction if not already done
    if (!bp->orig_instr) {
        if (pread64(memfd, &bp->orig_instr, sizeof(bp->orig_instr), bp->addr) < 0) {
            TRACE_ERROR("pread64(0x%zx) failed: %m", bp->addr);
            return false;
        }
    }
    breakpoint_instr_t instr = arm_breakpoint_instr();

    TRACE_LOG("Set breakpoint instr (0x%lX) at 0x%zX (old: 0x%zX)",
        instr.opcode, bp->addr, bp->orig_instr);

    // Write interupt instruction
    if (pwrite64(memfd, &instr.opcode, instr.size, bp->addr) < 0) {
        TRACE_ERROR("pwrite64(0x%zx) failed: %m", bp->addr);
        return false;
    }

    bp->is_set = true;

    return true;
}

arch_t arch = {
    .ptrace_interrupt = arm_ptrace_interrupt,
    .ptrace_resume = arm_ptrace_resume,
    .cpu_registers_get = arm_cpu_registers_get,
    .cpu_registers_set = arm_cpu_registers_set,
    .cpu_register_reference = arm_cpu_register_reference,
    .prepare_function_call = arm_prepare_function_call,
    .breakpoint_set = arm_breakpoint_set,
    .syscall_rewind_size = 4,
};
