/*
 * Copyright (C) 2022 Guillaume Pellegrino
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

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include "syscall.h"
#include "libraries.h"
#include "ptrace.h"
#include "arch.h"
#include "log.h"

#define SYSCALL_SIZE 2

#if SYSCALL_SIZE == 1
#define SYSCALL_MASK 0xff
#elif SYSCALL_SIZE == 2
#define SYSCALL_MASK 0xffff
#elif SYSCALL_SIZE == 4
#define SYSCALL_MASK 0xffffffff
#else
#error WrongSize
#endif

static size_t syscall_instr = 0;
static cpu_registers_t syscall_regs = {0};

void cpu_registers_print(cpu_registers_t *regs) {
    printf("syscall: %zu, arg1:%zu, arg2:%zu, arg3, %zu, pc:0x%zx, lr:0x%zx, ret: %zu\n",
        cpu_register_get(regs, cpu_register_syscall),
        cpu_register_get(regs, cpu_register_arg1),
        cpu_register_get(regs, cpu_register_arg2),
        cpu_register_get(regs, cpu_register_arg3),
        cpu_register_get(regs, cpu_register_pc),
        cpu_register_get(regs, cpu_register_ra),
        cpu_register_get(regs, cpu_register_retval));
}

bool is_syscall_instr(int pid) {
    cpu_registers_t regs = {0};
    size_t pc = 0;
    size_t instr = 0;

    cpu_registers_get(&regs, pid);
    pc = cpu_register_get(&regs, cpu_register_pc);
    instr = ptrace(PTRACE_PEEKTEXT, pid, (pc - SYSCALL_SIZE), 0);

    return (instr & SYSCALL_MASK) == syscall_instr;
}

bool syscall_init(int pid) {
    cpu_registers_t regs = {0};
    int status = 0;

    // Walk on a SYSCALL instruction
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) {
        TRACE_ERROR("Failed STEP: %m");
        goto error;
    }
    if (waitpid(pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", pid);
        goto error;
    }
    cpu_registers_get(&syscall_regs, pid);
    size_t pc = 0;
    pc = cpu_register_get(&syscall_regs, cpu_register_pc);
    syscall_instr = ptrace(PTRACE_PEEKTEXT, pid, (pc - SYSCALL_SIZE), 0) & SYSCALL_MASK;

    // Wait to leave SYSCALL instruction
    do {
        cpu_registers_get(&regs, pid);
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) != 0) {
            TRACE_ERROR("Failed STEP: %m");
            goto error;
        }
        if (waitpid(pid, &status, 0) < 0) {
            TRACE_ERROR("waitpid(%d) failed: %m", pid);
            goto error;
        }
    } while (is_syscall_instr(pid));

error:
    return true;
}
static bool syscall_hijack(int pid, size_t syscall, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6, size_t *ret) {
    cpu_registers_t regs = {0};
    cpu_registers_t save_regs = {0};
    int status = 0;

    cpu_registers_get(&regs, pid);
    save_regs = regs;

    // Set registers for SYSCALL instruction
    regs = syscall_regs;
    cpu_register_set(&regs, cpu_register_pc,
        cpu_register_get(&regs, cpu_register_pc) - SYSCALL_SIZE);
    cpu_register_set(&regs, cpu_register_syscall, syscall);
    cpu_register_set(&regs, cpu_register_arg1, arg1);
    cpu_register_set(&regs, cpu_register_arg2, arg2);
    cpu_register_set(&regs, cpu_register_arg3, arg3);
    cpu_register_set(&regs, cpu_register_arg4, arg4);
    cpu_register_set(&regs, cpu_register_arg5, arg5);
    cpu_register_set(&regs, cpu_register_arg6, arg6);
    if (!cpu_registers_set(&regs, pid)) {
        TRACE_ERROR("Failed to setregs for process %d (%m)", pid);
        return false;
    }

    cpu_registers_get(&regs, pid);

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) != 0) {
        TRACE_ERROR("Failed STEP: %m");
        return false;
    }
    if (waitpid(pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", pid);
        return false;
    }
    cpu_registers_get(&regs, pid);
    if (ret) {
        *ret = cpu_register_get(&regs, cpu_register_retval);
    }

    cpu_registers_set(&save_regs, pid);

    return true;
}

int syscall_open(int pid, void *path, int flags, mode_t mode) {
    size_t ret = 0;

    syscall_hijack(pid,
        SYS_open, (size_t) path, flags, mode, 0, 0, 0, &ret);

    return (ssize_t) ret;
}

void *syscall_mmap(int pid, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    size_t ret = 0;

#ifdef SYS_mmap
    syscall_hijack(pid,
        SYS_mmap, (size_t) addr, length, prot, flags, fd, offset, &ret);
#else
    syscall_hijack(pid,
        SYS_mmap2, (size_t) addr, length, prot, flags, fd, offset/4096, &ret);
#endif

    return (void *) ret;
}

int syscall_getpid(int pid) {
    size_t ret = 0;

    syscall_hijack(pid,
        SYS_getpid, 0, 0, 0, 0, 0, 0, &ret);

    return (ssize_t) ret;
}


