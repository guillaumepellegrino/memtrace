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

#define SYSCALL_PRIVATE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <unistd.h>
#include <time.h>
#include "syscall.h"
#include "libraries.h"
#include "ptrace.h"
#include "arch.h"
#include "log.h"

/*
static bool is_syscall_instr(syscall_ctx_t *ctx) {
    cpu_registers_t regs = {0};
    size_t pc = 0;
    size_t instr = 0;

    cpu_registers_get(&regs, ctx->pid);
    pc = cpu_register_get(&regs, cpu_register_pc);
    instr = ptrace(PTRACE_PEEKTEXT, ctx->pid, (pc - arch.syscall_size), 0);

    return (instr & SYSCALL_MASK) == ctx->syscall_instr;
}
*/

static bool memfd_read(int memfd, void *buf, size_t count, off64_t offset) {
    if (lseek64(memfd, offset, SEEK_SET) < 0) {
        TRACE_ERROR("Failed lseek %p: %m", offset);
        return false;
    }
    if (read(memfd, buf, count) < 0) {
        TRACE_ERROR("Failed read(memfd) at 0x%zx: %m", offset);
        return false;
    }

    return true;
}

static bool memfd_write(int memfd, const void *buf, size_t count, off64_t offset) {
    if (lseek64(memfd, offset, SEEK_SET) < 0) {
        TRACE_ERROR("Failed lseek %p: %m", offset);
        return false;
    }
    if (write(memfd, buf, count) < 0) {
        TRACE_ERROR("Failed write(memfd) at 0x%zx: %m", offset);
        return false;
    }

    return true;
}

static void cpu_registers_print(cpu_registers_t *regs) {
    printf("syscall: %zu, arg1:%zu, arg2:%zu, arg3: %zu, pc:0x%zx, lr:0x%zx, ret: %zu",
        cpu_register_get(regs, cpu_register_syscall),
        cpu_register_get(regs, cpu_register_arg1),
        cpu_register_get(regs, cpu_register_arg2),
        cpu_register_get(regs, cpu_register_arg3),
        cpu_register_get(regs, cpu_register_pc),
        cpu_register_get(regs, cpu_register_ra),
        cpu_register_get(regs, cpu_register_retval));
}

static void TRACE_CPUREG(int pid, const char *fmt) {
    time_t now = time(NULL);
    cpu_registers_t regs = {0};
    cpu_registers_get(&regs, pid);
    printf("%s: ", fmt);
    cpu_registers_print(&regs);
    printf(" @%s", asctime(localtime(&now)));
}

static bool syscall_trace(syscall_ctx_t *ctx) {
    int status = 0;

    // Enter SYSCALL
    TRACE_CPUREG(ctx->pid, "Resume execution ...");
    if (ptrace(PTRACE_SYSCALL, ctx->pid, 0, 0) != 0) {
        TRACE_ERROR("Failed STEP: %m");
        return false;
    }
    if (waitpid(ctx->pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", ctx->pid);
        return false;
    }
    TRACE_CPUREG(ctx->pid, "Paused:Enter SYSCALL");

    TRACE_CPUREG(ctx->pid, "Resume execution ...");
    if (ptrace(PTRACE_SYSCALL, ctx->pid, 0, 0) != 0) {
        TRACE_ERROR("Failed STEP: %m");
        return false;
    }
    if (waitpid(ctx->pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", ctx->pid);
        return false;
    }
    TRACE_CPUREG(ctx->pid, "Paused: Exit SYSCALL");

    return true;
}

/**
 * We do not want to interrupt the current syscall.
 * Thus, we wait for current syscall to finish.
 * After that, we should be able to insert some system calls
 * without breaking the current execution flow.
 */
bool syscall_init(syscall_ctx_t *ctx, int pid, int memfd) {
    cpu_registers_t syscall_regs = {0};
    size_t pc = 0;
    int status = 0;

    ctx->pid = pid;
    ctx->memfd = memfd;

    // Enter a SYSCALL instruction
    TRACE_CPUREG(pid, "[INIT] Resume execution ...");
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) {
        TRACE_ERROR("Failed STEP: %m");
        goto error;
    }
    if (waitpid(pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", pid);
        goto error;
    }
    cpu_registers_get(&syscall_regs, pid);
    pc = cpu_register_get(&syscall_regs, cpu_register_pc);
    pc &= ~1; // arm specific
    if (!memfd_read(memfd, &ctx->syscall_instr, arch.syscall_size, (pc - arch.syscall_size))) {
        TRACE_ERROR("Failed to read syscall instruction");
        goto error;
    }

    TRACE_CPUREG(pid, "[INIT] Paused:Enter SYSCALL");

    // Exit SYSCALL instruction
    TRACE_CPUREG(pid, "[INIT] Resume execution ...");
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) {
        TRACE_ERROR("Failed STEP: %m");
        goto error;
    }
    if (waitpid(pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", pid);
        goto error;
    }
    TRACE_CPUREG(pid, "[INIT] Paused: Exit SYSCALL");

    if (!syscall_trace(ctx)) {
        goto error;
    }

error:
    return true;
}
static bool syscall_hijack(syscall_ctx_t *ctx, size_t syscall, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6, size_t *ret) {
    cpu_registers_t regs = {0};
    cpu_registers_t save_regs = {0};
    size_t pc = 0;
    size_t save_instr = 0;
    int status = 0;

    // Save current instruction and registers
    // arm specific code to be moved in HAL.
    cpu_registers_get(&regs, ctx->pid);
    save_regs = regs;
    pc = cpu_register_get(&regs, cpu_register_pc) & ~1;
    if (!memfd_read(ctx->memfd, &save_instr, arch.syscall_size, pc)) {
        TRACE_ERROR("Failed to save currrent instruction");
        return false;
    }

    // Set Syscall instruction
    if (!memfd_write(ctx->memfd, &ctx->syscall_instr, arch.syscall_size, pc+2)) {
        TRACE_ERROR("Failed to set syscall instruction");
        return false;
    }
    // Set registers for SYSCALL instruction
    cpu_register_set(&regs, cpu_register_syscall, syscall);
    cpu_register_set(&regs, cpu_register_arg1, arg1);
    cpu_register_set(&regs, cpu_register_arg2, arg2);
    cpu_register_set(&regs, cpu_register_arg3, arg3);
    cpu_register_set(&regs, cpu_register_arg4, arg4);
    cpu_register_set(&regs, cpu_register_arg5, arg5);
    cpu_register_set(&regs, cpu_register_arg6, arg6);
    if (!cpu_registers_set(&regs, ctx->pid)) {
        TRACE_ERROR("Failed to setregs for process %d (%m)", ctx->pid);
        return false;
    }

    // Enter SYSCALL
    TRACE_CPUREG(ctx->pid, "[HIJACK] Resume execution ...");
    if (ptrace(PTRACE_SYSCALL, ctx->pid, 0, 0) != 0) {
        TRACE_ERROR("Failed STEP: %m");
        return false;
    }
    if (waitpid(ctx->pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", ctx->pid);
        return false;
    }
    TRACE_CPUREG(ctx->pid, "[HIJACK] Paused:Enter SYSCALL");

    // Exit SYSCALL
    TRACE_CPUREG(ctx->pid, "[HIJACK] Resume execution ...");
    if (ptrace(PTRACE_SYSCALL, ctx->pid, 0, 0) != 0) {
        TRACE_ERROR("Failed STEP: %m");
        return false;
    }
    if (waitpid(ctx->pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", ctx->pid);
        return false;
    }
    cpu_registers_get(&regs, ctx->pid);
    if (ret) {
        *ret = cpu_register_get(&regs, cpu_register_retval);
    }
    TRACE_CPUREG(ctx->pid, "[HIJACK] Paused:Exit SYSCALL");

    // Restored saved instruction and registers
    if (!memfd_write(ctx->memfd, &save_instr, arch.syscall_size, pc)) {
        TRACE_ERROR("Failed to restore saved instruction");
        return false;
    }
    cpu_registers_set(&save_regs, ctx->pid);

    return true;
}

int syscall_open(syscall_ctx_t *ctx, void *path, int flags, mode_t mode) {
    size_t ret = 0;

    syscall_hijack(ctx,
        SYS_open, (size_t) path, flags, mode, 0, 0, 0, &ret);

    return (ssize_t) ret;
}

void *syscall_mmap(syscall_ctx_t *ctx, void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    size_t ret = 0;

#ifdef SYS_mmap
    syscall_hijack(ctx,
        SYS_mmap, (size_t) addr, length, prot, flags, fd, offset, &ret);
#else
    syscall_hijack(ctx,
        SYS_mmap2, (size_t) addr, length, prot, flags, fd, offset/4096, &ret);
#endif

    return (void *) ret;
}

int syscall_getpid(syscall_ctx_t *ctx) {
    size_t ret = 0;

    syscall_hijack(ctx,
        SYS_getpid, 0, 0, 0, 0, 0, 0, &ret);

    return (ssize_t) ret;
}


