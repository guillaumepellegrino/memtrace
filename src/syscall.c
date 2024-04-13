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
#include <string.h>
#include <time.h>
#include <signal.h>
#include "syscall.h"
#include "libraries.h"
#include "ptrace.h"
#include "arch.h"
#include "log.h"

#define MAGIC_RET_ADDR 0x00

#if 0
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

typedef struct {
    size_t regs[7];
    size_t number;
} syscall_args_t;

// On some old kernels r4, r5, r6 are not passed by PTRACE_SETREGS.
// We must find another way to pass syscall with more than 4x arguments
void arm_syscall32(const syscall_args_t *args) {
    asm volatile(
        // set syscall number
        "ldr r7, [r0, #28]\n\t"

        // set syscall args from r0 to r5.
        // r0 must be set at last (since it contains args)
        "ldr r6, [r0, #24]\n\t"
        "ldr r5, [r0, #20]\n\t"
        "ldr r4, [r0, #16]\n\t"
        "ldr r3, [r0, #12]\n\t"
        "ldr r2, [r0, #8]\n\t"
        "ldr r1, [r0, #4]\n\t"
        "ldr r0, [r0]\n\t"

        // perform the syscall
        // expected to be catched by PTRACE_SYSCALL, here.
        "svc 0\n\t"

        : /* No outputs */
        : "r" (args));
}

bool syscall_hijack2(syscall_ctx_t *ctx, size_t syscall, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6, size_t *ret) {

    CONSOLE("syscall_hijack2()");

    syscall_args_t args = {0};
    args.regs[0] = arg1;
    args.regs[1] = arg2;
    args.regs[2] = arg3;
    args.regs[3] = arg4;
    args.regs[4] = arg5;
    args.regs[5] = arg6;
    args.regs[6] = 0;
    args.number = syscall;


    void *rw_mem = syscall_mmap(ctx, NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if (((ssize_t) rw_mem) < 0 && ((ssize_t) rw_mem) > -255) {
        TRACE_ERROR("mmap() failed: %p", rw_mem);
        return false;
    }
    void *exe_mem = syscall_mmap(ctx, NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if (((ssize_t) exe_mem) < 0 && ((ssize_t) rw_mem) > -255) {
        TRACE_ERROR("mmap() failed: %p", exe_mem);
        return false;
    }
    CONSOLE("rw_mem: %p", rw_mem);
    CONSOLE("exe_mem: %p", exe_mem);

    if (!memfd_write(ctx->memfd, &args, sizeof(args), (size_t) rw_mem)) {
        CONSOLE("Failed to write syscall arguments at %p", rw_mem);
        return false;
    }
    if (!memfd_write(ctx->memfd, (void *) arm_syscall32, 4096, (size_t) exe_mem)) {
        CONSOLE("Failed to write syscall program at %p", exe_mem);
        return false;
    }


    cpu_registers_t regs = {0};
    cpu_registers_t save_regs = {0};
    size_t pc = 0;

    // Read and save registers
    cpu_registers_get(&regs, ctx->pid);
    save_regs = regs;

    // Resume execution and wait for SYSCALL-Exit
    cpu_register_set(&regs, cpu_register_syscall, (size_t) SYS_getppid);
    if (!resume_execution(ctx, &regs)) {
        TRACE_ERROR("SYS_getppid failed");
        return false;
    }

    // Resume execution and wait for SYSCALL-Enter
    cpu_register_set(&regs, cpu_register_pc, ((size_t) exe_mem));
    cpu_register_set(&regs, cpu_register_arg1, (size_t) rw_mem);
    if (!resume_execution(ctx, &regs)) {
        TRACE_ERROR("Entering function call failed");
        return false;
    }
    // Resume execution and wait for SYSCALL-Exit
    if (!resume_execution(ctx, &regs)) {
        TRACE_ERROR("Function call failed");
        return false;
    }
    cpu_registers_get(&regs, ctx->pid);
    if (ret) {
        *ret = cpu_register_get(&regs, cpu_register_retval);
    }
    cpu_registers_print(&regs);

    // Rewind to syscall instruction
    // and restore registers
    pc = cpu_register_get(&save_regs, cpu_register_pc);
    cpu_register_set(&save_regs, cpu_register_pc, (pc - arch.syscall_rewind_size));

    // Resume execution and wait for SYSCALL-Enter event
    if (!resume_execution(ctx, &save_regs)) {
        TRACE_ERROR("failed");
        return false;
    }

    CONSOLE("syscall_hijack2() DONE");

    return true;
}

#endif

/**
 * We wait to enter a SYSCALL instruction for initialization.
 * We can then alterate the registers to hijack the syscall.
 */
bool syscall_init(syscall_ctx_t *ctx, int pid, int memfd) {
    cpu_registers_t syscall_regs = {0};
    int status = 0;

    ctx->pid = pid;
    ctx->memfd = memfd;

    // Resume execution and wait for SYSCALL-Enter event
    //TRACE_CPUREG(pid, "[INIT] Resume execution ...");
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) {
        TRACE_ERROR("Failed STEP: %m");
        goto error;
    }
    if (waitpid(pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", pid);
        goto error;
    }
    cpu_registers_get(&syscall_regs, pid);

    //TRACE_CPUREG(pid, "[INIT] Paused:Enter SYSCALL");

error:
    return true;
}

static bool resume_until(const syscall_ctx_t *ctx, cpu_registers_t *regs, enum __ptrace_request ptrace_req) {
    const struct timespec timeout = {.tv_sec = 10};
    int status = 0;
    int sig = 0;
    sigset_t sigmask = {0};
    siginfo_t siginfo = {0};

    // Block SIGCHLD signal
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &sigmask, NULL);

    // Set registers and resume SYSCALL
    regs->set_return_addr = true;
    if (!cpu_registers_set(regs, ctx->pid)) {
        TRACE_ERROR("Failed to setregs for process %d (%m)", ctx->pid);
        goto error;
    }
    do {
        if (ptrace(ptrace_req, ctx->pid, 0, 0) != 0) {
            TRACE_ERROR("ptrace(SYSCALL, %d) failed: %m", ctx->pid);
            goto error;
        }

        // Wait for next SYSCALL
        if (sigtimedwait(&sigmask, &siginfo, &timeout) < 0) {
            TRACE_ERROR("syscall execution timeout for %d: %m", ctx->pid);
            goto error;
        }
        if (waitpid(ctx->pid, &status, 0) < 0) {
            TRACE_ERROR("waitpid(%d) failed: %m", ctx->pid);
            goto error;
        }
        if (!cpu_registers_get(regs, ctx->pid)) {
            TRACE_ERROR("Failed to setregs for process %d (%m)", ctx->pid);
            goto error;
        }
        if (WIFSIGNALED(status)) {
            sig = WTERMSIG(status);
            TRACE_ERROR("process terminated by signal:%d", sig);
            goto error;
        }
        if (!WIFSTOPPED(status)) {
            TRACE_ERROR("process was not stopped by a signal");
            goto error;
        }
        sig = WSTOPSIG(status);

        if (cpu_register_get(regs, cpu_register_pc) == MAGIC_RET_ADDR) {
            // process has reached MAGIC_RET_ADDR
            return true;
        }
        switch (sig) {
            case (SIGTRAP|0x80):
                // process was well stopped by a PTRACE_SYSCALL event
                // either we are entering the syscal, either we are exiting the syscall.
                return true;
            case SIGTRAP:
                // process was stopped by an interrupt
                return true;
            case SIGQUIT:
            case SIGILL:
            case SIGABRT:
            case SIGBUS:
            case SIGFPE:
            case SIGKILL:
            case SIGSEGV:
            case SIGTERM:
                TRACE_ERROR("process was stopped by signal %d instead of %d (SIGTRAP)", sig, SIGTRAP);
                goto error;
            default:
                TRACE_WARNING("Ignoring received signal %d", sig);
                break;
        }
    } while (true);

    return true;

error:
    cpu_registers_print(regs);
    return false;
}

static bool resume_until_syscall(const syscall_ctx_t *ctx, cpu_registers_t *regs) {
    return resume_until(ctx, regs, PTRACE_SYSCALL);
}

static bool resume_until_interrupt(const syscall_ctx_t *ctx, cpu_registers_t *regs) {
    return resume_until(ctx, regs, PTRACE_CONT);
}

#if 0
bool resume_execution_until_syscall_enter(const syscall_ctx_t *ctx, cpu_registers_t *regs) {
    bool rt = false;

    while (true) {
        rt = resume_execution(ctx, regs);

        /*
         * On ARM CPU, IP is used to denote syscall entry/exit:
         * IP = 0 -> entry, =1 -> exit
         */
        size_t reg_ip = regs->raw.uregs[12];
        if (reg_ip == 0) {
            break;
        }
    }

    return rt;
}
#endif

bool syscall_function(syscall_ctx_t *ctx, size_t function, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t *ret) {
    cpu_registers_t regs = {0};
    cpu_registers_t save_regs = {0};
    size_t pc = 0;

    // Read and save registers
    cpu_registers_get(&regs, ctx->pid);
    save_regs = regs;

    // We are entering a SYSCALL.
    // Resume execution with a dummy SYS_getpid syscall and wait for SYSCALL-Exit.
    cpu_register_set(&regs, cpu_register_syscall, (size_t) SYS_getppid);
    if (!resume_until_syscall(ctx, &regs)) {
        TRACE_ERROR("SYS_getppid failed");
        return false;
    }

    // Run our function until the program stop at MAGIC_RET_ADDR
    cpu_register_set(&regs, cpu_register_pc, function);
    cpu_register_set(&regs, cpu_register_ra, MAGIC_RET_ADDR);
    cpu_register_set(&regs, cpu_register_arg1, arg1);
    cpu_register_set(&regs, cpu_register_arg2, arg2);
    cpu_register_set(&regs, cpu_register_arg3, arg3);
    cpu_register_set(&regs, cpu_register_arg4, arg4);
    if (!resume_until_interrupt(ctx, &regs)) {
        TRACE_ERROR("function call failed");
        return false;
    }
    if (ret) {
        *ret = cpu_register_get(&regs, cpu_register_retval);
    }

    // Rewind to syscall instruction
    // and restore registers
    pc = cpu_register_get(&save_regs, cpu_register_pc);
    cpu_register_set(&save_regs, cpu_register_pc, (pc - arch.syscall_rewind_size));

    // Resume execution and wait for SYSCALL-Enter event
    if (!resume_until_syscall(ctx, &save_regs)) {
        TRACE_ERROR("failed to resume program");
        return false;
    }

    return true;
}

/**
 * When syscall_hijack() is called, we assume are already entering a SYSCALL.
 *
 * We can thus:
 * - Save current registers to restore them later
 * - Alterate the registers to hijack the syscall
 * - Resume execution and wait for the SYSCALL-Exit event.
 * - Rewind back from one instruction and restore the original instructions.
 * - Resume execution and wait for the SYSCALL-Enter event.
 */
static bool syscall_hijack(syscall_ctx_t *ctx, size_t syscall, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6, size_t *ret) {
    cpu_registers_t regs = {0};
    cpu_registers_t save_regs = {0};
    size_t pc = 0;
    int status = 0;

    // Save current registers
    cpu_registers_get(&regs, ctx->pid);
    save_regs = regs;

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

    // Resume execution and wait for SYSCALL-Exit event
    //TRACE_CPUREG(ctx->pid, "[HIJACK] Resume execution ...");
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
    //TRACE_CPUREG(ctx->pid, "[HIJACK] Paused:Exit SYSCALL");

    // Rewind to syscall instruction
    // and restore registers
    pc = cpu_register_get(&save_regs, cpu_register_pc);
    cpu_register_set(&save_regs, cpu_register_pc, (pc - arch.syscall_rewind_size));
    cpu_registers_set(&save_regs, ctx->pid);

    // Resume execution and wait for SYSCALL-Enter event
    //TRACE_CPUREG(ctx->pid, "[INIT] Resume execution ...");
    if (ptrace(PTRACE_SYSCALL, ctx->pid, 0, 0) != 0) {
        TRACE_ERROR("Failed STEP: %m");
        return false;
    }
    if (waitpid(ctx->pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", ctx->pid);
        return false;
    }
    //TRACE_CPUREG(ctx->pid, "[INIT] Paused:Enter SYSCALL");

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

int syscall_munmap(syscall_ctx_t *ctx, void *addr, size_t length) {
    size_t ret = 0;

    syscall_hijack(ctx,
        SYS_munmap, (size_t) addr, length, 0, 0, 0, 0, &ret);

    return ret;
}

int syscall_getpid(syscall_ctx_t *ctx) {
    size_t ret = 0;

    syscall_hijack(ctx,
        SYS_getpid, 0, 0, 0, 0, 0, 0, &ret);

    return (ssize_t) ret;
}

