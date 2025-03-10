/*
 * Copyright (C) 2022 Guillaume Pellegrino
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

#define SYSCALL_PRIVATE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include "syscall.h"
#include "libraries.h"
#include "ptrace.h"
#include "breakpoint.h"
#include "coredump.h"
#include "memfd.h"
#include "arch.h"
#include "log.h"

#define MAGIC_RET_ADDR 0x00

void syscall_registers_print(cpu_registers_t *regs) {
    size_t number = cpu_register_get(regs, cpu_register_syscall);
    const char *syscall = syscall_name(number);
    if (!syscall) {
        syscall = "??";
    }
    CONSOLE("scn:%zd(%s) pc:0x%zx r0:%zx, r1:%zx, r2: %zx, r3: %zx, r4: %zx, lr:0x%zx, sp:%zx(rt:%zx)",
        number, syscall,
        cpu_register_get(regs, cpu_register_pc),
        cpu_register_get(regs, cpu_register_syscall_arg1),
        cpu_register_get(regs, cpu_register_syscall_arg2),
        cpu_register_get(regs, cpu_register_syscall_arg3),
        cpu_register_get(regs, cpu_register_syscall_arg4),
        cpu_register_get(regs, cpu_register_syscall_arg5),
        cpu_register_get(regs, cpu_register_ra),
        cpu_register_get(regs, cpu_register_sp),
        cpu_register_get(regs, cpu_register_retval));

#if 0
    int64_t *r = (int64_t *) regs->raw.regs;
    for (int i = 0; i < 32; i++) {
        CONSOLE(" - r%d=%"PRId64, i, r[i]);
    }
#endif
}

#ifdef PTRACE_GET_SYSCALL_INFO
// This struct is a dirty copy from /usr/include/sys/ptrace.h.
// musl and glibc are naming ptrace_syscall_info differently :/
// So, we define our own ptrace_syscall_info as a workaround.
struct memtrace_ptrace_syscall_info
{
  uint8_t op;			/* One of the enum
				   __ptrace_get_syscall_info_op
				   values.  */
  uint32_t arch __attribute__ ((__aligned__ (4))); /* AUDIT_ARCH_*
							value.  */
  uint64_t instruction_pointer; /* Instruction pointer.  */
  uint64_t stack_pointer;	/* Stack pointer.  */
  union
  {
    /* System call number and arguments, for
       PTRACE_SYSCALL_INFO_ENTRY.  */
    struct
    {
      uint64_t nr;
      uint64_t args[6];
    } entry;
    /* System call return value and error flag, for
       PTRACE_SYSCALL_INFO_EXIT.  */
    struct
    {
      int64_t rval;
      uint8_t is_error;
    } exit;
    /* System call number, arguments and SECCOMP_RET_DATA portion of
       SECCOMP_RET_TRACE return value, for
       PTRACE_SYSCALL_INFO_SECCOMP.  */
    struct
    {
      uint64_t nr;
      uint64_t args[6];
      uint32_t ret_data;
    } seccomp;
  };
};
#endif

static void TRACE_CPUREG_IMPL(int pid, const char *fmt) {
    char s[64];
    time_t now = time(NULL);
    strftime(s, sizeof(s), "%Hh%M %Ss", localtime(&now));
    CONSOLE_RAW("[%s]", s);

    cpu_registers_t regs = {0};
    cpu_registers_get(&regs, pid);
#ifdef PTRACE_GET_SYSCALL_INFO
    struct memtrace_ptrace_syscall_info info = {0};
    if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *) sizeof(info), &info) != 0) {
        //TRACE_ERROR("Failed to get SYSCALL info for pid %d: %m", pid);
    }

    const char *op = "unknown";
    switch (info.op) {
        case PTRACE_SYSCALL_INFO_ENTRY:
            op = "SYSCALL-Enter";
            break;
        case PTRACE_SYSCALL_INFO_EXIT:
            op = "SYSCALL-Exit";
            break;
        case PTRACE_SYSCALL_INFO_SECCOMP:
            op = "SECCOMP";
            break;
        case PTRACE_SYSCALL_INFO_NONE:
            op = "Interrupt";
            break;
        default:
            break;
    }
    CONSOLE_RAW("[%s]", op);
#elif __arm__
    /*
     * On ARM CPU, IP is used to denote syscall entry/exit:
     * IP = 0 -> entry, =1 -> exit
     */
    size_t reg_ip = regs.raw.uregs[12];
    const char *op = (reg_ip == 0) ? "SYSCALL-Enter" : "SYSCALL-Exit";
    CONSOLE_RAW("[%s]", op);
#endif
    CONSOLE_RAW(" %s\n  ", fmt);
    syscall_registers_print(&regs);
}

/** Log CPU Registers if CPUREG env var is set */
void TRACE_CPUREG(int pid, const char *fmt) {
    static int tristate;

    if (tristate == 0) {
        tristate = getenv("CPUREG") ? 1 : 2;
    }
    if (tristate == 1) {
        TRACE_CPUREG_IMPL(pid, fmt);
    }
}

/** Resume process until it is interrupted by specified ptrace request */
static bool syscall_resume_until(const syscall_ctx_t *ctx, cpu_registers_t *regs, int ptrace_req) {
    const struct timespec timeout = {.tv_sec = 10};
    cpu_registers_t local = {0};
    int status = 0;
    int sig = 0;
    sigset_t sigmask = {0};
    siginfo_t siginfo = {0};

    // Block SIGCHLD signal
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &sigmask, NULL);

    // Set registers and resume SYSCALL
    if (regs) {
        if (!cpu_registers_set(regs, ctx->pid)) {
            TRACE_ERROR("Failed to setregs for process %d (%m)", ctx->pid);
            goto error;
        }
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
        if (waitpid(ctx->pid, &status, __WALL) < 0) {
            TRACE_ERROR("waitpid(%d) failed: %m", ctx->pid);
            goto error;
        }
        if (regs) {
            if (!cpu_registers_get(regs, ctx->pid)) {
                TRACE_ERROR("Failed to getregs for process %d (%m)", ctx->pid);
            }
            if (cpu_register_get(regs, cpu_register_pc) == 0) {
                return true;
            }
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
    cpu_registers_get(&local, ctx->pid);
    syscall_registers_print(&local);
    coredump_write_file("memtrace-error.core", ctx->pid, NULL);
    return false;
}

bool syscall_resume_until_syscall(const syscall_ctx_t *ctx, cpu_registers_t *regs) {
    return syscall_resume_until(ctx, regs, PTRACE_SYSCALL);
}

bool syscall_resume_until_interrupt(const syscall_ctx_t *ctx, cpu_registers_t *regs) {
    return syscall_resume_until(ctx, regs, PTRACE_CONT);
}

bool syscall_resume_until_singlestep(const syscall_ctx_t *ctx, cpu_registers_t *regs) {
    return syscall_resume_until(ctx, regs, PTRACE_SINGLESTEP);
}

/** Run process step by step */
void stepbystep(syscall_ctx_t *ctx) {
    while(syscall_resume_until_singlestep(ctx, NULL)) {
        TRACE_CPUREG(ctx->pid, "SINGLESTEP");
        cpu_registers_t regs = {0};
        cpu_registers_get(&regs, ctx->pid);
        if (ctx->bp_addr == cpu_register_get(&regs, cpu_register_pc)) {
            CONSOLE("Breakpoint reached !");
            return;
        }
    }
    TRACE_CPUREG(ctx->pid, "SINGLESTEP END");
}

/** Initialize the syscall context. */
bool syscall_initialize(syscall_ctx_t *ctx, int pid, libraries_t *libraries) {
    assert(ctx);
    assert(pid);
    assert(libraries);

    bool rt = false;
    ctx->memfd = memfd_open(pid);
    if (ctx->memfd < 0) {
        goto error;
    }
    ctx->pid = pid;
    ctx->libraries = libraries;
    ctx->bp_addr = 0;

    TRACE_CPUREG(pid, "Process has been interrupted");
    if (!arch.ptrace_interrupt(ctx)) {
        TRACE_ERROR("Failed to interrupt process");
        goto error;
    }
    rt = true;
error:
    return rt;
}

void syscall_cleanup(syscall_ctx_t *ctx) {
    if (ctx->pid) {
        bool rt = false;
        int status = 0;
        if (!arch.ptrace_resume(ctx)) {
            TRACE_ERROR("Failed to resume process");
            goto error;
        }

        // Check process did not crash just after resuming execution
        if (ptrace(PTRACE_CONT, ctx->pid, 0, 0) != 0) {
            TRACE_ERROR("ptrace(SYSCALL, %d) failed: %m", ctx->pid);
            goto error;
        }
        usleep(10*1000);
        int pid = waitpid(ctx->pid, &status, __WALL|WNOHANG);
        if (pid < 0) {
            TRACE_ERROR("waitpid(%d) failed: %m", ctx->pid);
            goto error;
        }
        if (pid > 0) {
            if (WIFSIGNALED(status)) {
                TRACE_ERROR("process terminated by signal:%d", WTERMSIG(status));
                goto error;
            }
            if (!WIFSTOPPED(status)) {
                TRACE_ERROR("process was stopped by signal %d", WSTOPSIG(status));
                goto error;
            }
        }
        rt = true;
error:
        if (!rt) {
            cpu_registers_t local = {0};
            cpu_registers_get(&local, ctx->pid);
            syscall_registers_print(&local);
            coredump_write_file("memtrace-error.core", ctx->pid, NULL);
        }
#if 0
        while(true) {
            cpu_registers_t regs = {0};
            cpu_registers_get(&regs, ctx->pid);
            if (!syscall_resume_until_syscall(ctx, &regs)) {
                return;
            }
            TRACE_CPUREG(ctx->pid, "ENTER-SYSCALL");

            cpu_registers_get(&regs, ctx->pid);
            if (!syscall_resume_until_syscall(ctx, &regs)) {
                return;
            }
            TRACE_CPUREG(ctx->pid, "EXIT-SYSCALL");
        }
#endif

        close(ctx->memfd);
        ctx->memfd = -1;
        ctx->pid = 0;
    }
}

int syscall_pid(syscall_ctx_t *ctx) {
    return ctx ? ctx->pid : 0;
}

int syscall_memfd(syscall_ctx_t *ctx) {
    return ctx && ctx->pid ? ctx->memfd : -1;
}

cpu_registers_t *syscall_save_regs(syscall_ctx_t *ctx) {
    return ctx ? &ctx->save_regs : NULL;
}

/**
 * Very simply mark the syscall context to generate a coredump
 * the next time we temper the registers in order to perform a syscall
 * or a function call.
 * It may be used for debugging syscall or function injection.
 *
 * set the env var FCALL_CORE=1 for debugging function injection.
 */
void syscall_do_coredump_at_next_tampering(syscall_ctx_t *ctx) {
    ctx->do_coredump = true;
}

/**
 * Punch a breakpoint instruction in the target process.
 * We punch the breakpoint at _start() to function to be sure it will not be called.
 */
size_t syscall_punch_breakpoint(syscall_ctx_t *ctx) {
    breakpoint_t bp = {0};
    library_symbol_t sym = libraries_find_symbol(ctx->libraries, "_start");
    if (!sym.addr) {
        sym = libraries_find_symbol(ctx->libraries, "__libc_start_main");
        if (!sym.addr) {
            TRACE_ERROR("Could not find _start() or __libc_start_main() function in target process");
            return 0;
        }
    }
    if (!arch.breakpoint_set(&bp, ctx->memfd, sym.addr)) {
        TRACE_ERROR("Failed to set breakpoint %s() function at %p", sym.name, sym.addr);
        return 0;
    }
    CONSOLE("Breakpoint set at 0x%"PRIx64" in %s()", sym.addr, sym.name);

    return sym.addr;
}

/** Run a function until the program hit the breakpoint in RA register. */
bool syscall_function(syscall_ctx_t *ctx, size_t function, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t *ret) {
    if (!ctx->bp_addr && arch.breakpoint_set) {
        ctx->bp_addr = syscall_punch_breakpoint(ctx);
        if (!ctx->bp_addr) {
            TRACE_ERROR("Could not punch a breakpoint in target process");
            return false;
        }
    }

    cpu_registers_t regs = ctx->save_regs;
    cpu_register_set(&regs, cpu_register_pc, function);
    cpu_register_set(&regs, cpu_register_ra, ctx->bp_addr);
    cpu_register_set(&regs, cpu_register_arg1, arg1);
    cpu_register_set(&regs, cpu_register_arg2, arg2);
    cpu_register_set(&regs, cpu_register_arg3, arg3);
    cpu_register_set(&regs, cpu_register_arg4, arg4);
    if (arch.prepare_function_call) {
        arch.prepare_function_call(&regs, ctx->pid);
    }
    if (ctx->do_coredump) {
        cpu_registers_set(&regs, ctx->pid);
        coredump_write_file("memtrace-fcall.core", ctx->pid, NULL);
        ctx->do_coredump = false;
    }

    cpu_registers_set(&regs, ctx->pid);
    TRACE_CPUREG(ctx->pid, "Call function");
    if (!syscall_resume_until_interrupt(ctx, &regs)) {
        TRACE_ERROR("function call failed");
        return false;
    }

    if (ret) {
        *ret = cpu_register_get(&regs, cpu_register_retval);
    }

    return true;
}

/** Simply call syscall(snr, arg1, arg2, arg3) function */
bool syscall_hijack(syscall_ctx_t *ctx, size_t syscall, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6, size_t *ret) {
    if (!ctx->syscall_addr) {
        library_symbol_t sym = libraries_find_symbol(ctx->libraries, "syscall");
        ctx->syscall_addr = sym.addr;
        if (!ctx->syscall_addr) {
            TRACE_ERROR("Could not find syscall() function in target process");
            return false;
        }
    }
    return syscall_function(ctx, ctx->syscall_addr,
        syscall, arg1, arg2, arg3, ret);
}

int syscall_open(syscall_ctx_t *ctx, void *path, int flags, mode_t mode) {
    size_t ret = 0;

#ifdef SYS_open
     syscall_hijack(ctx,
         SYS_open, (size_t) path, flags, mode, 0, 0, 0, &ret);
#else
    syscall_hijack(ctx,
        SYS_openat, AT_FDCWD, (size_t) path, flags, mode, 0, 0, &ret);
#endif

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

int syscall_number(const char *name) {
    for (size_t i = 0; syscall_table[i].name; i++) {
        if (!strcmp(name, syscall_table[i].name)) {
            return syscall_table[i].number;
        }
    }
    return 0;
}

const char *syscall_name(int number) {
    for (size_t i = 0; syscall_table[i].name; i++) {
        if (syscall_table[i].number == number) {
            return syscall_table[i].name;
        }
    }
    return 0;
}
