#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include "syscall_hijack.h"
#include "ftrace.h"
#include "ptrace.h"
#include "arch.h"
#include "log.h"

static bool syscall_hijack(int pid, size_t syscall, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6, size_t *ret) {
    struct user_regs_struct regs = {0};
    struct user_regs_struct save_regs = {0};
    ftrace_fcall_t fcall = {0};
    int status = 0;

    // Wait for next syscall
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0) {
        TRACE_ERROR("ptrace(SYSCALL, %d) failed: %m", pid);
        return false;
    }
    if (waitpid(pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", pid);
        return false;
    }
    if (!ptrace_stopped_by_syscall(status)) {
        TRACE_ERROR("process(%d) was not stopped by syscall (status: %d)", pid, status);
        return false;
    }

    // Save registers
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        TRACE_ERROR("Failed to getregs for process %d", pid);
        return false;
    }
    save_regs = regs;

    // Set registers
    regs.orig_rax = syscall;
    regs.rdi = arg1;
    regs.rsi = arg2;
    regs.rdx = arg3;
    regs.r10 = arg4;
    regs.r8  = arg5;
    regs.r9  = arg6;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0) {
        TRACE_ERROR("Failed to setregs for process %d (%m)", pid);
        return false;
    }

    // Wait for syscall done
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0) {
        TRACE_ERROR("ptrace(SYSCALL, %d) failed: %m", pid);
        return false;
    }
    if (waitpid(pid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", pid);
        return false;
    }
    if (!ptrace_stopped_by_syscall(status)) {
        TRACE_ERROR("process(%d) was not stopped by syscall (stautus: %d)", pid, status);
        return false;
    }
    if (!arch.ftrace_fcall_fill(&fcall, pid)) {
        TRACE_ERROR("Failed to get registers");
        return false;
    }
    if (ret) {
        *ret = fcall.retval;
    }

    // Restore saved registers
    if (ptrace(PTRACE_SETREGS, pid, NULL, &save_regs) != 0) {
        TRACE_ERROR("Failed to setregs for process %d (%m)", pid);
        return false;
    }

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

    syscall_hijack(pid,
        SYS_mmap, (size_t) addr, length, prot, flags, fd, offset, &ret);

    return (void *) ret;
}



