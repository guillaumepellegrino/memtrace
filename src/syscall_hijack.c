#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include "syscall_hijack.h"
#include "ptrace.h"
#include "arch.h"
#include "log.h"

void cpu_registers_dump(cpu_registers_t *regs) {
    CONSOLE("registers:");
    for (int i = 0; i < 18; i++) {
        CONSOLE("  r%02d: 0x%0lx", i, regs->raw.uregs[i]);
    }
    CONSOLE("");
}

static bool syscall_hijack(int pid, size_t syscall, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6, size_t *ret) {
    cpu_registers_t regs = {0};
    cpu_registers_t save_regs = {0};
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
    if (!cpu_registers_get(&regs, pid)) {
        TRACE_ERROR("Failed to getregs for process %d", pid);
        return false;
    }
/*
    int syscall = cpu_register_get(&regs, cpu_register_syscall);
    switch (syscall) {
        case SYS_restart_syscall: CONSOLE("SYS_restart_syscall"); break;
        case SYS_read: CONSOLE("SYS_read"); break;
        case SYS_write: CONSOLE("SYS_write"); break;
        case SYS_getpid: CONSOLE("SYS_getpid"); break;
        case SYS_nanosleep: CONSOLE("SYS_nanosleep"); break;
        default: CONSOLE("SYS_%d", syscall); break;
    }
    cpu_registers_dump(&regs);
    */
    save_regs = regs;

    // Set registers
    cpu_register_set(&regs, cpu_register_syscall, syscall);
    cpu_register_set(&regs, cpu_register_arg1, arg1);
    cpu_register_set(&regs, cpu_register_arg2, arg2);
    cpu_register_set(&regs, cpu_register_arg3, arg3);
    cpu_register_set(&regs, cpu_register_arg4, arg4);
    cpu_register_set(&regs, cpu_register_arg5, arg5);
    cpu_register_set(&regs, cpu_register_arg6, arg6);

    //CONSOLE("WRITE REGISTERS:");
    //cpu_registers_dump(&regs);


    if (!cpu_registers_set(&regs, pid)) {
        TRACE_ERROR("Failed to setregs for process %d (%m)", pid);
        return false;
    }

    // Wait for syscall done
    if (ptrace(PTRACE_SET_SYSCALL, pid, NULL, syscall) != 0) {
        TRACE_ERROR("ptrace(SYSCALL, %d) failed: %m", pid);
        return false;
    }
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
    if (!cpu_registers_get(&regs, pid)) {
        TRACE_ERROR("Failed to getregs for process %d", pid);
        return false;
    }

    CONSOLE("READ REGISTERS:");
    cpu_registers_dump(&regs);
    if (ret) {
        *ret = cpu_register_get(&regs, cpu_register_retval);
    }

    // Restore saved registers
    if (!cpu_registers_set(&save_regs, pid)) {
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

#ifdef SYS_mmap
    syscall_hijack(pid,
        SYS_mmap, (size_t) addr, length, prot, flags, fd, offset, &ret);
#else
    // TODO: TEST ME
    syscall_hijack(pid,
        SYS_mmap2, (size_t) addr, length, prot, flags, fd, offset, &ret);
#endif

    return (void *) ret;
}

int syscall_getpid(int pid) {
    size_t ret = 0;

    syscall_hijack(pid,
        SYS_getpid, 0, 0, 0, 0, 0, 0, &ret);

    CONSOLE("getpid()->%zu", ret);

    return (ssize_t) ret;
}


