#define _LARGEFILE64_SOURCE
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "breakpoint.h"
#include "threads.h"
#include "evlp.h"
#include "ptrace.h"
#include "arch.h"
#include "log.h"

typedef struct {
    void **callstack;
    size_t size;
} callstack_userdata_t;

/**
 * Set a breakpoint at the specified address.
 * Implementation is platform specific.
 */
static bool breakpoint_set(breakpoint_t *bp, int memfd, size_t addr) {
    return arch.breakpoint_set(bp, memfd, addr);
}

/** Unset the previously set breakpoint */
static bool breakpoint_unset(breakpoint_t *bp) {
    bool rt = true;

    if (bp && bp->is_set) {
        // Set back the original instruction
        if (pwrite64(bp->memfd, &bp->orig_instr, sizeof(bp->orig_instr), bp->addr) < 0) {
            TRACE_ERROR("pwrite64(0x%zx) failed: %m", bp->addr);
            rt = false;
        }
        bp->is_set = false;
    }

    return rt;
}

bool breakpoint_wait_until(int pid, DIR *threads, int memfd, long addr, breakpoint_handler_t stop_condition, void *userdata) {
    breakpoint_t bp = {0};
    bool rt = false;

    while (!evlp_stopped()) {
        TRACE_LOG("Set breakpoint at 0x%lx", addr);
        int tid = -1;
        int status = 0;
        cpu_registers_t regs;
        long pc;

        // Set the breakpoint
        if (!(breakpoint_set(&bp, memfd, addr))) {
            TRACE_ERROR("Failed to set breakpoint");
            goto error;
        }

        // Continue Threads execution until breakpoint is encountered
        if (!threads_continue(threads)) {
            TRACE_ERROR("Failed to continue: %m");
            goto error;
        }
        if ((tid = wait(&status)) < 0) {
            TRACE_ERROR("wait(%d) failed: %m", pid);
            goto error;
        }

        // Stop others threads execution
        threads_interrupt_except(threads, tid);
        if (!breakpoint_unset(&bp)) {
            TRACE_ERROR("Failed to unset breakpoint for %d", tid);
            goto error;
        }

        if (!cpu_registers_get(&regs, tid)) {
            TRACE_ERROR("Failed to get registers");
            goto error;
        }
        pc = cpu_register_get(&regs, cpu_register_pc);
        TRACE_LOG("%d is at 0x%lx", tid, pc);

        // Did we met the stop condition ?
        if (stop_condition(tid, memfd, &regs, userdata)) {
            break;
        }

        // Walk on the breakpoint
        if (!ptrace_step(tid)) {
            TRACE_ERROR("Failed to step: %m", tid);
            goto error;
        }
    }

    rt = true;
error:
    breakpoint_unset(&bp);
    return rt;
}

static bool callstack_matched(int tid, int memfd, cpu_registers_t *regs, void *_userdata) {
    callstack_userdata_t *userdata = _userdata;
    void **callstack = userdata->callstack;
    size_t size = userdata->size;
    size_t sp = cpu_register_get(regs, cpu_register_sp);
    ssize_t i = 0;
    ssize_t len = 0;
    size_t j = 2;

    if ((size_t) callstack[1] != cpu_register_get(regs, cpu_register_ra)) {
        return false;
    }

    if ((len = pread64(memfd, g_buff, sizeof(g_buff), sp)) < 0) {
        TRACE_ERROR("Failed to read SP at 0x%zx: %m", sp);
        return false;
    }
    len /= sizeof(size_t);

    for (i = 0; i < len; i++) {
        size_t pc = ((size_t *) g_buff)[i];
        if (pc == (size_t) callstack[j]) {
            j++;

            if (j >= size) {
                return true;
            }
            if (callstack[j] == NULL) {
                return true;
            }
        }
    }

    return j >= 10;
}

bool breakpoint_wait_until_callstack_matched(int pid, DIR *threads, int memfd, long addr, void **callstack, size_t size) {
    callstack_userdata_t userdata = {
        .callstack = callstack,
        .size = size,
    };

    return breakpoint_wait_until(pid, threads, memfd, addr, callstack_matched, &userdata);
}

static bool always_matched(int tid, int memfd, cpu_registers_t *regs, void *_userdata) {
    return true;
}

bool breakpoint_wait(int pid, DIR *threads, int memfd, long addr) {
    return breakpoint_wait_until(pid, threads, memfd, addr, always_matched, NULL);
}

static bool log_forever_matched(int tid, int memfd, cpu_registers_t *regs, void *_userdata) {
    cpu_registers_print(regs);
    return false;
}

bool breakpoint_log_forever(int pid, DIR *threads, int memfd, long addr) {
    bool rt = breakpoint_wait_until(pid, threads, memfd, addr, log_forever_matched, NULL);
    evlp_set_exit(false);
    return rt;
}
