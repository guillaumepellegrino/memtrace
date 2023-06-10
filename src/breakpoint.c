#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <wait.h>
#include "breakpoint.h"
#include "threads.h"
#include "evlp.h"
#include "ptrace.h"
#include "arch.h"
#include "log.h"

breakpoint_t *breakpoint_set(int memfd, size_t addr) {
    return arch.breakpoint_set(memfd, addr);
}

bool breakpoint_unset(breakpoint_t *bp) {
    bool rt = true;

    if (bp) {
        // Set back the original instruction
        if (pwrite64(bp->memfd, &bp->orig_instr, sizeof(bp->orig_instr), bp->addr) < 0) {
            TRACE_ERROR("pwrite64(0x%zx) failed: %m", bp->addr);
            rt = false;
        }
        free(bp);
    }

    return rt;
}

bool process_callstack_match(cpu_registers_t *regs, int memfd, void **callstack, size_t size) {
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

bool breakpoint_wait_until(int pid, DIR *threads, int memfd, long addr, void **callstack, size_t size) {
    bool rt = false;
    breakpoint_t *bp = NULL;

    while (!evlp_stopped()) {
        CONSOLE("Set breakpoint at 0x%lx", addr);
        int tid = -1;
        int status = 0;
        cpu_registers_t regs;
        long pc;

        // Set the breakpoint
        if (!(bp = breakpoint_set(memfd, addr))) {
            TRACE_ERROR("Failed to set breakpoint");
            goto error;
        }

        // Continue execution until breakpoint is encountered
        /*
        do {
            if (evlp_stopped()) {
                goto error;
            }
            */
            if (!threads_continue(threads)) {
                TRACE_ERROR("Failed to continue: %m");
                goto error;
            }
            if ((tid = wait(&status)) < 0) {
                TRACE_ERROR("wait(%d) failed: %m", pid);
                goto error;
            }
            if (!cpu_registers_get(&regs, tid)) {
                TRACE_ERROR("Failed to get registers");
                goto error;
            }
            pc = cpu_register_get(&regs, cpu_register_pc);

            // FIXME: pc comparison must be improved
            // and is platform specific
        //} while (pc != bp->addr);

        // Stop others threads execution
        threads_interrupt_except(threads, tid);
        if (!breakpoint_unset(bp)) {
            TRACE_ERROR("Failed to unset breakpoint for %d", tid);
            bp = NULL;
            goto error;
        }
        bp = NULL;

        CONSOLE("%d is at 0x%lx", tid, pc);

        // Did we met the stop condition ?
        if (process_callstack_match(&regs, memfd, callstack, size)) {
            //break;
        }

        // Walk on the breakpoint
        if (!ptrace_step(tid)) {
            TRACE_ERROR("Failed to step: %m", tid);
            goto error;
        }
        if (!cpu_registers_get(&regs, tid)) {
            TRACE_ERROR("Failed to get registers");
            goto error;
        }
        pc = cpu_register_get(&regs, cpu_register_pc);
        CONSOLE("%d singlestep at 0x%lx", tid, pc);
    }

    rt = true;
error:
    breakpoint_unset(bp);
    bp = NULL;
    return rt;
}
