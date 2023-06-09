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

typedef enum {
    arm_cpu_mode_arm = 0,
    arm_cpu_mode_thumb16,
    arm_cpu_mode_thumb32,
} arm_cpu_mode_t;

typedef struct {
    long opcode;
    long size;
} breakpoint_instr_t;

struct _breakpoint {
    int memfd;
    long addr;
    long orig_instr;
};

//gdb implementation
//calloc: 0xb6f338fd (0xb6ede000 + 0x558fd)
//ptrace(PTRACE_PEEKTEXT, 12092, 0xb6f338fc, [0x201ea40]) = 0
//ptrace(PTRACE_POKEDATA, 12092, 0xb6f338fc, 0xa000f7f0) = 0
//
//> - two-byte thumb breakpoint: 0xde01
//> - four-byte thumb breakpoint: 0xa000f7f0
//> - arm breakpoint: 0xe7f001f0
static breakpoint_instr_t arm_breakpoint_instr(arm_cpu_mode_t cpu_mode) {
    switch (cpu_mode) {
        case arm_cpu_mode_arm:
            return (breakpoint_instr_t) {
                .opcode = 0xe7f001f0,
                .size = 4,
            };
        case arm_cpu_mode_thumb32:
            return (breakpoint_instr_t) {
                .opcode = 0xa000f7f0,
                .size = 4,
            };
        case arm_cpu_mode_thumb16:
            return (breakpoint_instr_t) {
                .opcode = 0xDE01,
                .size = 2,
            };
        default:
            abort();
    }
}

static arm_cpu_mode_t arm_get_cpu_mode(long addr, long instr) {
    if (!(addr & 0x01)) {
        return arm_cpu_mode_arm;
    }
    if (addr & 0x02) {
        // Instruction is not aligned on 4xbits => THUM16
        return arm_cpu_mode_thumb16;
    }
    else {
        // 16/32 bit Thumb Instruction Encoding
        // Half Word 1 :
        //      11100.xxxx: 16bits Thumb instruction
        //      111xx.xxxx: 32bits Thumb-2 instruction
        //      xxxxx.xxxx: 16bits Thumb instruction
        long opcode = (instr & 0xF800) >> 11;
        switch (opcode) {
            case 0b11101:
            case 0b11110:
            case 0b11111:
                return arm_cpu_mode_thumb32;
            default:
                return arm_cpu_mode_thumb16;
        }
    }
}

breakpoint_t *breakpoint_set(int memfd, long breakpoint_addr) {
    breakpoint_t *bp = NULL;
    long addr = breakpoint_addr & ~1;
    long orig_instr = 0;

    // Read original instruction
    if (pread64(memfd, &orig_instr, sizeof(orig_instr), addr) < 0) {
        TRACE_ERROR("pread64(0x%zx) failed: %m", addr);
        return NULL;
    }
    arm_cpu_mode_t cpu_mode = arm_get_cpu_mode(addr, orig_instr);
    breakpoint_instr_t instr = arm_breakpoint_instr(cpu_mode);

    CONSOLE("Set breakpoint instr (0x%lX) at 0x%lX (old: 0x%lX)",
        instr.opcode, addr, orig_instr);

    // Read interuption instruction
    if (pwrite64(memfd, &instr.opcode, instr.size, addr) < 0) {
        TRACE_ERROR("pwrite64(0x%zx) failed: %m", addr);
        return NULL;
    }

    if (!(bp = calloc(1, sizeof(breakpoint_t)))) {
        return NULL;
    }

    bp->memfd = memfd;
    bp->addr = addr;
    bp->orig_instr = orig_instr;

    return bp;
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
        int it = -1;
        int status = 0;
        cpu_registers_t regs;
        long pc;

        // Set the breakpoint
        if (!(bp = breakpoint_set(memfd, addr))) {
            TRACE_ERROR("Failed to set breakpoint");
            goto error;
        }

        // Continue execution until breakpoint is encountered
        do {
            if (evlp_stopped()) {
                goto error;
            }
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
        } while (pc != bp->addr);

        // Stop others threads execution
        threads_for_each(it, threads) {
            if (it == tid) {
                continue;
            }
            if (ptrace(PTRACE_INTERRUPT, it, NULL, NULL) != 0) {
                TRACE_ERROR("ptrace(INTERRUPT, %d) failed: %m", it);
                goto error;
            }
            if (waitpid(it, &status, 0) < 0) {
                TRACE_ERROR("wait(%d) failed: %m", it);
                goto error;
            }
            CONSOLE("waitpid(%d) done", it);
        }
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
