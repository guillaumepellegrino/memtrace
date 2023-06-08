#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "breakpoint.h"
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

static long make_mask(long size) {
    long mask = 0;
    long i;
    for (i = 0; i < size; i++) {
        mask |= 0xFF << (8L * i);
    }
    return mask;
}

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

breakpoint_t *breakpoint_set(int pid, long breakpoint_addr) {
    breakpoint_t *bp = NULL;
    long addr = breakpoint_addr & ~1;
    long orig_instr = 0;

    // PEEKTEXT and POKETEXT MUST be word aligned
    long offset = addr % sizeof(long);
    addr = (addr / sizeof(long)) * sizeof(long);

    // Read original instruction
    if ((orig_instr = ptrace(PTRACE_PEEKTEXT, pid, addr, 0)) == -1 && errno != 0) {
        TRACE_ERROR("ptrace(PEEKTEXT, %d, 0x%zx) failed: %m", pid, addr);
        return NULL;
    }
    arm_cpu_mode_t cpu_mode = arm_get_cpu_mode(addr, orig_instr);
    breakpoint_instr_t instr = arm_breakpoint_instr(cpu_mode);
    long mask = make_mask(instr.size) << (8L * offset);
    long INT = instr.opcode << (8L * offset);
    long brk_instr = (orig_instr & ~mask) | INT;

    CONSOLE("Set breakpoint instr (0x%lX) at 0x%lX (old: 0x%lX, new: 0x%lX)",
        instr.opcode, addr, orig_instr, brk_instr);
    if (ptrace(PTRACE_POKETEXT, pid, addr, brk_instr) == -1) {
        TRACE_ERROR("ptrace(POKETEXT, %d, 0x%lx, 0x%lx) failed: %m", pid, addr, brk_instr);
        return NULL;
    }

    if (!(bp = calloc(1, sizeof(breakpoint_t)))) {
        return NULL;
    }

    bp->pid = pid;
    bp->addr = addr;
    bp->orig_instr = orig_instr;

    return bp;
}

void breakpoint_unset(breakpoint_t *bp) {
    if (bp) {
        if (ptrace(PTRACE_POKETEXT, bp->pid, bp->addr, bp->orig_instr) != 0) {
            TRACE_ERROR("ptrace(POKETEXT, %d) failed: %m", bp->pid);
        }
        free(bp);
    }
}
