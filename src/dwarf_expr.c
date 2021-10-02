/*
 * Copyright (C) 2021 Guillaume Pellegrino
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

#include <stdlib.h>
#include "types.h"
#include "log.h"
#include "elf_file.h"

typedef enum {
    DW_OP_addr                  = 0x03,
    DW_OP_deref                 = 0x06,
    DW_OP_const1u               = 0x08,
    DW_OP_const1s               = 0x09,
    DW_OP_const2u               = 0x0a,
    DW_OP_const2s               = 0x0b,
    DW_OP_const4u               = 0x0c,
    DW_OP_const4s               = 0x0d,
    DW_OP_const8u               = 0x0e,
    DW_OP_const8s               = 0x0f,
    DW_OP_constu                = 0x10,
    DW_OP_consts                = 0x11,
    DW_OP_dup                   = 0x12,
    DW_OP_drop                  = 0x13,
    DW_OP_over                  = 0x14,
    DW_OP_pick                  = 0x15,
    DW_OP_swap                  = 0x16,
    DW_OP_rot                   = 0x17,
    DW_OP_xderef                = 0x18,
    DW_OP_abs                   = 0x19,
    DW_OP_and                   = 0x1a,
    DW_OP_div                   = 0x1b,
    DW_OP_minus                 = 0x1c,
    DW_OP_mod                   = 0x1d,
    DW_OP_mul                   = 0x1e,
    DW_OP_neg                   = 0x1f,
    DW_OP_not                   = 0x20,
    DW_OP_or                    = 0x21,
    DW_OP_plus                  = 0x22,
    DW_OP_plus_uconst           = 0x23,
    DW_OP_shl                   = 0x24,
    DW_OP_shr                   = 0x25,
    DW_OP_shra                  = 0x26,
    DW_OP_xor                   = 0x27,
    DW_OP_skip                  = 0x2f,
    DW_OP_bra                   = 0x28,
    DW_OP_eq                    = 0x29,
    DW_OP_ge                    = 0x2a,
    DW_OP_gt                    = 0x2b,
    DW_OP_le                    = 0x2c,
    DW_OP_lt                    = 0x2d,
    DW_OP_ne                    = 0x2e,
    DW_OP_lit0                  = 0x30,
    DW_OP_lit31                 = DW_OP_lit0 + 31,
    DW_OP_reg0                  = 0x50,
    DW_OP_reg31                 = DW_OP_reg0 + 31,
    DW_OP_breg0                 = 0x70,
    DW_OP_breg31                = DW_OP_breg0 + 31,
    DW_OP_regx                  = 0x90,
    DW_OP_fbreg                 = 0x91,
    DW_OP_bregx                 = 0x92,
    DW_OP_piece                 = 0x93,
    DW_OP_deref_size            = 0x94,
    DW_OP_xderef_size           = 0x95,
    DW_OP_nop                   = 0x96,
    DW_OP_push_object_address   = 0x97,
    DW_OP_call2                 = 0x98,
    DW_OP_call4                 = 0x99,
    DW_OP_call_ref              = 0x9a,
} DW_OP_t;


/**
 * POSTFIX operations on a simple stack machine
 * Each element of the stack has a type and a value
 * generic_type = integer with machine size and unspecified sign
 */
typedef struct {
    unsigned int idx;
    long values[128];
} dwarf_stack_t;

static void push(dwarf_stack_t *stack, long value) {
    if (stack->idx >= countof(stack->values)) {
        return;
    }

    stack->values[stack->idx++] = value;
}

static long pop(dwarf_stack_t *stack) {
    if (stack->idx == 0) {
        return 0;
    }

    return stack->values[--stack->idx];
}

static long pick(dwarf_stack_t *stack, unsigned int num) {
    if (stack->idx <= num) {
        return 0;
    }

    return stack->values[(stack->idx - 1) - num];
}

bool dwarf_expr_evaluate_opcode(dwarf_stack_t *stack, elf_file_t *file) {
    uint8_t opcode = elf_file_read_u8(file);
    long tmp1;
    long tmp2;
    long tmp3;

    switch (opcode) {
        case DW_OP_addr:
            push(stack, elf_file_read_addr(file));
            break;
        case DW_OP_deref:
            break;
        case DW_OP_const1u:
            push(stack, elf_file_read_u8(file));
            break;
        case DW_OP_const1s:
            push(stack, elf_file_read_i8(file));
            break;
        case DW_OP_const2u:
            push(stack, elf_file_read_u16(file));
            break;
        case DW_OP_const2s:
            push(stack, elf_file_read_i16(file));
            break;
        case DW_OP_const4u:
            push(stack, elf_file_read_u32(file));
            break;
        case DW_OP_const4s:
            push(stack, elf_file_read_i32(file));
            break;
        case DW_OP_const8u:
            push(stack, elf_file_read_u64(file));
            break;
        case DW_OP_const8s:
            push(stack, elf_file_read_i64(file));
            break;
        case DW_OP_constu:
            push(stack, elf_file_read_uleb128(file));
            break;
        case DW_OP_consts:
            push(stack, elf_file_read_sleb128(file));
            break;
        case DW_OP_dup:
            push(stack, pick(stack, 0));
            break;
        case DW_OP_drop:
            pop(stack);
            break;
        case DW_OP_over:
            push(stack, pick(stack, 1));
            break;
        case DW_OP_pick:
            push(stack, pick(stack, elf_file_read_u8(file)));
            break;
        case DW_OP_swap:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp1);
            push(stack, tmp2);
            break;
        case DW_OP_rot:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            tmp3 = pop(stack);
            push(stack, tmp1);
            push(stack, tmp3);
            push(stack, tmp2);
            break;
        case DW_OP_xderef:
            break;
        case DW_OP_abs:
            push(stack, labs(pop(stack)));
            break;
        case DW_OP_and:
            push(stack, pop(stack) & pop(stack));
            break;
        case DW_OP_div:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp1 ? (tmp2 / tmp1) : 0);
            break;
        case DW_OP_minus:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp2 - tmp1);
            break;
        case DW_OP_mod:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp1 ? (tmp2 % tmp1) : 0);
            break;
        case DW_OP_mul:
            push(stack, pop(stack) * pop(stack));
            break;
        case DW_OP_neg:
            push(stack, -pop(stack));
            break;
        case DW_OP_not:
            push(stack, ~pop(stack));
            break;
        case DW_OP_or:
            push(stack, pop(stack) | pop(stack));
            break;
        case DW_OP_plus:
            push(stack, pop(stack) + pop(stack));
            break;
        case DW_OP_plus_uconst:
            push(stack, pop(stack) + elf_file_read_uleb128(file));
            break;
        case DW_OP_shl:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp2 << tmp1);
            break;
        case DW_OP_shr:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp2 >> tmp1);
            break;
        case DW_OP_shra:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp2 >> tmp1);
            break;
        case DW_OP_xor:
            push(stack, pop(stack) ^ pop(stack));
            break;
        case DW_OP_skip:
            tmp1 = elf_file_read_u16(file);
            elf_file_seek(file, elf_file_tell(file) + tmp1);
            break;
        case DW_OP_bra:
            if (pop(stack)) {
                tmp1 = elf_file_read_u16(file);
                elf_file_seek(file, elf_file_tell(file) + tmp1);
            }
            break;
        case DW_OP_eq:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp2 == tmp1);
            break;
        case DW_OP_ge:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp2 >= tmp1);
            break;
        case DW_OP_gt:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp2 > tmp1);
            break;
        case DW_OP_le:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp2 <= tmp1);
            break;
        case DW_OP_lt:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp2 < tmp1);
            break;
        case DW_OP_ne:
            tmp1 = pop(stack);
            tmp2 = pop(stack);
            push(stack, tmp2 != tmp1);
            break;
        case DW_OP_regx:
            tmp1 = elf_file_read_u8(file);
            break;
        case DW_OP_deref_size:
            break;
        case DW_OP_bregx:
            break;
        case DW_OP_nop:
            break;
        case DW_OP_fbreg:
        case DW_OP_piece:
        case DW_OP_xderef_size:
        case DW_OP_push_object_address:
        case DW_OP_call2:
        case DW_OP_call4:
        case DW_OP_call_ref:
        default:
            TRACE_ERROR("Unknown opcode %u", opcode);
            return false;
    }

    return true;
}

long dwarf_expr_do_evaluate(elf_file_t *file, uint64_t cfa, uint64_t eof) {
    dwarf_stack_t stack = {0};
    uint64_t offset = 0;

    // PUSH CFA
    push(&stack, cfa);

    // Evaluate expression Opcode while
    // we did not reach end of expresion
    while ((offset = elf_file_tell(file)) < eof) {
        if (!dwarf_expr_evaluate_opcode(&stack, file)) {
            return 0;
        }
    }

    // POP Result
    return pop(&stack);
}

long dwarf_expr_evaluate(elf_file_t *file, uint64_t cfa, uint64_t offset, size_t size) {
    long value = 0;
    uint64_t old_offset = 0;

    old_offset = elf_file_tell(file);
    elf_file_seek(file, offset);
    value = dwarf_expr_do_evaluate(file, cfa, offset + size);
    elf_file_seek(file, old_offset);

    return value;
}
