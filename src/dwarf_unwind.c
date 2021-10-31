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

#define TRACE_ZONE TRACE_ZONE_UNWIND
#include "dwarf_unwind.h"
#include "debug_frame.h"
#include "libraries.h"
#include "elf.h"
#include "ftrace.h"
#include "log.h"

static inline size_t cpu_registers_get(cpu_registers_t *registers, uint32_t regnum) {
    return (regnum < countof(registers->r)) ?
        registers->r[regnum] : 0;
}


static inline void cpu_registers_set(cpu_registers_t *registers, uint32_t regnum, size_t value) {
    if (regnum < countof(registers->r)) {
        registers->r[regnum] = value;
    }
}

void cpu_registers_print(const cpu_registers_t *registers) {
    size_t i;
    for (i = 0; i < 17; i++) {
        CONSOLE("  r[%zu] = 0x%zx", i, registers->r[i]);
    }
}

bool debug_frame_unwind(ftrace_t *ftrace, debug_frame_rules_t *rules, cpu_registers_t *current) {
    cpu_registers_t unwind = *current;
    debug_frame_register_t *reg = NULL;
    uint32_t regnum = 0;
    size_t cfa = 0;
    size_t value = 0;

    cfa = cpu_registers_get(current, rules->cfa_reg_number) + rules->cfa_reg.value;
    cpu_registers_set(&unwind, rules->cfa_reg_number, cfa);

    for (regnum = 0; regnum < countof(rules->registers); regnum++) {
        reg = &rules->registers[regnum];
        switch (reg->rule) {
            case debug_frame_register_rule_undefined:
                cpu_registers_set(&unwind, regnum, 0);
                break;
            case debug_frame_register_rule_same_value:
                break;
            case debug_frame_register_rule_offset:
                if (!ftrace_read_word(ftrace, cfa + reg->value, &value)) {
                    TRACE_ERROR("Failed to read address 0x%zx: %m", cfa + reg->value);
                }
                cpu_registers_set(&unwind, regnum, value);
                break;
            case debug_frame_register_rule_val_offset:
                cpu_registers_set(&unwind, regnum, cfa + reg->value);
                break;
            case debug_frame_register_rule_reg:
                cpu_registers_set(&unwind, regnum, reg->value);
                break;
            case debug_frame_register_rule_expression:
                TRACE_ERROR("Expression not implemented");
                cpu_registers_set(&unwind, regnum, 0);
                break;
            case debug_frame_register_rule_val_expression:
                TRACE_ERROR("Expression not implemented");
                cpu_registers_set(&unwind, regnum, 0);
                break;
            case debug_frame_register_rule_architectural:
                TRACE_ERROR("not implemented");
                cpu_registers_set(&unwind, regnum, 0);
                break;
            default:
                break;
        }
    }

    *current = unwind;

    return true;
}

bool dwarf_unwind(libraries_t *libraries, const ftrace_fcall_t *fcall, size_t *callstack, size_t size) {
    cpu_registers_t registers = {0};
    debug_frame_rules_t rules = {0};
    const library_t *library = NULL;
    size_t pc = fcall->ra;
    size_t ra = 0;
    size_t i = 0;

    if (!libraries || !fcall || !callstack || !size) {
        TRACE_ERROR("NULL");
        return false;
    }

    TRACE_LOG("Unwind callstack at 0x%zx", pc);

    registers = fcall->registers;

    callstack[0] = fcall->pc;
    for (i = 1; i < size; i++) {
        if (!(library = libraries_find(libraries, pc))) {
            TRACE_LOG("    0x%zx not found in libraries", pc);
            return i > 0;
        }

        callstack[i] = pc;
        ra = library_relative_address(library, pc);

        TRACE_LOG("    %s+0x%zx", library->name, ra);
        if (!library->frame_file) {
            TRACE_LOG("    No debug info for %s+0x%zx", library->name, ra);
            return i > 0;
        }

        if (!debug_frame_ex(library->frame_hdr_file, library->frame_file, &rules, ra)) {
            TRACE_LOG("    Debug symbol not found for %s+0x%zx", library->name, ra);
            return i > 0;
        }

        if (!debug_frame_unwind(fcall->ftrace, &rules, &registers)) {
            TRACE_ERROR("    Failed to unwind %s+0x%zx", library->name, ra);
            return i > 0;
        }
        pc = registers.r[rules.ra_reg_number];
    }

    return true;
}

