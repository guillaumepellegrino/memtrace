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

#define _GNU_SOURCE
#define TRACE_ZONE TRACE_ZONE_DEBUG_LINE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <endian.h>
#include <inttypes.h>
#include "debug_line.h"
#include "elf.h"
#include "elf_file.h"
#include "log.h"

/* Line Number Standard Opcode Encodings */
typedef enum {
    DW_LNS_extended_opcode = 0x00,
    DW_LNS_copy,
    DW_LNS_advance_pc,
    DW_LNS_advance_line,
    DW_LNS_set_file,
    DW_LNS_set_column,
    DW_LNS_negate_stmt,
    DW_LNS_set_basic_block,
    DW_LNS_const_add_pc,
    DW_LNS_fixed_advance_pc,
    DW_LNS_set_prologue_end,
    DW_LNS_set_epilogue_begin,
    DW_LNS_set_isa,
} DNS_LNS_t;

/* Line Number Extended Opcode Encodings */
typedef enum {
    DW_LNE_end_sequence = 0x01,
    DW_LNE_set_address,
    DW_LNE_define_file,
    DW_LNE_set_discriminator,
    DW_LNE_lo_user,
    DW_LNE_hi_user,
} DW_LNE_t;

// The .debug_line section allows to determine the source code file and line number for a given address in memory. The content is broken down by Compilation Units (CU) representing one main source code file.
//
//Each CU has a header: 
typedef struct __attribute__((packed)) {
    uint64_t unit_length;
    uint16_t version;
    uint32_t header_length;
    uint8_t min_instruction_length;
    uint8_t max_operations_per_instruction;
    uint8_t default_is_stmt;
    int8_t line_base;
    uint8_t line_range;
    uint8_t opcode_base;
    uint8_t std_opcode_lengths[12];
} debug_line_header_t;

// followed by a list of directories, a list of files (referencing what directory they are in), and a series of line number statements, e.g. 
typedef struct {
    uint64_t address;
    uint32_t op_index;
    uint32_t file;
    uint32_t line;
    uint32_t column;
    bool basic_block;
    bool end_sequence;
    bool prologue_end;
    bool epilogue_begin;
    uint32_t isa;
    uint32_t discriminator;
} debug_line_state_machine_t;

typedef struct {
    elf_file_t *fp;
    elf_t *elf;
    uint64_t search_address;
    debug_line_state_machine_t sm;
    debug_line_header_t header;
    size_t directory_count;
    size_t file_count;
    char *directories[256];
    char *files[512];
} debug_line_ctx_t;

static bool debug_line_interpret_special_opcode(uint32_t opcode, debug_line_ctx_t *ctx) {
    uint64_t offset = elf_file_tell(ctx->fp);
    // opcode = (desired_line_increment - line_base) + (line_range * operation_advance) + opcode_base 

    uint32_t adjusted_opcode = opcode - ctx->header.opcode_base;
    uint32_t operation_advance = adjusted_opcode / ctx->header.line_range;
    uint32_t address_increment = ctx->header.min_instruction_length
        * (ctx->sm.op_index + operation_advance);

    uint32_t line_increment = ctx->header.line_base + (adjusted_opcode % ctx->header.line_range);

    // 1. Add a signed integer to line 
    ctx->sm.line += line_increment;

    // 2. Modify address and op_index
    ctx->sm.address += address_increment;

    // 3. Append a row to the matrix (ignored)
    // 4) - 7)
    ctx->sm.basic_block = false;
    ctx->sm.prologue_end = false;
    ctx->sm.epilogue_begin = false;
    ctx->sm.discriminator = 0;

    TRACE_DWARF("<%"PRIx64"> SpeOP[%d] advance PC by %u to 0x%"PRIx64" and Line by %u to %u",
        offset, adjusted_opcode, address_increment, ctx->sm.address, line_increment, ctx->sm.line);
    return true;
}

static bool debug_line_interpret_extended_opcode(debug_line_ctx_t *ctx) {
    int opcode = 0;
    uint32_t len = 0;
    uint64_t offset = elf_file_tell(ctx->fp);

    // Read extended opcode len
    if ((len = elf_file_read_uleb128(ctx->fp)) > 1024) {
        TRACE_ERROR("<%"PRIx64"> OPCode len (%u) is too much large", offset, len);
        return false;
    }

    opcode = elf_file_read_u8(ctx->fp);

    switch (opcode) {
        case DW_LNE_end_sequence: {
            TRACE_DWARF("<%"PRIx64"> ExtOP[%u](len:%u) End of sequence", offset, opcode, len);
            ctx->sm.end_sequence = true;
            return true;
        }
        case DW_LNE_set_address: {
            uint64_t addr = elf_file_read_addr(ctx->fp);
            TRACE_DWARF("<%"PRIx64"> ExtOP[%u](len:%u) set_address 0x%"PRIx64"", offset, opcode, len, addr);
            ctx->sm.address = addr;
            ctx->sm.op_index = 0;
            break;
        }
        /*
        case DW_LNE_define_file: {
            char file[512];
            TRACE_DWARF("ExtOP[%u](len:%u) ", opcode, len);
            elf_file_read_string(file, sizeof(file), &ctx->fp);
            uint32_t directory_idx = elf_file_read_uleb128(&ctx->fp);
            uint32_t lastchange = elf_file_read_uleb128(&ctx->fp);
            uint32_t length = elf_file_read_uleb128(&ctx->fp);
            break;
        }
        case DW_LNE_set_discriminator: {
            TRACE_DWARF("ExtOP[%u](len:%u) ", opcode, len);
            break;
        }
        case DW_LNE_lo_user: {
            TRACE_DWARF("ExtOP[%u](len:%u) ", opcode, len);
            break;
        }
        case DW_LNE_hi_user: {
            TRACE_DWARF("ExtOP[%u](len:%u) ", opcode, len);
            break;
        }
        */
        default: {
            TRACE_DWARF("<%"PRIx64"> ExtOP[%u](len:%u) Unknown", offset, opcode, len);
            if (len > 1) {
                elf_file_discard(ctx->fp, len - 1);
            }
            break;
        }
    }

    return true;
}

/**
 * Interprete Debug Line opcode
 *
 *  special opcodes: [OPCODE]
 *    OPCODE is 1 byte
 *    OPCODE is larger or equal to header.opcode_base
 *
 *  standard opcodes: [OPCODE+ARG...]
 *    OPCODE is 1 byte
 *    ARG is LEB128
 *
 *  extended opcode: [0x00+OPCODE_LEN+OPCODE
 *    OPCODE_LEN is unsigned LEB128
 *    OPCODE is variadic len
 */
static bool debug_line_interpret_opcode(int opcode, debug_line_ctx_t *ctx) {
    uint64_t offset = elf_file_tell(ctx->fp);
    switch (opcode) {
        case DW_LNS_extended_opcode: {
            return debug_line_interpret_extended_opcode(ctx);
        }
        case DW_LNS_copy: {
            TRACE_DWARF("<%"PRIx64"> OP[%d] Copy", offset, opcode);
            // Append a row to the matrix: ignored
            ctx->sm.discriminator = 0;
            ctx->sm.basic_block = 0;
            ctx->sm.prologue_end = 0;
            ctx->sm.epilogue_begin = false;
            break;
        }
        case DW_LNS_advance_pc: {
            uint32_t arg = elf_file_read_uleb128(ctx->fp);
            uint32_t address_increment = arg * ctx->header.min_instruction_length;
            ctx->sm.address += address_increment;

            TRACE_DWARF("<%"PRIx64"> OP[%d] Advance PC by %u to 0x%"PRIx64"", offset, opcode, address_increment, ctx->sm.address);
            break;
        }
        case DW_LNS_advance_line: {
            int32_t arg = elf_file_read_sleb128(ctx->fp);
            TRACE_DWARF("<%"PRIx64"> OP[%d] Advance line by %u to %u", offset, opcode, arg, ctx->sm.line+arg);
            ctx->sm.line += arg;
            break;
        }
        case DW_LNS_set_file: {
            uint32_t arg = elf_file_read_uleb128(ctx->fp);
            TRACE_DWARF("<%"PRIx64"> OP[%d] Set file %u", offset, opcode, arg);
            ctx->sm.file = arg;
            break;
        }
        case DW_LNS_set_column: {
            uint32_t arg = elf_file_read_uleb128(ctx->fp);
            TRACE_DWARF("<%"PRIx64"> OP[%d] Set column %"PRIu32, offset, opcode, arg);
            ctx->sm.column = arg;
            break;
        }
        case DW_LNS_negate_stmt: {
            TRACE_DWARF("<%"PRIx64"> OP[%d] Negate stmt", offset, opcode);
            break;
        }
        case DW_LNS_set_basic_block: {
            TRACE_DWARF("<%"PRIx64"> OP[%d] Set basic block", offset, opcode);
            ctx->sm.basic_block = true;
            break;
        }
        case DW_LNS_const_add_pc: {
            uint32_t adjusted_opcode = 255 - ctx->header.opcode_base;
            uint32_t operation_advance = adjusted_opcode / ctx->header.line_range;
            uint32_t address_increment = ctx->header.min_instruction_length
                * (ctx->sm.op_index + operation_advance);
            ctx->sm.address += address_increment;
            TRACE_DWARF("<%"PRIx64"> OP[%d] Add const %u to PC at 0x%"PRIx64"", offset, opcode, address_increment, ctx->sm.address);
            break;
        }
        case DW_LNS_fixed_advance_pc: {
            uint32_t address_increment = elf_file_read_u16(ctx->fp);
            ctx->sm.address += address_increment;
            TRACE_DWARF("<%"PRIx64"> OP[%d] fixed advance pc by %u at 0x%"PRIx64"", offset, opcode, address_increment, ctx->sm.address);
            break;
        }
        case DW_LNS_set_prologue_end: {
            TRACE_DWARF("<%"PRIx64"> OP[%d] set prologue end", offset, opcode);
            ctx->sm.prologue_end = true;
            break;
        }
        case DW_LNS_set_epilogue_begin: {
            TRACE_DWARF("<%"PRIx64"> OP[%d] set epilogue begin", offset, opcode);
            ctx->sm.epilogue_begin = true;
            break;
        }
        case DW_LNS_set_isa: {
            int32_t arg = elf_file_read_sleb128(ctx->fp);
            TRACE_DWARF("<%"PRIx64"> OP[%d] set isa %d", offset, opcode, arg);
            ctx->sm.isa = arg;
            break;
        }
        default: {
            if (opcode >= ctx->header.opcode_base) {
                debug_line_interpret_special_opcode(opcode, ctx);
            }
            else {
                TRACE_DWARF("<%"PRIx64"> OP[%d] Unknown opcode", offset, opcode);
                return false;
            }
            break;
        }
    }

    return true;
}

bool debug_line_process_cu(debug_line_ctx_t *ctx) {
    size_t i = 0;
    char path[512];
    if ((ctx->header.unit_length = elf_file_read_u32(ctx->fp)) > 0xffffff00) {
        ctx->header.unit_length = elf_file_read_u64(ctx->fp);
        elf_file_setdwarf64(ctx->fp, true);
    }
    uint64_t cu_start_offset = elf_file_tell(ctx->fp);
    ctx->header.version = elf_file_read_u16(ctx->fp);
    ctx->header.header_length = elf_file_read_dwarfaddr(ctx->fp);
    ctx->header.min_instruction_length = elf_file_read_u8(ctx->fp);
    if (ctx->header.version >= 4) {
        ctx->header.max_operations_per_instruction = elf_file_read_u8(ctx->fp);
    }
    ctx->header.default_is_stmt = elf_file_read_u8(ctx->fp);
    ctx->header.line_base = elf_file_read_u8(ctx->fp);
    ctx->header.line_range = elf_file_read_u8(ctx->fp);
    ctx->header.opcode_base = elf_file_read_u8(ctx->fp);
    elf_file_read(ctx->fp, ctx->header.std_opcode_lengths, 12);

    switch (ctx->header.version) {
        case 2:
        case 3:
            break;
        default:
            TRACE_ERROR("DWARF Version %d unsupported", ctx->header.version);
            return false;
    }

    TRACE_LOG("");
    TRACE_LOG("Debug line Header:");
    TRACE_LOG("  length                 : %"PRIu64, ctx->header.unit_length);
    TRACE_LOG("  version                : %"PRIu16, ctx->header.version);
    TRACE_LOG("  header_length          : %"PRIu32, ctx->header.header_length);
    TRACE_LOG("  min_instruction_length : %"PRIu8,  ctx->header.min_instruction_length);
    if (ctx->header.version >= 4) {
        TRACE_LOG("  max_operations_per_insr: %"PRIu8,  ctx->header.max_operations_per_instruction);
    }
    TRACE_LOG("  default_is_stmt        : %"PRIu8,  ctx->header.default_is_stmt);
    TRACE_LOG("  line_base              : %"PRIi8,  ctx->header.line_base);
    TRACE_LOG("  line_rang              : %"PRIu8,  ctx->header.line_range);
    TRACE_LOG("  opcode_base            : %"PRIu8,  ctx->header.opcode_base);

    TRACE_DWARF("Codes op:");
    for (i = 0; i < sizeof(ctx->header.std_opcode_lengths); i++) {
        TRACE_DWARF("  std_opcode_lengths[%zu] : %"PRIu8, i+1, ctx->header.std_opcode_lengths[i]);
    }

    TRACE_DWARF("Directories:");
    i = 1;
    ctx->directories[0] = strdup(".");
    while (elf_file_read_string(ctx->fp, path, sizeof(path))) {
        if (!path[0]) {
            break;
        }

        if (i >= countof(ctx->directories)) {
            TRACE_ERROR("Max directories reached");
            break;
        }
        assert((ctx->directories[i] = strdup(path)));
        TRACE_DWARF("  [%zu] %s", i, path);
        i++;
    }
    ctx->directory_count = i;

    TRACE_DWARF("Files:");
    i = 1;
    ctx->files[0] = strdup("");
    while (elf_file_read_string(ctx->fp, path, sizeof(path))) {
        if (!path[0]) {
            break;
        }
        uint32_t directory_idx = elf_file_read_uleb128(ctx->fp);
        uint32_t lastchange = elf_file_read_uleb128(ctx->fp);
        uint32_t filelength = elf_file_read_uleb128(ctx->fp);

        const char *directory = (directory_idx < ctx->directory_count) ?
            ctx->directories[directory_idx] : ".";

        if (i >= countof(ctx->files)) {
            TRACE_ERROR("Max files reached");
            break;
        }
        assert(asprintf(&ctx->files[i], "%s/%s", directory, path) > 0);
        TRACE_DWARF("  [%zu] %"PRIu32" %u %u %s/%s", i, directory_idx, lastchange, filelength, directory, path);
        i++;
    }
    ctx->file_count = i;

    if (ctx->header.unit_length <= ctx->header.header_length + 6) {
        TRACE_DWARF("opcode list is empty");
        return true;
    }

    size_t size = ctx->header.unit_length - ctx->header.header_length;

    for (i = 0; i < size; i++) {
        uint64_t offset = elf_file_tell(ctx->fp);
        uint64_t cu_length = offset - cu_start_offset;
        if (cu_length >= ctx->header.unit_length) {
            TRACE_LOG("<%"PRIx64"> End of CU (length: 0x%"PRIx64") [0x%"PRIx64", 0x%"PRIx64"]", offset, ctx->header.unit_length, cu_start_offset, offset);
            break;
        }

        int opcode = elf_file_read_u8(ctx->fp);

        if (opcode == EOF) {
            TRACE_ERROR("EOF");
            return false;
        }

        if (!debug_line_interpret_opcode(opcode, ctx)) {
            TRACE_ERROR("Failed to interpret opcode %d", opcode);
            return false;
        }

        const char *file = (ctx->sm.file < ctx->file_count) ? ctx->files[ctx->sm.file] : "??";

        TRACE_DWARF("0x%"PRIx64": %s:%d",
            ctx->sm.address, file, ctx->sm.line);

        if (ctx->sm.address >= ctx->search_address) {
            break;
        }
        if (ctx->sm.end_sequence ) {
            ctx->sm = (debug_line_state_machine_t) {
                .file = 1,
                .line = 1,
            };
        }
    }

    return true;
}

debug_line_info_t *debug_line_ex(elf_t *elf, elf_file_t *line_file, uint64_t address) {
    debug_line_info_t *info = NULL;
    size_t i = 0;
    bool rt = true;
    size_t rdbytes = 0;

    if (!elf || !line_file || !address) {
        return NULL;
    }

    elf_file_seek(line_file, 0);

    do {
        debug_line_ctx_t ctx = {
            .fp = line_file,
            .elf = elf,
            .search_address = address,
            .sm = {
                .file = 1,
                .line = 1,
            },
        };

        if ((rt = debug_line_process_cu(&ctx))) {
            if (ctx.sm.address >= ctx.search_address) {
                const char *file = (ctx.sm.file < ctx.file_count) ? ctx.files[ctx.sm.file] : "??";
                info = calloc(1, sizeof(debug_line_info_t));
                assert(info);
                info->address = address;
                info->file = strdup(file);
                info->line = ctx.sm.line;
            }

            rdbytes += ctx.header.unit_length + ctx.header.header_length + 4;
        }
        else {
            TRACE_ERROR("Failed to process debug_line CU for %s", elf_name(elf));
        }

        for (i = 0; i < ctx.directory_count; i++) {
            free(ctx.directories[i]);
        }
        for (i = 0; i < ctx.file_count; i++) {
            free(ctx.files[i]);
        }

        if (elf_file_eof(line_file) == 1) {
            TRACE_LOG("End of .debug_line section");
            break;
        }
    } while (rt && !info);

    return info;
}

debug_line_info_t *debug_line(elf_t *elf, uint64_t address) {
    const section_header_t *section = NULL;
    elf_file_t *fp = NULL;

    if (!elf || !address) {
        TRACE_ERROR("NULL arguments");
        return NULL;
    }

    if (!(section = elf_section_header_get(elf, ".debug_line"))) {
        TRACE_ERROR("Failed to get .debug_line section for %s", elf_name(elf));
        return NULL;
    }

    if (!(fp = elf_section_open(elf, section))) {
        TRACE_ERROR("Failed to get .debug_line section file pointer for %s", elf_name(elf));
        return NULL;
    }

    return debug_line_ex(elf, fp, address);
}

void debug_line_info_free(debug_line_info_t *info) {
    if (info) {
        free(info->file);
        free(info);
    }
}
