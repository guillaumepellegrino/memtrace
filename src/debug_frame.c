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
#define TRACE_ZONE TRACE_ZONE_DEBUG_FRAME
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug_frame.h"
#include "elf.h"
#include "elf_file.h"
#include "log.h"

static bool debug_frame_read_entry(debug_frame_ctx_t *ctx);

void debug_frame_rules_print(debug_frame_rules_t *rules) {
    uint32_t regnum = 0;
    debug_frame_register_t *reg = NULL;

    fprintf(stderr, "   LOC: 0x%"PRIx64", CFA: r%u+%d", rules->loc, rules->cfa_reg_number, rules->cfa_reg.value);
    for (regnum = 0; regnum < countof(rules->registers); regnum++) {
        reg = &rules->registers[regnum];
        switch (reg->rule) {
            case debug_frame_register_rule_undefined:
                fprintf(stderr, ", r%u:u", regnum);
                break;
            case debug_frame_register_rule_same_value:
                fprintf(stderr, ", r%u:s", regnum);
                break;
            case debug_frame_register_rule_offset:
                fprintf(stderr, ", r%u:c%s%d", regnum, (reg->value>=0?"+":""), reg->value);
                break;
            case debug_frame_register_rule_val_offset:
                fprintf(stderr, ", r%u:[c%s%d]", regnum, (reg->value>=0?"+":""), reg->value);
                break;
            case debug_frame_register_rule_reg:
                fprintf(stderr, ", r%u:r%d", regnum, reg->value);
                break;
            case debug_frame_register_rule_expression:
                fprintf(stderr, ", r%u:expr", regnum);
                break;
            case debug_frame_register_rule_val_expression:
                fprintf(stderr, ", r%u:val_expr", regnum);
                break;
            case debug_frame_register_rule_architectural:
                fprintf(stderr, ", r%u:a", regnum);
                break;
            default:
                break;
        }
    }
    fprintf(stderr, ", ra:r%u", rules->ra_reg_number);
    fprintf(stderr, "\n");
}

debug_frame_register_t *register_reference(debug_frame_rules_t *rules, uint8_t regnumber) {
    static debug_frame_register_t null;
    
    if (regnumber >= countof(rules->registers)) {
        memset(&null, 0, sizeof(null));
        return &null;
    }

    return &rules->registers[regnumber];
}

uint8_t debug_frame_encoding_size(elf_file_t *file, uint8_t encoding) {
    switch (encoding & 0x0F) {
        case DW_EH_PE_ptr:
            return elf_file_64bit(file);
        case DW_EH_PE_udata2:
        case DW_EH_PE_sdata2:
            return 2;
        case DW_EH_PE_udata4:
        case DW_EH_PE_sdata4:
            return 4;
        case DW_EH_PE_udata8:
        case DW_EH_PE_sdata8:
            return 8;
        case DW_EH_PE_uleb128:
        case DW_EH_PE_sleb128:
        case DW_EH_PE_omit:
        default:
            return 0;
    }
}

uint64_t debug_frame_read_encoded_ptr(elf_file_t *file, uint8_t encoding) {
    uint64_t encoded_pointer = 0;
    uint64_t decoded_pointer = 0;
    uint64_t section_offset = 0;
    uint64_t offset = elf_file_tell(file);

    switch (encoding & 0x0F) {
        case DW_EH_PE_ptr:
            encoded_pointer = elf_file_read_addr(file);
            break;
        case DW_EH_PE_uleb128:
            encoded_pointer = elf_file_read_uleb128(file);
            break;
        case DW_EH_PE_udata2:
            encoded_pointer = elf_file_read_u16(file);
            break;
        case DW_EH_PE_udata4:
            encoded_pointer = elf_file_read_u32(file);
            break;
        case DW_EH_PE_udata8:
            encoded_pointer = elf_file_read_u64(file);
            break;
        case DW_EH_PE_sleb128:
            encoded_pointer = elf_file_read_sleb128(file);
            break;
        case DW_EH_PE_sdata2:
            encoded_pointer = elf_file_read_i16(file);
            break;
        case DW_EH_PE_sdata4:
            encoded_pointer = elf_file_read_i32(file);
            break;
        case DW_EH_PE_sdata8:
            encoded_pointer = elf_file_read_i64(file);
            break;
        case DW_EH_PE_omit:
            //TRACE_LOG("omit: (encodig: 0x%x)", encoding);
            return 0;
        default:
            TRACE_ERROR("Failed to decode pointer");
            return 0;
    }

    switch (encoding & 0x70) {
        case DW_EH_PE_absptr:
            decoded_pointer = encoded_pointer;
            break;
        case DW_EH_PE_pcrel:
            section_offset = elf_file_section(file)->sh_offset ;
            decoded_pointer = encoded_pointer + section_offset + offset;
            break;
        case DW_EH_PE_textrel:
            TRACE_ERROR("Unsupported DW_EH_PE_textrel");
            break;
        case DW_EH_PE_datarel:
            section_offset = elf_file_section(file)->sh_offset;
            decoded_pointer = encoded_pointer + section_offset;
            break;
        default:
            TRACE_ERROR("Failed to decode pointer (encoding: 0x%x)", encoding);
            return 0;
    }

    if (encoding & DW_EH_PE_indirect) {
        TRACE_LOG("Unsupported DW_EH_PE_indirect");
    }

    //TRACE_LOG("READ_PTR(encoding:0x%x, encoded_pointer:%"PRId64", decoded_ptr:0x%"PRIx64")",
    //    encoding, /*encoding_str,*/ encoded_pointer, decoded_pointer);

    return decoded_pointer;
}

bool debug_frame_read_instructions(debug_frame_ctx_t *ctx, debug_frame_rules_t *rules) {
    elf_file_t *frame_file = ctx->frame_file;

    uint8_t opcode = elf_file_read_u8(frame_file);
    uint8_t opcode_low = opcode & 0x3F;
    uint8_t opcode_high = opcode >> 6;
    variant_value_t op1 = {.u64 = 0};
    variant_value_t op2 = {.u64 = 0};
    debug_frame_register_t *reg = NULL;

    switch (opcode_high) {
        case DW_CFA_other: {
            switch (opcode_low) {
                /** Row Creation Instructions */
                case DW_CFA_set_loc: {
                    op1.u64 = debug_frame_read_encoded_ptr(frame_file, ctx->cie.fde_encoding);
                    if (ctx->lookup_pc && ctx->lookup_pc <= op1.u64) {
                        ctx->found = true;
                        //CONSOLE("lookup=0x%"PRIx64", loc=0x%"PRIx64, ctx->lookup_pc, rules->loc);
                        break;
                    }
                    rules->loc = op1.u64;
                    TRACE_LOG("   DW_CFA_set_loc 0x%"PRIx64, rules->loc);
                    break;
                }
                case DW_CFA_advance_loc1: {
                    op1.u64 = rules->loc + elf_file_read_u8(frame_file)
                        * ctx->cie.code_alignment_factor;

                    if (ctx->lookup_pc && ctx->lookup_pc <= op1.u64) {
                        ctx->found = true;
                        break;
                    }
                    rules->loc = op1.u64;
                    TRACE_LOG("   DW_CFA_advance_loc1 0x%"PRIx64, rules->loc);
                    break;
                }
                case DW_CFA_advance_loc2: {
                    op1.u64 = rules->loc + elf_file_read_u16(frame_file)
                        * ctx->cie.code_alignment_factor;

                    if (ctx->lookup_pc && ctx->lookup_pc <= op1.u64) {
                        ctx->found = true;
                        break;
                    }
                    rules->loc = op1.u64;
                    TRACE_LOG("   DW_CFA_advance_loc1 0x%"PRIx64, rules->loc);
                    break;
                }
                case DW_CFA_advance_loc4: {
                    op1.u64 = rules->loc + elf_file_read_u32(frame_file)
                        * ctx->cie.code_alignment_factor;

                    if (ctx->lookup_pc && ctx->lookup_pc <= op1.u64) {
                        ctx->found = true;
                        break;
                    }
                    rules->loc = op1.u64;
                    TRACE_LOG("   DW_CFA_advance_loc1 0x%"PRIx64, rules->loc);
                    break;
                }

                /** CFA Definition Instructions */
                case DW_CFA_def_cfa: {
                    rules->cfa_reg_number = elf_file_read_uleb128(frame_file);
                    rules->cfa_reg.rule = debug_frame_register_rule_offset;
                    rules->cfa_reg.value = elf_file_read_uleb128(frame_file);
                    TRACE_LOG("   DW_CFA_def_cfa r%u+%d", rules->cfa_reg_number, rules->cfa_reg.value);
                    break;
                }
                case DW_CFA_def_cfa_sf: {
                    rules->cfa_reg_number = elf_file_read_uleb128(frame_file);
                    rules->cfa_reg.rule = debug_frame_register_rule_offset;
                    rules->cfa_reg.value = elf_file_read_sleb128(frame_file) * ctx->cie.data_alignment_factor;
                    TRACE_LOG("   DW_CFA_def_cfa_sf r%u+%d", rules->cfa_reg_number, rules->cfa_reg.value);
                    break;
                }
                case DW_CFA_def_cfa_register: {
                    rules->cfa_reg_number = elf_file_read_uleb128(frame_file);
                    rules->cfa_reg.rule = debug_frame_register_rule_offset;
                    TRACE_LOG("   DW_CFA_def_cfa_register r%u+%d", rules->cfa_reg_number, rules->cfa_reg.value);
                    break;
                }
                case DW_CFA_def_cfa_offset: {
                    rules->cfa_reg.rule = debug_frame_register_rule_offset;
                    rules->cfa_reg.value = elf_file_read_uleb128(frame_file);
                    TRACE_LOG("   DW_CFA_def_cfa_offset r%u+%d", rules->cfa_reg_number, rules->cfa_reg.value);
                    break;
                }
                case DW_CFA_def_cfa_offset_sf: {
                    rules->cfa_reg.rule = debug_frame_register_rule_offset;
                    rules->cfa_reg.value = elf_file_read_sleb128(frame_file) * ctx->cie.data_alignment_factor;
                    TRACE_LOG("   DW_CFA_def_cfa_offset_sf r%u+%d", rules->cfa_reg_number, rules->cfa_reg.value);
                    break;
                }
                case DW_CFA_def_cfa_expression: {
                    op1.u64 = elf_file_read_uleb128(frame_file);
                    elf_file_discard(frame_file, op1.u64);
                    rules->cfa_reg.rule = debug_frame_register_rule_expression;
                    TRACE_LOG("   DW_CFA_def_cfa_expression BLOCK[%"PRIu64"]", op1.u64);
                    break;
                }

                /** Register Rule Instructions */
                case DW_CFA_undefined: {
                    op1.u64 = elf_file_read_uleb128(frame_file);
                    reg = register_reference(rules, op1.u64);
                    reg->rule = debug_frame_register_rule_undefined;
                    TRACE_LOG("   DW_CFA_undefined 0x%"PRIx64, op1.u64);
                    break;
                }
                case DW_CFA_same_value: {
                    op1.u64 = elf_file_read_uleb128(frame_file);
                    reg = register_reference(rules, op1.u64);
                    reg->rule = debug_frame_register_rule_same_value;
                    TRACE_LOG("   DW_CFA_same_value 0x%"PRIx64, op1.u64);
                    break;
                }
                case DW_CFA_offset_extended: {
                    op1.u64 = elf_file_read_uleb128(frame_file);
                    op2.i64 = elf_file_read_uleb128(frame_file) * ctx->cie.data_alignment_factor;
                    reg = register_reference(rules, op1.u64);
                    reg->rule = debug_frame_register_rule_offset;
                    reg->value = op2.i64;
                    TRACE_LOG("   DW_CFA_offset_extended 0x%"PRIx64" %"PRId64, op1.u64, op2.i64);
                    break;
                }
                case DW_CFA_offset_extended_sf: {
                    op1.u64 = elf_file_read_uleb128(frame_file);
                    op2.i64 = elf_file_read_sleb128(frame_file) * ctx->cie.data_alignment_factor;
                    reg = register_reference(rules, op1.u64);
                    reg->rule = debug_frame_register_rule_offset;
                    reg->value = op2.i64;
                    TRACE_LOG("   DW_CFA_offset_extended_sf 0x%"PRIx64" %"PRIi64, op1.u64, op2.i64);
                    break;
                }
                case DW_CFA_val_offset: {
                    op1.u64 = elf_file_read_uleb128(frame_file);
                    op2.i64 = elf_file_read_uleb128(frame_file) * ctx->cie.data_alignment_factor;
                    reg = register_reference(rules, op1.u64);
                    reg->rule = debug_frame_register_rule_val_offset;
                    reg->value = op2.i64;
                    TRACE_LOG("   DW_CFA_val_offset 0x%"PRIx64" %"PRId64, op1.u64, op2.i64);
                    break;
                }
                case DW_CFA_val_offset_sf: {
                    op1.u64 = elf_file_read_uleb128(frame_file);
                    op2.i64 = elf_file_read_sleb128(frame_file) * ctx->cie.data_alignment_factor;
                    reg = register_reference(rules, op1.u64);
                    reg->rule = debug_frame_register_rule_val_offset;
                    reg->value = op2.i64;
                    TRACE_LOG("   DW_CFA_val_offset_sf 0x%"PRIx64" %"PRIi64, op1.u64, op2.i64);
                    break;
                }
                case DW_CFA_register: {
                    op1.u64 = elf_file_read_uleb128(frame_file);
                    op2.u64 = elf_file_read_uleb128(frame_file);
                    reg = register_reference(rules, op1.u64);
                    reg->rule  = debug_frame_register_rule_reg;
                    reg->value = op2.u64;
                    TRACE_LOG("   DW_CFA_register 0x%"PRIx64" 0x%"PRIx64, op1.u64, op2.u64);
                    break;
                }
                case DW_CFA_expression: {
                    op1.u64 = elf_file_read_uleb128(frame_file);
                    op2.u64 = elf_file_read_uleb128(frame_file);
                    elf_file_discard(frame_file, op2.u64);
                    reg = register_reference(rules, op1.u64);
                    reg->rule = debug_frame_register_rule_expression;
                    TRACE_LOG("   DW_CFA_expression 0x%"PRIx64" BLOCK[%"PRIu64"]", op1.u64, op2.u64);
                    break;
                }
                case DW_CFA_val_expression: {
                    op1.u64 = elf_file_read_uleb128(frame_file);
                    op2.u64 = elf_file_read_uleb128(frame_file);
                    elf_file_discard(frame_file, op2.u64);
                    reg = register_reference(rules, op1.u64);
                    reg->rule = debug_frame_register_rule_val_expression;
                    TRACE_LOG("   DW_CFA_val_expression 0x%"PRIx64" BLOCK[%"PRIu64"]", op1.u64, op2.u64);
                    break;
                }
                case DW_CFA_restore_extended: {
                    op1.u64 = elf_file_read_uleb128(frame_file);
                    TRACE_LOG("   DW_CFA_restore_extended r%"PRIu64, op1.u64);

                    memcpy(
                        register_reference(rules, op1.u64),
                        register_reference(&ctx->cie.rules, op1.u64),
                        sizeof(debug_frame_register_t));
                    break;
                }

                /** Row State Instructions */
                case DW_CFA_remember_state: {
                    TRACE_LOG("   DW_CFA_remember_state");
                    break;
                }
                case DW_CFA_restore_state: {
                    TRACE_LOG("   DW_CFA_restore_state");
                    break;
                }

                /** Padding instruction */
                case DW_CFA_nop: {
                    TRACE_LOG("   DW_CFA_nop");
                    break;
                }

                default: {
                    TRACE_LOG("   0x%02x", opcode);
                    break;
                }
            }
            break;
        }
        case DW_CFA_advance_loc: {
            op1.u64 = rules->loc + opcode_low
                * ctx->cie.code_alignment_factor;

            if (ctx->lookup_pc && ctx->lookup_pc <= op1.u64) {
                ctx->found = true;
                break;
            }
            rules->loc = op1.u64;
            TRACE_LOG("   DW_CFA_advance_loc 0x%"PRIx64, rules->loc);
            break;
        }
        case DW_CFA_offset: {
            op1.i64 = elf_file_read_uleb128(frame_file) * ctx->cie.data_alignment_factor;
            reg = register_reference(rules, opcode_low);
            reg->rule = debug_frame_register_rule_offset;
            reg->value = op1.i64;
            TRACE_LOG("   DW_CFA_offset %"PRId64, op1.i64);
            break;
        }
        case DW_CFA_restore: {
            TRACE_LOG("   DW_CFA_restore r%u", opcode_low);
            memcpy(
                register_reference(rules, opcode_low),
                register_reference(&ctx->cie.rules, opcode_low),
                sizeof(debug_frame_register_t));
            break;
        }
        default: {
            TRACE_LOG("   Unknown opcode 0x%x", opcode);
            break;
        }
    }

    if (!ctx->lookup_pc || verbose >= 1 || zone & TRACE_ZONE) {
        debug_frame_rules_print(rules);
    }

    return true;
}

static void debug_frame_read_cie_entry(elf_file_t *frame_file, debug_frame_cie_t *cie, uint64_t length, uint64_t _start_offset) {
    uint8_t i = 0;

    *cie = (debug_frame_cie_t) {0};
    cie->length = length;
    cie->cie_id = _start_offset;
    cie->version = elf_file_read_u8(frame_file);
    cie->augmentation = elf_file_read_strp(frame_file);
    if (cie->version >= 4) {
        cie->address_size = elf_file_read_u8(frame_file);
        cie->segment_size = elf_file_read_u8(frame_file);
    }
    cie->code_alignment_factor = elf_file_read_uleb128(frame_file);
    cie->data_alignment_factor = elf_file_read_sleb128(frame_file);
    cie->return_address_register = elf_file_read_uleb128(frame_file);

    if (cie->augmentation && cie->augmentation[0] == 'z') {
        cie->augmentation_size = elf_file_read_uleb128(frame_file);
        for (i = 1; cie->augmentation[i]; i++) {
            switch (cie->augmentation[i]) {
                case 'L':
                    cie->lsda_encoding = elf_file_read_u8(frame_file);
                    break;
                case 'R':
                    cie->fde_encoding = elf_file_read_u8(frame_file);
                    break;
                case 'P':
                    cie->handler_encoding = elf_file_read_u8(frame_file);
                    cie->handler = debug_frame_read_encoded_ptr(frame_file, cie->handler_encoding);
                    break;
                case 'S':
                    cie->signal_frame = elf_file_read_u8(frame_file);
                    break;
                default:
                    TRACE_ERROR("Unknown Augmentation string '%c'", cie->augmentation[i]);
                    break;
            }
        }
    }

    TRACE_LOG("[0x%"PRIx64"] cie length=0x%"PRIx64" \"%s\" cf=%"PRIu64" df=%"PRId64" ra=%"PRIu64"",
        _start_offset,
        cie->length,
        cie->augmentation?cie->augmentation:"",
        cie->code_alignment_factor,
        cie->data_alignment_factor,
        cie->return_address_register);
}

bool debug_frame_read_fde_entry(debug_frame_ctx_t *ctx, uint64_t length, uint64_t id, uint64_t _start_offset, uint64_t start_offset) {
    elf_file_t *frame_file = ctx->frame_file;
    uint64_t cie_id = 0;
    if (id > start_offset) {
        TRACE_ERROR("cie_pointer is out of range");
        return false;
    }
    cie_id = start_offset - id;

    ctx->fde = (debug_frame_fde_t) {0};
    ctx->fde.length = length;
    ctx->fde.cie_pointer = id;

    // To continue FDE reading, we first need to read
    // read the cie with corresponding cie_id
    if (!ctx->cie.length || ctx->cie.cie_id != cie_id) {
        TRACE_LOG("Read CIE 0x%"PRIx64, cie_id);

        // Seek file to corresponding cie_id and read the CIE entry
        uint64_t pos = elf_file_tell(frame_file);
        //CONSOLE("seek cie_id: 0x%"PRIx64, cie_id);
        elf_file_seek(frame_file, cie_id);
        if (!debug_frame_read_entry(ctx)) {
            TRACE_ERROR("Failed to parse CIE 0x%"PRIx64, cie_id);
            return false;
        }
        elf_file_seek(frame_file, pos);
    }

    ctx->fde.pc_begin = debug_frame_read_encoded_ptr(frame_file, ctx->cie.fde_encoding);
    ctx->fde.pc_range = debug_frame_read_encoded_ptr(frame_file, ctx->cie.fde_encoding & 0x0F);
    if (ctx->cie.augmentation && ctx->cie.augmentation[0] == 'z') {
        ctx->fde.augmentation_size = elf_file_read_uleb128(frame_file);
    }
    ctx->fde.offset = _start_offset;

    TRACE_LOG("[0x%"PRIx64"] FDE ctx->cie=0x%"PRIx64", pc=0x%"PRIx64"..0x%"PRIx64,
        _start_offset,
        cie_id,
        ctx->fde.pc_begin,
        ctx->fde.pc_begin + ctx->fde.pc_range);

    return true;
}

static bool debug_frame_read_entry(debug_frame_ctx_t *ctx) {
    elf_file_t *frame_file = ctx->frame_file;
    debug_frame_rules_t *rules = NULL;
    uint64_t length = 0;
    uint64_t _start_offset = 0;
    uint64_t start_offset = 0;
    uint64_t id = 0;
    uint64_t offset = 0;

    _start_offset = elf_file_tell(frame_file);
    if ((length = elf_file_read_u32(frame_file)) > 0xffffff00) {
        length = elf_file_read_u64(frame_file);
        elf_file_setdwarf64(frame_file, true);
    }
    start_offset = elf_file_tell(frame_file);
    id = elf_file_read_dwarfaddr(frame_file);

    if (id == 0 || id == 0xffffffff) {
        debug_frame_read_cie_entry(frame_file, &ctx->cie, length, _start_offset);

        if (ctx->cie.length == 0) {
            if (ctx->lookup_pc && ctx->lookup_pc <= ctx->fde.rules.loc) {
                ctx->found = true;
            }
            return false;
        }

        rules = &ctx->cie.rules;
        rules->ra_reg_number = ctx->cie.return_address_register;
    }
    else {
        if (!debug_frame_read_fde_entry(ctx, length, id, _start_offset, start_offset)) {
            return false;
        }

        if (ctx->lookup_pc) {
            if (ctx->lookup_pc < ctx->fde.pc_begin
            || ctx->lookup_pc >= ctx->fde.pc_begin + ctx->fde.pc_range) {
                // This is not the FDE we are looking for
                goto exit;
            }
        }

        ctx->fde.rules = ctx->cie.rules;
        ctx->fde.rules.loc = ctx->fde.pc_begin;
        rules = &ctx->fde.rules;
    }

    while (!elf_file_eof(frame_file)) {
        offset = elf_file_tell(frame_file);

        if (offset >= start_offset + length) {
            break;
        }
        if (!debug_frame_read_instructions(ctx, rules)) {
            break;
        }
        if (ctx->found) {
            break;
        }
    }

exit:
    elf_file_seek(frame_file, start_offset + length);

    if (!elf_file_eof(frame_file)) {
        return true;
    }
    else {
        if (ctx->lookup_pc && ctx->lookup_pc <= rules->loc) {
            ctx->found = true;
        }
        return false;
    }
}

// TODO: It may be needed to build debug_frame_hdr
uint64_t debug_frame_hdr_search(elf_file_t *file, uint64_t pc) {
    debug_frame_hdr_t hdr = {0};


    elf_file_seek(file, 0);
    hdr.version = elf_file_read_u8(file);
    hdr.eh_frame_ptr_enc = elf_file_read_u8(file);
    hdr.fde_count_enc = elf_file_read_u8(file);
    hdr.table_enc = elf_file_read_u8(file);
    hdr.eh_frame_ptr = debug_frame_read_encoded_ptr(file, hdr.eh_frame_ptr_enc);
    hdr.fde_count = debug_frame_read_encoded_ptr(file, hdr.fde_count_enc);
    hdr.fde_size = debug_frame_encoding_size(file, hdr.table_enc);

    if (!hdr.fde_count || !hdr.fde_size) {
        TRACE_ERROR("Failed to parse .debug_frame_hdr");
        return 0;
    }
#if 0
    uint32_t i;
    uint64_t initial_location = 0;
    uint64_t addr = 0;
    uint64_t z_addr = 0;
    for (i = 0; i < hdr.fde_count; i++) {
        initial_location = debug_frame_read_encoded_ptr(file, hdr.table_enc);
        addr = debug_frame_read_encoded_ptr(file, hdr.table_enc);

        if (initial_location > pc) {
            return z_addr;
        }

        z_addr = addr;
    }

    return 0;
#else

    uint64_t table = elf_file_tell(file);
    uint64_t initial_location = 0;
    uint64_t seekidx = 0;
    uint64_t addr;

    int32_t begin_idx = 0;
    int32_t end_idx = hdr.fde_count;
    int32_t middle_idx = 0;


    //CONSOLE("lookup pc: 0x%"PRIx64, pc);
    //CONSOLE("table:     0x%"PRIx64, table);

    while (begin_idx <= end_idx) {
        middle_idx = begin_idx + (end_idx - begin_idx) / 2;
        seekidx = table + (middle_idx * hdr.fde_size * 2);
        elf_file_seek(file, seekidx);
        initial_location = debug_frame_read_encoded_ptr(file, hdr.table_enc);
        //CONSOLE("  [0x%04x] value: 0x%"PRIx64" at 0x%"PRIx64, middle_idx, initial_location, seekidx);
        if (initial_location == pc) {
            addr = debug_frame_read_encoded_ptr(file, hdr.table_enc);
            return addr;
        }
        else if (initial_location < pc) {
            begin_idx = middle_idx + 1;
        }
        else {
            end_idx = middle_idx - 1;
        }
    }

    if (initial_location > pc) {
        middle_idx--;
    }

    seekidx = table + (middle_idx * hdr.fde_size * 2);
    elf_file_seek(file, seekidx);
    initial_location = debug_frame_read_encoded_ptr(file, hdr.table_enc);
    addr = debug_frame_read_encoded_ptr(file, hdr.table_enc);

    //CONSOLE("  [0x%04x] value: 0x%"PRIx64, middle_idx, initial_location);

    return addr;
#endif
}

bool debug_frame_ex(elf_file_t *frame_hdr_file, elf_file_t *frame_file, debug_frame_rules_t *result, uint64_t pc) {
    debug_frame_ctx_t ctx = {
        .frame_file = frame_file,
        .lookup_pc = pc,
    };
    uint64_t fde_addr = 0;

    if (frame_hdr_file && pc) {
        uint64_t section_offset = elf_file_section(frame_file)->sh_offset;
        if (!(fde_addr = debug_frame_hdr_search(frame_hdr_file, pc))) {
            return false;
        }
        if (fde_addr < section_offset) {
            return false;
        }
        fde_addr -= section_offset;

        // Seek to the FDE entry
        //CONSOLE("fde_addr: 0x%"PRIx64", pc: 0x%"PRIx64, fde_addr, pc);
        if (fde_addr) {
            elf_file_seek(frame_file, fde_addr);
            debug_frame_read_entry(&ctx);
        }
    }
    else {
        // Iterate through all entries
        elf_file_seek(frame_file, 0);
        while (debug_frame_read_entry(&ctx)) {
            if (ctx.found) {
                break;
            }
        }
    }

    if (ctx.found && result) {
        *result = ctx.fde.rules;
        result->ra_reg_number = ctx.cie.return_address_register;
    }

    return ctx.found;
}

bool debug_frame(elf_t *elf, debug_frame_rules_t *result, uint64_t pc) {
    elf_file_t *frame_file = NULL;
    bool rt = false;

    if (!elf) {
        TRACE_ERROR("NULL arguments");
        goto exit;
    }

    if (!(frame_file = elf_section_open_from_name(elf, ".eh_frame"))) {
        TRACE_ERROR("Failed to get .eh_frame section for %s", elf_name(elf));
        goto exit;
    }

    TRACE_LOG("Dump .eh_frame for %s", elf_name(elf));
    rt = debug_frame_ex(NULL, frame_file, result, pc);

exit:
    if (frame_file) {
        elf_file_close(frame_file);
    }

    return rt;
}



