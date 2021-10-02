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

#ifndef DEBUG_FRAME_H
#define DEBUG_FRAME_H

#include "types.h"

/**
 * Documentation for .eh_frame_hdr:
 * https://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
 *
 * Documentation for .eh_frame:
 * https://refspecs.linuxfoundation.org/LSB_1.3.0/gLSB/gLSB/ehframehdr.html
 *
 * Documentation for .debug_frame:
 * http://dwarfstd.org/doc/Dwarf3.pdf
 *
 */

/* DWARF Exception Header value format */
#define DW_EH_PE_ptr            0x00    /* pointer-sized unsigned value */
#define DW_EH_PE_uleb128        0x01    /* ULEB128 value */
#define DW_EH_PE_udata2         0x02    /* unsigned 16-bit value */
#define DW_EH_PE_udata4         0x03    /* unsigned 32-bit value */
#define DW_EH_PE_udata8         0x04    /* unsigned 64-bit value */
#define DW_EH_PE_sleb128        0x09    /* SLEB128 value */
#define DW_EH_PE_sdata2         0x0a    /* signed 16-bit value */
#define DW_EH_PE_sdata4         0x0b    /* signed 32-bit value */
#define DW_EH_PE_sdata8         0x0c    /* signed 64-bit value */
#define DW_EH_PE_omit           0x0f    /* no value is present */

/* DWARF Exception Header application */
#define DW_EH_PE_absptr         0x00    /* absolute value */
#define DW_EH_PE_pcrel          0x10    /* program-counter relative */
#define DW_EH_PE_textrel        0x20    /* Value is relative to the beginning of the .eh_frame_hdr section. */
#define DW_EH_PE_datarel        0x30    /* data-relative */
#define DW_EH_PE_funcrel        0x40    /* function relative */
#define DW_EH_PE_aligned        0x50    /* Value is aligned to an address unit sized boundary */

/* When this bit is set, the encoded value is the address of the real pointer result, not the pointer result itself. */
#define DW_EH_PE_indirect       0x80

typedef enum {
    DW_CFA_other                 = 0x00,
    DW_CFA_advance_loc           = 0x01,
    DW_CFA_offset                = 0x02,
    DW_CFA_restore               = 0x03,
} DW_CFA_low_t;

typedef enum {
    DW_CFA_nop                  = 0x00,
    DW_CFA_set_loc              = 0x01,
    DW_CFA_advance_loc1         = 0x02,
    DW_CFA_advance_loc2         = 0x03,
    DW_CFA_advance_loc4         = 0x04,
    DW_CFA_offset_extended      = 0x05,
    DW_CFA_restore_extended     = 0x06,
    DW_CFA_undefined            = 0x07,
    DW_CFA_same_value           = 0x08,
    DW_CFA_register             = 0x09,
    DW_CFA_remember_state       = 0x0a,
    DW_CFA_restore_state        = 0x0b,
    DW_CFA_def_cfa              = 0x0c,
    DW_CFA_def_cfa_register     = 0x0d,
    DW_CFA_def_cfa_offset       = 0x0e,
    DW_CFA_def_cfa_expression   = 0x0f,
    DW_CFA_expression           = 0x10,
    DW_CFA_offset_extended_sf   = 0x11,
    DW_CFA_def_cfa_sf           = 0x12,
    DW_CFA_def_cfa_offset_sf    = 0x13,
    DW_CFA_val_offset           = 0x14,
    DW_CFA_val_offset_sf        = 0x15,
    DW_CFA_val_expression       = 0x16,
    DW_CFA_lo_user              = 0x1c,
    DW_CFA_hi_user              = 0x3c
} DW_CFA_high_t;

#if 0
# this mechanism describe a very large table that has the following structure:
    LOC CFA R0 R1 ... RN
    L0
    L1
    ...
    LN

where:
    LOC: Location in the code source
    CFA: The rule which allow to compute the Canonical Frame Address
#endif

/** Register rules list */

typedef enum {
    debug_frame_register_rule_unknown,

    /** A register that has this rule has no recoverable value in the previous frame.
     * (By convention, it is not preserved by a callee.) */
    debug_frame_register_rule_undefined,

    /** This register has not been modified from theprevious frame.
     *  (By convention, it is preserved by the callee, but the callee has not modified it.) */
    debug_frame_register_rule_same_value,

    /** The previous value of this register is saved at the address CFA+N
     *  where CFA is the current CFA value and N is a signed offset. */
    debug_frame_register_rule_offset,

    /** The previous value of this register is the value CFA+N
     *  where CFA is the current CFA value and N is a signed offset. */
    debug_frame_register_rule_val_offset,

    /** The previous value of this register is stored in another register numbered R. */
    debug_frame_register_rule_reg,

    /** The previous value of this register is located at the address produced
     *  by executing the DWARF expression E (see Section 2.5 on page 26). */
    debug_frame_register_rule_expression,

    /** The previous value of this register is the value produced
     * by executing the DWARF expression E (see Section 2.5 on page 26). */
    debug_frame_register_rule_val_expression,

    /** The rule is defined externally to this specification by the augmenter. */
    debug_frame_register_rule_architectural,
} debug_frame_register_rule_t;

typedef struct {
    debug_frame_register_rule_t rule;
    int32_t value;
} debug_frame_register_t;

typedef struct {
    /** location in the source code */
    uint64_t loc;

    uint32_t cfa_reg_number;
    uint32_t ra_reg_number;
    debug_frame_register_t cfa_reg;
    debug_frame_register_t registers[32];
} debug_frame_rules_t;


/** Common Information Entry (CIE) */
typedef struct {
    uint64_t length;
    uint64_t cie_id;
    uint8_t version;
    const char *augmentation;
    uint8_t address_size;
    uint8_t segment_size;
    uint64_t code_alignment_factor;
    int64_t data_alignment_factor;
    uint64_t return_address_register;
    uint64_t augmentation_size;
    uint8_t lsda_encoding;
    uint8_t fde_encoding;
    uint8_t handler_encoding;
    uint64_t handler;
    bool signal_frame;
    debug_frame_rules_t rules;
} debug_frame_cie_t;

/** Frame Description Entry (FDE) */
typedef struct {
    uint64_t length;

    // A 4 byte unsigned value that when subtracted from the offset of the current FDE yields the offset of the start of the associated CIE. This value shall never be 0.
    uint64_t cie_pointer;

    // An encoded constant that indicates the address of the initial location associated with this FDE.
    uint64_t pc_begin;

    // An encoded constant that indicates the number of bytes of instructions associated with this FDE.
    uint64_t pc_range;

    // An unsigned LEB128 encoded value indicating the length in bytes of the Augmentation Data. This field is only present if the Augmentation String in the associated CIE contains the character 'z'.
    uint64_t augmentation_size;

    uint64_t offset;

    debug_frame_rules_t rules;
} debug_frame_fde_t;

typedef struct {
    /** Version of .eh_frame_hdr  */
    uint8_t version;

    /** Encoding format of eh_frame_ptr */
    uint8_t eh_frame_ptr_enc;

    /** Encoding format of fde_count */
    uint8_t fde_count_enc;

    /** Encoding format of the binary search table */
    uint8_t table_enc;

    /** Pointer to the start of .eh_frame section */
    uint64_t eh_frame_ptr;

    /** Count of entries in the binary search table */
    uint64_t fde_count;

    uint64_t fde_size;
} debug_frame_hdr_t;

/** Call Frame Instructions (CFI)  */
typedef struct {
    debug_frame_cie_t cie;
    debug_frame_fde_t fde[];
} debug_frame_cfi_t;

typedef struct {
    elf_file_t *frame_file;
    debug_frame_cie_t cie;
    debug_frame_fde_t fde;
    uint64_t lookup_pc;
    bool found;
} debug_frame_ctx_t;

bool debug_frame(elf_t *elf, debug_frame_rules_t *result, uint64_t pc);
bool debug_frame_ex(elf_file_t *frame_hdr_file, elf_file_t *frame_file, debug_frame_rules_t *result, uint64_t pc);
void debug_frame_rules_print(debug_frame_rules_t *rules);

#endif
