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
#define TRACE_ZONE TRACE_ZONE_DEBUG_INFO
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug_info.h"
#include "elf_main.h"
#include "elf_file.h"
#include "log.h"

typedef struct _debug_die_entry debug_die_entry_t;
typedef struct _debug_die debug_die_t;
typedef struct _debug_abbrev_map debug_abbrev_map_t;
typedef struct _debug_info_cu debug_info_cu_t;
typedef bool (*debug_die_handler_t)(debug_info_cu_t *cu, debug_die_t *die);

typedef enum {
    DW_TAG_array_type = 0x01,
    DW_TAG_class_type = 0x02,
    DW_TAG_entry_point = 0x03,
    DW_TAG_enumeration_type = 0x04,
    DW_TAG_formal_parameter = 0x05,
    DW_TAG_imported_declaration = 0x08,
    DW_TAG_label = 0x0a,
    DW_TAG_lexical_block = 0x0b,
    DW_TAG_member = 0x0d,
    DW_TAG_pointer_type = 0x0f,
    DW_TAG_reference_type = 0x10,
    DW_TAG_compile_unit = 0x11,
    DW_TAG_string_type = 0x12,
    DW_TAG_structure_type = 0x13,
    DW_TAG_subroutine_type = 0x15,
    DW_TAG_typedef = 0x16,
    DW_TAG_union_type = 0x17,
    DW_TAG_unspecified_parameters = 0x18,
    DW_TAG_variant = 0x19,
    DW_TAG_common_block = 0x1a,
    DW_TAG_common_inclusion = 0x1b,
    DW_TAG_inheritance = 0x1c,
    DW_TAG_inlined_subroutine = 0x1d,
    DW_TAG_module = 0x1e,
    DW_TAG_ptr_to_member_type = 0x1f,
    DW_TAG_set_type = 0x20,
    DW_TAG_subrange_type = 0x21,
    DW_TAG_with_stmt = 0x22,
    DW_TAG_access_declaration = 0x23,
    DW_TAG_base_type = 0x24,
    DW_TAG_catch_block = 0x25,
    DW_TAG_const_type = 0x26,
    DW_TAG_constant = 0x27,
    DW_TAG_enumerator = 0x28,
    DW_TAG_file_type = 0x29,
    DW_TAG_friend = 0x2a,
    DW_TAG_namelist = 0x2b,
    DW_TAG_namelist_item = 0x2c,
    DW_TAG_packed_type = 0x2d,
    DW_TAG_subprogram = 0x2e,
    DW_TAG_template_type_param = 0x2f,
    DW_TAG_template_value_param = 0x30,
    DW_TAG_thrown_type = 0x31,
    DW_TAG_try_block = 0x32,
    DW_TAG_variant_part = 0x33,
    DW_TAG_variable = 0x34,
    DW_TAG_volatile_type = 0x35,
    DW_TAG_dwarf_procedure = 0x36,
    DW_TAG_restrict_type = 0x37,
    DW_TAG_interface_type = 0x38,
    DW_TAG_namespace = 0x39,
    DW_TAG_imported_module = 0x3a,
    DW_TAG_unspecified_type = 0x3b,
    DW_TAG_partial_unit = 0x3c,
    DW_TAG_imported_unit = 0x3d,
    DW_TAG_condition = 0x3f,
    DW_TAG_shared_type = 0x40,
    DW_TAG_type_unit = 0x41,
    DW_TAG_rvalue_reference_type = 0x42,
    DW_TAG_template_alias = 0x43,
    DW_TAG_coarray_type = 0x44,
    DW_TAG_generic_subrange = 0x45,
    DW_TAG_dynamic_type = 0x46,
    DW_TAG_atomic_type = 0x47,
    DW_TAG_call_site = 0x48,
    DW_TAG_call_site_parameter = 0x49,
    DW_TAG_skeleton_unit = 0x4a,
    DW_TAG_immutable_type = 0x4b,
    DW_TAG_lo_user = 0x4080,
    DW_TAG_hi_user = 0xffff,
} DW_TAG_t;

typedef enum {
    DW_AT_sibling = 0x01,
    DW_AT_location = 0x02,
    DW_AT_name = 0x03,
    DW_AT_ordering = 0x09,
    DW_AT_subscr_data = 0x0a,
    DW_AT_byte_size = 0x0b,
    DW_AT_bit_offset = 0x0c,
    DW_AT_bit_size = 0x0d,
    DW_AT_element_list = 0x0f,
    DW_AT_stmt_list = 0x10,
    DW_AT_low_pc = 0x11,
    DW_AT_high_pc = 0x12,
    DW_AT_language = 0x13,
    DW_AT_member = 0x14,
    DW_AT_discr = 0x15,
    DW_AT_discr_value = 0x16,
    DW_AT_visibility = 0x17,
    DW_AT_import = 0x18,
    DW_AT_string_length = 0x19,
    DW_AT_common_reference = 0x1a,
    DW_AT_comp_dir = 0x1b,
    DW_AT_const_value = 0x1c,
    DW_AT_containing_type = 0x1d,
    DW_AT_default_value = 0x1e,
    DW_AT_inline = 0x20,
    DW_AT_lower_bound = 0x22,
    DW_AT_producer = 0x25,
    DW_AT_prototyped = 0x27,
    DW_AT_return_addr = 0x2a,
    DW_AT_start_scope = 0x2c,
    DW_AT_bit_stride = 0x2e,
    DW_AT_upper_bound = 0x2f,
    DW_AT_abstract_origin = 0x31,
    DW_AT_accessibility = 0x32,
    DW_AT_address_class = 0x33,
    DW_AT_artificial = 0x34,
    DW_AT_base_types = 0x35,
    DW_AT_calling_convention = 0x36,
    DW_AT_count = 0x37,
    DW_AT_data_member_location = 0x38,
    DW_AT_decl_column = 0x39,
    DW_AT_decl_file = 0x3a,
    DW_AT_decl_line = 0x3b,
    DW_AT_declaration = 0x3c,
    DW_AT_discr_list = 0x3d,
    DW_AT_encoding = 0x3e,
    DW_AT_external = 0x3f,
    DW_AT_frame_base = 0x40,
    DW_AT_friend = 0x41,
    DW_AT_identifier_case = 0x42,
    DW_AT_macro_info = 0x43,
    DW_AT_namelist_items = 0x44,
    DW_AT_priority = 0x45,
    DW_AT_segment = 0x46,
    DW_AT_specification = 0x47,
    DW_AT_static_link = 0x48,
    DW_AT_type = 0x49,
    DW_AT_use_location = 0x4a,
    DW_AT_variable_parameter = 0x4b,
    DW_AT_virtuality = 0x4c,
    DW_AT_vtable_elem_location = 0x4d,
    DW_AT_allocated = 0x4e,
    DW_AT_associated = 0x4f,
    DW_AT_data_location = 0x50,
    DW_AT_byte_stride = 0x51,
    DW_AT_entry_pc = 0x52,
    DW_AT_use_UTF8 = 0x53,
    DW_AT_extension = 0x54,
    DW_AT_ranges = 0x55,
    DW_AT_trampoline = 0x56,
    DW_AT_call_column = 0x57,
    DW_AT_call_file = 0x58,
    DW_AT_call_line = 0x59,
    DW_AT_description = 0x5a,
    DW_AT_binary_scale = 0x5b,
    DW_AT_decimal_scale = 0x5c,
    DW_AT_small = 0x5d,
    DW_AT_decimal_sign = 0x5e,
    DW_AT_digit_count = 0x5f,
    DW_AT_picture_string = 0x60,
    DW_AT_mutable = 0x61,
    DW_AT_threads_scaled = 0x62,
    DW_AT_explicit = 0x63,
    DW_AT_object_pointer = 0x64,
    DW_AT_endianity = 0x65,
    DW_AT_elemental = 0x66,
    DW_AT_pure = 0x67,
    DW_AT_recursive = 0x68,
    DW_AT_signature = 0x69,
    DW_AT_main_subprogram = 0x6a,
    DW_AT_data_bit_offset = 0x6b,
    DW_AT_const_expr = 0x6c,
    DW_AT_enum_class = 0x6d,
    DW_AT_linkage_name = 0x6e,
    DW_AT_string_length_bit_size = 0x6f,
    DW_AT_string_length_byte_size = 0x70,
    DW_AT_rank = 0x71,
    DW_AT_str_offsets_base = 0x72,
    DW_AT_addr_base = 0x73,
    DW_AT_rnglists_base = 0x74,
    DW_AT_dwo_name = 0x76,
    DW_AT_reference = 0x77,
    DW_AT_rvalue_reference = 0x78,
    DW_AT_macros = 0x79,
    DW_AT_call_all_calls = 0x7a,
    DW_AT_call_all_source_calls = 0x7b,
    DW_AT_call_all_tail_calls = 0x7c,
    DW_AT_call_return_pc = 0x7d,
    DW_AT_call_value = 0x7e,
    DW_AT_call_origin = 0x7f,
    DW_AT_call_parameter = 0x80,
    DW_AT_call_pc = 0x81,
    DW_AT_call_tail_call = 0x82,
    DW_AT_call_target = 0x83,
    DW_AT_call_target_clobbered = 0x84,
    DW_AT_call_data_location = 0x85,
    DW_AT_call_data_value = 0x86,
    DW_AT_noreturn = 0x87,
    DW_AT_alignment = 0x88,
    DW_AT_export_symbols = 0x89,
    DW_AT_deleted = 0x8a,
    DW_AT_defaulted = 0x8b,
    DW_AT_loclists_base = 0x8c,
    DW_AT_lo_user = 0x2000,
    DW_AT_hi_user = 0x3fff,
} DW_AT_t;

typedef enum {
    DW_FORM_addr = 0x01,
    DW_FORM_block2 = 0x03,
    DW_FORM_block4 = 0x04,
    DW_FORM_data2 = 0x05,
    DW_FORM_data4 = 0x06,
    DW_FORM_data8 = 0x07,
    DW_FORM_string = 0x08,
    DW_FORM_block = 0x09,
    DW_FORM_block1 = 0x0a,
    DW_FORM_data1 = 0x0b,
    DW_FORM_flag = 0x0c,
    DW_FORM_sdata = 0x0d,
    DW_FORM_strp = 0x0e,
    DW_FORM_udata = 0x0f,
    DW_FORM_ref_addr = 0x10,
    DW_FORM_ref1 = 0x11,
    DW_FORM_ref2 = 0x12,
    DW_FORM_ref4 = 0x13,
    DW_FORM_ref8 = 0x14,
    DW_FORM_ref_udata = 0x15,
    DW_FORM_indirect = 0x16,
    DW_FORM_sec_offset = 0x17,
    DW_FORM_exprloc = 0x18,
    DW_FORM_flag_present = 0x19,
    DW_FORM_ref_sig8 = 0x20,
} DW_FORM_t;

struct _debug_die_entry {
    uint8_t name;
    uint8_t form;
    variant_value_t value;
};

struct _debug_die {
    uint8_t tag;
    bool has_children;
    uint8_t size;
    debug_die_entry_t entries[64];
};

struct _debug_abbrev_map {
    uint64_t offsets[1024];
};

struct _debug_info_cu {
    elf_file_t *abbrev_file;
    elf_file_t *info_file;
    elf_file_t *str_file;
    debug_die_handler_t handler;
    void *userdata;

    uint64_t unit_length;
    uint16_t version;
    uint64_t debug_abbrev_offset;
    uint8_t address_size;
};


static bool debug_abbrev_map_parse(elf_file_t *file, uint64_t debug_abbrev_offset, debug_abbrev_map_t *abbrev_map) {
    elf_file_seek(file, debug_abbrev_offset);

    while (true) {
        uint16_t number = 0;
        if ((number = elf_file_read_uleb128(file)) == 0) {
            break;
        }
        if (number > countof(abbrev_map->offsets)) {
            TRACE_ERROR("abbrev number exceed max size");
            return false;
        }

        abbrev_map->offsets[number] = elf_file_tell(file);

        uint8_t tag = elf_file_read_uleb128(file);
        uint8_t has_children = elf_file_read_u8(file);
        (void) tag;
        (void) has_children;

        while (true) {
            uint8_t name = elf_file_read_uleb128(file);
            DW_FORM_t form = elf_file_read_uleb128(file);
            (void) form;
            if (name == 0) {
                break;
            }
        }
    }

    return true;
}

static bool debug_abbrev_parse(elf_file_t *file, uint64_t offset, debug_die_t *die) {
    elf_file_seek(file, offset);

    die->tag = elf_file_read_uleb128(file);
    die->has_children = elf_file_read_u8(file);

    size_t i;
    for (i = 0; i < countof(die->entries); i++) {
        debug_die_entry_t *entry = &die->entries[i];

        entry->name = elf_file_read_uleb128(file);
        entry->form = elf_file_read_uleb128(file);
        if (entry->name == 0) {
            break;
        }
    }

    die->size = i;

    return true;
}

static bool debug_info_parse_cu(debug_info_cu_t *cu) {
    static char str[512];
    debug_abbrev_map_t abbrev_map = {0};

    uint64_t _cu_start_offset = elf_file_tell(cu->info_file);
    if ((cu->unit_length = elf_file_read_u32(cu->info_file)) > 0xffffff00) {
        cu->unit_length = elf_file_read_u64(cu->info_file);
        elf_file_setdwarf64(cu->info_file, true);
    }
    uint64_t cu_start_offset = elf_file_tell(cu->info_file);
    cu->version = elf_file_read_u16(cu->info_file);
    cu->debug_abbrev_offset = elf_file_read_dwarfaddr(cu->info_file);
    cu->address_size = elf_file_read_u8(cu->info_file);

    TRACE_LOG("<%"PRIx64"> Start of CU", _cu_start_offset);
    TRACE_LOG("unit_length:     0x%"PRIx64, cu->unit_length);
    TRACE_LOG("version:         %u", cu->version);
    TRACE_LOG("abbrev_offset:   0x%"PRIx64, cu->debug_abbrev_offset);
    TRACE_LOG("address_size:    %u", cu->address_size);

    if (!debug_abbrev_map_parse(cu->abbrev_file, cu->debug_abbrev_offset, &abbrev_map)) {
        TRACE_ERROR("Failed to parse .debug_abbrev at offset 0x%"PRIx64, cu->debug_abbrev_offset);
        return false;
    }

    size_t i;
    for (i = 0; true; i++) {
        debug_die_t die = {0};
        uint64_t offset = elf_file_tell(cu->info_file);
        uint64_t cu_length = offset - cu_start_offset;

        if (cu_length >= cu->unit_length) {
            TRACE_LOG("<%"PRIx64"> End of CU (length: 0x%"PRIx64") [0x%"PRIx64", 0x%"PRIx64"]", offset, cu->unit_length, cu_start_offset, offset);
            break;
        }

        DW_TAG_t abbrev_number = elf_file_read_uleb128(cu->info_file);
        if (abbrev_number == 0) {
            TRACE_DWARF("<%"PRIx64"> DIE %zu", offset, i);
            TRACE_DWARF("    Abbreviation Number: %u", abbrev_number);
            continue;
        }
        if (abbrev_number >= countof(abbrev_map.offsets)) {
            TRACE_ERROR("abbrev number (%u) exceed max size", abbrev_number);
            return false;
        }

        uint64_t abbrev_offset = abbrev_map.offsets[abbrev_number];

        TRACE_DWARF("<%"PRIx64"> DIE %zu", offset, i);
        TRACE_DWARF("    Abbreviation Number: %u (offset: 0x%"PRIx64")", abbrev_number, abbrev_offset);
        if (!debug_abbrev_parse(cu->abbrev_file, abbrev_offset, &die)) {
            TRACE_ERROR("Failed to parse .debug_abbrev at offset 0x%"PRIx64, abbrev_offset);
            return false;
        }

        size_t j;
        for (j = 0; j < die.size; j++) {
            debug_die_entry_t *entry = &die.entries[j];

            switch (entry->form) {
                case DW_FORM_addr: {
                    uint64_t addr = elf_file_read_addr(cu->info_file);
                    entry->value.u64 = addr;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_addr: 0x%"PRIu64, entry->name, addr);
                    break;
                }
                case DW_FORM_block2: {
                    uint16_t length = elf_file_read_u16(cu->info_file);
                    uint16_t k = 0;
                    entry->value.u16 = length;
                    for (k = 0; k < length; k++) {
                        elf_file_read_u8(cu->info_file);
                    }

                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_block2: %u", entry->name, length);
                    break;
                }
                case DW_FORM_block4: {
                    uint32_t length = elf_file_read_u32(cu->info_file);
                    uint32_t k = 0;
                    entry->value.u32 = length;
                    for (k = 0; k < length; k++) {
                        elf_file_read_u8(cu->info_file);
                    }
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_block4: 0x%x", entry->name, length);
                    break;
                }
                case DW_FORM_data2: {
                    uint16_t data2 = elf_file_read_u16(cu->info_file);
                    entry->value.u16 = data2;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_data2: 0x%x", entry->name, data2);
                    break;
                }
                case DW_FORM_data4: {
                    uint32_t data4 = elf_file_read_u32(cu->info_file);
                    entry->value.u32 = data4;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_data4: 0x%x", entry->name, data4);
                    break;
                }
                case DW_FORM_data8: {
                    uint64_t data8 = elf_file_read_u64(cu->info_file);
                    entry->value.u64 = data8;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_data8: 0x%"PRIu64, entry->name, data8);
                    break;
                }
                case DW_FORM_string: {
                    elf_file_read_string(cu->info_file, str, sizeof(str));
                    entry->value.str = str;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_string: %s", entry->name, str);
                    break;
                }
                case DW_FORM_block: {
                    uint64_t length = elf_file_read_uleb128(cu->info_file);
                    uint64_t k = 0;
                    entry->value.u64 = length;
                    for (k = 0; k < length; k++) {
                        elf_file_read_u8(cu->info_file);
                    }
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_block: %"PRIu64, entry->name, length);
                    break;
                }
                case DW_FORM_block1: {
                    uint8_t length = elf_file_read_u8(cu->info_file);
                    uint8_t k = 0;
                    entry->value.u8 = length;
                    for (k = 0; k < length; k++) {
                        elf_file_read_u8(cu->info_file);
                    }
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_block1: %u", entry->name, length);
                    break;
                }
                case DW_FORM_data1: {
                    uint8_t data1 = elf_file_read_u8(cu->info_file);
                    entry->value.u8 = data1;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_data1: %u", entry->name, data1);
                    break;
                }
                case DW_FORM_flag: {
                    uint8_t flag = elf_file_read_u8(cu->info_file);
                    entry->value.u8 = flag;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_flag: 0x%x", entry->name, flag);
                    break;
                }
                case DW_FORM_sdata: {
                    int64_t data = elf_file_read_sleb128(cu->info_file);
                    entry->value.i64 = data;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_sdata: 0x%"PRIx64, entry->name, data);
                    break;
                }
                case DW_FORM_strp: {
                    uint64_t strp = elf_file_read_dwarfaddr(cu->info_file);
                    elf_file_seek(cu->str_file, strp);
                    elf_file_read_string(cu->str_file, str, sizeof(str));
                    entry->value.str = str;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_strp: (0x%"PRIx64") '%s'", entry->name, strp, str);
                    break;
                }
                case DW_FORM_udata: {
                    uint64_t data = elf_file_read_uleb128(cu->info_file);
                    entry->value.u64 = data;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_udata: 0x%"PRIx64, entry->name, data);
                    break;
                }
                case DW_FORM_ref_addr: {
                    uint64_t ref = elf_file_read_dwarfaddr(cu->info_file);
                    entry->value.u64 = ref;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_ref_addr: 0x%"PRIx64, entry->name, ref);
                    break;
                }
                case DW_FORM_ref1: {
                    uint8_t ref1 = elf_file_read_u8(cu->info_file);
                    entry->value.u8 = ref1;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_ref1: 0x%x", entry->name, ref1);
                    break;
                }
                case DW_FORM_ref2: {
                    uint16_t ref2 = elf_file_read_u16(cu->info_file);
                    entry->value.u16 = ref2;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_ref2: 0x%x", entry->name, ref2);
                    break;
                }
                case DW_FORM_ref4: {
                    uint32_t ref4 = elf_file_read_u32(cu->info_file);
                    entry->value.u32 = ref4;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_ref4: 0x%x", entry->name, ref4);
                    break;
                }
                case DW_FORM_ref8: {
                    uint64_t ref8 = elf_file_read_u64(cu->info_file);
                    entry->value.u64 = ref8;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_ref8: 0x%"PRIx64, entry->name, ref8);
                    break;
                }
                case DW_FORM_ref_udata: {
                    uint64_t data = elf_file_read_uleb128(cu->info_file);
                    entry->value.u64 = data;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_ref_udata: 0x%"PRIx64, entry->name, data);
                    break;
                }
                case DW_FORM_indirect: {
                    uint64_t data = elf_file_read_uleb128(cu->info_file);
                    entry->value.u64 = data;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_indirect: 0x%"PRIx64, entry->name, data);
                    break;
                }
                case DW_FORM_sec_offset: {
                    uint64_t offset = elf_file_read_dwarfaddr(cu->info_file);
                    entry->value.u64 = offset;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_sec_offset: 0x%"PRIx64, entry->name, offset);
                    break;
                }
                case DW_FORM_exprloc: {
                    uint32_t length = elf_file_read_uleb128(cu->info_file);
                    size_t k;
                    for (k = 0; k < length; k++) {
                        elf_file_read_u8(cu->info_file);
                    }
                    entry->value.u32 = length;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_form_exprloc: [%u]", entry->name, length);
                    break;
                }
                case DW_FORM_flag_present: {
                    entry->value.u8 = 1;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_flag_present: 0x%x", entry->name, 1);
                    break;
                }
                case DW_FORM_ref_sig8: {
                    uint8_t sig8 = elf_file_read_u8(cu->info_file);
                    entry->value.u8 = sig8;
                    TRACE_DWARF("    DW_AT_0x%02x    DW_FORM_ref_sig8: 0x%x", entry->name, sig8);
                    break;
                }
                default: {
                    TRACE_ERROR("Unknown form 0x%x", entry->form);
                    return false;
                }
            }
        }

        if (cu->handler(cu, &die)) {
            return true;
        }
    }

    return true;
}

static bool debug_die_find_function(debug_info_cu_t *cu, debug_die_t *die) {
    debug_info_t *info = cu->userdata;
    const char *function = NULL;
    uint64_t low_pc = 0;
    uint64_t high_pc = 0;
    uint64_t min_addr = 0;
    uint64_t max_addr = 0;
    size_t i = 0;

    if (die->tag != DW_TAG_subprogram) {
        return false;
    }

    for (i = 0; i < die->size; i++) {
        debug_die_entry_t *entry = &die->entries[i];
        switch (entry->name) {
            case DW_AT_name:
                function = entry->value.str;
                break;
            case DW_AT_low_pc:
                low_pc = entry->value.u64;
                break;
            case DW_AT_high_pc:
                high_pc = entry->value.u64;
                break;
            default:
                break;
        }
    }

    min_addr = low_pc;
    max_addr = low_pc + high_pc;

    if (info->address >= min_addr && info->address <= max_addr) {
        TRACE_LOG("%s() in [0x%"PRIx64", 0x%"PRIx64"]", function, min_addr, max_addr);
        info->offset = info->address - min_addr;
        info->function = strdup(function ? function : "??");
        info->resolved = true;
        return true;
    }

    return false;
}

debug_info_t *debug_info_function_ex(elf_t *elf, elf_file_t *abbrev_file, elf_file_t *info_file, elf_file_t *str_file, uint64_t address) {
    debug_info_t *info = NULL;

    if (!elf || !abbrev_file || !info_file || !str_file || !address) {
        return NULL;
    }

    elf_file_seek(abbrev_file, 0);
    elf_file_seek(info_file, 0);
    elf_file_seek(str_file, 0);

    if (!(info = calloc(1, sizeof(debug_info_cu_t)))) {
        TRACE_ERROR("calloc failed: %m");
        return NULL;
    }
    info->address = address;

    do {
        debug_info_cu_t cu = {
            .abbrev_file = abbrev_file,
            .info_file = info_file,
            .str_file = str_file,
            .handler = debug_die_find_function,
            .userdata = info,
        };
        if (!debug_info_parse_cu(&cu)) {
            TRACE_ERROR("Failed to parse Compile Unit from %s", elf_name(elf));
            goto error;
        }
        if (info->resolved) {
            return info;
        }
    } while (elf_file_eof(info_file) != 1);

error:
    free(info);
    return NULL;
}

debug_info_t *debug_info_function(elf_t *elf, uint64_t address) {
    debug_info_t *info = NULL;
    const section_header_t *abbrev_section = NULL;
    const section_header_t *info_section = NULL;
    const section_header_t *str_section = NULL;
    elf_file_t *abbrev_file = NULL;
    elf_file_t *info_file = NULL;
    elf_file_t *str_file = NULL;

    if (!elf || !address) {
        TRACE_ERROR("NULL arguments");
        goto exit;
    }

    if (!(abbrev_section = elf_section_header_get(elf, ".debug_abbrev"))) {
        TRACE_ERROR("Failed to get .debug_abbrev section for %s", elf_name(elf));
        goto exit;
    }

    if (!(abbrev_file = elf_section_open(elf, abbrev_section))) {
        TRACE_ERROR("Failed to get .debug_abbrev section file for %s", elf_name(elf));
        goto exit;
    }

    if (!(info_section = elf_section_header_get(elf, ".debug_info"))) {
        TRACE_ERROR("Failed to get .debug_info section for %s", elf_name(elf));
        goto exit;
    }

    if (!(info_file = elf_section_open(elf, info_section))) {
        TRACE_ERROR("Failed to get .debug_info section file pointer for %s", elf_name(elf));
        goto exit;
    }

    if (!(str_section = elf_section_header_get(elf, ".debug_str"))) {
        TRACE_ERROR("Failed to get .debug_str section for %s", elf_name(elf));
        goto exit;
    }

    if (!(str_file = elf_section_open(elf, str_section))) {
        TRACE_ERROR("Failed to get .debug_str section file for %s", elf_name(elf));
        goto exit;
    }

    info = debug_info_function_ex(elf, abbrev_file, info_file, str_file, address);

exit:
    if (abbrev_file) {
        elf_file_close(abbrev_file);
    }
    if (info_file) {
        elf_file_close(info_file);
    }
    if (str_file) {
        elf_file_close(str_file);
    }

    return info;
}

void debug_info_free(debug_info_t *info) {
    free(info->function);
    free(info);
}
