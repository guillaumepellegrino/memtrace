/*
 * Copyright (C) 2022 Guillaume Pellegrino
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

#include "elf_sym.h"
#include "elf_main.h"
#include "elf_file.h"
#include "log.h"
#include <string.h>

#define STB_LOCAL  0
#define STB_GLOBAL 1
#define STB_WEAK   2

#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3
#define STT_FILE    4
#define STT_COMMON  5
#define STT_TLS     6

typedef struct {
    uint32_t st_name;  /* index into .strtab */
    uint8_t  st_info;  /* Type and binding */
    uint8_t  st_other; /* Visibility */
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} elf_sym_entry_t;

void elf_sym_entry_read(elf_file_t *symtab, elf_sym_entry_t *sym) {
    if (!elf_file_64bit(symtab)) {
        // ELF32
        sym->st_name  = elf_file_read_u32(symtab);
        sym->st_value = elf_file_read_u32(symtab);
        sym->st_size  = elf_file_read_u32(symtab);
        sym->st_info  = elf_file_read_u8(symtab);
        sym->st_other = elf_file_read_u8(symtab);
        sym->st_shndx = elf_file_read_u16(symtab);
    }
    else {
        // ELF64
        sym->st_name  = elf_file_read_u32(symtab);
        sym->st_info  = elf_file_read_u8(symtab);
        sym->st_other = elf_file_read_u8(symtab);
        sym->st_shndx = elf_file_read_u16(symtab);
        sym->st_value = elf_file_read_u64(symtab);
        sym->st_size  = elf_file_read_u64(symtab);
    }
}

elf_sym_t elf_sym(elf_file_t *symtab, elf_file_t *strtab, uint64_t address) {
    elf_sym_entry_t sym;
    elf_sym_t result = {0};

    elf_file_seek(symtab, 0);

    do {
        elf_sym_entry_read(symtab, &sym);

        if ((sym.st_info & 0x0f) == STT_FUNC && address >= sym.st_value && address < sym.st_value + sym.st_size) {
            elf_file_seek(strtab, sym.st_name);
            result.name = elf_file_read_strp(strtab);
            result.offset = address - sym.st_value;
            result.section_index = sym.st_shndx;
            return result;
        }
    } while (!elf_file_eof(symtab));

    return result;
}

elf_sym_t elf_sym_from_idx(elf_file_t *symtab, elf_file_t *strtab, uint32_t idx) {
    elf_sym_entry_t sym;
    elf_sym_t result = {0};

    size_t entry_size = elf_file_64bit(symtab) ? 24 : 16;
    elf_file_seek(symtab, entry_size * idx);
    elf_sym_entry_read(symtab, &sym);
    elf_file_seek(strtab, sym.st_name);
    result.name = elf_file_read_strp(strtab);
    result.offset = sym.st_value;
    result.section_index = sym.st_shndx;
    return result;
}

elf_sym_t elf_sym_from_name(elf_file_t *symtab, elf_file_t *strtab, const char *name) {
    elf_sym_entry_t sym;
    elf_sym_t result = {0};

    elf_file_seek(symtab, 0);

    do {
        const char *symname = NULL;

        elf_sym_entry_read(symtab, &sym);
        elf_file_seek(strtab, sym.st_name);

        switch (sym.st_info & 0x0f) {
            case STT_FUNC:
            case STT_OBJECT:
                symname = elf_file_read_strp(strtab);
                break;
            default:
                break;
        }

        if (symname && !strcmp(symname, name)) {
            result.name = symname;
            result.offset = sym.st_value;
            result.section_index = sym.st_shndx;
            return result;
        }
    } while (!elf_file_eof(symtab));

    return result;
}

elf_sym_t elf_sym_from_addr(elf_file_t *symtab, elf_file_t *strtab, size_t addr) {
    elf_sym_entry_t sym;
    elf_sym_t result = {0};

    elf_file_seek(symtab, 0);

    do {
        elf_sym_entry_read(symtab, &sym);
        elf_file_seek(strtab, sym.st_name);

        switch (sym.st_info & 0x0f) {
            case STT_FUNC:
            case STT_OBJECT:
                if (addr >= sym.st_value && addr < (sym.st_value + sym.st_size)) {
                    result.name = elf_file_read_strp(strtab);
                    result.offset = sym.st_value;
                    result.section_index = sym.st_shndx;
                    return result;
                }
                break;
            default:
                break;
        }
    } while (!elf_file_eof(symtab));

    return result;
}

