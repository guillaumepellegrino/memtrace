/*
 * Copyright (C) 2022 Guillaume Pellegrino
 * This file is part of memtrace <https://github.com/guillaumepellegrino/memtrace>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
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

#include "elf_file.h"
#include "elf_sym.h"
#include "elf_relocate.h"
#include "log.h"
#include <string.h>
#include <elf.h>

typedef struct {
    const char *name;
    elf_relocate_t *result;
    bool found;
} find_by_name_ctx_t;

static uint32_t rela_get_reloc_type(elf_t *elf, uint64_t reloc_info) {
    const elf_header_t *hdr = elf_header(elf);
    if (hdr->ei_class == ei_class_64bit) {
        return ELF32_R_TYPE(reloc_info);
    }

    switch (hdr->e_machine) {
        case EM_MIPS:
            //not implemented
            //return ELF64_MIPS_R_TYPE (reloc_info);
            assert(false);
            return 0;
        case EM_SPARCV9:
            //not implemented
            //return ELF64_R_TYPE_ID (reloc_info);
            assert(false);
            return 0;
        default:
            return ELF64_R_TYPE(reloc_info);
    }
}

static uint64_t rela_get_reloc_symindex(elf_t *elf, uint64_t reloc_info) {
    const elf_header_t *hdr = elf_header(elf);

    return (hdr->ei_class == ei_class_64bit)
        ? ELF64_R_SYM (reloc_info) : ELF32_R_SYM (reloc_info);
}

static bool rela_read(elf_t *elf, elf_file_t *rela_file, elf_file_t *symtab, elf_file_t *strtab, elf_relocate_handler_t handler, void *userdata) {
    while (!elf_file_eof(rela_file)) {
        elf_relocate_t rela;
        rela.sh_type = sh_type_rela;
        rela.offset = elf_file_read_addr(rela_file);
        rela.info = elf_file_read_addr(rela_file);
        rela.addend = elf_file_read_addr(rela_file);
        rela.type = rela_get_reloc_type(elf, rela.info);
        rela.symidx = rela_get_reloc_symindex(elf, rela.info);
        rela.sym = elf_sym_from_idx(symtab, strtab, rela.symidx);
        if (!handler(&rela, userdata)) {
            break;
        }
    }

    return true;
}

static uint32_t rel_get_reloc_type(elf_t *elf, uint64_t reloc_info) {
    return ELF32_R_TYPE(reloc_info) & 0xFF;
}

static uint64_t rel_get_reloc_symindex(elf_t *elf, uint64_t reloc_info) {
    return ELF32_R_SYM(reloc_info);
}

static bool rel_read(elf_t *elf, elf_file_t *rela_file, elf_file_t *symtab, elf_file_t *strtab, elf_relocate_handler_t handler, void *userdata) {
    while (!elf_file_eof(rela_file)) {
        elf_relocate_t rela;
        rela.sh_type = sh_type_rel;
        rela.offset = elf_file_read_addr(rela_file);
        rela.info = elf_file_read_addr(rela_file);
        rela.type = rel_get_reloc_type(elf, rela.info);
        rela.addend = 0;
        rela.symidx = rel_get_reloc_symindex(elf, rela.info);
        rela.sym = elf_sym_from_idx(symtab, strtab, rela.symidx);
        if (!handler(&rela, userdata)) {
            break;
        }
    }

    return true;
}

/* https://refspecs.linuxbase.org/elf/gabi4+/ch4.reloc.html */
bool elf_relocate_read(elf_t *elf, elf_file_t *rela_file, elf_file_t *symtab, elf_file_t *strtab, elf_relocate_handler_t handler, void *userdata) {
    sh_type_t type = sh_type_rela;
    const section_header_t *hdr = NULL;

    hdr = elf_file_section(rela_file);
    elf_file_seek(rela_file, 0);

    if (hdr) {
        type = hdr->sh_type;
    }

    switch (type) {
        case sh_type_rela:
            return rela_read(elf, rela_file, symtab, strtab, handler, userdata);
        case sh_type_rel:
            return rel_read(elf, rela_file, symtab, strtab, handler, userdata);
        default:
            return false;
    }
}

static bool dump_handler(elf_relocate_t *rela, void *userdata) {
    TRACE_WARNING("offset: 0x%"PRIx64" info: 0x%"PRIx64" (type: 0x%x, symidx: 0x%x (%s)) addend: 0x%"PRIx64,
            rela->offset, rela->info, rela->type, rela->symidx, rela->sym.name, rela->addend);
    return true;
}

bool elf_relocate_dump(elf_t *elf, elf_file_t *rela_file, elf_file_t *symtab, elf_file_t *strtab) {
    return elf_relocate_read(elf, rela_file, symtab, strtab, dump_handler, NULL);
}

static bool find_by_name_handler(elf_relocate_t *rela, void *userdata) {
    find_by_name_ctx_t *ctx = userdata;

    if (rela->sym.name && !strcmp(rela->sym.name, ctx->name)) {
        ctx->found = true;
        *ctx->result = *rela;
        return false;
    }

    return true;
}

bool elf_relocate_find_by_name(elf_t *elf, elf_file_t *rela_file, elf_file_t *symtab, elf_file_t *strtab, const char *name, elf_relocate_t *result) {
    find_by_name_ctx_t ctx = {
        .name = name,
        .result = result,
    };

    elf_relocate_read(elf, rela_file, symtab, strtab, find_by_name_handler, &ctx);

    return ctx.found;
}
