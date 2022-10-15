#include "elf.h"
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

static uint32_t get_reloc_type(elf_t *elf, uint64_t reloc_info) {
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

static uint64_t get_reloc_symindex(elf_t *elf, uint64_t reloc_info) {
    const elf_header_t *hdr = elf_header(elf);

    return (hdr->ei_class == ei_class_64bit)
        ? ELF64_R_SYM (reloc_info) : ELF32_R_SYM (reloc_info);
}

// https://docs.oracle.com/cd/E23824_01/html/819-06
bool elf_relocate_read(elf_t *elf, elf_file_t *file, elf_file_t *symtab, elf_file_t *strtab, elf_relocate_handler_t handler, void *userdata) {
    elf_file_seek(file, 0);

    while (!elf_file_eof(file)) {
        elf_relocate_t rela;
        rela.offset = elf_file_read_addr(file);
        rela.info = elf_file_read_addr(file);
        rela.addend = elf_file_read_addr(file);
        rela.type = get_reloc_type(elf, rela.info);
        rela.symidx = get_reloc_symindex(elf, rela.info);
        rela.sym = elf_sym_from_idx(symtab, strtab, rela.symidx);
        if (!handler(&rela, userdata)) {
            break;
        }
    }

    return true;
}

static bool dump_handler(elf_relocate_t *rela, void *userdata) {
    CONSOLE("offset: 0x%"PRIx64" info: 0x%"PRIx64" (type: 0x%x, symidx: 0x%x (%s)) addend: 0x%"PRIx64,
            rela->offset, rela->info, rela->type, rela->symidx, rela->sym.name, rela->addend);
    return true;
}

bool elf_relocate_dump(elf_t *elf, elf_file_t *file, elf_file_t *symtab, elf_file_t *strtab) {
    return elf_relocate_read(elf, file, symtab, strtab, dump_handler, NULL);
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

bool elf_relocate_find_by_name(elf_t *elf, elf_file_t *file, elf_file_t *symtab, elf_file_t *strtab, const char *name, elf_relocate_t *result) {
    find_by_name_ctx_t ctx = {
        .name = name,
        .result = result,
    };

    elf_relocate_read(elf, file, symtab, strtab, find_by_name_handler, &ctx);

    return ctx.found;
}
