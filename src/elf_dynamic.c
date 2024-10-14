#include "elf.h"
#include "elf_main.h"
#include "elf_file.h"
#include "elf_sym.h"
#include "elf_dynamic.h"
#include "log.h"

typedef struct {
    size_t tag;
    size_t val;
} elf_dynamic_entry_t;

bool elf_dynamic_get_entry(elf_file_t *dynamic, size_t tag, size_t *val) {
    elf_file_seek(dynamic, 0);
    while (true) {
        elf_dynamic_entry_t entry = {0};
        entry.tag = elf_file_read_addr(dynamic);
        entry.val = elf_file_read_addr(dynamic);

        if (entry.tag == 0) {
            TRACE_LOG("Tag %zu not found in ELF Dynamic section", tag);
            return false;
        }
        if (entry.tag == tag) {
            *val = entry.val;
            TRACE_LOG("Tag %zu=%zu in ELF Dynamic section", tag, entry.val);
            return true;
        }
    }
}

elf_file_t *elf_dynamic_open_symtab(elf_t *elf, elf_file_t *dynamic) {
    size_t hash_offset = 0;
    size_t symtab_offset = 0;
    size_t sym_entry_size = 0;

    if (!elf_dynamic_get_entry(dynamic, DT_HASH, &hash_offset)) {
        return NULL;
    }
    if (!elf_dynamic_get_entry(dynamic, DT_SYMTAB, &symtab_offset)) {
        return NULL;
    }
    if (!elf_dynamic_get_entry(dynamic, DT_SYMENT, &sym_entry_size)) {
        return NULL;
    }

    elf_file_t *hash = elf_file_open(elf, sym_entry_size/8, hash_offset);
    if (!hash) {
        TRACE_LOG("Could not open DT_HASH from ELF Dynamic section");
        return NULL;
    }
    elf_file_read_addr(dynamic);
    size_t nchain = elf_file_read_addr(dynamic);
    elf_file_close(hash);

    elf_file_t *symtab = elf_file_open(elf, nchain, symtab_offset);
    if (!symtab) {
        TRACE_WARNING("Could not open symbol table using ELF Dynamic section");
        TRACE_WARNING("hash_offset:%zu, symtab_offset:%zu, sym_entry_size:%zu, nchain: %zu", hash_offset, symtab_offset, sym_entry_size, nchain);
        return NULL;
    }

    return symtab;
}

elf_file_t *elf_dynamic_open_rela(elf_t *elf, elf_file_t *dynamic) {
    size_t rela = 0;
    size_t relasz = 0;
    size_t relaent = 0;

    if (!elf_dynamic_get_entry(dynamic, DT_RELA, &rela)) {
        return NULL;
    }
    if (!elf_dynamic_get_entry(dynamic, DT_RELASZ, &relasz)) {
        return NULL;
    }
    if (!elf_dynamic_get_entry(dynamic, DT_RELAENT, &relaent)) {
        return NULL;
    }

    return elf_file_open(elf, relasz*relaent/8, rela);
}

elf_file_t *elf_dynamic_open_rel(elf_t *elf, elf_file_t *dynamic) {
    size_t rel = 0;
    size_t relsz = 0;
    size_t relent = 0;

    if (!elf_dynamic_get_entry(dynamic, DT_REL, &rel)) {
        return NULL;
    }
    if (!elf_dynamic_get_entry(dynamic, DT_RELSZ, &relsz)) {
        return NULL;
    }
    if (!elf_dynamic_get_entry(dynamic, DT_RELENT, &relent)) {
        return NULL;
    }

    return elf_file_open(elf, relsz*relent/8, rel);
}

elf_file_t *elf_dynamic_open_strtab(elf_t *elf, elf_file_t *dynamic) {
    size_t strtab_offset = 0;
    size_t strsz_offset = 0;

    if (!elf_dynamic_get_entry(dynamic, DT_STRTAB, &strtab_offset)) {
        return NULL;
    }
    if (!elf_dynamic_get_entry(dynamic, DT_STRSZ, &strsz_offset)) {
        return NULL;
    }

    return elf_file_open(elf, strsz_offset, strtab_offset);
}

