#include "elf.h"
#include "elf_main.h"
#include "elf_file.h"
#include "elf_sym.h"
#include "elf_dynamic.h"

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
            return false;
        }
        if (entry.tag == tag) {
            *val = entry.val;
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
        return NULL;
    }
    elf_file_read_addr(dynamic);
    size_t nchain = elf_file_read_addr(dynamic);
    elf_file_close(hash);

    return elf_file_open(elf, nchain, symtab_offset);
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

