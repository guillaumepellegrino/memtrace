#include "elf.h"
#include "elf_main.h"
#include "elf_file.h"
#include "elf_sym.h"
#include "elf_dynamic.h"
#include "log.h"

typedef struct {
    uint64_t tag;
    uint64_t val;
} elf_dynamic_entry_t;

bool elf_dynamic_get_entry(elf_file_t *dynamic, uint64_t tag, uint64_t *val) {
    elf_file_seek(dynamic, 0);
    while (true) {
        elf_dynamic_entry_t entry = {0};
        entry.tag = elf_file_read_addr(dynamic);
        entry.val = elf_file_read_addr(dynamic);

        if (entry.tag == 0) {
            TRACE_LOG("Tag %"PRIu64" not found in ELF Dynamic section", tag);
            return false;
        }
        if (entry.tag == tag) {
            *val = entry.val;
            TRACE_LOG("Tag 0x%"PRIx64"=0x%"PRIx64" in ELF Dynamic section", tag, entry.val);
            return true;
        }
    }
}

bool elf_dynamic_get_offset(elf_t *elf, elf_file_t *dynamic, uint64_t tag, uint64_t *poffset) {
    uint64_t addr = -1;
    int64_t offset = -1;
    if (!elf_dynamic_get_entry(dynamic, tag, &addr)) {
        return false;
    }

    offset = elf_addr_to_offset(elf, addr);
    if (offset < 0) {
        TRACE_WARNING("Could not find offset for Tag 0x%"PRIx64"=0x%"PRIx64" in %s", tag, addr, elf_name(elf));
        return false;
    }
    TRACE_LOG("Tag 0x%"PRIx64"=0x%"PRIx64" (offset: 0x%"PRIx64") in ELF Dynamic section", tag, addr, offset);
    *poffset = offset;

    return true;
}

elf_file_t *elf_dynamic_open_symtab(elf_t *elf, elf_file_t *dynamic) {
    uint64_t hash_offset = 0;
    uint64_t symtab_offset = 0;
    uint64_t sym_entry_size = 0;

    if (!elf_dynamic_get_offset(elf, dynamic, DT_HASH, &hash_offset)) {
        return NULL;
    }
    if (!elf_dynamic_get_offset(elf, dynamic, DT_SYMTAB, &symtab_offset)) {
        return NULL;
    }
    if (!elf_dynamic_get_entry(dynamic, DT_SYMENT, &sym_entry_size)) {
        return NULL;
    }

    elf_file_t *hash = elf_file_open(elf, 64, hash_offset);
    if (!hash) {
        TRACE_LOG("Could not open DT_HASH from ELF Dynamic section");
        return NULL;
    }
    uint64_t nbucket = elf_file_read_u32(hash);
    uint64_t nchain = elf_file_read_u32(hash);
    elf_file_close(hash);

    elf_file_t *symtab = elf_file_open(elf, nchain*sym_entry_size, symtab_offset);
    TRACE_LOG("hash_offset:0x%"PRIx64", symtab_offset:0x%"PRIx64", sym_entry_size:%"PRIu64", nbucket: %"PRIu64", nchain: %"PRIu64" for %s", hash_offset, symtab_offset, sym_entry_size, nbucket, nchain, elf_name(elf));
    if (!symtab) {
        TRACE_WARNING("Could not open symbol table using ELF Dynamic section");
        return NULL;
    }

    return symtab;
}

elf_file_t *elf_dynamic_open_rela_dyn(elf_t *elf, elf_file_t *dynamic) {
    uint64_t rela_offset = 0;
    uint64_t relasz = 0;

    if (!elf_dynamic_get_offset(elf, dynamic, DT_RELA, &rela_offset)) {
        return NULL;
    }
    if (!elf_dynamic_get_entry(dynamic, DT_RELASZ, &relasz)) {
        return NULL;
    }

    return elf_file_open(elf, relasz, rela_offset);
}

elf_file_t *elf_dynamic_open_rel_dyn(elf_t *elf, elf_file_t *dynamic) {
    uint64_t rel_offset = 0;
    uint64_t relsz = 0;

    if (!elf_dynamic_get_offset(elf, dynamic, DT_REL, &rel_offset)) {
        return NULL;
    }
    if (!elf_dynamic_get_entry(dynamic, DT_RELSZ, &relsz)) {
        return NULL;
    }

    return elf_file_open(elf, relsz, rel_offset);
}

elf_file_t *elf_dynamic_open_plt(elf_t *elf, elf_file_t *dynamic, uint32_t plt_type) {
    uint64_t pltrel = 0;
    uint64_t jmprel_offset = 0;
    uint64_t pltrelsz = 0;
    if (!elf_dynamic_get_entry(dynamic, DT_PLTREL, &pltrel)) {
        return NULL;
    }
    if (pltrel != plt_type) {
        return NULL;
    }
    if (!elf_dynamic_get_offset(elf, dynamic, DT_JMPREL, &jmprel_offset)) {
        return NULL;
    }
    if (!elf_dynamic_get_entry(dynamic, DT_PLTRELSZ, &pltrelsz)) {
        return NULL;
    }

    return elf_file_open(elf, pltrelsz, jmprel_offset);
}

elf_file_t *elf_dynamic_open_rela_plt(elf_t *elf, elf_file_t *dynamic) {
    return elf_dynamic_open_plt(elf, dynamic, DT_RELA);
}

elf_file_t *elf_dynamic_open_rel_plt(elf_t *elf, elf_file_t *dynamic) {
    return elf_dynamic_open_plt(elf, dynamic, DT_REL);
}

elf_file_t *elf_dynamic_open_strtab(elf_t *elf, elf_file_t *dynamic) {
    uint64_t strtab_offset = 0;
    uint64_t strsz = 0;

    if (!elf_dynamic_get_offset(elf, dynamic, DT_STRTAB, &strtab_offset)) {
        return NULL;
    }
    if (!elf_dynamic_get_entry(dynamic, DT_STRSZ, &strsz)) {
        return NULL;
    }

    return elf_file_open(elf, strsz, strtab_offset);
}

