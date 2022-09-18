#include "elf_sym.h"
#include "elf.h"
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
            return result;
/*
            CONSOLE("[0x%"PRIx64"] Symbol:", offset);
            CONSOLE("   name:  0x%"PRIx32" (%s)",  sym.st_name, name);
            CONSOLE("   info:  0x%"PRIx8,   sym.st_info);
            CONSOLE("   other: 0x%"PRIx8,   sym.st_other);
            CONSOLE("   shndx  0x%"PRIx16,  sym.st_shndx);
            CONSOLE("   value: 0x%"PRIx64,  sym.st_value);
            CONSOLE("   size:  0x%"PRIx64,  sym.st_size);
            */
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
    return result;
}

elf_sym_t elf_sym_from_name(elf_file_t *symtab, elf_file_t *strtab, const char *name) {
    elf_sym_entry_t sym;
    elf_sym_t result = {0};

    elf_file_seek(symtab, 0);

    do {
        elf_sym_entry_read(symtab, &sym);

        if ((sym.st_info & 0x0f) == STT_FUNC) {
            elf_file_seek(strtab, sym.st_name);
            const char *symname = elf_file_read_strp(strtab);

            if (symname && !strcmp(symname, name)) {
                result.name = symname;
                result.offset = sym.st_value;
                result.section_index = sym.st_shndx;
                return result;
            }
        }
    } while (!elf_file_eof(symtab));

    return result;
}
