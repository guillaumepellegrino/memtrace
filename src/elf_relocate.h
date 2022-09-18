#ifndef ELF_RELOCATE_H
#define ELF_RELOCATE_H

typedef struct {
    uint64_t offset;
    uint64_t info;
    uint64_t addend;
    uint32_t type;
    uint32_t symidx;
    elf_sym_t sym;
} elf_relocate_t;

typedef bool (*elf_relocate_handler_t)(elf_relocate_t *relocate, void *userdata);

bool elf_relocate_read(elf_t *elf, elf_file_t *file, elf_file_t *symtab, elf_file_t *strtab, elf_relocate_handler_t handler, void *userdata);
bool elf_relocate_dump(elf_t *elf, elf_file_t *file, elf_file_t *symtab, elf_file_t *strtab);
bool elf_relocate_find_by_name(elf_t *elf, elf_file_t *file, elf_file_t *symtab, elf_file_t *strtab, const char *name, elf_relocate_t *result);

#endif
