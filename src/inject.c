#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include "inject.h"
#include "log.h"
#include "ptrace.h"
#include "arch.h"
#include "libraries.h"
#include "elf.h"
#include "elf_file.h"
#include "elf_sym.h"
#include "elf_relocate.h"
#include "syscall_hijack.h"

struct _injecter {
    int pid; /** PID of the target process */
    libraries_t *libraries; /** Shared libraries from the target process */
    char *inject_libname; /** Name of the library to inject */
    void *straddr; /** Memory mapper on target process for writing string */
    void *inject_baseaddr; /** The base address where the library was injected */
    library_t *program_lib; /** Program library from target process */
    library_t *inject_lib; /** Injected library */
    library_t *c_lib; /** libc library from target process */
};

typedef struct {
    int pid;
    library_t *program;
    library_t *inject;
    library_t *libc;
} injecter_resolve_function_ctx_t;

static int64_t library_get_rela_offset(library_t *target, const char *fname) {
    elf_relocate_t rela;
    elf_file_t *rela_plt = library_get_elf_section(target, library_section_rela_plt);
    elf_file_t *rela_dyn = library_get_elf_section(target, library_section_rela_dyn);
    elf_file_t *dynsym = library_get_elf_section(target, library_section_dynsym);
    elf_file_t *dynstr = library_get_elf_section(target, library_section_dynstr);

    if (!dynsym || !dynstr) {
        TRACE_ERROR("Failed to open .dynsym and .dynstr sections for %s", elf_name(target->elf));
        return -1;
    }

    if (rela_plt && elf_relocate_find_by_name(target->elf, rela_plt, dynsym, dynstr, fname, &rela)) {
        return rela.offset;
    }
    if (rela_dyn && elf_relocate_find_by_name(target->elf, rela_dyn, dynsym, dynstr, fname, &rela)) {
        return rela.offset;
    }

    TRACE_WARNING("Relocation address not found for %s():%s", fname, elf_name(target->elf));

    // FIXME: We are assuming rela type is R_X86_64_JUMP_SLO
    return -1;
}

static bool library_replace_function(int pid, library_t *target, library_t *inject, size_t inject_baseaddr, const char *fname, const char *inject_fname) {
    CONSOLE("Replace %s():%s by %s():%s", fname, target->name, inject_fname, inject->name);

    size_t startcode = library_absolute_address(target, 0);
    //CONSOLE("startcode = 0x%zx", startcode);

    int64_t rela_fn_offset = library_get_rela_offset(target, fname);
    if (rela_fn_offset < 0) {
        return false;
    }

    size_t rela_fn_addr = startcode + rela_fn_offset;
    CONSOLE("Relocation function address: 0x%zx (offset: 0x%zx)", rela_fn_addr, rela_fn_offset);

    // Compute inject function offset
    elf_file_t *symtab = library_get_elf_section(inject, library_section_symtab);
    elf_file_t *strtab = library_get_elf_section(inject, library_section_strtab);
    if (!symtab || !strtab) {
        TRACE_ERROR(".symtab or .strtab not found");
        return false;
    }
    elf_sym_t sym = elf_sym_from_name(symtab, strtab, inject_fname);
    if (!sym.name) {
        TRACE_ERROR("%s not found", inject_fname);
        return false;
    }
    CONSOLE("Inject function offset: 0x%zx (section: %u)", sym.offset, sym.section_index);
    size_t fn_addr = inject_baseaddr + sym.offset;
    CONSOLE("function address: 0x%zx", fn_addr);

    CONSOLE("Replace function (*0x%zx = 0x%zx)", rela_fn_addr, fn_addr);
    if (ptrace(PTRACE_POKETEXT, pid, rela_fn_addr, fn_addr) != 0) {
        TRACE_ERROR("Failed to replace function: %m");
        return false;
    }
    return true;
}

static size_t relocate_address(const library_t *program, const library_t *lib, elf_relocate_t *rela) {
    switch (rela->type) {
        case R_X86_64_64:
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
            return library_absolute_address(lib, rela->offset);
        case R_X86_64_RELATIVE:
            return library_absolute_address(program, rela->offset);
        case R_X86_64_NONE:
        case R_X86_64_PC32:
        case R_X86_64_GOT32:
        case R_X86_64_PLT32:
        case R_X86_64_COPY:
        case R_X86_64_GOTPCREL:
        case R_X86_64_32:
        case R_X86_64_32S:
        case R_X86_64_16:
        case R_X86_64_PC16:
        case R_X86_64_8:
        case R_X86_64_PC8:
        case R_X86_64_DTPMOD64:
        case R_X86_64_DTPOFF64:
        case R_X86_64_TPOFF64:
        case R_X86_64_TLSGD:
        case R_X86_64_TLSLD:
        case R_X86_64_DTPOFF32:
        case R_X86_64_GOTTPOFF:
        case R_X86_64_TPOFF32:
        case R_X86_64_PC64:
        case R_X86_64_GOTOFF64:
        case R_X86_64_GOTPC32:
        case R_X86_64_GOT64:
        case R_X86_64_GOTPCREL64:
        case R_X86_64_GOTPC64:
        case R_X86_64_GOTPLT64:
        case R_X86_64_PLTOFF64:
        case R_X86_64_SIZE32:
        case R_X86_64_SIZE64:
        case R_X86_64_GOTPC32_TLSDESC:
        case R_X86_64_TLSDESC_CALL:
        case R_X86_64_TLSDESC:
        case R_X86_64_IRELATIVE:
        case R_X86_64_RELATIVE64:
        case R_X86_64_GOTPCRELX:
        case R_X86_64_REX_GOTPCRELX:
        default:
            CONSOLE("%x is not handled", rela->type);
            return 0;
    }
}

size_t resolve_function_fromlib(elf_relocate_t *rela, injecter_resolve_function_ctx_t *ctx, library_t *lib) {
    // Compute lib function offset
    elf_file_t *symtab = library_get_elf_section(lib, library_section_dynsym);
    elf_file_t *strtab = library_get_elf_section(lib, library_section_dynstr);
    if (!symtab || !strtab) {
        TRACE_ERROR(".dynsym or .dynstr not found");
        return 0;
    }
    elf_sym_t sym = elf_sym_from_name(symtab, strtab, rela->sym.name);
    if (!sym.name) {
        //TRACE_ERROR("%s not found (section idx: %d)", rela->sym.name, rela->sym.section_index);
        return 0;
    }

    return library_absolute_address(lib, sym.offset);
}

bool resolve_function(elf_relocate_t *rela, void *userdata) {
    injecter_resolve_function_ctx_t *ctx = userdata;
    size_t rela_addr = 0;
    size_t sym_addr = 0;

    if (!(rela_addr = relocate_address(ctx->program, ctx->inject, rela))) {
        TRACE_ERROR("Failed to get %s() relocation adress", rela->sym.name);
        return true;
    }

    if (!(sym_addr = resolve_function_fromlib(rela, ctx, ctx->libc))) {
        if (!(sym_addr = resolve_function_fromlib(rela, ctx, ctx->inject))) {
            if (!(sym_addr = resolve_function_fromlib(rela, ctx, ctx->program))) {
                TRACE_WARNING("Function %s() was not resolved", rela->sym.name);
                return true;
            }
        }
    }

    CONSOLE("Resolve %s() (*0x%zx = 0x%zx)", rela->sym.name, rela_addr, sym_addr);
    if (ptrace(PTRACE_POKETEXT, ctx->pid, rela_addr, sym_addr) != 0) {
        TRACE_ERROR("Failed to replace function");
        return true;
    }

    return true;
}

static bool injecter_resolve_functions(int pid, library_t *program, library_t *inject, library_t *libc) {
    injecter_resolve_function_ctx_t ctx = {
        .pid = pid,
        .program = program,
        .inject = inject,
        .libc = libc,
    };
    elf_file_t *rela_plt_file = library_get_elf_section(inject, library_section_rela_plt);
    elf_file_t *rela_dyn_file = library_get_elf_section(inject, library_section_rela_dyn);
    elf_file_t *dynsym_file = library_get_elf_section(inject, library_section_dynsym);
    elf_file_t *dynstr_file = library_get_elf_section(inject, library_section_dynstr);
    if (!rela_plt_file || !rela_dyn_file || !dynsym_file || !dynstr_file) {
        TRACE_ERROR("Failed to open .rela.plt section");
        return false;
    }

    CONSOLE("[Resolve functions for %s]", elf_name(inject->elf));
    if (!elf_relocate_read(inject->elf, rela_plt_file, dynsym_file, dynstr_file, resolve_function, &ctx)) {
        TRACE_ERROR("Failed to process .rela.plt section");
        return false;
    }

    if (!elf_relocate_read(inject->elf, rela_dyn_file, dynsym_file, dynstr_file, resolve_function, &ctx)) {
        TRACE_ERROR("Failed to process .rela.dyn section");
        return false;
    }
    CONSOLE("");

    return true;
}

injecter_t *injecter_create(int pid) {
    injecter_t *injecter = NULL;

    assert(pid);
    assert((injecter = calloc(1, sizeof(injecter_t))));
    injecter->pid = pid;

    return injecter;
}

void injecter_destroy(injecter_t *injecter) {
    if (!injecter) {
        return;
    }

    if (injecter->libraries) {
        libraries_destroy(injecter->libraries);
    }

    free(injecter->inject_libname);
    free(injecter);
}

bool injecter_load_library(injecter_t *injecter, const char *libname) {
    elf_t *elf = NULL;
    const program_header_t *ph = NULL;
    FILE *fp = NULL;

    assert(injecter);
    assert(libname);

    injecter->inject_libname = strdup(libname);
    if (!(fp = fopen(injecter->inject_libname, "r"))) {
        TRACE_ERROR("fopen %s failed: %m", injecter->inject_libname);
        return false;
    }
    if (!(elf = elf_open_local(injecter->inject_libname))) {
        TRACE_ERROR("Failed to open %s", injecter->inject_libname);
        return false;
    }

    // Allocate memory for writing string
    injecter->straddr = syscall_mmap(injecter->pid,
        0, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    // Pre-allocate the memory
    // FIXME: What is the size to allocate ?
    injecter->inject_baseaddr = syscall_mmap(injecter->pid,
        0, 10*1000*1000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    if (!injecter->straddr || !injecter->inject_baseaddr) {
        TRACE_ERROR("mmap failed");
        return false;
    }

    char memfile[64];
    snprintf(memfile, sizeof(memfile), "/proc/%d/mem", injecter->pid);
    FILE *mem = fopen(memfile, "w");
    assert(mem);

    // Write library name in target memory
    fseek(mem, (size_t)injecter->straddr, SEEK_SET);
    fprintf(mem, "%s", injecter->inject_libname);
    fflush(mem);
    int fd = syscall_open(injecter->pid, injecter->straddr, O_RDONLY, 0);
    if (fd < 0) {
        TRACE_ERROR("Failed to open %s inside pid %d", injecter->inject_libname, injecter->pid);
        return false;
    }
    CONSOLE("%s opened in target process with fd:%d", injecter->inject_libname, fd);
    CONSOLE("%s mapped in target process at %p", injecter->inject_libname, injecter->inject_baseaddr);

    for (ph = elf_program_header_first(elf); ph; ph = elf_program_header_next(elf, ph)) {
        if (ph->p_type != p_type_load) {
            continue;
        }

        void *ptr = (void *) (((size_t) injecter->inject_baseaddr) + ph->p_vaddr);

        int prot = PROT_NONE;
        if (ph->p_flags & p_flags_r) {
            prot |= PROT_READ;
        }
        if (ph->p_flags & p_flags_w) {
            prot |= PROT_WRITE;
        }
        if (ph->p_flags & p_flags_x) {
            prot |= PROT_EXEC;
        }

        CONSOLE("Load program: ptr: %p, offset: %"PRIx64 ", size: %"PRIx64, ptr, ph->p_offset, ph->p_memsz);

        // Map memory on target process
        // Map address must be aligned according ph->p_align
        size_t mapaddr = (((size_t) ptr) / ph->p_align) * ph->p_align;
        size_t mapsize = (((size_t) ptr) % ph->p_align) + ph->p_memsz;
        size_t offset = (ph->p_offset / ph->p_align) * ph->p_align;
        if (syscall_mmap(injecter->pid,
            (void *) mapaddr, mapsize, prot, MAP_PRIVATE|MAP_FIXED, fd, offset) != (void *) mapaddr)
        {
            TRACE_ERROR("Failed to map memory");
            return false;
        }
        CONSOLE("Program mapped at 0x%zx (size=0x%zx)", mapaddr, mapsize);
    }


    const libraries_cfg_t cfg = {
        .pid = injecter->pid,
    };
    if (!(injecter->libraries = libraries_create(&cfg))) {
        TRACE_ERROR("Failed to open libraries");
        return false;
    }
    libraries_print(injecter->libraries, stdout);

    injecter->program_lib = libraries_first(injecter->libraries);
    injecter->c_lib = libraries_find_by_name(injecter->libraries, "/libc(\\.|-)");
    injecter->inject_lib = libraries_find_by_name(injecter->libraries, injecter->inject_libname);
    if (!injecter->program_lib) {
        TRACE_ERROR("Failed to find target lib");
        return false;
    }
    if (!injecter->c_lib) {
        TRACE_ERROR("Failed to find C lib");
        return false;
    }
    if (!injecter->inject_lib) {
        TRACE_ERROR("Failed to find inject lib");
        return false;
    }

    // Resolve functions from injected library
    injecter_resolve_functions(injecter->pid, injecter->program_lib, injecter->inject_lib, injecter->c_lib);

    // Initialize .bss section to zero
    const section_header_t *bss = elf_section_header_get(injecter->inject_lib->elf, ".bss");
    if (bss) {
        size_t bss_addr = library_absolute_address(injecter->inject_lib, bss->sh_addr);
        CONSOLE("Initializing BSS Section (addr = 0x%zx, size = 0x%zx)", bss_addr, bss->sh_size);
        fseek(mem, bss_addr, SEEK_SET);
        for (size_t i = 0; i < bss->sh_size; i++) {
            fputc(0, mem);
        }
        fflush(mem);
    }

    elf_close(elf);
    fclose(fp);
    fclose(mem);
    return true;
}

bool injecter_replace_function(injecter_t *injecter, const char *program_fname, const char *inject_fname) {
    bool ret = false;
    size_t i = 0;
    for (i = 0; i < libraries_count(injecter->libraries); i++) {
        library_t *lib = libraries_first(injecter->libraries) + i;
        if (lib != injecter->inject_lib) {
            ret |= library_replace_function(injecter->pid, lib, injecter->inject_lib, (size_t)injecter->inject_baseaddr, program_fname, inject_fname);
        }
    }
    return ret;
}
