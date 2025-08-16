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

#define TRACE_ZONE TRACE_ZONE_COREDUMP
#include <sys/procfs.h>
#include <sys/types.h>
#include "elf.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "log.h"
#include "list.h"
#include "coredump.h"
#include "memfd.h"
#include "arch.h"
#include "elf_main.h"

#define PIPE_RDEND 0
#define PIPE_WREND 1
#define section_name_empty 0
#define section_name_shstrtab 1
#define section_name_note0 11
#define section_name_load 17
#define section_name_list "\0.shstrtab\0note0\0load"

typedef struct _elf_program elf_program_t;

typedef struct {
    unsigned char   ei_magic[4];
    uint8_t         ei_class;
    uint8_t         ei_data;
    uint8_t         ei_version;
    uint8_t         ei_osabi;
    uint8_t         ei_abiversion;
    uint8_t         ei_padding[7];
    uint16_t        e_type;
    uint16_t        e_machine;
    uint32_t        e_version;
    size_t          e_entry;
    size_t          e_phoff;
    size_t          e_shoff;
    uint32_t        e_flags;
    uint16_t        e_ehsize;
    uint16_t        e_phentsize;
    uint16_t        e_phnum;
    uint16_t        e_shentsize;
    uint16_t        e_shnum;
    uint16_t        e_shstrndx;
} __attribute__((packed)) elf_header_packed_t;

typedef struct {
    uint32_t        p_type;
#ifdef __64BIT
    uint32_t        p_flags;
#endif
    size_t          p_offset;
    size_t          p_vaddr;
    size_t          p_paddr;
    size_t          p_filesz;
    size_t          p_memsz;
#ifdef __32BIT
    uint32_t        p_flags;
#endif
    size_t          p_align;
} __attribute__((packed)) program_header_packed_t;

typedef struct {
    uint32_t      sh_name;
    uint32_t      sh_type;
    size_t        sh_flags;
    size_t        sh_addr;
    size_t        sh_offset;
    size_t        sh_size;
    uint32_t      sh_link;
    uint32_t      sh_info;
    size_t        sh_addralign;
    size_t        sh_entsize;
} __attribute__((packed)) section_header_packed_t;

struct _elf_program {
    list_iterator_t it;
    void (*initialize_program_header)(elf_program_t *program, program_header_packed_t *ph);
    void (*initialize_section_header)(elf_program_t *program, section_header_packed_t *sh);
    size_t (*write)(elf_program_t *program, FILE *fp);
    void (*destroy)(elf_program_t *program);
    program_header_packed_t ph;
    section_header_packed_t sh;
};

typedef struct {
    elf_header_packed_t eh;
    list_t program_list;
    list_t section_list;
    int pid;
    int memfd; // reference on /proc/$pid/mem
} elf_coredump_t;

typedef struct {
    elf_program_t program;
    int pid;
    size_t begin;
    size_t end;
    p_flags_t flags;
    char *name;
} elf_program_library_t;

typedef struct {
    elf_program_t program;
    list_t list;
} elf_program_note_t;

typedef struct {
    list_iterator_t it;
    uint32_t type;
    char *name;
    uint32_t descsize;
    void *desc;
} elf_note_item_t;

typedef struct {
    list_iterator_t it;
    size_t start;
    size_t end;
    size_t file_offset;
    char *name;
} elf_note_file_t;

typedef struct {
    list_t list;
} elf_note_files_t;

static uint32_t align4(uint32_t size) {
    uint32_t rt = (size & 0xFFFFFFFC) + ((size & 0x3) ? 4 : 0);
    return rt;
}

size_t fwrite_align4(const void *ptr, size_t size, FILE *stream) {
    size_t remain = align4(size) - size;
    size_t i;
    fwrite(ptr, size, 1, stream);
    for (i = 0; i < remain; i++) {
        fputc(0, stream);
    }

    return size + remain;
}

bool elf_coredump_init(elf_coredump_t *coredump, int pid, int memfd) {
    static elf_header_packed_t me;

    if (me.ei_magic[0] == 0) {
        // Read own elf header
        int fd = -1;
        assert((fd = open("/proc/self/exe", O_RDONLY)) >= 0);
        assert(read(fd, &me, sizeof(me)) == sizeof(me));
        close(fd);
    }

    coredump->eh = (elf_header_packed_t) {
        .ei_magic       = {0x7F, 'E', 'L', 'F'},
        .ei_class       = me.ei_class,
        .ei_data        = me.ei_data,
        .ei_version     = me.ei_version,
        .ei_osabi       = me.ei_osabi,
        .ei_abiversion  = me.ei_abiversion,
        .e_type         = e_type_core,

        .e_machine      = me.e_machine,
        .e_version      = me.e_version,
        .e_entry        = 0x00,
        .e_phoff        = sizeof(elf_header_packed_t),
        .e_flags        = 0x00,
        .e_ehsize       = sizeof(elf_header_packed_t),
        .e_phentsize    = sizeof(program_header_packed_t),
        .e_phnum        = 0,
        .e_shentsize    = sizeof(section_header_packed_t),
        .e_shnum        = 0,
    };
    list_initialize(&coredump->program_list);
    coredump->pid = pid;
    coredump->memfd = memfd;

    return true;
}

void elf_coredump_cleanup(elf_coredump_t *coredump) {
    list_iterator_t *it = NULL;

    while ((it = list_first(&coredump->program_list))) {
        elf_program_t *program = container_of(it, elf_program_t, it);
        list_iterator_take(&program->it);
        if (program->destroy) {
            program->destroy(program);
        }
    }
}

static inline elf_coredump_t *elf_program_get_coredump(elf_program_t *program) {
    list_t *program_list = program->it.list;
    return container_of(program_list, elf_coredump_t, program_list);
}

void elf_coredump_add_program(elf_coredump_t *coredump, elf_program_t *program) {
    list_append(&coredump->program_list, &program->it);
}

void elf_coredump_write(elf_coredump_t *coredump, FILE *fp) {
    list_iterator_t *it = NULL;
    size_t section_index = 0;
    size_t offset = 0;
    size_t written = 0;
    size_t i = 0;

    // Initialize Program and Section ELF Headers
    list_for_each(it, &coredump->program_list) {
        elf_program_t *program = container_of(it, elf_program_t, it);
        if (program->initialize_program_header) {
            program->initialize_program_header(program, &program->ph);
        }
        if (program->initialize_section_header) {
            program->initialize_section_header(program, &program->sh);

            if (program->sh.sh_type == sh_type_strtab) {
                coredump->eh.e_shstrndx = section_index;
            }
            section_index++;
        }
    }

    // Compute ELF, Section and Program headers
    coredump->eh.e_phnum = 0;
    coredump->eh.e_shnum = 0;
    coredump->eh.e_shoff = sizeof(elf_header_packed_t);
    list_for_each(it, &coredump->program_list) {
        elf_program_t *program = container_of(it, elf_program_t, it);
        coredump->eh.e_phnum += program->initialize_program_header ? 1 : 0;
        coredump->eh.e_shnum += program->initialize_section_header ? 1 : 0;
    }
    offset = sizeof(elf_header_packed_t) + (coredump->eh.e_phnum * sizeof(program_header_packed_t));
    list_for_each(it, &coredump->program_list) {
        elf_program_t *program = container_of(it, elf_program_t, it);

        size_t size = 0;
        if (program->sh.sh_size) {
            program->sh.sh_offset = offset;
            size = program->sh.sh_size;
        }
        if (program->ph.p_filesz) {
            program->ph.p_offset = offset;
            size = program->ph.p_filesz;
        }
        offset += size;
        coredump->eh.e_shoff += program->initialize_program_header ?
            (sizeof(program_header_packed_t) + size) : size;
    }
    coredump->eh.e_shoff = align4(coredump->eh.e_shoff);

    // Write ELF Header
    written += fwrite(&coredump->eh, 1, sizeof(elf_header_packed_t), fp);

    // Write each program header
    list_for_each(it, &coredump->program_list) {
        elf_program_t *program = container_of(it, elf_program_t, it);
        if (!program->initialize_program_header) {
            continue;
        }
        written += fwrite(&program->ph, 1, sizeof(program_header_packed_t), fp);
    }

    // Write each program data
    list_for_each(it, &coredump->program_list) {
        elf_program_t *program = container_of(it, elf_program_t, it);
        if (!program->write) {
            continue;
        }
        written += program->write(program, fp);
    }

    // Complete with zero
    for (i = written; i < coredump->eh.e_shoff; i++) {
        fputc(0, fp);
    }

    // Write each section header
    list_for_each(it, &coredump->program_list) {
        elf_program_t *program = container_of(it, elf_program_t, it);
        if (!program->initialize_section_header) {
            continue;
        }
        fwrite(&program->sh, 1, sizeof(section_header_packed_t), fp);
    }

    // Ensure all data are written
    fflush(fp);
}

void initialize_null_section_header(elf_program_t *program, section_header_packed_t *sh) {
    sh->sh_name = section_name_empty;
    sh->sh_type = sh_type_null;
}

void elf_coredump_add_null_section(elf_coredump_t *coredump) {
    static elf_program_t program = {
        .initialize_section_header = initialize_null_section_header,
    };
    elf_coredump_add_program(coredump, &program);
}

void initialize_name_section_header(elf_program_t *program, section_header_packed_t *sh) {
    sh->sh_name = section_name_shstrtab;
    sh->sh_type = sh_type_strtab;
    sh->sh_size = sizeof(section_name_list);
    sh->sh_addralign = 1;
}

size_t write_name_section(elf_program_t *program, FILE *fp) {
    return fwrite(section_name_list, 1, sizeof(section_name_list), fp);
}

void elf_coredump_add_name_section(elf_coredump_t *coredump) {
    static elf_program_t program = {
        .initialize_section_header = initialize_name_section_header,
        .write = write_name_section,
    };
    elf_coredump_add_program(coredump, &program);
}

size_t note_size(elf_note_item_t *item) {
    return 0
        + 4 // name size
        + 4 // desc size
        + 4 // type
        + align4(strlen(item->name) + 1) // name string aligned on 4 bytes
        + align4(item->descsize); // desc data aligned on 4 bytes
}

size_t note_list_size(elf_program_note_t *note) {
    size_t size = 0;
    list_iterator_t *it;
    list_for_each(it, &note->list) {
        elf_note_item_t *item = container_of(it, elf_note_item_t, it);
        size += note_size(item);
    }
    return size;
}

void elf_program_note_initialize_header(elf_program_t *program, program_header_packed_t *ph) {
    elf_program_note_t *note = container_of(program, elf_program_note_t, program);
    ph->p_type = p_type_note;
    ph->p_filesz = note_list_size(note);
    ph->p_flags = p_flags_r;
    ph->p_align = 0x1;
}

void elf_section_note_initialize_header(elf_program_t *program, section_header_packed_t *sh) {
    elf_program_note_t *note = container_of(program, elf_program_note_t, program);
    sh->sh_name = section_name_note0;
    sh->sh_type = sh_type_note;
    sh->sh_size = note_list_size(note);
    sh->sh_flags = sh_flags_alloc;
    sh->sh_addralign = 1;
}

size_t elf_program_note_write(elf_program_t *program, FILE *fp) {
    size_t size = 0;
    elf_program_note_t *note = container_of(program, elf_program_note_t, program);
    list_iterator_t *it;
    list_for_each(it, &note->list) {
        elf_note_item_t *item = container_of(it, elf_note_item_t, it);
        size_t namesize = strlen(item->name) + 1;

        size += fwrite(&namesize, 1, 4, fp);
        size += fwrite(&item->descsize, 1, 4, fp);
        size += fwrite(&item->type, 1, 4, fp);

        size += fwrite_align4(item->name, namesize, fp);
        size += fwrite_align4(item->desc, item->descsize, fp);
    }

    return size;
}

void elf_program_note_destroy(elf_program_t *program) {

}

void elf_program_note_initialize(elf_program_note_t *note, elf_coredump_t *coredump) {
    note->program.initialize_program_header = elf_program_note_initialize_header;
    note->program.initialize_section_header = elf_section_note_initialize_header;
    note->program.write = elf_program_note_write;
    note->program.destroy = elf_program_note_destroy;
    elf_coredump_add_program(coredump, &note->program);
}

void elf_program_note_add(elf_program_note_t *note, uint32_t type, const char *name, const void *desc, size_t descsize) {
    elf_note_item_t *item = calloc(1, sizeof(elf_note_item_t));
    item->type = type;
    item->name = strdup(name);
    item->descsize = descsize;
    item->desc = malloc(descsize);
    memcpy(item->desc, desc, descsize);
    list_append(&note->list, &item->it);
}

void elf_program_note_add_prpsinfo(elf_program_note_t *note, int pid) {
    struct elf_prpsinfo info = {0};
    FILE *fp = NULL;

    info.pr_state = 0; /* Numeric process state.  */
    info.pr_sname = 0; /* Char for pr_state.  */
    info.pr_zomb = 0; /* Zombie.  */
    info.pr_nice = 0; /* Nice val.  */
    info.pr_flag = 0; /* Flags.  */
    info.pr_uid = 0;
    info.pr_gid = 0;
    info.pr_pid = pid;
    info.pr_ppid = 0;
    info.pr_pgrp = 0;
    info.pr_sid = 0;
    //info.pr_fname; /* Filename of executable.  */
    //info.pr_psargs;/* Initial part of arg list.  */


    // Fill pr_fname from /proc/%d/exe
    char exe[32];
    snprintf(exe, sizeof(exe), "/proc/%d/exe", pid);
    if (readlink(exe, g_buff, sizeof(g_buff)) > 0) {
        const char *sep = strrchr(g_buff, '/');
        const char *name = sep ? sep + 1 : g_buff;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wformat-truncation"
        snprintf(info.pr_fname, sizeof(info.pr_fname), "%s", name);
#pragma GCC diagnostic pop
    }

    // Fill pr_psargs from /proc/%d/cmdline
    snprintf(g_buff, sizeof(g_buff), "/proc/%d/cmdline", pid);
    if ((fp = fopen(g_buff, "r"))) {
        ssize_t len = 0;
        len = fread(info.pr_psargs, 1, sizeof(info.pr_psargs)-1, fp);
        if (len > 1) {
            ssize_t i = 0;
            for (i = 0; i < len-1; i++) {
                if (info.pr_psargs[i] == 0) {
                    info.pr_psargs[i] = ' ';
               }
            }
            info.pr_psargs[len] = 0;
        }
        else {
            info.pr_psargs[0] = 0;
        }
        fclose(fp);
    }

    // Fill from /proc/%d/stat
    snprintf(g_buff, sizeof(g_buff), "/proc/%d/stat", pid);
    if ((fp = fopen(g_buff, "r"))) {
        char *sep = NULL;
        char pr_sname = 0;
        unsigned int pr_flag = 0;
        long pr_nice = 0;
        assert(fread(g_buff, 1, sizeof(g_buff), fp) > 0);
        assert((sep = strchr(g_buff, ')')));
        sscanf(sep + 1,
            "%c"            /* Process state. */
            "%d%d%d"        /* Parent PID, group ID, session ID. */
            "%*d%*d"        /* tty_nr, tpgid (not used). */
            "%u"            /* Flags. */
            "%*s%*s%*s%*s"  /* minflt, cminflt, majflt, cmajflt (not used). */
            "%*s%*s%*s%*s"  /* utime, stime, cutime, cstime (not used). */
            "%*s"           /* Priority (not used). */
            "%ld",          /* Nice. */
            &pr_sname,
            &info.pr_ppid, &info.pr_pgrp, &info.pr_sid,
            &pr_flag,
            &pr_nice);

        fclose(fp);
    }

    elf_program_note_add(note, NT_PRPSINFO, "CORE", &info, sizeof(info));
}

void elf_program_note_add_prstatus(elf_program_note_t *note, int pid, cpu_registers_t *override) {
    prstatus_t prstatus = {
        .pr_pid = pid,
    };
    struct iovec iovec = {
        .iov_base = &prstatus.pr_reg,
        .iov_len = sizeof(prstatus.pr_reg),
    };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iovec) != 0) {
        TRACE_LOG("Failed to get NT_PRSTATUS registers: %m");
        return;
    }

    // Override registers from coredump with the one passed in function parameters
    if (override) {
        // for x64 only
        cpu_registers_t *regs = (cpu_registers_t *) prstatus.pr_reg;

        cpu_register_name_t copy[] = {
            cpu_register_pc,
            cpu_register_sp,
            cpu_register_fp,
            cpu_register_syscall,
            cpu_register_arg1,
            cpu_register_arg2,
            cpu_register_arg3,
            cpu_register_arg4,
            cpu_register_arg5,
        };
        for (size_t i = 0; i < countof(copy); i++) {
            cpu_register_set(regs, copy[i],
                cpu_register_get(override, copy[i]));
        }
    }
    elf_program_note_add(note, NT_PRSTATUS, "CORE", &prstatus, sizeof(prstatus));
}

void elf_program_note_add_prfpreg(elf_program_note_t *note, int pid) {
    struct iovec iovec = {
        .iov_base = g_buff,
        .iov_len = sizeof(g_buff),
    };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRFPREG, &iovec) != 0) {
        TRACE_LOG("Failed to get NT_PRFPREG registers: %m");
        return;
    }
    elf_program_note_add(note, NT_PRFPREG, "CORE", iovec.iov_base, iovec.iov_len);
}

void elf_program_note_add_xstate(elf_program_note_t *note, int pid) {
    struct iovec iovec = {
        .iov_base = g_buff,
        .iov_len = sizeof(g_buff),
    };
    if (ptrace(PTRACE_GETREGSET, pid, NT_X86_XSTATE, &iovec) != 0) {
        TRACE_LOG("Failed to get NT_X86_XSTATE registers: %m");
        return;
    }
    elf_program_note_add(note, NT_X86_XSTATE, "LINUX", iovec.iov_base, iovec.iov_len);
}

void elf_program_note_add_siginfo(elf_program_note_t *note, int pid) {
    siginfo_t siginfo = {0};
    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo) != 0) {
        TRACE_ERROR("Failed to get SIGINFO registers: %m");
        return;
    }
    elf_program_note_add(note, NT_SIGINFO, "CORE", &siginfo, sizeof(siginfo));
}

void elf_program_note_add_auxv(elf_program_note_t *note, int pid) {
    int fd = -1;
    ssize_t len = 0;

    snprintf(g_buff, sizeof(g_buff), "/proc/%d/auxv", pid);
    if ((fd = open(g_buff, O_RDONLY)) >= 0) {
        if ((len = read(fd, g_buff, sizeof(g_buff))) >= 0) {
            elf_program_note_add(note, NT_AUXV, "CORE", g_buff, len);
        }
        else {
            TRACE_ERROR("Failed to read /proc/$pid/auxv: %m");
        }
        close(fd);
    }
    else {
        TRACE_ERROR("Failed to open /proc/$pid/auxv: %m");
    }
}

void elf_note_files_add(elf_note_files_t *note_files, size_t start, size_t end, size_t file_offset, const char *name) {
    elf_note_file_t *file = calloc(1, sizeof(elf_note_file_t));
    file->start = start;
    file->end = end;
    file->file_offset = file_offset;
    file->name = strdup(name ? name : "??");
    list_append(&note_files->list, &file->it);
}

static void elf_program_note_add_files(elf_program_note_t *note, elf_note_files_t *note_files) {
    char *buff = NULL;
    size_t buffsize = 0;
    FILE *fp = NULL;
    size_t count = list_size(&note_files->list);
    size_t page_size = 1;
    list_iterator_t *it = NULL;

    assert((fp = open_memstream(&buff, &buffsize)));
    fwrite(&count, 1, sizeof(count), fp);
    fwrite(&page_size, 1, sizeof(page_size), fp);

    list_for_each(it, &note_files->list) {
        elf_note_file_t *file = container_of(it, elf_note_file_t, it);
        fwrite(&file->start, 1, sizeof(file->start), fp);
        fwrite(&file->end, 1, sizeof(file->end), fp);
        fwrite(&file->file_offset, 1, sizeof(file->file_offset), fp);
    }
    list_for_each(it, &note_files->list) {
        elf_note_file_t *file = container_of(it, elf_note_file_t, it);
        fputs(file->name, fp);
        putc(0, fp);
    }

    fclose(fp);
    elf_program_note_add(note, NT_FILE, "CORE", buff, buffsize);
    free(buff);
}

static void program_library_initialize_header(elf_program_t *program, program_header_packed_t *ph) {
    elf_program_library_t *pl = container_of(program, elf_program_library_t, program);
    ph->p_type = p_type_load;
    ph->p_filesz = ((size_t) pl->end) - ((size_t) pl->begin);
    ph->p_vaddr = (size_t) pl->begin;
    ph->p_memsz = ((size_t) pl->end) - ((size_t) pl->begin);
    ph->p_flags = pl->flags;
    ph->p_align = 1;
}

static void section_library_initialize_header(elf_program_t *program, section_header_packed_t *sh) {
    elf_program_library_t *pl = container_of(program, elf_program_library_t, program);

    sh->sh_name = section_name_load;
    sh->sh_type = sh_type_progbits;
    sh->sh_size = ((size_t) pl->end) - ((size_t) pl->begin);
    sh->sh_addr = (size_t) pl->begin;
    sh->sh_flags = sh_flags_alloc;
    sh->sh_flags |= pl->flags & p_flags_w ? sh_flags_write : 0;
    sh->sh_flags |= pl->flags & p_flags_x ? sh_flags_execinstr : 0;
    sh->sh_addralign = 1;
}

static size_t program_library_write(elf_program_t *program, FILE *fp) {
    elf_coredump_t *coredump = elf_program_get_coredump(program);
    elf_program_library_t *pl = container_of(program, elf_program_library_t, program);
    size_t pl_size = pl->end - pl->begin;
    size_t i;
    size_t remain;

    TRACE_LOG("Write %s at [%zx:%zx]", (pl->name?pl->name:""), pl->begin, pl->end);

    if (lseek64(coredump->memfd, pl->begin, SEEK_SET) < 0) {
        TRACE_ERROR("lseek 0x%zx: %m (%s)", pl->begin, pl->name);
    }

    for (i = 0; (i + sizeof(g_buff)) < pl_size; i+= sizeof(g_buff)) {
        if (read(coredump->memfd, g_buff, sizeof(g_buff)) <= 0) {
            goto error;
        }
        fwrite(g_buff, sizeof(g_buff), 1, fp);
    }

    remain = pl_size - i;
    if (read(coredump->memfd, g_buff, remain) <= 0) {
        goto error;
    }
    fwrite(g_buff, remain, 1, fp);
    return pl_size;

error:
    TRACE_LOG("Failed to read 0x%zx: %m (%s)", i, pl->name);
    memset(g_buff, 0, sizeof(g_buff));
    for (; (i + sizeof(g_buff)) < pl_size; i+= sizeof(g_buff)) {
        fwrite(g_buff, sizeof(g_buff), 1, fp);
    }
    remain = pl_size - i;
    fwrite(g_buff, remain, 1, fp);

    return pl_size;
}

static void program_library_destroy(elf_program_t *program) {
    free(program);
}

void elf_coredump_add_library(elf_coredump_t *coredump, int pid, size_t begin, size_t end, p_flags_t flags, const char *name) {
    elf_program_library_t *pl = calloc(1, sizeof(elf_program_library_t));
    pl->program.initialize_program_header = program_library_initialize_header;
    pl->program.initialize_section_header = section_library_initialize_header;
    pl->program.write = program_library_write;
    pl->program.destroy = program_library_destroy;
    pl->pid = pid;
    pl->begin = begin;
    pl->end = end;
    pl->flags = flags;
    pl->name = name ? strdup(name) : NULL;

    elf_coredump_add_program(coredump, &pl->program);
}

static void elf_coredump_map_files(elf_coredump_t *coredump, elf_note_files_t *note_files, int pid) {
    FILE *fp = NULL;

    snprintf(g_buff, sizeof(g_buff), "/proc/%d/maps", pid);
    if (!(fp = fopen(g_buff, "r"))) {
        TRACE_ERROR("Failed to open %s", g_buff);
        return;
    }

    while (fgets(g_buff, sizeof(g_buff), fp)) {
        char *sep = NULL;
        void *begin = NULL;
        void *end = NULL;
        char perm[5] = {0};
        size_t offset = 0;
        size_t flags = 0;
        const char *name = NULL;
        const char *topic = NULL;

        // Strip new line character
        if ((sep = strchr(g_buff, '\n'))) {
            *sep = 0;
        }

        // Scan line
        if ((sscanf(g_buff, "%p-%p %4s %zx", &begin, &end, perm, &offset) != 4)) {
            continue;
        }
        flags |= (perm[0] == 'r') ? p_flags_r : 0;
        flags |= (perm[1] == 'w') ? p_flags_w : 0;
        flags |= (perm[2] == 'x') ? p_flags_x : 0;
        if (flags == 0) {
            continue;
        }
        flags |= p_flags_r;

        // Get file name
        if ((name = strchr(g_buff, '/'))) {
            elf_note_files_add(note_files, (size_t) begin, (size_t) end, offset, name);
        }
        else {
            topic = strchr(g_buff, '[');
        }

        if (!topic || strcmp(topic, "[vvar]") != 0) {
            elf_coredump_add_library(coredump, pid, (size_t) begin, (size_t) end, flags, name);
        }
    }
    fclose(fp);
}

void coredump_write(int pid, int memfd, FILE *fp, cpu_registers_t *regs) {
    elf_coredump_t coredump = {0};
    elf_program_note_t note = {0};
    elf_note_files_t note_files = {0};

    elf_coredump_init(&coredump, pid, memfd);
    elf_coredump_add_null_section(&coredump);

    elf_program_note_initialize(&note, &coredump);
    elf_program_note_add_prpsinfo(&note, pid);
    elf_program_note_add_prstatus(&note, pid, regs);
    elf_program_note_add_prfpreg(&note, pid);
    elf_program_note_add_xstate(&note, pid);
    elf_program_note_add_siginfo(&note, pid);
    elf_program_note_add_auxv(&note, pid);
    elf_coredump_map_files(&coredump, &note_files, pid);
    elf_program_note_add_files(&note, &note_files);
    elf_coredump_add_name_section(&coredump);

    elf_coredump_write(&coredump, fp);
    elf_coredump_cleanup(&coredump);
}

void coredump_write_plain_file(const char *filename, int pid, cpu_registers_t *regs) {
    char defaultfile[64];
    int memfd = -1;
    FILE *core = NULL;

    if (!filename) {
        snprintf(defaultfile, sizeof(defaultfile), "memtrace-%d.core", pid);
        filename = defaultfile;
    }
    if (!(core = fopen(filename, "w"))) {
        TRACE_ERROR("Failed to open %s: %m", filename);
        goto error;
    }

    if ((memfd = memfd_open(pid)) < 0) {
        goto error;
    }

    fprintf(stderr, "Writing coredump to %s\n", filename);
    coredump_write(pid, memfd, core, regs);
    fprintf(stderr, "Writing coredump done\n");

error:
    if (memfd >= 0) {
        close(memfd);
    }
    if (core) {
        fclose(core);
    }
}

void coredump_write_gzip_file(const char *filename, int pid, cpu_registers_t *regs) {
    char defaultfile[64];
    int memfd = -1;
    int core = -1;
    int pipe_in[2];

    if (!filename) {
        snprintf(defaultfile, sizeof(defaultfile), "memtrace-%d.core.gz", pid);
        filename = defaultfile;
    }
    if ((memfd = memfd_open(pid)) < 0) {
        return;
    }
    if ((core = open(filename, O_CREAT|O_WRONLY, 0644)) < 0) {
        TRACE_ERROR("Failed to open %s: %m", filename);
        close(memfd);
        return;
    }

    assert(pipe(pipe_in) == 0);
    int child = fork();
    assert(child>= 0);

    if (child == 0) {
        // Set pipe as gzip's stdin
        // Set core file as gzip's stdout
        assert(dup2(pipe_in[PIPE_RDEND], 0) == 0);
        assert(dup2(core, 1) == 1);
        close(pipe_in[PIPE_RDEND]);
        close(pipe_in[PIPE_WREND]);
        close(core);

        const char *argv[] = {"gzip", "-c", NULL};
        execvp(argv[0], (char **) argv);
        assert(false);
    }

    close(core); // owned by child proc
    close(pipe_in[PIPE_RDEND]); // owned by child proc
    FILE *pipe_fp = fdopen(pipe_in[PIPE_WREND], "w");
    assert(pipe_fp);

    fprintf(stderr, "Writing gzip coredump to %s\n", filename);
    coredump_write(pid, memfd, pipe_fp, regs);
    fclose(pipe_fp);
    close(memfd);
    waitpid(child, NULL, __WALL);
    fprintf(stderr, "Writing gzip coredump done\n");
}

void coredump_write_file(const char *filename, int pid, cpu_registers_t *regs) {
    const char *extension = NULL;

    if (filename) {
        extension = strrchr(filename, '.');
    }
    if (extension && !strcmp(extension, ".gz")) {
        coredump_write_gzip_file(filename, pid, regs);
    }
    else {
        coredump_write_plain_file(filename, pid, regs);
    }
}
