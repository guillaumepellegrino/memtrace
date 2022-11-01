/*
 * Copyright (C) 2021 Guillaume Pellegrino
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <pthread.h>
#include <regex.h>
#include "libraries.h"
#include "elf_main.h"
#include "elf_file.h"
#include "elf_sym.h"
#include "list.h"
#include "arch.h"
#include "log.h"

#define stack_pointer_address() __builtin_frame_address(0)

struct _libraries {
    int pid;
    size_t count;
    library_t *list;
    list_t threads;
};

struct _library {
    elf_t *elf;
    char *name;
    elf_file_t *files[library_section_end];
    void *begin;
    void *end;
    size_t offset;
};

// TODO: move this in thread.c
typedef struct {
    list_iterator_t it;
    pthread_t id;
    void *begin;
    void *end;
} thread_stack_t;

bool thread_stack_update(thread_stack_t *thread, void *sp) {
    char buff[4096];
    bool rt = false;

    TRACE_WARNING("thread_stack_update(%p)", sp);

    //copy file in buffer
    const char *filename = "/proc/self/maps";
    const char *mode = "r";

    FILE *fp = fopen(filename, mode);
    if (!fp) {
        TRACE_ERROR("Failed to open /proc/self/maps: %m, fp:%p", fp);
        goto error;
    }

    while (fgets(buff, sizeof(buff), fp)) {
        char *sep = NULL;
        void *begin = NULL;
        void *end = NULL;

        // Strip new line character
        if ((sep = strchr(buff, '\n'))) {
            *sep = 0;
        }

        // Scan line
        if ((sscanf(buff, "%p-%p", &begin, &end) != 2)) {
            continue;
        }

        if (sp >= begin && sp < end) {
            thread->begin = begin;
            thread->end = end;
            rt = true;
            break;
        }
    }

error:
    if (fp) {
        fclose(fp);
    }
    return rt;
}

thread_stack_t *threads_findme(list_t *threads, void *sp) {
    pthread_t id = pthread_self();
    list_iterator_t *it = NULL;
    list_for_each(it, threads) {
        thread_stack_t *thread = container_of(it, thread_stack_t, it);
        if (thread->id != id) {
            continue;
        }
        // FIXME: update thread when sp is not in range
        return thread;
    }
    return NULL;
}

thread_stack_t *threads_addme(list_t *threads, void *sp) {
    thread_stack_t *thread = NULL;

    if (!(thread = calloc(1, sizeof(thread_stack_t)))) {
        return NULL;
    }
    thread->id = pthread_self();
    list_append(threads, &thread->it);
    thread_stack_update(thread, sp);

    return thread;
}

void threads_cleanup(list_t *threads) {
    list_iterator_t *it = NULL;

    while ((it = list_first(threads))) {
        thread_stack_t *thread = container_of(it, thread_stack_t, it);
        list_iterator_take(&thread->it);
        free(thread);
    }
}

static int so_qsort_compar(const void *lval, const void *rval) {
    const library_t *lso = lval;
    const library_t *rso = rval;

    if (lso->begin < rso->begin) {
        return -1;
    }
    else if (lso->begin > rso->end) {
        return 1;
    }
    else {
        return 0;
    }

}

static int so_bsearch_compar(const void *lval, const void *rval) {
    const void *address = lval;
    const library_t *library = rval;

    if (address < library->begin) {
        return -1;
    }
    else if (address > library->end) {
        return 1;
    }
    else {
        return 0;
    }
}

static bool libraries_contains(libraries_t *libraries, const void *begin, const void *end, const char *name) {
    size_t i = 0;
    for (i = 0; i < libraries->count; i++) {
        library_t *library = &libraries->list[i];

        if (library->begin != begin) {
            continue;
        }
        if (library->end != end) {
            continue;
        }
        if (strcmp(library->name, name) != 0) {
            continue;
        }
        return library;
    }

    return NULL;
}

static void libraries_entry_add(libraries_t *libraries, library_t *library, void *begin, void *end, const char *name) {
    elf_t *elf = elf_open(name);
    const program_header_t *program = elf_program_header_executable(elf);

    memset(library, 0, sizeof(*library));
    library->elf = elf;
    library->name = strdup(name);
    library->begin = begin;
    library->end = end;
    library->offset = program ? program->p_vaddr : 0;
}

libraries_t *libraries_create(int pid) {
    libraries_t *libraries = calloc(1, sizeof(libraries_t));
    assert(libraries);

    libraries->pid = pid;

    libraries_update(libraries);
    return libraries;
}

void libraries_update(libraries_t *libraries) {
    char buff[4096];

    assert(libraries);
    snprintf(buff, sizeof(buff), "/proc/%d/maps", libraries->pid);

    //copy file in buffer
    FILE *fp = fopen(buff, "r");
    if (!fp) {
        TRACE_ERROR("Failed to open %s", buff);
        return;
    }

    while (fgets(buff, sizeof(buff), fp)) {
        char *sep = NULL;
        void *begin = NULL;
        void *end = NULL;
        char perm[4] = {0};
        char *name = NULL;

        // Strip new line character
        if ((sep = strchr(buff, '\n'))) {
            *sep = 0;
        }

        // Scan line
        if ((sscanf(buff, "%p-%p %3s", &begin, &end, perm) != 3)) {
            continue;
        }

        // We are looking for files mapped in memory with READ/EXECUTE attributes
        if (perm[0] == 'r' && perm[2] == 'x' && (name = strchr(buff, '/'))) {
            library_t *library = NULL;

            // library is already in the list
            if (libraries_contains(libraries, begin, end, name)) {
                continue;
            }

            // Add the lib
            libraries->list = realloc(libraries->list, sizeof(library_t)*(libraries->count + 1));
            assert(libraries->list);
            library = &libraries->list[libraries->count];
            libraries_entry_add(libraries, library, begin, end, name);
            libraries->count++;
        }
    }

    qsort(libraries->list, libraries->count, sizeof(library_t), so_qsort_compar);

    fclose(fp);
}

void libraries_destroy(libraries_t *libraries) {
    size_t i = 0;
    size_t j = 0;

    assert(libraries);

    for (i = 0; i < libraries->count; i++) {
        library_t *library = &libraries->list[i];
        for (j = 0; j < library_section_end; j++) {
            elf_file_close(library->files[j]);
        }
        elf_close(library->elf);
        free(library->name);

    }
    free(libraries->list);
    threads_cleanup(&libraries->threads);
    free(libraries);
}

void libraries_print(const libraries_t *libraries, FILE *fp) {
    assert(libraries);
    assert(fp);

    size_t i = 0;

    fprintf(fp, "[libraries]\n");
    for (i = 0; i < libraries->count; i++) {
        library_t *library = &libraries->list[i];
        fprintf(fp, "[%p-%p] [%s]\n", library->begin, library->end, library->name);
    }
    fprintf(fp, "\n");
    fflush(fp);
}

library_t *libraries_find(libraries_t *libraries, size_t address) {
    assert(libraries);
    return bsearch((void *) address, libraries->list, libraries->count, sizeof(library_t), so_bsearch_compar);
}

library_t *libraries_find_by_name(libraries_t *libraries, const char *regex) {
    assert(libraries);
    regex_t preg;
    size_t i = 0;

    if (regcomp(&preg, regex, REG_NOSUB|REG_EXTENDED) == 1) {
        TRACE_ERROR("Failed to parse regex %s: %m", regex);
        return NULL;
    }

    for (i = 0; i < libraries->count; i++) {
        library_t *library = &libraries->list[i];
        if (regexec(&preg, library->name, 0, NULL, 0) == 0) {
            regfree(&preg);
            return library;
        }
    }

    regfree(&preg);
    return NULL;
}

library_t *libraries_get(libraries_t *libraries, size_t idx) {
    assert(libraries);
    return (idx < libraries->count) ?
        &libraries->list[idx] : NULL;
}

/** Return the count of libraries */
size_t libraries_count(const libraries_t *libraries) {
    assert(libraries);
    return libraries->count;
}

static void *libraries_stack_end(libraries_t *libraries, void *sp) {
    thread_stack_t *thread = NULL;

    if (!(thread = threads_findme(&libraries->threads, sp))) {
        if (!(thread = threads_addme(&libraries->threads, sp))) {
            return NULL;
        }
    }

    return thread->end;
}

void libraries_backtrace(libraries_t *libraries, cpu_registers_t *regs, void **callstack, size_t size) {
    assert(libraries);
    assert(callstack);
    assert(size);

    void *pc = (void *) cpu_register_get(regs, cpu_register_pc);
    void *sp = (void *) cpu_register_get(regs, cpu_register_sp);
    void *lr = (void *) cpu_register_get(regs, cpu_register_ra);
    void *end = libraries_stack_end(libraries, sp);
    size_t i = 0, j = 0;

    // start of the callstack
    callstack[j++] = pc;
    callstack[j++] = lr;

    // skip all the symbols on the stack before lr
    for (; ((size_t *)sp)+i < (size_t *)end; i++) {
        void *address = ((void **) sp)[i];
        if (address == lr) {
            i++;
            break;
        }
    }

    // search all the symbols on the stack
    for (; j < size && ((size_t *)sp)+i < (size_t *)end; i++) {
        void *address = ((void **) sp)[i];
        if (libraries_find(libraries, (size_t) address)) {
            callstack[j++] = address;
        }
    }

    // end callstack with null pointer
    if (j < size) {
        callstack[j] = NULL;
    }
}

void libraries_backtrace_print(libraries_t *libraries, void **callstack, size_t size, void *fp)  {
    assert(libraries);
    assert(callstack);

    for (size_t i = 0; i < size && callstack[i]; i++) {
        library_t *library = libraries_find(libraries, (size_t) callstack[i]);
        if (library) {
            elf_sym_t sym = {0};
            size_t ra = library_relative_address(library, (size_t) callstack[i]);
            elf_file_t *dynsym = library_get_elf_section(library, library_section_dynsym);
            elf_file_t *dynstr = library_get_elf_section(library, library_section_dynstr);
            elf_file_t *symtab = library_get_elf_section(library, library_section_symtab);
            elf_file_t *strtab = library_get_elf_section(library, library_section_strtab);

            if (dynsym && dynstr) {
                sym = elf_sym_from_addr(dynsym, dynstr, ra);
            }
            if (symtab && strtab && !sym.name) {
                sym = elf_sym_from_addr(symtab, strtab, ra);
            }

            if (sym.name) {
                size_t offset = ra - sym.offset;
                fprintf(fp, "[addr]%s+0x%zx | %s()+0x%zx\n", library_name(library), ra, sym.name, offset);
            }
            else {
                fprintf(fp, "[addr]%s+0x%zx\n", library_name(library), ra);
            }
        }
    }
    fflush(fp);
}

elf_t *library_elf(const library_t *library) {
    assert(library);
    return library->elf;
}

const char *library_name(const library_t *library) {
    assert(library);
    return library->name;
}

void *library_begin(const library_t *library) {
    assert(library);
    return library->begin;
}

void *library_end(const library_t *library) {
    assert(library);
    return library->end;
}

size_t library_offset(const library_t *library) {
    assert(library);
    return library->offset;
}

elf_file_t *library_get_elf_section(library_t *library, library_section_t section) {
    static const char *names[] = {
        [library_section_dynsym] = ".dynsym",
        [library_section_dynstr] = ".dynstr",
        [library_section_symtab] = ".symtab",
        [library_section_strtab] = ".strtab",
        [library_section_rel_dyn] = ".rel.dyn",
        [library_section_rel_plt] = ".rel.plt",
        [library_section_rela_dyn] = ".rela.dyn",
        [library_section_rela_plt] = ".rela.plt",
        [library_section_bss] = ".bss",
    };

    if (section >= library_section_end) {
        return NULL;
    }

    if (!library->files[section]) {
        library->files[section] = elf_section_open_from_name(library->elf, names[section]);
    }

    return library->files[section];
}

size_t library_relative_address(const library_t *library, size_t address) {
    assert(library);
    return (address - ((size_t) library->begin)) + library->offset;
}

size_t library_absolute_address(const library_t *library, size_t address) {
    assert(library);

    // TODO : Is it still working on ARM ?
    //return (address + ((size_t) library->begin)) + library->offset;

    return (address + ((size_t) library->begin)) - library->offset;
}
