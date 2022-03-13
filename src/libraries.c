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
#include "elf.h"
#include "elf_file.h"
#include "elf_sym.h"
#include "debug_info.h"
#include "debug_line.h"
#include "log.h"

struct _libraries {
    int pid;
    fs_t *fs;
    size_t count;
    library_t *list;
};

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

static void libraries_entry_add(library_t *library, void *begin, void *end, const char *name, fs_t *fs) {
    elf_t *elf = elf_open(name, fs);
    const program_header_t *program = elf_program_header_executable(elf);

    memset(library, 0, sizeof(*library));
    library->elf = elf;
    library->name = strdup(name);
    library->begin = begin;
    library->end = end;
    library->offset = program ? program->p_vaddr : 0;

    CONSOLE("Opening %s begin=%p offset=%zx", name, library->begin, library->offset);

    if (!(library->frame_hdr_file = elf_section_open_from_name(elf, ".debug_frame_hdr"))) {
        if (!(library->frame_hdr_file = elf_section_open_from_name(elf, ".eh_frame_hdr"))) {
            TRACE_LOG("%s: .debug_frame_hdr/.eh_frame_hdr section not found", library->name);
        }
    }
    if (!(library->frame_file = elf_section_open_from_name(elf, ".debug_frame"))) {
        if (!(library->frame_file = elf_section_open_from_name(elf, ".eh_frame"))) {
            TRACE_ERROR("%s: .debug_frame/.eh_frame section not found", library->name);
        }
    }
    //if (!(library->abbrev_file = elf_section_open_from_name(elf, ".debug_abbrev"))) {
    //    TRACE_LOG("%s: .debug_abbrev section not found", library->name);
    //}
    //if (!(library->info_file = elf_section_open_from_name(elf, ".debug_info"))) {
    //    TRACE_LOG("%s: .debug_info section not found", library->name);
    //}
    //if (!(library->str_file = elf_section_open_from_name(elf, ".debug_str"))) {
    //    TRACE_LOG("%s: .debug_str section not found", library->name);
    //}
    //if (!(library->line_file = elf_section_open_from_name(elf, ".debug_line"))) {
    //    TRACE_LOG("%s: .debug_line section not found", library->name);
    //}


    if (!(library->dynsym_file = elf_section_open_from_name(elf, ".dynsym"))) {
        TRACE_ERROR("%s: .dynsym section not found", library->name);
    }
    if (!(library->dynstr_file = elf_section_open_from_name(elf, ".dynstr"))) {
        TRACE_ERROR("%s: .dynstr section not found", library->name);
    }
    if (!library->abbrev_file || !library->info_file || !library->str_file || !library->line_file) {
        if (library->line_file) {
            elf_file_close(library->line_file);
            library->line_file = NULL;
        }
        if (library->info_file) {
            elf_file_close(library->info_file);
            library->info_file = NULL;
        }
        if (library->abbrev_file) {
            elf_file_close(library->abbrev_file);
            library->abbrev_file = NULL;
        }
        if (library->str_file) {
            elf_file_close(library->str_file);
            library->str_file = NULL;
        }
    }
}

libraries_t *libraries_create(int pid, fs_t *fs) {
    libraries_t *libraries = calloc(1, sizeof(libraries_t));
    assert(libraries);

    libraries->pid = pid;
    libraries->fs = fs;

    libraries_update(libraries);
    return libraries;
}

void libraries_update(libraries_t *libraries) {
    assert(libraries);

    snprintf(g_buff, sizeof(g_buff), "/proc/%d/maps", libraries->pid);

    //copy file in buffer
    FILE *fp = fopen(g_buff, "r");
    if (!fp) {
        TRACE_ERROR("Failed to open %s", g_buff);
        return;
    }

    while (fgets(g_buff, sizeof(g_buff), fp)) {
        char *sep = NULL;
        void *begin = NULL;
        void *end = NULL;
        char perm[4] = {0};
        char *name = NULL;

        // Strip new line character
        if ((sep = strchr(g_buff, '\n'))) {
            *sep = 0;
        }

        // Scan line
        if ((sscanf(g_buff, "%p-%p %3s", &begin, &end, perm) != 3)) {
            continue;
        }

        // We are looking for files mapped in memory with READ/EXECUTE attributes
        if (perm[0] == 'r' && perm[2] == 'x' && (name = strchr(g_buff, '/'))) {
            library_t *library = NULL;

            // skip ld library
            //if (strstr(name, "/ld-") || strstr(name, "/ld.")) {
            //    continue;
            //}

            // library is already in the list
            if (libraries_contains(libraries, begin, end, name)) {
                continue;
            }

            // Add the lib
            libraries->list = realloc(libraries->list, sizeof(library_t)*(libraries->count + 1));
            assert(libraries->list);
            library = &libraries->list[libraries->count];
            libraries_entry_add(library, begin, end, name, libraries->fs);
            libraries->count++;
        }
    }

    qsort(libraries->list, libraries->count, sizeof(library_t), so_qsort_compar);

    fclose(fp);
}

void libraries_destroy(libraries_t *libraries) {
    size_t i = 0;

    assert(libraries);

    for (i = 0; i < libraries->count; i++) {
        library_t *library = &libraries->list[i];
        elf_file_close(library->frame_hdr_file);
        elf_file_close(library->frame_file);
        elf_file_close(library->abbrev_file);
        elf_file_close(library->info_file);
        elf_file_close(library->str_file);
        elf_file_close(library->line_file);
        elf_file_close(library->dynsym_file);
        elf_file_close(library->dynstr_file);
        elf_close(library->elf);
        free(library->name);

    }
    free(libraries->list);
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
/*
void library_print_symbol(const library_t *library, size_t ra, FILE *fp) {
    debug_line_info_t *line = NULL;
    debug_info_t *info = NULL;
    elf_sym_t sym = {0};

    if (library->elf && library->line_file) {
        line = debug_line_ex(library->elf, library->line_file, ra);
    }
    if (library->elf && library->abbrev_file && library->info_file && library->str_file) {
        info = debug_info_function_ex(library->elf, library->abbrev_file, library->info_file, library->str_file, ra);
    }
    if (library->dynsym_file && library->dynstr_file) {
        sym = elf_sym(library->dynsym_file, library->dynstr_file, ra);
    }

    if (info && line) {
        fprintf(fp, "    %s() in %s:%d\n", info->function, line->file, line->line);
    }
    else if (info) {
        fprintf(fp, "    %s()+0x%"PRIx64" in %s\n", info->function, info->offset, library->name);
    }
    else if (sym.name) {
        fprintf(fp, "    %s()+0x%"PRIx64" in %s\n", sym.name, sym.offset, library->name);
    }
    else {
        fprintf(fp, "    %s:0x%zx\n", library->name, ra);
    }

    if (info) {
        debug_info_free(info);
    }
    if (line) {
        debug_line_info_free(line);
    }
}
*/

const library_t *libraries_find(const libraries_t *libraries, size_t address) {
    assert(libraries);
    return bsearch((void *) address, libraries->list, libraries->count, sizeof(library_t), so_bsearch_compar);
}

const library_t *libraries_find_by_name(const libraries_t *libraries, const char *regex) {
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

library_t *libraries_first(const libraries_t *libraries) {
    assert(libraries);
    return libraries->list;
}

/** Return the count of libraries */
size_t libraries_count(const libraries_t *libraries) {
    assert(libraries);
    return libraries->count;
}

size_t library_relative_address(const library_t *library, size_t address) {
    assert(library);
    return (address - ((size_t) library->begin)) + library->offset;
}

size_t library_absolute_address(const library_t *library, size_t address) {
    assert(library);
    return (address + ((size_t) library->begin)) + library->offset;
}
