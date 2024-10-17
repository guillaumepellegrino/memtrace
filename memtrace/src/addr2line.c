/*
 * Copyright (C) 2021 Guillaume Pellegrino
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

#define ADDR2LINE_PRIVATE
#include "addr2line.h"
#include "log.h"
#include "process.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    list_iterator_t it;
    char *so;
    process_t process;
} addr2line_process_t;

static addr2line_process_t *addr2line_find_by_so(addr2line_t *ctx, const char *so) {
    list_iterator_t *it = NULL;

    list_for_each(it, &ctx->list) {
        addr2line_process_t *addr2line = container_of(it, addr2line_process_t, it);
        if (!strcmp(addr2line->so, so)) {
            return addr2line;
        }
    }

    return NULL;
}

static addr2line_process_t *addr2line_create(addr2line_t *ctx, const char *so) {
    addr2line_process_t *addr2line = NULL;
    const char *cmd[] = {ctx->binary, "-e", so, "-f", NULL};

    assert((addr2line = calloc(1, sizeof(addr2line_process_t))));
    assert((addr2line->so = strdup(so)));
    if (!process_start(&addr2line->process, cmd)) {
        TRACE_ERROR("Failed to start %s", ctx->binary);
    }
    list_insert(&ctx->list, &addr2line->it);

    return addr2line;
}

static void addr2line_destroy(addr2line_process_t *addr2line) {
    list_iterator_take(&addr2line->it);
    free(addr2line->so);
    process_stop(&addr2line->process);
    free(addr2line);
}

static const char *addr2line_process_readline(addr2line_process_t *addr2line) {
    static char line[4096];

    if (addr2line->process.output) {
        if (!fgets(line, sizeof(line), addr2line->process.output)) {
            TRACE_ERROR("Failed to read line from %s: %m", addr2line->so);
            process_stop(&addr2line->process);
        }

        char *eol = strchr(line, '\n');
        if (eol) {
            *eol = 0;
        }
    }

    return line;
}

static void addr2line_resolve(addr2line_process_t *addr2line, uint64_t address, FILE *out) {
    bool error = false;
    const char *line = NULL;

    if (process_get_pid(&addr2line->process) <= 0) {
        fprintf(out, "%s:0x%"PRIx64" (addr2line error)\n", addr2line->so, address);
        return;
    }

    fprintf(addr2line->process.input, "0x%"PRIx64"\n", address);
    fflush(addr2line->process.input);

    line = addr2line_process_readline(addr2line);
    if (!strcmp(line, "??")) {
        //fprintf(out, "0x%"PRIx64" in %s\n", address, addr2line->so);
        error = true;
    }
    else {
        fprintf(out, "%s()", line);
    }

    line = addr2line_process_readline(addr2line);
    if (!error) {
        if (!strcmp(line, ":?")) {
            fprintf(out, " in %s\n", addr2line->so);
        }
        else {
            fprintf(out, " in %s\n", line);
        }
    }
}


void addr2line_initialize(addr2line_t *ctx, const char *binary) {
    assert(ctx);
    assert(binary);
    memset(ctx, 0, sizeof(addr2line_t));
    ctx->binary = strdup(binary);
}

void addr2line_cleanup(addr2line_t *ctx) {
    list_iterator_t *it = NULL;

    assert(ctx);
    while ((it = list_first(&ctx->list))) {
        addr2line_process_t *addr2line = container_of(it, addr2line_process_t, it);
        addr2line_destroy(addr2line);
    }
    free(ctx->binary);
}

void addr2line_print(addr2line_t *ctx, const char *so, uint64_t address, FILE *out) {
    addr2line_process_t *addr2line = NULL;

    assert(ctx);
    assert(so);
    assert(out);

    TRACE_LOG("%s -e %s -f 0x%"PRIx64, ctx->binary, so, address);
    if (!(addr2line = addr2line_find_by_so(ctx, so))) {
        addr2line = addr2line_create(ctx, so);
    }

    addr2line_resolve(addr2line, address, out);
}
