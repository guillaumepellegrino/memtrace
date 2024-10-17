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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <poll.h>
#include "gdb.h"
#include "net.h"
#include "log.h"

static void gdb_print(gdb_t *gdb, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(gdb->userout, fmt, ap);
    va_end(ap);
}

static void gdb_expect(gdb_t *gdb, const char *expect) {
    int i = 0;
    int c = 0;
    while ((c = fgetc(gdb->process.output)) != EOF) {
        fputc(c, gdb->userout);
        fflush(gdb->userout);

        if (c == '\n') {
            i = 0;
            continue;
        }

        g_buff[i++] = c;
        g_buff[i] = 0;

        if (!strncmp(g_buff, expect, strlen(expect))) {
            break;
        }
    }
}

static void gdb_cmd(gdb_t *gdb, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(gdb->userout, fmt, ap);
    va_end(ap);

    va_start(ap, fmt);
    vfprintf(gdb->process.input, fmt, ap);
    va_end(ap);

    fflush(gdb->process.input);
    gdb_expect(gdb, "(gdb) ");
}

bool gdb_initialize(gdb_t *gdb, const gdb_cfg_t *cfg) {
    const char *argv[] = {cfg->gdb_binary, NULL};

    if (!cfg->gdb_binary) {
        TRACE_ERROR("Missing gdb binary");
        return false;
    }
    if (!cfg->sysroot) {
        TRACE_ERROR("Missing gdb sysroot");
        return false;
    }
    if (!cfg->tgt_binary) {
        TRACE_ERROR("Missing gdb target binary");
        return false;
    }
    if (!cfg->coredump) {
        TRACE_ERROR("Missing gdb target binary");
        return false;
    }
    if (!cfg->userin || !cfg->userout) {
        TRACE_ERROR("Missing user input or output parameter");
        return false;
    }

    gdb->userin = cfg->userin;
    gdb->userout = cfg->userout;
    gdb_print(gdb, "Starting process '%s'\n", cfg->gdb_binary);
    if (!process_start(&gdb->process, argv)) {
        TRACE_ERROR("Failed to start gdb");
        return false;
    }

    gdb_expect(gdb, "(gdb) ");
    gdb_cmd(gdb, "set sysroot %s\n", cfg->sysroot);
    strlist_iterator_t *it = NULL;
    strlist_for_each(it, cfg->solib_search_path) {
        const char *str = strlist_iterator_value(it);
        gdb_cmd(gdb, "set solib-search-path %s\n", str);
    }
    gdb_cmd(gdb, "directory .\n");
    gdb_cmd(gdb, "file %s\n", cfg->tgt_binary);
    gdb_cmd(gdb, "core-file %s\n", cfg->coredump);

    return true;
}

void gdb_cleanup(gdb_t *gdb) {
    process_stop(&gdb->process);
}

void gdb_backtrace(gdb_t *gdb) {
    gdb_cmd(gdb, "backtrace\n");
}

bool gdb_interact(gdb_t *gdb) {
    enum {
        GDBOUT,
        USERIN,
    };

    int gdbin = fileno(gdb->process.input);
    int gdbout = fileno(gdb->process.output);
    int userin = fileno(gdb->userin);
    int userout = fileno(gdb->userout);

    fflush(gdb->process.output);
    fflush(gdb->userout);

    while (true) {
        struct pollfd fds[] = {
            [GDBOUT] = {
                .fd = gdbout,
                .events = POLLIN,
            },
            [USERIN] = {
                .fd = userin,
                .events = POLLIN,
            },
        };

        if (poll(fds, countof(fds), -1) < 0) {
            TRACE_ERROR("poll error: %m");
            break;
        }

        if (fds[GDBOUT].revents & POLLIN) {
            if (!fd_transfer(gdbout, userout)) {
                TRACE_ERROR("Failed to transfer gdb output to user output");
                return false;
            }
        }
        if (fds[USERIN].revents & POLLIN) {
            if (!fd_transfer(userin, gdbin)) {
                TRACE_ERROR("Failed to transfer user input to user input");
                return false;
            }
        }
        if (fds[GDBOUT].revents & POLLHUP) {
            TRACE_ERROR("gdbout POLLHUP");
            return true;
        }
        if (fds[USERIN].revents & POLLHUP) {
            TRACE_ERROR("userin POLLHUP");
            return false;
        }
    };

    return true;
}
