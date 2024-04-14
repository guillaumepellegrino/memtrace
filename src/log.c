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

#include "types.h"
#include "log.h"
#include <stdarg.h>
#include <string.h>

static const struct {
    int value;
    const char *str;
} zone_list[] = {
    {TRACE_ZONE_MAIN,           "main"},
    {TRACE_ZONE_DEBUG_FRAME,    "debug_frame"},
    {TRACE_ZONE_DEBUG_INFO,     "debug_info"},
    {TRACE_ZONE_DEBUG_LINE,     "debug_line"},
    {TRACE_ZONE_UNWIND,         "unwind"},
    {TRACE_ZONE_CONSOLE,        "console"},
    {TRACE_ZONE_COREDUMP,       "coredump"},
};

static const char *g_log_header = "";
int g_verbose = 1;
int g_zone = 0;

static const char *level2str(int level) {
    switch (level) {
        case 0:  return "ERR";
        case 1:  return "WRN";
        case 2:  return "LOG";
        case 3:  return "DBG";
        default: return "UKW";
    }
}

void log_set_header(const char *header) {
    g_log_header = header;
}

void log_more_verbose() {
    g_verbose++;
}

void log_set_trace_zones(char *zones) {
    const char *item = NULL;
    size_t i = 0;

    for (item = strtok(zones, ", "); item; item = strtok(NULL, ",| ")) {
        for (i = 0; i < countof(zone_list); i++) {
            if (!strcmp(item, zone_list[i].str)) {
                g_zone |= zone_list[i].value;
            }
        }
    }
}

void log_print_trace_zones(FILE *fp) {
    size_t i = 0;
    for (i = 0; i < countof(zone_list); i++) {
        if (i != 0) {
            fprintf(fp, ", ");
        }
        fprintf(fp, "%s", zone_list[i].str);
    }
}

void log_trace_print(int level, int zone_arg, const char *funct, int line, const char *fmt, ...) {
    va_list va;
    if (g_verbose >= level || g_zone & zone_arg) {
        va_start(va, fmt);
        fprintf(stderr, "%s[%s]  ", g_log_header, level2str(level));
        vfprintf(stderr, fmt, va);
        fprintf(stderr, " in %s:%d\n", funct, line);
        va_end(va);
    }
}
