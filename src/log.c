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

#include "types.h"
#include "log.h"
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

int verbose = 0;
int zone = 0;

void set_trace_zones(char *zones) {
    const char *item = NULL;
    size_t i = 0;

    for (item = strtok(zones, ", "); item; item = strtok(NULL, ",| ")) {
        for (i = 0; i < countof(zone_list); i++) {
            if (!strcmp(item, zone_list[i].str)) {
                zone |= zone_list[i].value;
            }
        }
    }
}

void print_trace_zones(FILE *fp) {
    size_t i = 0;
    for (i = 0; i < countof(zone_list); i++) {
        if (i != 0) {
            fprintf(fp, ", ");
        }
        fprintf(fp, "%s", zone_list[i].str);
    }
}
