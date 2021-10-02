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

#ifndef FTRACE_LOG_H
#define FTRACE_LOG_H

#include <stdio.h>

extern int verbose;
extern int zone;

#define TRACE_ZONE_NONE         0
#define TRACE_ZONE_MAIN         1 << 0
#define TRACE_ZONE_DEBUG_FRAME  1 << 1
#define TRACE_ZONE_DEBUG_INFO   1 << 2
#define TRACE_ZONE_DEBUG_LINE   1 << 3
#define TRACE_ZONE_UNWIND       1 << 4
#define TRACE_ZONE_CONSOLE      1 << 5

#ifndef TRACE_ZONE
#define TRACE_ZONE TRACE_ZONE_NONE
#endif


#define TRACE_DEBUG(fmt, ...) \
    do { \
        if (verbose >= 2 || zone & TRACE_ZONE) { \
            fprintf(stderr, "[DBG]  " fmt " in %s:%d\n", ##__VA_ARGS__, __FUNCTION__, __LINE__); \
        } \
    } while (0)

#define TRACE_LOG(fmt, ...) \
    do { \
        if (verbose >= 1 || zone & TRACE_ZONE) { \
            fprintf(stderr, "[LOG]  " fmt " in %s:%d\n", ##__VA_ARGS__, __FUNCTION__, __LINE__); \
        } \
    } while (0)

#define TRACE_WARNING(fmt, ...) \
    fprintf(stderr, "[WRN]  " fmt " in %s:%d\n", ##__VA_ARGS__, __FUNCTION__, __LINE__);

#define TRACE_ERROR(fmt, ...) \
    fprintf(stderr, "[ERR]  " fmt " in %s:%d\n", ##__VA_ARGS__, __FUNCTION__, __LINE__);

#define TRACE_ASSERT(value, fmt, ...) \
    do { \
        if ((value) != 0) { \
            fprintf(stderr, "[ASSERTION ERROR]  " fmt " in %s:%d\n", ##__VA_ARGS__, __FUNCTION__, __LINE__); \
            assert(0); \
        } \
    } while (0)

#define CONSOLE(fmt, ...) \
    fprintf(stderr, fmt "\n", ##__VA_ARGS__)

#define CONSOLE_RAW(fmt, ...) \
    fprintf(stderr, fmt, ##__VA_ARGS__)

#ifdef DWARF_DEBUG
#define TRACE_DWARF(fmt, ...) TRACE_DEBUG(fmt, ##__VA_ARGS__)
#else
#define TRACE_DWARF(fmt, ...) trace_debug_unused(fmt, ##__VA_ARGS__)
#endif


static inline void trace_debug_unused(const char *fmt, ...) {
    (void) fmt;
}

void set_trace_zones(char *zones);
void print_trace_zones(FILE *fp);

#endif
