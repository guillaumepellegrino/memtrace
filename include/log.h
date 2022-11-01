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
#define TRACE_ZONE_COREDUMP     1 << 6

#ifndef TRACE_ZONE
#define TRACE_ZONE TRACE_ZONE_NONE
#endif

#define TRACE_DEBUG(fmt, ...) \
    log_trace_print(3, TRACE_ZONE, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

#define TRACE_LOG(fmt, ...) \
    log_trace_print(2, TRACE_ZONE, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

#define TRACE_WARNING(fmt, ...) \
    log_trace_print(1, TRACE_ZONE, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

#define TRACE_ERROR(fmt, ...) \
    log_trace_print(0, TRACE_ZONE, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

#define CONSOLE(fmt, ...) \
    fprintf(stderr, fmt "\n", ##__VA_ARGS__)

#define CONSOLE_RAW(fmt, ...) \
    fprintf(stderr, fmt, ##__VA_ARGS__)

void log_set_header(const char *header);
void log_more_verbose();
void log_set_trace_zones(char *zones);
void log_print_trace_zones(FILE *fp);
void log_trace_print(int level, int zone_arg, const char *funct, int line, const char *fmt, ...);


#endif
