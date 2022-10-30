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

#ifndef FTRACE_TYPES_H
#define FTRACE_TYPES_H

#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>

#if (SIZE_MAX == UINT64_MAX)
#define __64BIT
#elif (SIZE_MAX == UINT32_MAX)
#define __32BIT
#else
#error "Unknown Architecture"
#endif

#define container_of(item, type, member) \
    ((type *)(((void *) item) - offsetof(type, member)))

#define countof(array) (sizeof(array)/sizeof(*array))
#define min(lval, rval) (((lval) < (rval)) ? (lval) : (rval))
#define max(lval, rval) (((lval) > (rval)) ? (lval) : (rval))
#define when_null(_op, _label) if (!(_op)) { goto _label; }
#define when_true(_op, _label) if ((_op)) { goto _label; }
#define G_BUFF_SIZE 32768

typedef enum _breakpoint_state breakpoint_state_t;
typedef union _variant_value variant_value_t;

typedef struct _evlp evlp_t;
typedef struct _evlp_handler evlp_handler_t;
typedef struct _backtrace backtrace_t;
typedef struct _libraries libraries_t;
typedef struct _library library_t;
typedef struct _elf elf_t;
typedef struct _elf_header elf_header_t;
typedef struct _program_header program_header_t;
typedef struct _section_header section_header_t;
typedef struct _elf_file elf_file_t;
typedef enum _fs_type fs_type_t;
typedef struct _fs_cfg fs_cfg_t;
typedef struct _fs fs_t;
typedef struct _console_cmd console_cmd_t;
typedef struct _console console_t;
typedef struct _cpu_registers cpu_registers_t;
typedef struct _strmap strmap_t;
typedef struct _strmap_iterator strmap_iterator_t;


union _variant_value {
    uint8_t  u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    int8_t   i8;
    int16_t  i16;
    int32_t  i32;
    int64_t  i64;
    const char *str;
};

struct _evlp_handler {
    void (*fn)(evlp_handler_t *self, int events);
};

extern char g_buff[G_BUFF_SIZE];

#endif
