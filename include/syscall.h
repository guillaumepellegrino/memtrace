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

#ifndef MEMTRACE_SYSCALL
#define MEMTRACE_SYSCALL

#ifndef SYSCALL_PRIVATE
#define SYSCALL_PRIVATE __attribute__((deprecated))
#endif

#include "types.h"
#include <sys/syscall.h>

typedef struct {
    int pid SYSCALL_PRIVATE;
    libraries_t *libraries SYSCALL_PRIVATE;
    int memfd SYSCALL_PRIVATE;
    bool do_coredump SYSCALL_PRIVATE;
    size_t bp_addr SYSCALL_PRIVATE;
} syscall_ctx_t;

typedef struct  {
    const char *name;
    int number;
} syscall_table_t;

extern const syscall_table_t syscall_table[];

bool syscall_initialize(syscall_ctx_t *ctx, int pid, libraries_t *libraries);
void syscall_cleanup(syscall_ctx_t *ctx);
int syscall_memfd(syscall_ctx_t *ctx);
bool syscall_function(syscall_ctx_t *ctx, size_t function, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t *retval);
bool syscall_hijack(syscall_ctx_t *ctx, size_t syscall, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6, size_t *ret);
int syscall_open(syscall_ctx_t *ctx, void *path, int flags, mode_t mode);
void *syscall_mmap(syscall_ctx_t *ctx, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int syscall_munmap(syscall_ctx_t *ctx, void *addr, size_t length);
int syscall_getpid(syscall_ctx_t *ctx);
void syscall_do_coredump_at_next_tampering(syscall_ctx_t *ctx);

int syscall_number(const char *name);
const char *syscall_name(int number);

#endif
