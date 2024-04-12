/*
 * Copyright (C) 2022 Guillaume Pellegrino
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

#ifndef MEMTRACE_SYSCALL
#define MEMTRACE_SYSCALL

#ifndef SYSCALL_PRIVATE
#define SYSCALL_PRIVATE __attribute__((deprecated))
#endif

#include "types.h"

typedef struct {
    int pid SYSCALL_PRIVATE;
    int memfd SYSCALL_PRIVATE;
    size_t syscall_instr SYSCALL_PRIVATE;
} syscall_ctx_t;

bool syscall_init(syscall_ctx_t *ctx, int pid, int memfd);
bool syscall_function(syscall_ctx_t *ctx, size_t function, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t *retval);
int syscall_open(syscall_ctx_t *ctx, void *path, int flags, mode_t mode);
void *syscall_mmap(syscall_ctx_t *ctx, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int syscall_munmap(syscall_ctx_t *ctx, void *addr, size_t length);
int syscall_getpid(syscall_ctx_t *ctx);

#endif
