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

#include "types.h"

bool syscall_init(int pid);
int syscall_open(int pid, void *path, int flags, mode_t mode);
void *syscall_mmap(int pid, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int syscall_getpid(int pid);

#endif
