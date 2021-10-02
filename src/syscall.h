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

#ifndef PTRACE_SYSCALL_H
#define PTRACE_SYSCALL_H

#ifndef SYSCALL_PRIVATE
#define SYSCALL_PRIVATE __attribute__((deprecated))
#endif

#include "ftrace.h"


struct _syscall {
    list_iterator_t it;
    size_t number               SYSCALL_PRIVATE;
    ftrace_handler_t handler    SYSCALL_PRIVATE;
    void *userdata              SYSCALL_PRIVATE;
};

void syscall_initialize(syscall_t *syscall, size_t number);
void syscall_cleanup(syscall_t *syscall);
void syscall_set_handler(syscall_t *syscall, ftrace_handler_t handler, void *userdata);
size_t syscall_number(syscall_t *syscall);
bool syscall_call(syscall_t *syscall, ftrace_fcall_t *fcall);
list_iterator_t *syscall_iterator(syscall_t *syscall);
syscall_t *syscall_from_iterator(list_iterator_t *it);



#endif
