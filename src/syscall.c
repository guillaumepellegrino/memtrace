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

#define SYSCALL_PRIVATE
#include "syscall.h"


void syscall_initialize(syscall_t *syscall, size_t number) {
    list_iterator_initialize(&syscall->it);
    syscall->number = number;
    syscall->handler = NULL;
    syscall->userdata = NULL;
}

void syscall_cleanup(syscall_t *syscall) {
    list_iterator_take(&syscall->it);
}

void syscall_set_handler(syscall_t *syscall, ftrace_handler_t handler, void *userdata) {
    syscall->handler = handler;
    syscall->userdata = userdata;
}

size_t syscall_number(syscall_t *syscall) {
    return syscall->number;
}

bool syscall_call(syscall_t *syscall, ftrace_fcall_t *fcall) {
    if (!syscall->handler) {
        return true;
    }

    return syscall->handler(fcall, syscall->userdata);
}

list_iterator_t *syscall_iterator(syscall_t *syscall) {
    return &syscall->it;
}

syscall_t *syscall_from_iterator(list_iterator_t *it) {
    return container_of(it, syscall_t, it);
}

