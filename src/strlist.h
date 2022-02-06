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

#ifndef FTRACE_STRLIST_H
#define FTRACE_STRLIST_H

#ifndef STRLIST_PRIVATE
#define STRLIST_PRIVATE __attribute__((deprecated))
#endif

#include "types.h"
#include "list.h"

/** iterate through the strlist */
#define strlist_for_each(it, strlist) \
    for (it = strlist_first(strlist); it; it = strlist_iterator_next(it))

typedef struct {
    list_iterator_t it STRLIST_PRIVATE;
    char *value STRLIST_PRIVATE;
} strlist_iterator_t;

typedef struct {
    list_t list STRLIST_PRIVATE;
} strlist_t;

void strlist_initialize(strlist_t *strlist);
void strlist_cleanup(strlist_t *strlist);
void strlist_insert(strlist_t *strlist, const char *str);
void strlist_append(strlist_t *strlist, const char *str);
strlist_iterator_t *strlist_first(strlist_t *strlist);
strlist_iterator_t *strlist_last(strlist_t *strlist);
strlist_iterator_t *strlist_iterator_next(strlist_iterator_t *strit);
strlist_iterator_t *strlist_iterator_prev(strlist_iterator_t *strit);
const char *strlist_iterator_value(strlist_iterator_t *strit);

#endif
