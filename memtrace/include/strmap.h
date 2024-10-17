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

#pragma once

#include "types.h"
#include "list.h"

struct _strmap {
    list_t list;
};

#define strmap_for_each(it, strmap) \
    for (it = strmap_first(strmap); it; it = strmap_iterator_next(it))

static inline void strmap_initialize(strmap_t *strmap) {
    list_initialize(&strmap->list);
}

void strmap_cleanup(strmap_t *strmap);
void strmap_add(strmap_t *strmap, const char *key, const char *value);
void strmap_add_fmt(strmap_t *strmap, const char *key, const char *fmt, ...);
const char *strmap_get(strmap_t *strmap, const char *key);
int strmap_get_fmt(strmap_t *strmap, const char *key, const char *fmt, ...);

strmap_iterator_t *strmap_first(strmap_t *strmap);
strmap_iterator_t *strmap_iterator_next(strmap_iterator_t *strit);
const char *strmap_iterator_key(strmap_iterator_t *strit);
const char *strmap_iterator_value(strmap_iterator_t *strit);

