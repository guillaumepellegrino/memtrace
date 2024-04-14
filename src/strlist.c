/*
 * Copyright (C) 2021 Guillaume Pellegrino
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

#define STRLIST_PRIVATE
#include <stdlib.h>
#include <string.h>
#include "strlist.h"

void strlist_initialize(strlist_t *strlist) {
    assert(strlist);
    list_initialize(&strlist->list);
}

void strlist_cleanup(strlist_t *strlist) {
    list_iterator_t *it = NULL;

    assert(strlist);
    while ((it = list_first(&strlist->list))) {
        strlist_iterator_t *strit = container_of(it, strlist_iterator_t, it);
        list_iterator_take(&strit->it);
        free(strit->value);
        free(strit);
    }
}

void strlist_insert(strlist_t *strlist, const char *str) {
    strlist_iterator_t *strit = NULL;

    assert(strlist);
    assert(str);
    assert((strit = calloc(1, sizeof(strlist_iterator_t))));
    list_insert(&strlist->list, &strit->it);
    assert((strit->value = strdup(str)));
}

#include "log.h"
void strlist_append(strlist_t *strlist, const char *str) {
    strlist_iterator_t *strit = NULL;

    assert(strlist);
    assert(str);
    assert((strit = calloc(1, sizeof(strlist_iterator_t))));
    list_append(&strlist->list, &strit->it);
    assert((strit->value = strdup(str)));
}

strlist_iterator_t *strlist_first(strlist_t *strlist) {
    assert(strlist);

    list_iterator_t *it = list_first(&strlist->list);
    return it ? container_of(it, strlist_iterator_t, it) : NULL;
}

strlist_iterator_t *strlist_last(strlist_t *strlist) {
    assert(strlist);

    list_iterator_t *it = list_last(&strlist->list);
    return it ? container_of(it, strlist_iterator_t, it) : NULL;
}

strlist_iterator_t *strlist_iterator_next(strlist_iterator_t *strit) {
    assert(strit);

    list_iterator_t *it = list_iterator_next(&strit->it);
    return it ? container_of(it, strlist_iterator_t, it) : NULL;
}

strlist_iterator_t *strlist_iterator_prev(strlist_iterator_t *strit) {
    assert(strit);

    list_iterator_t *it = list_iterator_prev(&strit->it);
    return it ? container_of(it, strlist_iterator_t, it) : NULL;
}

const char *strlist_iterator_value(strlist_iterator_t *strit) {
    assert(strit);
    return strit->value;
}
