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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "strmap.h"

struct _strmap_iterator {
    list_iterator_t it;
    char *key;
    char *value;
};

void strmap_cleanup(strmap_t *strmap) {
    list_iterator_t *it = NULL;

    if (!strmap) {
        return;
    }

    while ((it = list_first(&strmap->list))) {
        strmap_iterator_t *strit = container_of(it, strmap_iterator_t, it);
        list_iterator_take(it);
        free(strit->key);
        free(strit->value);
        free(strit);
    }
}

void strmap_add(strmap_t *strmap, const char *key, const char *value) {
    strmap_iterator_t *strit = NULL;

    if (!strmap || !key || !value) {
        return;
    }

    assert((strit = calloc(1, sizeof(strmap_iterator_t))));
    list_append(&strmap->list, &strit->it);
    assert((strit->key = strdup(key)));
    assert((strit->value = strdup(value)));
}

void strmap_add_fmt(strmap_t *strmap, const char *key, const char *fmt, ...) {
    va_list ap;
    char *value = NULL;

    if (!strmap || !key || !fmt) {
        return;
    }

    va_start(ap, fmt);
    if (vasprintf(&value, fmt, ap) >= 0) {
        strmap_add(strmap, key, value);
        free(value);
    }
    va_end(ap);
}

const char *strmap_get(strmap_t *strmap, const char *key) {
    list_iterator_t *it = NULL;

    if (!strmap || !key) {
        return NULL;
    }

    list_for_each(it, &strmap->list) {
        strmap_iterator_t *strit = container_of(it, strmap_iterator_t, it);
        if (!strcmp(strit->key, key)) {
            return strit->value;
        }
    }

    return NULL;
}

int strmap_get_fmt(strmap_t *strmap, const char *key, const char *fmt, ...) {
    va_list ap;
    int count = 0;
    const char *value = NULL;

    va_start(ap, fmt);
    if ((value = strmap_get(strmap, key))) {
        count = vsscanf(value, fmt, ap);
    }
    va_end(ap);

    return count;
}

strmap_iterator_t *strmap_first(strmap_t *strmap) {
    list_iterator_t *it = NULL;

    if (!strmap) {
        return NULL;
    }
    if (!(it = list_first(&strmap->list))) {
        return NULL;
    }

    return container_of(it, strmap_iterator_t, it);
}

strmap_iterator_t *strmap_iterator_next(strmap_iterator_t *strit) {
    list_iterator_t *it = NULL;

    if (!strit) {
        return NULL;
    }
    if (!(it = list_iterator_next(&strit->it))) {
        return NULL;
    }

    return container_of(it, strmap_iterator_t, it);
}

const char *strmap_iterator_key(strmap_iterator_t *strit) {
    return strit ? strit->key : NULL;
}

const char *strmap_iterator_value(strmap_iterator_t *strit) {
    return strit ? strit->value : NULL;
}
