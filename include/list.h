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

#ifndef FTRACE_LIST_H
#define FTRACE_LIST_H

/** iterate through the list */
#define list_for_each(it, list) \
    for (it = list_first(list); it; it = list_iterator_next(it))

typedef struct _list_iterator list_iterator_t;
typedef struct _list list_t;

/** a linked list */
struct _list {
    list_iterator_t *first;
    list_iterator_t *last;
};

/** linked list iterator */
struct _list_iterator {
    list_t *list;
    list_iterator_t *next;
    list_iterator_t *prev;
};

/** intialize list */
static inline void list_initialize(list_t *list) {
    list->first = NULL;
    list->last = NULL;
}

/** insert a new iterator at the head of the list */
static inline void list_insert(list_t *list, list_iterator_t *it) {
    it->list = list;
    it->next = list->first;
    it->prev = NULL;
    if (list->first) {
        list->first->prev = it;
    }
    list->first = it;
    if (!list->last) {
        list->last = it;
    }
}

/** append a new iterator at the tail of the list */
static inline void list_append(list_t *list, list_iterator_t *it) {
    it->list = list;
    it->next = NULL;
    it->prev = list->last;
    if (list->last) {
        list->last->next = it;
    }
    list->last = it;
    if (!list->first) {
        list->first = it;
    }
}

/** return the first iterator from the list */
static inline list_iterator_t *list_first(list_t *list) {
    return list->first;
}

/** return the last iterator from the list */
static inline list_iterator_t *list_last(list_t *list) {
    return list->last;
}

/** return next it from the list */
static inline list_iterator_t *list_iterator_next(list_iterator_t *it) {
    return it->next;
}

/** return prev it from the list */
static inline list_iterator_t *list_iterator_prev(list_iterator_t *it) {
    return it->prev;
}

/** take iterator from list */
static inline void list_iterator_take(list_iterator_t *it) {
    list_t *list = it->list;
    list_iterator_t *next = it->next;
    list_iterator_t *prev = it->prev;
    if (list) {
        if (list->first == it) {
            list->first = it->next;
        }
        if (list->last == it) {
            list->last = it->prev;
        }
        if (prev) {
            prev->next = next;
        }
        if (next) {
            next->prev = prev;
        }
        it->list = NULL;
        it->next = NULL;
        it->prev = NULL;
    }
}

/** initialize list iterator */
static inline void list_iterator_initialize(list_iterator_t *it) {
    it->list = NULL;
    it->next = NULL;
    it->prev = NULL;
}

/** cleanup list iterator */
static inline void list_cleanup(list_t *list) {
    list_iterator_t *it;
    while ((it = list_first(list))) {
        list_iterator_take(it);
    }
}

static inline size_t list_size(list_t *list) {
    size_t size = 0;
    list_iterator_t *it;
    list_for_each(it, list) {
        size++;
    }
    return size;
}

#endif
