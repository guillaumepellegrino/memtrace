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

#ifndef HASHMAP_H
#define HASHMAP_H

#ifndef HASHMAP_PRIVATE
#define HASHMAP_PRIVATE __attribute__((deprecated))
#endif

#include "types.h"
#include "list.h"

typedef struct _hashmap_cfg hashmap_cfg_t;
typedef struct _hashmap hashmap_t;
typedef struct _hashmap_bucket hashmap_bucket_t;
typedef struct _hashmap_iterator hashmap_iterator_t;

/** return a hash of key */
typedef uint32_t (*hash_key_t)(hashmap_t *hashmap, void *key);

/** return true if both key matches */
typedef bool (*match_key_t)(hashmap_t *hashmap, void *lkey, void *rkey);

/** The comparison function must return an integer less than, equal to, or greater than zero if the first argument is  considered  to
    be  respectively less than, equal to, or greater than the second.  If two members compare as equal, their order in the sorted array is undefined. */
typedef int (*hashmap_compar_t)(const hashmap_iterator_t **lval, const hashmap_iterator_t **rval);

/** destroy key and iterator */
typedef void (*hashmap_iterator_destroy_t)(void *key, hashmap_iterator_t *iterator);

struct _hashmap_cfg {
    uint32_t size;                          /** hashmap size */
    hash_key_t hash;                        /** the hash function, used to hash the key */
    match_key_t match;                      /** the match function, used to verify if two keys match */
    hashmap_iterator_destroy_t destroy;     /** hashmap_iterator_t destructor */
};

struct _hashmap {
    hashmap_cfg_t cfg           HASHMAP_PRIVATE;
    hashmap_bucket_t *buckets   HASHMAP_PRIVATE;
    list_t iterators            HASHMAP_PRIVATE;
};

struct _hashmap_bucket {
    list_t iterators            HASHMAP_PRIVATE;
};

struct _hashmap_iterator {
    list_iterator_t hashmap_it  HASHMAP_PRIVATE;
    list_iterator_t bucket_it   HASHMAP_PRIVATE;
    void *key                   HASHMAP_PRIVATE;
};

/** Iterate through the iterators */
#define hashmap_for_each(it, hashmap) \
    for (it = hashmap_first(hashmap); it; it = hashmap_iterator_next(it))

/** Initialize hashmap according configuration */
void hashmap_initialize(hashmap_t *hashmap, const hashmap_cfg_t *cfg);

/** Clear the content of the hashmap */
void hashmap_clear(hashmap_t *hashmap);

/** Cleanup hashmap and clear the content of the hashmap */
void hashmap_cleanup(hashmap_t *hashmap);

/** Return the iterator matching the key */
hashmap_iterator_t *hashmap_get(hashmap_t *hashmap, void *key);

/** Add this iterator to hashmap using key */
void hashmap_add(hashmap_t *hashmap, void *key, hashmap_iterator_t *iterator);

/** Return the first iterator from hashmap */
hashmap_iterator_t *hashmap_first(hashmap_t *hashmap);

/** Return the next iterator from hashmap */
hashmap_iterator_t *hashmap_iterator_next(hashmap_iterator_t *iterator);

/** Destroy iterator and remove it from hashmap */
void hashmap_iterator_destroy(hashmap_iterator_t *iterator);

/** Sort the hashmap */
void hashmap_qsort(hashmap_t *hashmap, hashmap_compar_t compar);

#endif
