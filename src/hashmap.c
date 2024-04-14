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

#define HASHMAP_PRIVATE
#include <assert.h>
#include <stdlib.h>
#include "hashmap.h"

void hashmap_initialize(hashmap_t *hashmap, const hashmap_cfg_t *cfg) {
    assert(hashmap);
    assert(cfg);
    assert(cfg->hash);
    assert(cfg->match);
    assert(cfg->size);

    hashmap->cfg = cfg[0];
    hashmap->buckets = calloc(sizeof(hashmap_bucket_t), cfg->size);
    list_initialize(&hashmap->iterators);
}

void hashmap_clear(hashmap_t *hashmap) {
    assert(hashmap);

    list_iterator_t *it;
    while ((it = list_first(&hashmap->iterators))) {
        hashmap_iterator_t *hashmap_iterator = container_of(it, hashmap_iterator_t, hashmap_it);
        hashmap_iterator_destroy(hashmap_iterator);
    }
}

void hashmap_cleanup(hashmap_t *hashmap) {
    hashmap_clear(hashmap);
    free(hashmap->buckets);
    hashmap->buckets = NULL;
}

hashmap_iterator_t *hashmap_get(hashmap_t *hashmap, void *key) {
    assert(hashmap);
    assert(key);

    hashmap_cfg_t *cfg = &hashmap->cfg;

    uint32_t idx = cfg->hash(hashmap, key) % cfg->size;

    list_iterator_t *it = NULL;
    list_for_each(it, &hashmap->buckets[idx].iterators) {
        hashmap_iterator_t *hashmap_iterator = container_of(it, hashmap_iterator_t, bucket_it);
        if (cfg->match(hashmap, hashmap_iterator->key, key)) {
            return hashmap_iterator;
        }
    }

    return NULL;
}

void hashmap_add(hashmap_t *hashmap, void *key, hashmap_iterator_t *iterator) {
    assert(hashmap);
    assert(key);
    assert(iterator);

    hashmap_cfg_t *cfg = &hashmap->cfg;
    uint32_t idx = cfg->hash(hashmap, key) % cfg->size;

    *iterator = (hashmap_iterator_t) {
        .key = key,
    };
    list_append(&hashmap->iterators, &iterator->hashmap_it);
    list_append(&hashmap->buckets[idx].iterators, &iterator->bucket_it);
}

hashmap_iterator_t *hashmap_first(hashmap_t *hashmap) {
    assert(hashmap);
    list_iterator_t *it = list_first(&hashmap->iterators);
    return it ? container_of(it, hashmap_iterator_t, hashmap_it) : NULL;
}

hashmap_iterator_t *hashmap_iterator_next(hashmap_iterator_t *iterator) {
    assert(iterator);
    list_iterator_t *it = list_iterator_next(&iterator->hashmap_it);
    return it ? container_of(it, hashmap_iterator_t, hashmap_it) : NULL;
}

void hashmap_iterator_destroy(hashmap_iterator_t *iterator) {
    list_t *list;
    hashmap_t *hashmap;

    assert(iterator);
    assert((list = iterator->hashmap_it.list));
    hashmap = container_of(list, hashmap_t, iterators);

    list_iterator_take(&iterator->bucket_it);
    list_iterator_take(&iterator->hashmap_it);
    if (hashmap->cfg.destroy) {
        hashmap->cfg.destroy(hashmap, iterator->key, iterator);
    }
}

void hashmap_qsort(hashmap_t *hashmap, hashmap_compar_t compar) {
    ssize_t i, size;
    hashmap_iterator_t **array, *it;

    assert(hashmap);

    /** Populate an array of iterators in HEAP */
    size = list_size(&hashmap->iterators);
    assert((array = calloc(size, sizeof(hashmap_iterator_t*))));
    for (i = 0, it = hashmap_first(hashmap); i < size; i++, it = hashmap_iterator_next(it)) {
        array[i] = it;
    }

    /** Sort the array */
    qsort(array, size, sizeof(hashmap_iterator_t *), (int (*)(const void *, const void *)) compar);

    /** Rebuild the list according array */
    list_cleanup(&hashmap->iterators);
    list_initialize(&hashmap->iterators);
    for (i = size-1; i >= 0; i--) {
        list_insert(&hashmap->iterators, &array[i]->hashmap_it);
    }

    free(array);
}

