#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "symcache.h"
#include "libraries.h"

struct _symcache_item {
    list_iterator_t it;
    library_symbol_t sym;
};

static library_symbol_t nullsym = {0};

void symcache_cleanup(symcache_t *cache) {
    assert(cache);

    list_iterator_t *it = NULL;

    strlist_cleanup(&cache->nulls);
    while ((it = list_first(&cache->items))) {
        symcache_item_t *item = container_of(it, symcache_item_t, it);
        list_iterator_take(&item->it);
        free(item);
    }
}

void symcache_push(symcache_t *cache, library_symbol_t *sym) {
    assert(cache);
    assert(sym);

    symcache_item_t *item = calloc(1, sizeof(symcache_item_t));
    memcpy(&item->sym, sym, sizeof(*sym));
    list_insert(&cache->items, &item->it);
}

void symcache_push_null(symcache_t *cache, const char *key) {
    assert(cache);
    assert(key);

    strlist_insert(&cache->nulls, key);
}

library_symbol_t *symcache_find(symcache_t *cache, const char *key) {
    assert(cache);
    assert(key);

    list_iterator_t *it = NULL;

    if (strlist_contains(&cache->nulls, key)) {
        return &nullsym;
    }

    list_for_each(it, &cache->items) {
        symcache_item_t *item = container_of(it, symcache_item_t, it);
        if (!strcmp(key, item->sym.name)) {
            return &item->sym;
        }
    }

    return NULL;
}
