#ifndef SYMCACHE_H
#define SYMCACHE_H

#include "types.h"
#include "list.h"
#include "strlist.h"

typedef struct _symcache symcache_t;
typedef struct _symcache_item symcache_item_t;

struct _symcache {
    list_t items;
    strlist_t nulls;
};

/** Cleanup the cache */
void symcache_cleanup(symcache_t *cache);

/** Push an ELF symbol into cache */
void symcache_push(symcache_t *cache, library_symbol_t *sym);

void symcache_push_null(symcache_t *cache, const char *name);

/** Find an ELF symbol in cache */
library_symbol_t *symcache_find(symcache_t *cache, const char *key);

#endif
