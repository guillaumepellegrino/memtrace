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
const char *strmap_get(strmap_t *strmap, const char *key);

strmap_iterator_t *strmap_first(strmap_t *strmap);
strmap_iterator_t *strmap_iterator_next(strmap_iterator_t *strit);
const char *strmap_iterator_key(strmap_iterator_t *strit);
const char *strmap_iterator_value(strmap_iterator_t *strit);
