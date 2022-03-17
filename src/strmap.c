#include <stdlib.h>
#include <string.h>
#include "strmap.h"

typedef struct {
    list_iterator_t it;
    char *key;
    char *value;
} strmap_iterator_t;

void strmap_cleanup(strmap_t *strmap) {
    list_iterator_t *it = NULL;

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

    assert((strit = calloc(1, sizeof(strmap_iterator_t))));
    list_append(&strmap->list, &strit->it);
    assert((strit->key = strdup(key)));
    assert((strit->value = strdup(value)));
}

const char *strmap_get(strmap_t *strmap, const char *key) {
    list_iterator_t *it = NULL;
    list_for_each(it, &strmap->list) {
        strmap_iterator_t *strit = container_of(it, strmap_iterator_t, it);
        if (!strcmp(strit->key, key)) {
            return strit->value;
        }
    }

    return NULL;
}
