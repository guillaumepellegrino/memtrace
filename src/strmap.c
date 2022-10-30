#include <stdlib.h>
#include <string.h>
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
