#include "types.h"
#include "list.h"

typedef struct _strmap strmap_t;

struct _strmap {
    list_t list;
};

static inline void strmap_initialize(strmap_t *strmap) {
    list_initialize(&strmap->list);
}

void strmap_cleanup(strmap_t *strmap);
void strmap_add(strmap_t *strmap, const char *key, const char *value);
const char *strmap_get(strmap_t *strmap, const char *key);
