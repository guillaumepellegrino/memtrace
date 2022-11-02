#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

// Disable optimization option to avoid memset() calling itself
#pragma GCC push_options
#pragma GCC optimize ("no-tree-pre")

char *strchr(const char *s, int c) {
    for (size_t i = 0; s[i]; i++) {
        if (s[i] == c) {
            return (char *) &s[i];
        }
    }
    return NULL;
}

char *strrchr(const char *s, int c) {
    char *last = NULL;
    for (size_t i = 0; s[i]; i++) {
        if (s[i] == c) {
            last = (char *) &s[i];
        }
    }
    return last;
}

int strcmp(const char *s1, const char *s2) {
    size_t i = 0;

    for (i = 0; s1[i] && s2[i]; i++) {
        if (s1[i] != s2[i]) {
            return s1[i] - s2[i];
        }
    }

    return s1[i] - s2[i];
}

size_t strlen(const char *s) {
    size_t i = 0;

    for (i = 0; s[i]; i++);

    return i;
}

void *memcpy(void *dest, const void *src, size_t n) {
    size_t i = 0;

    for (i = 0; i < n; i++) {
        ((unsigned char *) dest)[i] = ((unsigned char *) src)[i];
    }

    return dest;
}

void *memset(void *s, int c, size_t n) {
    size_t i = 0;

    for (i = 0; i < n; i++) {
        ((unsigned char *) s)[i] = c;
    }

    return s;
}

#pragma GCC pop_options
