#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "agent.h"

static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;
static bool global_lock_init = false;
static agent_t g_agent = {0};


static void cleanup() {
    agent_cleanup(&g_agent);
}

static void try_initialize() {
    pthread_mutexattr_t attr;

    pthread_mutex_lock(&init_lock);
    if (global_lock_init) {
        pthread_mutex_unlock(&init_lock);
        return;
    }

    // initialize global lock
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&global_lock, &attr);
    global_lock_init = true;
    pthread_mutex_unlock(&init_lock);


    if (agent_initialize(&g_agent)) {
        atexit(cleanup);
    }
    else {
        printf("Failed to initialize memtrace agent\n");
    }
}

bool hooks_lock() {
    return pthread_mutex_lock(&global_lock) == 0;
}

void hooks_unlock(bool locked) {
    if (locked) {
        pthread_mutex_unlock(&global_lock);
    }
}

void *malloc_hook(size_t size) {
    bool locked = false;
    void *newptr = NULL;

    try_initialize();
    locked = hooks_lock();
    newptr = malloc(size);
    if (locked) {
        agent_malloc(&g_agent, size, newptr);
    }
    hooks_unlock(locked);

    return newptr;
}

void *calloc_hook(size_t nmemb, size_t size) {
    bool locked = false;
    void *newptr = NULL;

    try_initialize();
    locked = hooks_lock();
    newptr = calloc(nmemb, size);
    if (locked) {
        agent_calloc(&g_agent, nmemb, size, newptr);
    }
    hooks_unlock(locked);

    return newptr;
}

void *realloc_hook(void *ptr, size_t size) {
    bool locked = false;
    void *newptr = NULL;

    try_initialize();
    locked = hooks_lock();
    newptr = realloc(ptr, size);
    if (locked) {
        agent_realloc(&g_agent, ptr, size, newptr);
    }
    hooks_unlock(locked);

    return newptr;
}

void *reallocarray_hook(void *ptr, size_t nmemb, size_t size) {
    bool locked = false;
    void *newptr = NULL;

    try_initialize();
    locked = hooks_lock();
    newptr = reallocarray(ptr, nmemb, size);
    if (locked) {
        agent_reallocarray(&g_agent, ptr, nmemb, size, newptr);
    }
    hooks_unlock(locked);

    return newptr;
}

void free_hook(void *ptr) {
    bool locked = false;

    try_initialize();
    locked = hooks_lock();
    if (locked) {
        agent_free(&g_agent, ptr);
    }
    free(ptr);
    hooks_unlock(locked);
}
