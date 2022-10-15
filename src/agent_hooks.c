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
#include <ucontext.h>
#include "agent_hooks.h"
#include "agent.h"
#include "arch.h"

#define stack_pointer_address() (size_t) __builtin_frame_address(0)
#define return_address()        (size_t) __builtin_return_address(0)

static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;
static bool global_lock_init = false;
static agent_t g_agent = {0};


static void cleanup() {
    agent_cleanup(&g_agent);
}

static void try_initialize() {
    bool locked = false;
    pthread_mutexattr_t attr = {0};

    pthread_mutex_lock(&init_lock);
    if (global_lock_init) {
        pthread_mutex_unlock(&init_lock);
        return;
    }

    // initialize global lock and lock it
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutex_init(&global_lock, &attr);
    locked = hooks_lock();
    global_lock_init = true;
    pthread_mutex_unlock(&init_lock);

    // initialize agent
    if (agent_initialize(&g_agent)) {
        atexit(cleanup);
    }
    else {
        printf("Failed to initialize memtrace agent\n");
    }
    hooks_unlock(locked);
}

bool hooks_lock() {
    return pthread_mutex_lock(&global_lock) == 0;
}

void hooks_unlock(bool locked) {
    if (locked) {
        pthread_mutex_unlock(&global_lock);
    }
}

void *malloc_hook(size_t size, size_t arg2, size_t arg3) {
    //ucontext_t ucp = {0};
    //getcontext(&ucp);
    size_t sp = stack_pointer_address();
    size_t ra = return_address();
    cpu_registers_t regs = {0};
    cpu_register_set(&regs, cpu_register_pc, (size_t) malloc);
    cpu_register_set(&regs, cpu_register_sp, sp);
    //cpu_register_set(&regs, cpu_register_fp, ucp.uc_mcontext.gregs[REG_RBP]);
    cpu_register_set(&regs, cpu_register_ra, ra);
    cpu_register_set(&regs, cpu_register_arg1, size);
    cpu_register_set(&regs, cpu_register_arg2, arg2);
    cpu_register_set(&regs, cpu_register_arg3, arg3);
    bool locked = false;
    void *newptr = NULL;

    try_initialize();
    locked = hooks_lock();
    newptr = malloc(size);
    if (locked) {
        /*
        printf("RSP=0x%llx, RBP=0x%llx (sp=0x%p, fp=0x%zx),\n",
            ucp.uc_mcontext.gregs[REG_RSP],
            ucp.uc_mcontext.gregs[REG_RBP],
            &ucp,
            sp);
            */
        agent_alloc(&g_agent, &regs, size, newptr);
    }
    hooks_unlock(locked);

    return newptr;
}

void *calloc_hook(size_t nmemb, size_t size, size_t arg3) {
    size_t sp = stack_pointer_address();
    size_t ra = return_address();
    cpu_registers_t regs = {0};
    cpu_register_set(&regs, cpu_register_pc, (size_t) calloc);
    cpu_register_set(&regs, cpu_register_sp, sp);
    cpu_register_set(&regs, cpu_register_ra, ra);
    cpu_register_set(&regs, cpu_register_arg1, nmemb);
    cpu_register_set(&regs, cpu_register_arg2, size);
    cpu_register_set(&regs, cpu_register_arg3, arg3);
    bool locked = false;
    void *newptr = NULL;

    try_initialize();
    locked = hooks_lock();
    newptr = calloc(nmemb, size);
    if (locked) {
        agent_alloc(&g_agent, &regs, (nmemb*size), newptr);
    }
    hooks_unlock(locked);

    return newptr;
}

void *realloc_hook(void *ptr, size_t size) {
    size_t sp = stack_pointer_address();
    size_t ra = return_address();
    cpu_registers_t regs = {0};
    cpu_register_set(&regs, cpu_register_pc, (size_t) realloc);
    cpu_register_set(&regs, cpu_register_sp, sp);
    cpu_register_set(&regs, cpu_register_ra, ra);
    cpu_register_set(&regs, cpu_register_arg1, (size_t) ptr);
    cpu_register_set(&regs, cpu_register_arg2, size);
    bool locked = false;
    void *newptr = NULL;

    try_initialize();
    locked = hooks_lock();
    newptr = realloc(ptr, size);
    if (locked) {
        if (ptr) {
            agent_dealloc(&g_agent, ptr);
        }
        if (newptr) {
            agent_alloc(&g_agent, &regs, size, newptr);
        }
    }
    hooks_unlock(locked);

    return newptr;
}

void *reallocarray_hook(void *ptr, size_t nmemb, size_t size) {
    size_t sp = stack_pointer_address();
    size_t ra = return_address();
    cpu_registers_t regs = {0};
    cpu_register_set(&regs, cpu_register_pc, (size_t) reallocarray);
    cpu_register_set(&regs, cpu_register_sp, sp);
    cpu_register_set(&regs, cpu_register_ra, ra);
    cpu_register_set(&regs, cpu_register_arg1, (size_t) ptr);
    cpu_register_set(&regs, cpu_register_arg2, nmemb);
    cpu_register_set(&regs, cpu_register_arg3, size);
    bool locked = false;
    void *newptr = NULL;

    try_initialize();
    locked = hooks_lock();
    newptr = reallocarray(ptr, nmemb, size);
    if (locked) {
        if (ptr) {
            agent_dealloc(&g_agent, ptr);
        }
        if (newptr) {
            agent_alloc(&g_agent, &regs, (nmemb*size), newptr);
        }
    }
    hooks_unlock(locked);

    return newptr;
}

void free_hook(void *ptr) {
    bool locked = false;

    try_initialize();
    locked = hooks_lock();
    if (locked) {
        agent_dealloc(&g_agent, ptr);
    }
    free(ptr);
    hooks_unlock(locked);
}

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

void *memset(void *s, int c, size_t n) {
    size_t i = 0;

    for (i = 0; i < n; i++) {
        ((unsigned char *) s)[i] = c;
    }

    return s;
}
