/*
 * Copyright (C) 2022 Guillaume Pellegrino
 * This file is part of memtrace <https://github.com/guillaumepellegrino/memtrace>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
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
#include "log.h"

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
        TRACE_ERROR("Failed to initialize memtrace agent");
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
    size_t sp = stack_pointer_address();
    size_t ra = return_address();
    cpu_registers_t regs = {0};
    cpu_register_set(&regs, cpu_register_pc, (size_t) malloc);
    cpu_register_set(&regs, cpu_register_sp, sp);
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

pid_t fork_hook() {
    pid_t pid = fork();

    if (pid == 0) {
        // we do not follow child process allocations
        agent_unfollow_allocs(&g_agent);
    }

    return pid;
}

void *reallocarray_hook(void *ptr, size_t nmemb, size_t size) {
    size_t sp = stack_pointer_address();
    size_t ra = return_address();
    cpu_registers_t regs = {0};
    cpu_register_set(&regs, cpu_register_pc, (size_t) realloc);
    cpu_register_set(&regs, cpu_register_sp, sp);
    cpu_register_set(&regs, cpu_register_ra, ra);
    cpu_register_set(&regs, cpu_register_arg1, (size_t) ptr);
    cpu_register_set(&regs, cpu_register_arg2, nmemb);
    cpu_register_set(&regs, cpu_register_arg3, size);
    bool locked = false;
    void *newptr = NULL;

    try_initialize();
    locked = hooks_lock();
    // reallocarray() may not exist in old c library
    newptr = realloc(ptr, nmemb * size);
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
