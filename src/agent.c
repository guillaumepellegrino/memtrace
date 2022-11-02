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
#include <fcntl.h>
#include <pthread.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <pthread.h>
#include "agent.h"
#include "agent_hooks.h"
#include "libraries.h"
#include "elf_main.h"
#include "elf_file.h"
#include "coredump.h"
#include "evlp.h"
#include "bus.h"
#include "arch.h"
#include "log.h"

typedef struct {
    hashmap_iterator_t it;
    ssize_t count;
    ssize_t size;
    void **callstack;
    size_t number;
    bus_connection_t *do_coredump;
} block_t;

typedef struct {
    hashmap_iterator_t it;
    size_t ptr_size;
    void *ptr;
    block_t *block;
} allocation_t;

static uint32_t allocations_maps_hash(hashmap_t *hashmap, void *key) {
    size_t addr = (size_t) key;
    return addr >> 2;
}

static bool allocations_maps_match(hashmap_t *hashmap, void *lkey, void *rkey) {
    size_t laddr = (size_t) lkey;
    size_t raddr = (size_t) rkey;

    return laddr == raddr;
}

static void allocations_maps_destroy(hashmap_t *hashmap, void *key, hashmap_iterator_t *it) {
    agent_t *agent = container_of(hashmap, agent_t, allocations);
    allocation_t *allocation = container_of(it, allocation_t, it);

    block_t *block = allocation->block;
    block->count -= 1;
    block->size -= allocation->ptr_size;
    agent->stats.free_count += 1;
    agent->stats.free_size += allocation->ptr_size;
    agent->stats.byte_inuse -= allocation->ptr_size;
    agent->stats.count_inuse -= 1;
    if (block->count <= 0) {
        hashmap_iterator_destroy(&block->it);
    }

    free(allocation);
}

static uint32_t blocks_maps_hash(hashmap_t *hashmap, void *key) {
    agent_t *agent = container_of(hashmap, agent_t, blocks);
    size_t *callstack = key;
    uint32_t hash = 0;
    size_t i = 0;

    for (i = 0; i < agent->callstack_size && callstack[i]; i++) {
        hash ^= callstack[i];
    }

    return hash;
}

static bool blocks_maps_match(hashmap_t *hashmap, void *lkey, void *rkey) {
    agent_t *agent = container_of(hashmap, agent_t, blocks);
    size_t *lcallstack = lkey;
    size_t *rcallstack = rkey;
    size_t i = 0;

    for (i = 0; i < agent->callstack_size && lcallstack[i]; i++) {
        if (lcallstack[i] != rcallstack[i]) {
            return false;
        }
    }

    return true;
}

static int blocks_map_compar(const hashmap_iterator_t **lval, const hashmap_iterator_t **rval) {
    block_t *lblock = container_of(*lval, block_t, it);
    block_t *rblock = container_of(*rval, block_t, it);

    return rblock->count - lblock->count;
}

static void blocks_maps_destroy(hashmap_t *hashmap, void *key, hashmap_iterator_t *it) {
    agent_t *agent = container_of(hashmap, agent_t, blocks);
    block_t *block = container_of(it, block_t, it);
    agent->stats.block_inuse -= 1;
    free(block->callstack);
    free(block);
}


static int ipc_socket() {
    struct sockaddr_un bindaddr = {
        .sun_family = AF_UNIX,
    };
    int s = -1;

    if ((s = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0)) < 0) {
        TRACE_ERROR("Failed to create ipc socket: %m");
        return -1;
    }

    snprintf(bindaddr.sun_path, sizeof(bindaddr.sun_path),
        "/tmp/memtrace-agent-%d", getpid());

    if (bind(s, (struct sockaddr *) &bindaddr, sizeof(bindaddr)) != 0) {
        TRACE_ERROR("Failed to bind ipc socket to %s: %m", bindaddr.sun_path);
        return -1;
    }
    if (listen(s, 10) != 0) {
        TRACE_ERROR("Failed to listen ipc socket: %m");
        return -1;
    }

    return s;
}

static void ipc_socket_close(int ipc) {
    struct sockaddr_un bindaddr = {
        .sun_family = AF_UNIX,
    };

    close(ipc);
    snprintf(bindaddr.sun_path, sizeof(bindaddr.sun_path),
        "/tmp/memtrace-agent-%d", getpid());
    unlink(bindaddr.sun_path);
}

static bool agent_status(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {
    bool lock = hooks_lock();
    agent_t *agent = container_of(topic, agent_t, status_topic);
    //time_t now = time(NULL);
    fprintf(fp, "HEAP SUMMARY\n"/*, asctime(localtime(&now))*/);
    fprintf(fp, "    in use: %zu allocs, %zu bytes in %zu contexts\n",
        agent->stats.count_inuse, agent->stats.byte_inuse, agent->stats.block_inuse);
    fprintf(fp, "    total heap usage: %zu allocs, %zu frees, %zu bytes allocated\n",
        agent->stats.alloc_count, agent->stats.free_count, agent->stats.alloc_size);
    fprintf(fp, "[cmd_done]\n");
    fflush(fp);
    hooks_unlock(lock);

    return true;
}

static bool agent_report(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {
    bool lock = hooks_lock();
    agent_t *agent = container_of(topic, agent_t, report_topic);
    size_t i = 0;
    size_t max = 10;
    hashmap_iterator_t *it = NULL;

    strmap_get_fmt(options, "count", "%zu", &max);

    hashmap_qsort(&agent->blocks, blocks_map_compar);
    hashmap_for_each(it, &agent->blocks) {
        block_t *block = container_of(it, block_t, it);

        if (max > 0 && i >= max) {
            break;
        }

        fprintf(fp, "Memory allocation context n°%zu\n", i);
        fprintf(fp, "%zd allocs, %zd bytes were not free\n", block->count, block->size);
        libraries_backtrace_print(agent->libraries, block->callstack, agent->callstack_size, fp);
        fprintf(fp, "\n");

        i++;
    }

    fprintf(fp, "HEAP SUMMARY\n"/*, asctime(localtime(&now))*/);
    fprintf(fp, "    in use: %zu allocs, %zu bytes in %zu contexts\n",
        agent->stats.count_inuse, agent->stats.byte_inuse, agent->stats.block_inuse);
    fprintf(fp, "    total heap usage: %zu allocs, %zu frees, %zu bytes allocated\n",
        agent->stats.alloc_count, agent->stats.free_count, agent->stats.alloc_size);
    fprintf(fp, "[cmd_done]\n");
    fflush(fp);
    hooks_unlock(lock);

    return true;
}

static bool agent_clear(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {
    bool lock = hooks_lock();
    agent_t *agent = container_of(topic, agent_t, clear_topic);
    hashmap_clear(&agent->allocations);
    agent->stats.alloc_count = 0;
    agent->stats.alloc_size = 0;
    agent->stats.free_count = 0;
    agent->stats.free_size = 0;
    agent->stats.byte_inuse = 0;
    agent->stats.count_inuse = 0;
    agent->stats.block_inuse = 0;

    fprintf(fp, "List of allocations clear\n");
    fprintf(fp, "[cmd_done]\n");
    fflush(fp);
    hooks_unlock(lock);

    return true;
}

bus_connection_t *block_get_coredump_connection(block_t *block, bus_t *bus) {
    bus_connection_t *connection = NULL;

    if (!block->do_coredump) {
        goto error;
    }
    for (connection = bus_first_connection(bus); connection; connection = bus_connection_next(connection)) {
        if (block->do_coredump == connection) {
            break;
        }
    }
    if (!connection) {
        // connection no longer exist.
        block->do_coredump = NULL;
    }

error:
    return connection;
}

/**
 * Read coredump request and mark the specified context for coredump
 */
static bool agent_coredump(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {
    agent_t *agent = container_of(topic, agent_t, coredump_topic);
    size_t i = 0;
    size_t context_idx = 0;
    hashmap_iterator_t *it = NULL;
    block_t *block = NULL;
    int retval = false;
    const char *descr = "";
    bool lock = hooks_lock();

    strmap_get_fmt(options, "context", "%zu", &context_idx);

    // Lookup for context by index
    hashmap_qsort(&agent->blocks, blocks_map_compar);
    hashmap_for_each(it, &agent->blocks) {
        if (context_idx == i) {
            block = container_of(it, block_t, it);
            break;
        }
        i++;
    }
    if (!block) {
        descr = "Memory allocation context not found";
        goto error;
    }

    // Check if block is already marked for coredump.
    if (block_get_coredump_connection(block, &agent->bus)) {
        descr = "Memory allocation context already marked for coredump";
        goto error;
    }

    // Mark block for coredump.
    block->do_coredump = connection;
    retval = true;
    descr = "Waiting to hit memory allocation context";
    TRACE_WARNING("Memory context n°%zu marked for coredump generation", context_idx);
error:
    strmap_add_fmt(options, "retval", "%d", retval);
    strmap_add(options, "descr", descr);
    bus_connection_write_reply(connection, options);
    hooks_unlock(lock);
    return true;
}

void *ipc_accept_loop(void *arg) {
    agent_t *agent = arg;

    signal(SIGPIPE, SIG_IGN);

    TRACE_WARNING("Entered event loop");
    if (!bus_ipc_listen(&agent->bus, agent->ipc)) {
        TRACE_ERROR("Failed to listen on ipc socket");
        return NULL;
    }
    evlp_main(agent->evlp);
    TRACE_WARNING("Exiting event loop");

    return NULL;
}

bool agent_initialize(agent_t *agent) {
    log_set_header("[memtrace-agent]");
    if (!(agent->libraries = libraries_create(getpid()))) {
        TRACE_ERROR("Failed to create libraries");
        return false;
    }
    const hashmap_cfg_t allocations_maps_cfg = {
        .size       = 4000,
        .hash       = allocations_maps_hash,
        .match      = allocations_maps_match,
        .destroy    = allocations_maps_destroy,
    };
    const hashmap_cfg_t blocks_maps_cfg = {
        .size       = allocations_maps_cfg.size,
        .hash       = blocks_maps_hash,
        .match      = blocks_maps_match,
        .destroy    = blocks_maps_destroy,
    };
    agent->callstack_size = 10;
    hashmap_initialize(&agent->allocations, &allocations_maps_cfg);
    hashmap_initialize(&agent->blocks, &blocks_maps_cfg);

    libraries_print(agent->libraries, stdout);

    if ((agent->ipc = ipc_socket()) < 0) {
        return false;
    }

    if (pthread_create(&agent->thread, NULL, ipc_accept_loop, agent) != 0) {
        TRACE_ERROR("Failed to create thread: %m");
        return false;
    }

    agent->follow_allocs = true;


    agent->evlp = evlp_create();
    bus_initialize(&agent->bus, agent->evlp, "memtrace-agent", "memtrace");
    agent->status_topic.name = "status";
    agent->status_topic.read = agent_status;
    bus_register_topic(&agent->bus, &agent->status_topic);
    agent->report_topic.name = "report";
    agent->report_topic.read = agent_report;
    bus_register_topic(&agent->bus, &agent->report_topic);
    agent->clear_topic.name = "clear";
    agent->clear_topic.read = agent_clear;
    bus_register_topic(&agent->bus, &agent->clear_topic);
    agent->coredump_topic.name = "coredump";
    agent->coredump_topic.read = agent_coredump;
    bus_register_topic(&agent->bus, &agent->coredump_topic);

    return true;
}

void agent_cleanup(agent_t *agent) {
    bus_cleanup(&agent->bus);
    evlp_destroy(agent->evlp);
    libraries_destroy(agent->libraries);
    ipc_socket_close(agent->ipc);
    agent->follow_allocs = false;
}

void agent_unfollow_allocs(agent_t *agent) {
    agent->follow_allocs = false;
}

static void agent_notify_do_coredump(block_t *block, bus_connection_t *connection, cpu_registers_t *regs) {
    strmap_t options = {0};
    size_t tid = syscall(SYS_gettid);
    strmap_add_fmt(&options, "tid", "%zu", tid);
    strmap_add_fmt(&options, "pc", "%zu", cpu_register_get(regs, cpu_register_pc));
    strmap_add_fmt(&options, "sp", "%zu", cpu_register_get(regs, cpu_register_sp));
    strmap_add_fmt(&options, "fp", "%zu", cpu_register_get(regs, cpu_register_fp));
    strmap_add_fmt(&options, "ra", "%zu", cpu_register_get(regs, cpu_register_ra));
    strmap_add_fmt(&options, "arg1", "%zu", cpu_register_get(regs, cpu_register_arg1));
    strmap_add_fmt(&options, "arg2", "%zu", cpu_register_get(regs, cpu_register_arg2));
    strmap_add_fmt(&options, "arg3", "%zu", cpu_register_get(regs, cpu_register_arg3));
    TRACE_WARNING("Write NotifyDoCoredump request for %d", tid);
    bus_connection_write_request(connection, "NotifyDoCoredump", &options);
    bus_connection_read_reply(connection, NULL);
    TRACE_WARNING("NotifyDoCoredump done");
    block->do_coredump = NULL;
    strmap_cleanup(&options);
}

void agent_alloc(agent_t *agent, cpu_registers_t *regs, size_t size, void *newptr) {
    hashmap_iterator_t *it = NULL;
    void **callstack = NULL;
    block_t *block = NULL;
    allocation_t *allocation = NULL;
    bus_connection_t *connection = NULL;

    if (!agent->follow_allocs) {
        return;
    }
    if (pthread_self() == agent->thread) {
        // ignore allocation from the agent itself
        return;
    }

    assert((callstack = calloc(agent->callstack_size, sizeof(size_t))));
    libraries_backtrace(agent->libraries, regs, callstack, agent->callstack_size);


    //if (agent->dump_all) {
    //    libraries_backtrace_print(agent->libraries, callstack, agent->callstack_size, stdout);
    //}

    if ((it = hashmap_get(&agent->blocks, callstack))) {
        block = container_of(it, block_t, it);
        free(callstack);

        if ((connection = block_get_coredump_connection(block, &agent->bus))) {
            agent_notify_do_coredump(block, connection, regs);
        }
    }
    else {
        block = calloc(1, sizeof(block_t));
        assert(block);
        block->callstack = callstack;
        hashmap_add(&agent->blocks, block->callstack, &block->it);
        agent->stats.block_inuse += 1;
    }

    // create allocation
    assert((allocation = calloc(1, sizeof(allocation_t))));
    assert(allocation);
    allocation->ptr_size = size;
    allocation->ptr = newptr;
    allocation->block = block;
    hashmap_add(&agent->allocations, newptr, &allocation->it);

    // increment statistics
    block->count += 1;
    block->size += size;
    agent->stats.alloc_count += 1;
    agent->stats.alloc_size += size;
    agent->stats.byte_inuse += size;
    agent->stats.count_inuse += 1;
}

void agent_dealloc(agent_t *agent, void *ptr) {
    hashmap_iterator_t *it = NULL;

    if (!agent->follow_allocs) {
        return;
    }
    if (pthread_self() == agent->thread) {
        // ignore allocation from the agent itself
        return;
    }

    if (ptr && (it = hashmap_get(&agent->allocations, ptr))) {
        allocation_t *allocation = container_of(it, allocation_t, it);
        hashmap_iterator_destroy(&allocation->it);
    }
}
