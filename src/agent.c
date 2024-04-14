/*
 * Copyright (C) 2022 Guillaume Pellegrino
 * This file is part of memtrace <https://github.com/guillaumepellegrino/memtrace>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
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
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <pthread.h>
#include "agent.h"
#include "agent_hooks.h"
#include "libraries.h"
#include "elf_main.h"
#include "elf_file.h"
#include "evlp.h"
#include "bus.h"
#include "arch.h"
#include "log.h"

typedef struct {
    hashmap_iterator_t it;
    list_t allocations;
    ssize_t count;
    ssize_t size;
    void **callstack;
    void **large_callstack;
    size_t number;
    bool do_large_callstack;
} block_t;

typedef struct {
    hashmap_iterator_t it;
    list_iterator_t block_it;
    size_t ptr_size;
    void *ptr;
    size_t when;
    block_t *block;
} allocation_t;

static inline void sample_circbuf_append(sample_circbuf_t *circbuf, sample_t value) {
    circbuf->values[circbuf->wridx] = value;
    circbuf->wridx += 1;
    circbuf->wridx %= countof(circbuf->values);
}

static inline size_t sample_circbuf_first_idx(sample_circbuf_t *circbuf) {
    return circbuf->wridx;
}

static inline size_t sample_circbuf_last_idx(sample_circbuf_t *circbuf) {
    size_t idx = circbuf->wridx;
    return (idx != 0) ? (idx - 1) : (countof(circbuf->values) - 1);
}

static inline sample_t sample_circbuf_first(sample_circbuf_t *circbuf) {
    return circbuf->values[sample_circbuf_first_idx(circbuf)];
}

static inline sample_t sample_circbuf_last(sample_circbuf_t *circbuf) {
    return circbuf->values[sample_circbuf_last_idx(circbuf)];
}

static inline sample_t sample_circbuf_last_sub_first(sample_circbuf_t *circbuf) {
    sample_t last = sample_circbuf_last(circbuf);
    sample_t first = sample_circbuf_first(circbuf);
    last.bytes -= first.bytes;
    last.count -= first.count;
    return last;
}

static const char *toolchain_path() {
    static char toolchain[256];
    char *sep = NULL;

    snprintf(toolchain, sizeof(toolchain), "%s", COMPILER);

    if ((sep = strrchr(toolchain, '/'))) {
        sep = toolchain;
        if ((sep = strrchr(sep, '-'))) {
            sep[1] = 0;
        }
    }
    else {
        toolchain[0] = 0;
    }

    return toolchain;
}

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
    list_iterator_take(&allocation->block_it);

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
    free(block->large_callstack);
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

static void agent_status_unlocked(agent_t *agent, FILE *fp) {
    char date[30] = {0};
    sample_t lasthour = sample_circbuf_last_sub_first(&agent->stats.lasthour);
    time_t now = time(NULL);
    asctime_r(localtime(&now), date);

    fprintf(fp, "HEAP SUMMARY %s\n", date);
    fprintf(fp, "    in use: %zu allocs, %zu bytes in %zu contexts\n",
        agent->stats.count_inuse, agent->stats.byte_inuse, agent->stats.block_inuse);
    fprintf(fp, "    total heap usage: %zu allocs, %zu frees, %zu bytes allocated\n",
        agent->stats.alloc_count, agent->stats.free_count, agent->stats.alloc_size);
    fprintf(fp, "    memory leaked since last hour: %zd allocs, %zd bytes\n", lasthour.count, lasthour.bytes);
    fprintf(fp, "[cmd_done]\n");
    fflush(fp);
}

static bool agent_status(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {
    bool lock = hooks_lock();
    agent_t *agent = container_of(topic, agent_t, status_topic);
    agent_status_unlocked(agent, fp);
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

    fprintf(fp, "memtrace report:\n");
    fprintf(fp, "[sysroot]%s\n", SYSROOT);
    fprintf(fp, "[toolchain]%s\n", toolchain_path());

    hashmap_qsort(&agent->blocks, blocks_map_compar);
    hashmap_for_each(it, &agent->blocks) {
        block_t *block = container_of(it, block_t, it);
        void *callstack = block->large_callstack ? block->large_callstack : block->callstack;
        size_t callstack_size = block->large_callstack ? agent->large_callstack_size : agent->callstack_size;

        if (max > 0 && i >= max) {
            break;
        }


        fprintf(fp, "Memory allocation context n°%zu\n", i);
        fprintf(fp, "%zd allocs, %zd bytes were not free\n", block->count, block->size);
        libraries_backtrace_print(agent->libraries, callstack, callstack_size, fp);
        fprintf(fp, "\n");

        i++;
    }

    agent_status_unlocked(agent, fp);
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

/**
 * Read getcontext request and return the specified context
 */
static bool agent_getcontext(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {
    agent_t *agent = container_of(topic, agent_t, getcontext_topic);
    size_t i = 0;
    size_t context_idx = 0;
    hashmap_iterator_t *it = NULL;
    block_t *block = NULL;
    int retval = false;
    const char *descr = "Success";
    bool lock = hooks_lock();
    char key[32];

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

    // Print callstack associated to context
    for (i = 0; i < agent->callstack_size; i++) {
        snprintf(key, sizeof(key), "%zu", i);
        strmap_add_fmt(options, key, "%p", block->callstack[i]);
    }
    retval = true;

error:
    strmap_add_fmt(options, "retval", "%d", retval);
    strmap_add(options, "descr", descr);
    bus_connection_write_reply(connection, options);
    hooks_unlock(lock);

    return true;
}

static void memtrace_dataviewer_write(agent_t *agent, FILE *fp) {
    hashmap_iterator_t *it = NULL;
    size_t i = 0;
    size_t max = 10;
    size_t max_samples = 300;
    size_t time_interval = agent->elapsed > max_samples ?
        (agent->elapsed / max_samples) : 1;

    fprintf(fp, "#!/usr/bin/env dataviewer\n");
    fprintf(fp, "\n");
    fprintf(fp, "#[sysroot]%s\n", SYSROOT);
    fprintf(fp, "#[toolchain]%s\n", toolchain_path());
    fprintf(fp, "\n");
    fprintf(fp, "[dataview]\n");
    fprintf(fp, "type = 'XY'\n");
    fprintf(fp, "title = 'Memtrace report'\n");
    fprintf(fp, "x_title = 'Time'\n");
    fprintf(fp, "x_unit = 'seconds'\n");
    fprintf(fp, "y_title = 'Memory allocation'\n");
    fprintf(fp, "y_unit = 'Bytes'\n");
    fprintf(fp, "description = '''\n");
    fprintf(fp, "Top 10 memory allocations since program start\n");
    fprintf(fp, "measured with memtrace\n");
    fprintf(fp, "'''\n");
    fprintf(fp, "\n");

    hashmap_qsort(&agent->blocks, blocks_map_compar);
    hashmap_for_each(it, &agent->blocks) {
        if (max > 0 && i >= max) {
            break;
        }

        block_t *block = container_of(it, block_t, it);
        void *callstack = block->large_callstack ? block->large_callstack : block->callstack;
        size_t callstack_size = block->large_callstack ? agent->large_callstack_size : agent->callstack_size;

        fprintf(fp, "[chart.%zu]\n", i);
        fprintf(fp, "title = 'Allocation Context n°%zu'\n", i);
        fprintf(fp, "description = '''%zd allocs, %zd bytes were not free\n", block->count, block->size);
        libraries_backtrace_print(agent->libraries, callstack, callstack_size, fp);
        fprintf(fp, "'''\n");
        fprintf(fp, "\n");

        i++;
    }
    fprintf(fp, "\n");
    fprintf(fp, "[data]\n");

    i = 0;
    hashmap_for_each(it, &agent->blocks) {
        if (max > 0 && i >= max) {
            break;
        }

        size_t time = 0;
        size_t cumulated = 0;
        block_t *block = container_of(it, block_t, it);
        list_iterator_t *jt = NULL;
        fprintf(fp, "%zu = [\n", i);
        fprintf(fp, "0, 0,\n");
        jt = list_first(&block->allocations);
        for (time = time_interval; time < agent->elapsed; time += time_interval) {
            for (; jt; jt = list_iterator_next(jt)) {
                allocation_t *alloc = container_of(jt, allocation_t, block_it);
                if (alloc->when > time) {
                    break;
                }
                cumulated += alloc->ptr_size;
            }
            fprintf(fp, "%zu, %zu,\n", time, cumulated);
        }
        fprintf(fp, "%zu, %zu,\n", agent->elapsed, block->size);
        fprintf(fp, "]\n");
        i++;
    }

    fprintf(fp, "[cmd_done]\n");
    fflush(fp);
}

static bool agent_dataviewer(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {
    agent_t *agent = container_of(topic, agent_t, dataviewer_topic);

    bool lock = hooks_lock();
    memtrace_dataviewer_write(agent, fp);
    hooks_unlock(lock);
    return true;
}


static void agent_stats_lasthour_handler(evlp_handler_t *self, int events) {
    agent_t *agent = container_of(self, agent_t, stats_lasthour_handler);
    uint64_t timestamp = 0;
    sample_t value = {
        .bytes = agent->stats.byte_inuse,
        .count = agent->stats.count_inuse,
    };
    bool lock = false;

    if (read(agent->stats_lasthour_timerfd, &timestamp, sizeof(timestamp)) < 0) {
        TRACE_ERROR("read timer error: %m");
        return;
    }

    lock = hooks_lock();

    TRACE_WARNING("Stats LastHour Update");
    sample_circbuf_append(&agent->stats.lasthour, value);

    hooks_unlock(lock);
}

/**
 * Mark the first 10x blocks for a Large Callstack.
 */
static void agent_mark_blocks_for_large_callstack(agent_t *agent) {
    size_t i = 0;
    hashmap_iterator_t *it = NULL;

    hashmap_qsort(&agent->blocks, blocks_map_compar);
    hashmap_for_each(it, &agent->blocks) {
        block_t *block = container_of(it, block_t, it);

        if (i >= 10) {
            break;
        }

        block->do_large_callstack = true;
        i++;
    }
}

static void agent_periodic_job_handler(evlp_handler_t *self, int events) {
    agent_t *agent = container_of(self, agent_t, periodic_job_handler);
    uint64_t timestamp = 0;
    bool lock = false;

    if (read(agent->periodic_job_timerfd, &timestamp, sizeof(timestamp)) < 0) {
        TRACE_ERROR("read timer error: %m");
        return;
    }

    lock = hooks_lock();
    agent->elapsed = time(NULL) - agent->start_time;
    if (agent->elapsed % 5 == 0) {
        agent_mark_blocks_for_large_callstack(agent);
    }
    hooks_unlock(lock);
}

static void *ipc_accept_loop(void *arg) {
    agent_t *agent = arg;

    TRACE_WARNING("Control Thread - Entering event loop");
    signal(SIGPIPE, SIG_IGN);
    if (!bus_ipc_listen(&agent->bus, agent->ipc)) {
        TRACE_ERROR("Failed to listen on ipc socket");
        return NULL;
    }
    evlp_main(agent->evlp);
    TRACE_WARNING("Control Thread - Exiting event loop");

    return NULL;
}

bool agent_initialize(agent_t *agent) {
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
    agent->large_callstack_size = 50;
    agent->start_time = time(NULL);
    agent->elapsed = 0;
    hashmap_initialize(&agent->allocations, &allocations_maps_cfg);
    hashmap_initialize(&agent->blocks, &blocks_maps_cfg);

    if ((agent->ipc = ipc_socket()) < 0) {
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
    agent->getcontext_topic.name = "getcontext";
    agent->getcontext_topic.read = agent_getcontext;
    bus_register_topic(&agent->bus, &agent->getcontext_topic);
    agent->dataviewer_topic.name = "dataviewer";
    agent->dataviewer_topic.read = agent_dataviewer;
    bus_register_topic(&agent->bus, &agent->dataviewer_topic);

    agent->stats_lasthour_handler.fn = agent_stats_lasthour_handler;
    assert((agent->stats_lasthour_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)) >= 0);
    assert(evlp_add_handler(agent->evlp, &agent->stats_lasthour_handler, agent->stats_lasthour_timerfd, EPOLLIN));
    {
        struct itimerspec itimer = {
            .it_interval.tv_sec = 60*60/10,
            .it_value.tv_sec = 60*60/10,
        };
        timerfd_settime(agent->stats_lasthour_timerfd, 0, &itimer, NULL);
    }

    agent->periodic_job_handler.fn = agent_periodic_job_handler;
    assert((agent->periodic_job_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)) >= 0);
    assert(evlp_add_handler(agent->evlp, &agent->periodic_job_handler, agent->periodic_job_timerfd, EPOLLIN));
    {
        struct itimerspec itimer = {
            .it_interval.tv_sec = 1,
            .it_value.tv_sec = 1,
        };
        timerfd_settime(agent->periodic_job_timerfd, 0, &itimer, NULL);
    }

    return true;
}

void agent_cleanup(agent_t *agent) {
    evlp_remove_handler(agent->evlp, agent->stats_lasthour_timerfd);
    close(agent->stats_lasthour_timerfd);
    bus_cleanup(&agent->bus);
    evlp_destroy(agent->evlp);
    libraries_destroy(agent->libraries);
    ipc_socket_close(agent->ipc);
    agent->follow_allocs = false;
}

void agent_unfollow_allocs(agent_t *agent) {
    agent->follow_allocs = false;
}

void agent_alloc(agent_t *agent, cpu_registers_t *regs, size_t size, void *newptr) {
    hashmap_iterator_t *it = NULL;
    void **callstack = NULL;
    block_t *block = NULL;
    allocation_t *allocation = NULL;

    if (!agent->follow_allocs) {
        return;
    }
    if (pthread_self() == agent->thread) {
        // ignore allocation from the agent itself
        return;
    }

    if (agent->stats.alloc_count == 0) {
        TRACE_WARNING("Memory allocations are tracked !");
    }

    // let's start the control thread if not already done
    if (!agent->thread) {
        if (pthread_create(&agent->thread, NULL, ipc_accept_loop, agent) != 0) {
            TRACE_ERROR("Failed to create thread: %m");
        }
        libraries_update(agent->libraries);
    }

    assert((callstack = calloc(agent->callstack_size, sizeof(size_t))));
    libraries_backtrace(agent->libraries, regs, callstack, agent->callstack_size);

    //if (agent->dump_all) {
    //    libraries_backtrace_print(agent->libraries, callstack, agent->callstack_size, stdout);
    //}

    if ((it = hashmap_get(&agent->blocks, callstack))) {
        block = container_of(it, block_t, it);
        free(callstack);

        if (block->do_large_callstack && !block->large_callstack) {
            assert((block->large_callstack = calloc(agent->large_callstack_size, sizeof(size_t))));
            libraries_backtrace(agent->libraries, regs, block->large_callstack, agent->large_callstack_size);
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
    allocation->when = agent->elapsed;
    hashmap_add(&agent->allocations, newptr, &allocation->it);
    list_append(&block->allocations, &allocation->block_it);

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

