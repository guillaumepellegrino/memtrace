/*
 * Copyright (C) 2021 Guillaume Pellegrino
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

#ifndef AGENT_H
#define AGENT_H

#include "types.h"
#include "hashmap.h"
#include "bus.h"
#include <semaphore.h>

typedef struct {
    ssize_t bytes;
    ssize_t count;
} sample_t;

typedef struct {
    size_t wridx;
    sample_t values[11];
} sample_circbuf_t;

typedef struct {
    size_t alloc_count;
    size_t alloc_size;
    size_t free_count;
    size_t free_size;
    size_t byte_inuse;
    size_t count_inuse;
    size_t block_inuse;
    sample_circbuf_t lasthour;
} stats_t;

typedef struct {
    bool follow_allocs;
    int pid;
    libraries_t *libraries;
    size_t callstack_size;
    size_t large_callstack_size;
    hashmap_t allocations;
    hashmap_t blocks;
    stats_t stats;
    int ipc;
    pthread_t thread;
    evlp_t *evlp;
    bus_t bus;
    bus_topic_t resume_topic;
    bus_topic_t status_topic;
    bus_topic_t report_topic;
    bus_topic_t clear_topic;
    bus_topic_t getcontext_topic;
    bus_topic_t dataviewer_topic;
    evlp_handler_t stats_lasthour_handler;
    int stats_lasthour_timerfd;
    evlp_handler_t periodic_job_handler;
    int periodic_job_timerfd;
    time_t start_time;
    size_t elapsed;
    uint64_t available_uid;
    sem_t wait4resume;
} agent_t;

bool agent_initialize(agent_t *agent);
void agent_cleanup(agent_t *agent);
void agent_unfollow_allocs(agent_t *agent);
void agent_alloc(agent_t *agent, cpu_registers_t *regs, size_t size, void *newptr);
void agent_dealloc(agent_t *agent, void *ptr);

#endif
