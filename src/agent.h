/*
 * Copyright (C) 2021 Guillaume Pellegrino
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

#ifndef AGENT_H
#define AGENT_H

typedef struct {
    int ipc;
    pthread_t thread;

} agent_t;

bool agent_initialize(agent_t *agent);
void agent_cleanup(agent_t *agent);
void agent_malloc(agent_t *agent, size_t size, void *newptr);
void agent_calloc(agent_t *agent, size_t nmemb, size_t size, void *newptr);
void agent_realloc(agent_t *agent, void *ptr, size_t size, void *newptr);
void agent_reallocarray(agent_t *agent, void *ptr, size_t nmemb, size_t size, void *newptr);
void agent_free(agent_t *agent, void *ptr);

#endif
