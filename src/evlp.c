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
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <fcntl.h>
#include <syscall.h>
#include "evlp.h"
#include "log.h"

struct _evlp {
    int epfd;
    bool run;
};

evlp_t *evlp_create() {
    evlp_t *evlp = NULL;

    assert((evlp = calloc(1, sizeof(evlp_t))));
    assert((evlp->epfd = epoll_create1(EPOLL_CLOEXEC)) > 0);

    return evlp;
}

void evlp_destroy(evlp_t *evlp) {
    close(evlp->epfd);
    free(evlp);
}

bool evlp_add_handler(evlp_t *evlp, evlp_handler_t *handler, int fd, int events) {
    struct epoll_event event = {
        .events = events,
        .data.ptr = handler,
    };

    assert(evlp);
    assert(handler);
    if (epoll_ctl(evlp->epfd, EPOLL_CTL_ADD, fd, &event) < 0) {
        TRACE_ERROR("epoll_ctl() add fd:%d error: %m", fd);
        return false;
    }

    return true;
}

bool evlp_main(evlp_t *evlp) {
    struct epoll_event event = {0};

    assert(evlp);

    evlp->run = true;
    while (evlp->run) {
        int cnt = 0;
        if ((cnt = epoll_wait(evlp->epfd, &event, 1, -1)) <= 0) {
            TRACE_ERROR("epoll_wait() error: %m");
            return false;
        }
        evlp_handler_t *handler = event.data.ptr;
        handler->fn(handler, event.events);
    }

    return true;
}

void evlp_stop(evlp_t *evlp) {
    assert(evlp);
    evlp->run = false;
}
