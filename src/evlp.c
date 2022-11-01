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
#include <signal.h>
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
    evlp_handler_t sighandler;
    int sfd;
};

static void evlp_signal_handler(evlp_handler_t *self, int events) {
    evlp_t *evlp = container_of(self, evlp_t, sighandler);
    struct signalfd_siginfo fdsi = {0};

    if (read(evlp->sfd, &fdsi, sizeof(fdsi)) < 0) {
        TRACE_ERROR("Failed to read signalfd");
        goto error;
    }

    switch (fdsi.ssi_signo) {
        case SIGINT:
            TRACE_WARNING("SIGINT received. Exit event loop");
            break;
        case SIGQUIT:
            TRACE_WARNING("SIGQUIT received. Exit event loop");
            break;
        case SIGTERM:
            TRACE_WARNING("SIGTERM received. Exit event loop");
            break;
        default:
            TRACE_ERROR("Unknown signal %d received. Exit event loop", fdsi.ssi_signo);
            break;
    }

error:
    evlp->run = false;
}

evlp_t *evlp_create() {
    evlp_t *evlp = NULL;
    sigset_t mask = {0};

    assert((evlp = calloc(1, sizeof(evlp_t))));
    assert((evlp->epfd = epoll_create1(EPOLL_CLOEXEC)) > 0);

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGQUIT);
    sigaddset(&mask, SIGTERM);

    assert(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
    evlp->sighandler.fn = evlp_signal_handler;
    assert((evlp->sfd = signalfd(-1, &mask, 0)) >= 0);
    assert(evlp_add_handler(evlp, &evlp->sighandler, evlp->sfd, EPOLLIN));

    return evlp;
}

void evlp_destroy(evlp_t *evlp) {
    assert(evlp);
    evlp_remove_handler(evlp, evlp->epfd);
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

void evlp_remove_handler(evlp_t *evlp, int fd) {
    assert(evlp);

    if (fd >= 0) {
        epoll_ctl(evlp->epfd, EPOLL_CTL_DEL, fd, NULL);
    }
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
