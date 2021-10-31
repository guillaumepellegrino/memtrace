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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "net.h"
#include "log.h"

int tcp_connect(const char *address, const char *port) {
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *ai_list = NULL, *ai = NULL;
    int rt = -1;
    int client = -1;

    if ((rt = getaddrinfo(address, port, &hints, &ai_list)) != 0) {
        TRACE_ERROR("Failed to resolve %s:%s. %s", address, port, gai_strerror(rt));
        return -1;
    }

    for (ai = ai_list; ai; ai = ai->ai_next) {
        if ((client = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
            TRACE_ERROR("Failed to create TCP client socket: %m");
            continue;
        }

        if (connect(client, ai->ai_addr, ai->ai_addrlen) == -1 && errno != EINPROGRESS) {
            TRACE_ERROR("Failed to connect: %m");
            close(client), client = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(ai_list);

    return client;
}

int tcp_listen(const char *address, const char *port) {
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *ai_list = NULL, *ai = NULL;
    int rt = -1;
    int yes = 1;
    int server = -1;

    if ((rt = getaddrinfo(address, port, &hints, &ai_list)) != 0) {
        TRACE_ERROR("Failed to resolve %s:%s. %s", address, port, gai_strerror(rt));
        return -1;
    }

    for (ai = ai_list; ai; ai = ai->ai_next) {
        if ((server = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
            TRACE_ERROR("Failed to create TCP server socket: %m");
            continue;
        }

        if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
            TRACE_ERROR("Failed to set setsockopt(SO_REUSEADDR): %m");
            close(server), server = -1;
            continue;
        }

        if (bind(server, ai->ai_addr, ai->ai_addrlen) == -1) {
            TRACE_ERROR("Failed to bind socket: %m");
            close(server), server = -1;
            continue;
        }

        if (listen(server, 1) < 0) {
            TRACE_ERROR("Failed to listen on socket: %m");
            close(server), server = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(ai_list);

    return server;
}

int tcp_accept(int server) {
    int client = -1;

    if ((client = accept(server, NULL, NULL)) == -1) {
        TRACE_ERROR("Failed to accept: %m");
        return -1;
    }

    return client;
}

int udp_connect(const char *address, const char *port) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM,
    };
    struct addrinfo *ai_list = NULL, *ai = NULL;
    int rt = -1;
    int client = -1;

    if ((rt = getaddrinfo(address, port, &hints, &ai_list)) != 0) {
        TRACE_ERROR("Failed to resolve %s:%s. %s", address, port, gai_strerror(rt));
        return -1;
    }

    for (ai = ai_list; ai; ai = ai->ai_next) {
        if ((client = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
            TRACE_ERROR("Failed to create UDP client socket: %m");
            continue;
        }

        if (connect(client, ai->ai_addr, ai->ai_addrlen) == -1) {
            TRACE_ERROR("Failed to connect socket: %m");
            close(client), client = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(ai_list);

    return client;
}

int mcast_listen(const char *address, const char *port) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM,
    };
    struct addrinfo *ai_list = NULL, *ai = NULL;
    int rt = -1;
    int yes = 1;
    int s = -1;

    if ((rt = getaddrinfo(address, port, &hints, &ai_list)) != 0) {
        TRACE_ERROR("Failed to resolve %s:%s. %s", address, port, gai_strerror(rt));
        return -1;
    }

    for (ai = ai_list; ai; ai = ai->ai_next) {
        struct ip_mreqn mreq = {
            .imr_multiaddr = ((struct sockaddr_in *) ai->ai_addr)->sin_addr,
            .imr_ifindex = 0,
        };

        if ((s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
            TRACE_ERROR("Failed to create UDP socket: %m");
            continue;
        }

        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
            TRACE_ERROR("Failed to set setsockopt(SO_REUSEADDR): %m");
            close(s), s = -1;
            continue;
        }

        if (bind(s, ai->ai_addr, ai->ai_addrlen) == -1) {
            TRACE_ERROR("Failed to bind socket to %s:%s : %m", address, port);
            close(s), s = -1;
            continue;
        }

        if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &mreq, sizeof(mreq)) < 0) {
            TRACE_ERROR("Failed to send multicast membership for %s : %m", address);
            close(s), s = -1;
            continue;
        }
    }

    return s;
}

