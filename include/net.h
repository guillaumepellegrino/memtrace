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



#ifndef FTRACE_NET_H
#define FTRACE_NET_H

#include "types.h"

/**
 * Create a TCP socket and connect to the client denominated by addr:port using getaddrinfo()
 */
int tcp_connect(const char *address, const char *port);

/**
 * Create a TCP listen socket using getaddrinfo()
 */
int tcp_listen(const char *address, const char *port);

/**
 * Accept TCP Client from TCP listening socket
 */
int tcp_accept(int server);

/**
 * Create an UDP Multicast listening socket using getaddrinfo()
 */
int mcast_listen(const char *address, const char *port);

/**
 * Send packet on UDP Multicast socket
 */
int mcast_send(int fd, const void *buf, size_t count, const char *address, const char *port);

bool fd_transfer(int from, int to);

#endif
