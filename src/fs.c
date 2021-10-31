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

#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include "fs.h"
#include "net.h"
#include "log.h"

#define FS_DEFAULT_MCASTADDR "224.0.0.251"
#define FS_DEFAULT_BINDADDR "::0"
#define FS_DEFAULT_PORT "3002"
#define GET_REQUEST "GET/REQUEST/"
#define GET_REPLY "GET/REPLY/"

typedef struct {
    char msgtype[32]; /** message type: ["announce", "query" ] */
    char service[32]; /** service name: ["memtrace", "memtrace-fs" ] */
    char from[INET6_ADDRSTRLEN] /** source ip address from packet sender */;
    char port[8]; /** service port */
} mcast_msg_t;

static const char *fs_cfg_bindaddr(const fs_cfg_t *cfg) {
    return cfg->hostname ? cfg->hostname : FS_DEFAULT_BINDADDR;
}

static const char *fs_cfg_port(const fs_cfg_t *cfg) {
    return cfg->port ? cfg->port : FS_DEFAULT_PORT;
}

static const char *fs_cfg_mcastaddr(const fs_cfg_t *cfg) {
    return cfg->mcastaddr ? cfg->mcastaddr : FS_DEFAULT_MCASTADDR;
}

/** Announce the service on the specified port on the multicast socket */
static bool fs_mcast_announce(int mcast, const char *service, const char *port) {
    char buff[512];
    int len = snprintf(buff, sizeof(buff),
        "msgtype: announce\n"
        "service: %s\n"
        "port: %s\n",
        service, port);

    if (write(mcast, buff, len) <= 0) {
        TRACE_ERROR("Failed to announce service: %m");
        return false;
    }

    return true;
}

/** Query the specified service on the multicast socket */
static bool fs_mcast_query(int mcast, const char *service) {
    char buff[512];
    int len = snprintf(buff, sizeof(buff),
        "msgtype: query\n"
        "service: %s\n",
        service);

    if (write(mcast, buff, len) <= 0) {
        TRACE_ERROR("Failed to announce service: %m");
        return false;
    }

    return true;
}

/** Read a message from the multicast socket */
static bool fs_mcast_read(int mcast, mcast_msg_t *msg) {
    char buff[512];
    ssize_t len;
    const char *sep = ":\n\r\t ";
    const char *key = NULL;
    const char *value = NULL;
    struct sockaddr_in src = {0};
    socklen_t srclen = sizeof(src);

    memset(msg, 0, sizeof(*msg));

    if ((len = recvfrom(mcast, buff, sizeof(buff), 0, &src, &srclen)) <= 0) {
        TRACE_ERROR("Failed to read multicast message: %m");
        return false;
    }
    inet_ntop(AF_INET, &src.sin_addr, msg->from, srclen);

    key = strtok(buff, sep);
    value = strtok(NULL, sep);

    while (key && value) {
        if (!strcmp(key, "msgtype")) {
            snprintf(msg->msgtype, sizeof(msg->msgtype), "%s", value);
        }
        if (!strcmp(key, "service")) {
            snprintf(msg->service, sizeof(msg->service), "%s", value);
        }
        if (!strcmp(key, "port")) {
            snprintf(msg->port, sizeof(msg->port), "%s", value);
        }
        key = strtok(NULL, sep);
        value = strtok(NULL, sep);
    }


    return true;
}

/** Return the real path of the file */
char *fs_path(strlist_t *directories, const char *path) {
    strlist_iterator_t *it = NULL;

    strlist_for_each(it, directories) {
        char *realpath = NULL;
        struct stat st = {0};
        const char *directory = strlist_iterator_value(it);

        if (asprintf(&realpath, "%s/%s", directory, path) <= 0) {
            continue;
        }

        if (stat(realpath, &st) == 0) {
            return realpath;
        }

        free(realpath);
    }

    return NULL;
}

/** Serve File System GET request */
bool fs_server_serve_get_request(fs_server_t *server, char *request) {
    uint64_t size = 0;
    uint64_t offset_u64 = 0;
    uint64_t xbytes = 0;
    char *sep = NULL;
    char *filename = NULL;
    char *path = NULL;
    char *buff = NULL;
    FILE *fp = NULL;
    bool rt = false;

    if (sscanf(request, GET_REQUEST "size=%"PRIu64"/offset=%"PRIu64":", &size, &offset_u64) != 2) {
        TRACE_ERROR("Failed to parse %s", request);
        goto error;
    }

    if (!(sep = strchr(request, ':'))) {
        TRACE_ERROR("Failed to parse %s", request);
        goto error;
    }
    filename = sep + 1;
    rt = true;

    TRACE_LOG(GET_REQUEST "size=%"PRIu64"/offset=%"PRIu64":%s", size, offset_u64, filename);

    if (!(path = fs_path(&server->cfg.directories, filename))) {
        TRACE_ERROR("%s: not found", filename);
        goto error;
    }

    if (!(fp = fopen(path, "r"))) {
        TRACE_ERROR("Failed to open %s: %m", path);
        goto error;
    }

    if (fseek(fp, offset_u64, SEEK_SET) != 0) {
        TRACE_ERROR("Failed to seek at %s:%"PRIu64" %m", path, offset_u64);
        goto error;
    }

    if (!(buff = calloc(1, size))) {
        TRACE_ERROR("Failed to calloc %s: %m", path);
        goto error;
    }

    if ((xbytes = fread(buff, 1, size, fp)) != size) {
        TRACE_WARNING("File partially sent %s", filename);
    }

    TRACE_LOG("Serving %s", path);
    fprintf(server->socket, GET_REPLY "size=%"PRIu64"\n", xbytes);
    fwrite(buff, 1, xbytes, server->socket);
    fflush(server->socket);

error:
    if (xbytes == 0) {
        fprintf(server->socket, GET_REPLY "size=0\n");
        fflush(server->socket);
    }
    free(path);
    free(buff);
    if (fp) {
        fclose(fp);
    }

    return rt;
}

/** Serve File System request */
static bool fs_server_serve_request(fs_server_t *fs) {
    char request[512];
    char *sep = NULL;
    bool rt = false;

    if (!fgets(request, sizeof(request), fs->socket)) {
        TRACE_ERROR("Failed to read line from socket");
        return false;
    }
    if ((sep = strchr(request, '\n'))) {
        *sep = 0;
    }

    if (!strncmp(request, GET_REQUEST, strlen(GET_REQUEST))) {
        rt = fs_server_serve_get_request(fs, request);
    }
    else {
        TRACE_ERROR("Unknown request %s", request);
    }

    return rt;
}

/** File System : Announce service through multicast and wait for an incoming TCP connection to accept */
static FILE *fs_tcp_accept(int server, int mcastsrv, int mcastcli, const fs_cfg_t *cfg) {
    enum {
        POLL_MCAST_SRV = 0,
        POLL_SRV,
        POLL_TIMERFD,
    };
    mcast_msg_t msg = {0};
    FILE *fp = NULL;
    int client = -1;
    int timerfd = -1;
    struct itimerspec itimer = {
        .it_interval.tv_sec = 2,
        .it_value.tv_sec = 2,
    };

    CONSOLE("Waiting for client to connect");

    // announce the service through multicast
    fs_mcast_announce(mcastcli, cfg->me, fs_cfg_port(cfg));
    assert((timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)) >= 0);
    timerfd_settime(timerfd, 0, &itimer, NULL);

    do {
        // Wait for an event on one of these file descriptors
        struct pollfd pollfds[] = {
            [POLL_MCAST_SRV] = {.fd = mcastsrv, .events = POLLIN},
            [POLL_SRV]       = {.fd = server, .events = POLLIN},
            [POLL_TIMERFD]   = {.fd = timerfd, .events = POLLIN},
        };
        int rt = poll(pollfds, countof(pollfds), -1);
        if (rt < 0) {
            TRACE_ERROR("poll error: %m");
            break;
        }

        if (pollfds[POLL_MCAST_SRV].revents & POLLIN) {
            // handle multicast message: announce the service through multicast when queried
            if (fs_mcast_read(mcastsrv, &msg)) {
                if (!strcmp(msg.msgtype, "query") && !strcmp(msg.service, cfg->me)) {
                    TRACE_WARNING("Replying to query");
                    fs_mcast_announce(mcastcli, cfg->me, fs_cfg_port(cfg));
                }
            }
        }
        if (pollfds[POLL_SRV].revents & POLLIN) {
            // handle tcp connection: return the FILE pointer on the client socket
            if ((client = accept(server, NULL, NULL)) == -1) {
                TRACE_ERROR("Failed to accept: %m");
            }
            if (!(fp = fdopen(client, "w+"))) {
                TRACE_ERROR("fdopen() failed: %m");
                close(client);
            }
        }
        if (pollfds[POLL_TIMERFD].revents & POLLIN) {
            // handle timer expiration: announce the service through multicast
            uint64_t value = 0;
            assert(read(timerfd, &value, sizeof(value))>0);
            fs_mcast_announce(mcastcli, cfg->me, fs_cfg_port(cfg));
        }
    } while (!fp);

    CONSOLE("Client connected");

    close(timerfd);

    return fp;
}

/** File System : Query service through multicast and try to establish TCP connection */
static FILE *fs_tcp_connect(int mcastsrv, int mcastcli, const fs_cfg_t *cfg) {
    enum {
        POLL_MCAST_SRV = 0,
        POLL_TIMERFD,
    };
    mcast_msg_t msg = {0};
    FILE *fp = NULL;
    int s = -1;
    int timerfd = -1;
    const char *connectaddr = cfg->hostname;
    struct itimerspec itimer = {
        .it_interval.tv_sec = 2,
        .it_value.tv_sec = 2,
    };

    assert((timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)) >= 0);
    timerfd_settime(timerfd, 0, &itimer, NULL);

    if (!connectaddr) {
        // The connect address is unknown: Query the service address through multicast
        fs_mcast_query(mcastcli, cfg->tgt);
    }
    while (!connectaddr) {
        // Wait for an event on one of these file descriptors
        struct pollfd pollfds[] = {
            [POLL_MCAST_SRV] = {.fd = mcastsrv, .events = POLLIN},
            [POLL_TIMERFD]   = {.fd = timerfd, .events = POLLIN},
        };
        int rt = poll(pollfds, countof(pollfds), -1);
        if (rt < 0) {
            TRACE_ERROR("poll error: %m");
            break;
        }
        if (pollfds[POLL_MCAST_SRV].revents & POLLIN) {
            // handle multicast message: Retrieve the connect address and port through service announcement
            if (fs_mcast_read(mcastsrv, &msg)) {
                if (!strcmp(msg.msgtype, "announce") && !strcmp(msg.service, cfg->tgt)) {
                    TRACE_WARNING("%s announced on %s:%s", msg.service, msg.from, msg.port);
                    connectaddr = msg.from;
                }
            }
        }
        if (pollfds[POLL_TIMERFD].revents & POLLIN) {
            // handle timer expiration: Query the service address through multicast again
            uint64_t value = 0;
            assert(read(timerfd, &value, sizeof(value)) > 0);
            fs_mcast_query(mcastcli, cfg->tgt);
        }
    }
    close(timerfd);
    if (!connectaddr) {
        return NULL;
    }

    CONSOLE("Connecting to [%s]:%s", connectaddr, fs_cfg_port(cfg));
    if ((s = tcp_connect(connectaddr, fs_cfg_port(cfg))) < 0) {
        return NULL;
    }
    if (!(fp = fdopen(s, "w+"))) {
        TRACE_ERROR("fdopen() failed: %m");
        close(s);
        return NULL;
    }
    CONSOLE("Connected");

    return fp;
}

/** Initialize file system */
bool fs_initialize(fs_t *fs, const fs_cfg_t *cfg) {
    bool rt = false;

    if (!fs || !cfg) {
        TRACE_ERROR("Invalid arguments: %m");
        return false;
    }

    fs->cfg = *cfg;

    /** Create multicast client and server socket to announce the service */
    if ((fs->mcastsrv = mcast_listen(fs_cfg_mcastaddr(cfg), FS_DEFAULT_PORT)) < 0) {
        TRACE_WARNING("Failed to create UDP multicast listening socket");
    }
    if ((fs->mcastcli = udp_connect(fs_cfg_mcastaddr(cfg), FS_DEFAULT_PORT)) < 0) {
        TRACE_WARNING("Failed to create UDP multicast client socket");
    }

    switch (cfg->type) {
        case fs_type_local: {
            break;
        }
        case fs_type_tcp_server: {
            int server = -1;

            CONSOLE("Listening on [%s]:%s", fs_cfg_bindaddr(cfg), fs_cfg_port(cfg));
            if ((server = tcp_listen(fs_cfg_bindaddr(cfg), fs_cfg_port(cfg))) < 0) {
                TRACE_ERROR("Failed to listen on %s:%s", fs_cfg_bindaddr(cfg), fs_cfg_port(cfg));
                goto error;
            }

            if (!(fs->socket = fs_tcp_accept(server, fs->mcastsrv, fs->mcastsrv, cfg))) {
                close(server);
                goto error;
            }
            close(server);
            break;
        }
        case fs_type_tcp_client: {
            if (!(fs->socket = fs_tcp_connect(fs->mcastsrv, fs->mcastcli, cfg))) {
                goto error;
            }
            break;
        }
        default: {
            goto error;
        }
    }

    rt = true;

error:
    return rt;
}

/** Initialize file system server */
// TODO: this can probably be merged with fs_initialize()
// TODO: cleanup code
bool fs_server_initialize(fs_server_t *fs, const fs_cfg_t *cfg) {
    bool rt = false;

    if (!fs || !cfg) {
        TRACE_ERROR("Invalid arguments: %m");
        return false;
    }

    fs->cfg = *cfg;

    /** Create multicast client and server socket to announce the service */
    if ((fs->mcastsrv = mcast_listen(fs_cfg_mcastaddr(cfg), FS_DEFAULT_PORT)) < 0) {
        TRACE_WARNING("Failed to create UDP multicast listening socket");
    }
    if ((fs->mcastcli = udp_connect(fs_cfg_mcastaddr(cfg), FS_DEFAULT_PORT)) < 0) {
        TRACE_WARNING("Failed to create UDP multicast client socket");
    }

    switch (cfg->type) {
        case fs_type_tcp_server:
            CONSOLE("Listening on [%s]:%s", fs_cfg_bindaddr(cfg), fs_cfg_port(cfg));
            if ((fs->server = tcp_listen(fs_cfg_bindaddr(cfg), fs_cfg_port(cfg))) < 0) {
                TRACE_ERROR("Failed to listen on %s:%s", fs_cfg_bindaddr(cfg), fs_cfg_port(cfg));
                goto error;
            }
            break;
        case fs_type_tcp_client:
            if (!(fs->socket = fs_tcp_connect(fs->mcastsrv, fs->mcastcli, cfg))) {
                goto error;
            }
            break;
        default:
            goto error;

    }

    rt = true;

error:
    return rt;
}

/** Serve the File System to connected client */
bool fs_server_serve(fs_server_t *fs) {
    bool rt = true;

    while (true) {
        if (fs->cfg.type == fs_type_tcp_server) {
            if (!fs->socket) {
                if (!(fs->socket = fs_tcp_accept(fs->server, fs->mcastsrv, fs->mcastcli, &fs->cfg))) {
                    break;
                }
            }
        }
        if (!fs->socket) {
            TRACE_ERROR("fs->socket is NULL");
            break;
        }

        if (!fs_server_serve_request(fs)) {
            if (fs->cfg.type == fs_type_tcp_server) {
                fclose(fs->socket);
                fs->socket = NULL;
                continue;
            }
            break;
        }
    }

    return rt;
}

