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
#include "addr2line.h"
#include "elf.h"
#include "gdb.h"
#include "net.h"

#define FS_DEFAULT_MCASTADDR "224.0.0.251"
#define FS_DEFAULT_BINDADDR "::0"
#define FS_DEFAULT_PORT "3002"

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
static bool fs_mcast_announce(int mcast, const fs_cfg_t *cfg) {
    char buff[512];
    int len = snprintf(buff, sizeof(buff),
        "msgtype: announce\n"
        "service: %s\n"
        "port: %s\n",
        cfg->me, fs_cfg_port(cfg));

    if (mcast_send(mcast, buff, len, fs_cfg_mcastaddr(cfg), fs_cfg_port(cfg)) <= 0) {
        TRACE_ERROR("Failed to announce service: %m");
        return false;
    }

    return true;
}

/** Query the specified service on the multicast socket */
static bool fs_mcast_query(int mcast, const fs_cfg_t *cfg) {
    char buff[512];
    int len = snprintf(buff, sizeof(buff),
        "msgtype: query\n"
        "service: %s\n",
        cfg->tgt);

    if (mcast_send(mcast, buff, len, fs_cfg_mcastaddr(cfg), fs_cfg_port(cfg)) <= 0) {
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

/** Return true if path is allowed by ACLs */
static bool fs_check_acls(strlist_t *acls, const char *path) {
    strlist_iterator_t *it = NULL;

    strlist_for_each(it, acls) {
        const char *acl = strlist_iterator_value(it);
        if (!strncmp(acl, path, strlen(acl))) {
            return true;
        }
    }

    return false;
}

/** Return true if path is safe (and does not contains "/../"in path */
static bool fs_path_is_safe(const char *_path) {
    bool rt = true;
    char *path = NULL;
    char *node = NULL;

    path = strdup(_path);

    for (node = strtok(path, "/"); node; node = strtok(NULL, "/")) {
        if (!strcmp(node, "..")) {
            rt = false;
            break;
        }
    }

    free(path);

    return rt;
}

/** Return the real path of the file */
static char *fs_path(const char *sysroot, strlist_t *files, strlist_t *directories, strlist_t *acls, const char *path) {
    const char *filename = NULL;
    strlist_iterator_t *it = NULL;

    if (!fs_path_is_safe(path)) {
        TRACE_ERROR("'/../' are forbinden in path (%s)", path);
        return NULL;
    }

    if (!(filename = strrchr(path, '/'))) {
        filename = path;
    }

    strlist_for_each(it, files) {
        const char *lookup = NULL;
        const char *file = strlist_iterator_value(it);
        if (!(lookup = strrchr(file, '/'))) {
            lookup = file;
        }

        if (!strcmp(filename, lookup)) {
            return strdup(file);
        }
    }

    strlist_for_each(it, directories) {
        char *realpath = NULL;
        struct stat st = {0};
        const char *directory = strlist_iterator_value(it);

        assert(asprintf(&realpath, "%s/%s", directory, path) > 0);

        if (stat(realpath, &st) == 0) {
            return realpath;
        }

        free(realpath);
    }

    if (sysroot) {
        char *realpath = NULL;
        struct stat st = {0};

        assert(asprintf(&realpath, "%s/%s", sysroot, path) > 0);

        if (stat(realpath, &st) == 0) {
            return realpath;
        }

        if (fs_check_acls(acls, realpath)) {
            TRACE_ERROR("Server is not allowed to access: %s", realpath);
            free(realpath);
            return NULL;
        }

        free(realpath);
    }

    return NULL;
}

/** Serve File System GET request */
static bool fs_serve_get_request(fs_t *server, char *request) {
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

    if (!(path = fs_path(server->sysroot, &server->cfg.files, &server->cfg.directories, &server->cfg.acls, filename))) {
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

/**  memtrace server set the sysroot PATH according what tells the client */
static bool fs_serve_post_sysroot(fs_t *server, char *request) {
    char *path = request + strlen(POST_SYSROOT);

    free(server->sysroot);
    server->sysroot = strdup(path);
    TRACE_LOG("Sysroot directory: %s", path);

    return true;
}

static bool fs_serve_report_request(fs_t *server, char *request) {
    const char cmd[] = REPORT_REQUEST " addr2line=";
    const char *binary = NULL;
    char *sep = NULL;


    if (!strstr(request, cmd)) {
        TRACE_ERROR("Failed to parse command");
        return false;
    }
    if ((sep = strchr(request, '\n'))) {
        *sep = 0;
    }
    binary = request + strlen(cmd);

    TRACE_LOG(REPORT_REQUEST " addr2line=%s", binary);

    addr2line_initialize(binary);

    // Read the whole report in RAM
    char *buff = NULL;
    size_t bufflen = 0;
    FILE *mem = open_memstream(&buff, &bufflen);
    if (!mem) {
        TRACE_ERROR("Failed to open memstream");
        return false;
    }
    size_t len = 4096;
    char *line = malloc(len);
    while(fgets(line, len, server->socket)) {
        if (!strcmp(line, REPORT_REQUEST_END"\n")) {
            break;
        }
        fprintf(mem, "%s", line);
    }
    rewind(mem);

    // Send the translated report as a reply
    fprintf(server->socket, REPORT_REPLY"\n");
    while(fgets(line, len, mem)) {
        uint64_t ra = 0;
        const char *so = NULL;
        char *path = NULL;
        if (sscanf(line, "ra=0x%"PRIx64":", &ra) == 1) {
            if ((sep = strchr(line, '\n'))) {
                *sep = 0;
            }
            so = strchr(line, ':') + 1;

            if (!(path = fs_path(server->sysroot, &server->cfg.files, &server->cfg.directories, &server->cfg.acls, so))) {
                TRACE_ERROR("%s: not found", so);
                fprintf(server->socket, "0x%"PRIx64" in %s\n", ra, so);
                continue;
            }
            addr2line_print(path, ra, server->socket);
        }
        else {
            fprintf(server->socket, "%s", line);
        }
        free(path);
    }
    fprintf(server->socket, REPORT_REPLY_END"\n");

    fclose(mem);
    free(line);

    addr2line_cleanup();
    return true;
}

static bool file_transfer(FILE *in, FILE *out, size_t size) {
    size_t xbytes = 0;
    size_t remain = 0;

    for (xbytes = 0; (xbytes + sizeof(g_buff)) < size; xbytes += sizeof(g_buff)) {
        if (fread(g_buff, sizeof(g_buff), 1, in) != 1) {
            TRACE_ERROR("Failed to read: %m");
            return false;
        }
        if (fwrite(g_buff, sizeof(g_buff), 1, out) != 1) {
            TRACE_ERROR("Failed to write: %m");
            return false;
        }
    }
    remain = size - xbytes;

    if (fread(g_buff, remain, 1, in) != 1) {
        TRACE_ERROR("Failed to read: %m");
        return false;
    }
    if (fwrite(g_buff, remain, 1, out) != 1) {
        TRACE_ERROR("Failed to write: %m");
        return false;
    }

    return true;
}

static bool fs_transfer_coredump(fs_t *server, const char *filename) {
    bool rt = false;
    ssize_t elf_header_len = 0x40;
    FILE *fp = NULL;
    fs_cfg_t fs_cfg = {
        .type = fs_type_local,
        .me = server->cfg.me,
    };
    fs_t localfs = {0};
    elf_t *elf = NULL;
    const elf_header_t *hdr = NULL;
    size_t xbytes = 0;

    assert(fs_initialize(&localfs, &fs_cfg));

    if (fread(g_buff, elf_header_len, 1, server->socket) != 1) {
        TRACE_ERROR("Failed to read socket: %m");
        goto error;
    }
    if (!(fp = fopen(filename, "w"))) {
        TRACE_ERROR("Failed to open %s: %m", filename);
        goto error;
    }
    if (fwrite(g_buff, elf_header_len, 1, fp) != 1) {
        TRACE_ERROR("Failed to write: %m");
        goto error;
    }
    fflush(fp);

    if (!(elf = elf_parse_header(filename, &localfs))) {
        TRACE_ERROR("Failed to parse coredump header");
        goto error;
    }
    hdr = elf_header(elf);
    xbytes = hdr->e_shoff + (hdr->e_shentsize * hdr->e_shnum) - elf_header_len;

    if (!file_transfer(server->socket, fp, xbytes)) {
        TRACE_ERROR("Failed to transfer coredump");
        goto error;
    }
    CONSOLE("Coredump transfered");

    rt = true;
error:
    if (elf) {
        elf_close(elf);
    }
    if (fp) {
        fclose(fp);
    }
    fs_cleanup(&localfs);
    return rt;
}

static bool fs_serve_gdb_request(fs_t *server, char *request) {
    TRACE_WARNING("%s", request);

    bool rt = false;
    const char cmd[] = GDB_REQUEST " gdb=";
    char filename[] = "/tmp/memtrace-target.core";
    gdb_cfg_t cfg = {
        .solib_search_path = &server->cfg.directories,
        .sysroot = server->sysroot,
        .coredump = filename,
        .userin = server->socket,
        .userout = server->socket,
    };
    gdb_t gdb = {0};
    char *sep = NULL;


    if (!strstr(request, cmd)) {
        TRACE_ERROR("Failed to parse command");
        return false;
    }
    cfg.gdb_binary = request + strlen(cmd);
    if (!fgets(g_buff, sizeof(g_buff), server->socket)) {
        TRACE_ERROR("Failed to read program name");
        return false;
    }
    if ((sep = strchr(g_buff, '\n'))) {
        *sep = 0;
    }
    cfg.tgt_binary = strdup(g_buff);

    if (!fs_transfer_coredump(server, filename)) {
        goto error;
    }

    if (!cfg.sysroot) {
        TRACE_ERROR("Unknown sysroot");
        goto error;
    }

    CONSOLE("Starting %s", cfg.gdb_binary);
    if (!gdb_initialize(&gdb, &cfg)) {
        TRACE_ERROR("Failed to start gdb");
        goto error;
    }
    gdb_backtrace(&gdb);
    gdb_interact(&gdb);
    fprintf(server->socket, "\n"GDB_REPLY_END"\n");
    CONSOLE("Done");

    rt = true;
error:
    gdb_cleanup(&gdb);
    return rt;
}

/** Serve File System request */
static bool fs_serve_request(fs_t *fs) {
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
        rt = fs_serve_get_request(fs, request);
    }
    else if (!strncmp(request, POST_SYSROOT, strlen(POST_SYSROOT))) {
        rt = fs_serve_post_sysroot(fs, request);
    }
    else if (!strncmp(request, REPORT_REQUEST, strlen(REPORT_REQUEST))) {
        rt = fs_serve_report_request(fs, request);
    }
    else if (!strncmp(request, GDB_REQUEST, strlen(GDB_REQUEST))) {
        rt = fs_serve_gdb_request(fs, request);
    }
    else {
        TRACE_ERROR("Unknown request %s", request);
    }

    return rt;
}

/** File System : Announce service through multicast and wait for an incoming TCP connection to accept */
static FILE *fs_tcp_accept(int server, int mcast, const fs_cfg_t *cfg) {
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
    fs_mcast_announce(mcast, cfg);
    assert((timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)) >= 0);
    timerfd_settime(timerfd, 0, &itimer, NULL);

    do {
        // Wait for an event on one of these file descriptors
        struct pollfd pollfds[] = {
            [POLL_MCAST_SRV] = {.fd = mcast, .events = POLLIN},
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
            if (fs_mcast_read(mcast, &msg)) {
                if (!strcmp(msg.msgtype, "query") && !strcmp(msg.service, cfg->me)) {
                    CONSOLE("Replying to query");
                    fs_mcast_announce(mcast, cfg);
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
            fs_mcast_announce(mcast, cfg);
        }
    } while (!fp);

    CONSOLE("Client connected");

    close(timerfd);

    return fp;
}

/** File System : Query service through multicast and try to establish TCP connection */
static FILE *fs_tcp_connect(int mcast, const fs_cfg_t *cfg) {
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
        fs_mcast_query(mcast, cfg);
    }
    while (!connectaddr) {
        // Wait for an event on one of these file descriptors
        struct pollfd pollfds[] = {
            [POLL_MCAST_SRV] = {.fd = mcast, .events = POLLIN},
            [POLL_TIMERFD]   = {.fd = timerfd, .events = POLLIN},
        };
        int rt = poll(pollfds, countof(pollfds), -1);
        if (rt < 0) {
            TRACE_ERROR("poll error: %m");
            break;
        }
        if (pollfds[POLL_MCAST_SRV].revents & POLLIN) {
            // handle multicast message: Retrieve the connect address and port through service announcement
            if (fs_mcast_read(mcast, &msg)) {
                if (!strcmp(msg.msgtype, "announce") && !strcmp(msg.service, cfg->tgt)) {
                    CONSOLE("%s announced on %s:%s", msg.service, msg.from, msg.port);
                    connectaddr = msg.from;
                }
            }
        }
        if (pollfds[POLL_TIMERFD].revents & POLLIN) {
            // handle timer expiration: Query the service address through multicast again
            uint64_t value = 0;
            assert(read(timerfd, &value, sizeof(value)) > 0);
            fs_mcast_query(mcast, cfg);
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
    fs->mcast = -1;
    fs->server = -1;
    fs->socket = NULL;
    fs->sysroot = NULL;

    /** Create multicast client and server socket to announce the service */
    if ((fs->mcast = mcast_listen(fs_cfg_mcastaddr(cfg), FS_DEFAULT_PORT)) < 0) {
        TRACE_WARNING("Failed to create UDP multicast listening socket");
    }

    switch (cfg->type) {
        case fs_type_local: {
            CONSOLE("Running %s in local mode", cfg->me);
            break;
        }
        case fs_type_tcp_server: {
            CONSOLE("Listening on [%s]:%s", fs_cfg_bindaddr(cfg), fs_cfg_port(cfg));
            if ((fs->server = tcp_listen(fs_cfg_bindaddr(cfg), fs_cfg_port(cfg))) < 0) {
                TRACE_ERROR("Failed to listen on %s:%s", fs_cfg_bindaddr(cfg), fs_cfg_port(cfg));
                goto error;
            }

            if (!(fs->socket = fs_tcp_accept(fs->server, fs->mcast, cfg))) {
                goto error;
            }
            break;
        }
        case fs_type_tcp_client: {
            if (cfg->hostname) {
                CONSOLE("Connect to [%s]:%s", cfg->hostname, fs_cfg_port(cfg));
            }
            else {
                CONSOLE("Query %s service on [%s]:%s", cfg->tgt, fs_cfg_mcastaddr(cfg), fs_cfg_port(cfg));
            }

            if (!(fs->socket = fs_tcp_connect(fs->mcast, cfg))) {
                goto error;
            }
            break;
        }
        default: {
            goto error;
        }
    }

#ifdef SYSROOT
    if (fs->socket) {
        fprintf(fs->socket, POST_SYSROOT SYSROOT "\n");
        fflush(fs->socket);
    }
#endif

    rt = true;

error:
    return rt;
}

void fs_cleanup(fs_t *fs) {
    if (fs->mcast != -1) {
        close(fs->mcast);
    }
    if (fs->server != -1) {
        close(fs->server);
    }
    if (fs->socket) {
        fclose(fs->socket);
    }
    free(fs->sysroot);
}

/** Serve the File System to connected client */
bool fs_serve(fs_t *fs) {
    bool rt = true;

    while (true) {
        if (fs->cfg.type == fs_type_tcp_server) {
            if (!fs->socket) {
                if (!(fs->socket = fs_tcp_accept(fs->server, fs->mcast, &fs->cfg))) {
                    break;
                }
            }
        }
        if (!fs->socket) {
            TRACE_ERROR("fs->socket is NULL");
            break;
        }

        if (!fs_serve_request(fs)) {
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

