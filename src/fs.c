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
#include <fcntl.h>
#include "fs.h"
#include "net.h"
#include "log.h"

#define FS_DEFAULT_BINDADDR "::0"
#define FS_DEFAULT_PORT "3002"
#define GET_REQUEST "GET/REQUEST/"
#define GET_REPLY "GET/REPLY/"

char *fs_path(strlist_t *directories, const char *name) {
    strlist_iterator_t *it = NULL;

    strlist_for_each(it, directories) {
        char *realpath = NULL;
        struct stat st = {0};
        const char *directory = strlist_iterator_value(it);

        if (asprintf(&realpath, "%s/%s", directory, name) <= 0) {
            continue;
        }

        if (stat(realpath, &st) == 0) {
            return realpath;
        }

        free(realpath);
    }

    return NULL;
}

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

static int fs_tcp_listen(const fs_cfg_t *cfg) {
    int s = -1;
    const char *bindaddr = cfg->bindaddr;
    const char *bindport = cfg->bindport;

    if (!cfg->bindaddr) {
        bindaddr = FS_DEFAULT_BINDADDR;
    }
    if (!cfg->bindport) {
        bindport = FS_DEFAULT_PORT;
    }
    CONSOLE("Listening on [%s]:%s", bindaddr, bindport);
    if ((s = tcp_listen(bindaddr, bindport)) < 0) {
        TRACE_ERROR("Failed to listen on %s:%s", bindaddr, bindport);
        return -1;
    }

    return s;
}

static FILE *fs_tcp_accept(int server, const fs_cfg_t *cfg) {
    FILE *fp = NULL;
    int client = -1;

    CONSOLE("Waiting for client to connect");
    if ((client = accept(server, NULL, NULL)) == -1) {
        TRACE_ERROR("Failed to accept: %m");
        return NULL;
    }
    if (!(fp = fdopen(client, "w+"))) {
        TRACE_ERROR("fdopen() failed: %m");
        close(client);
        return NULL;
    }
    CONSOLE("Client connected");

    return fp;
}

static FILE *fs_tcp_connect(const fs_cfg_t *cfg) {
    FILE *fp = NULL;
    int s = -1;
    const char *connectaddr = cfg->connectaddr;
    const char *connectport = cfg->connectport;

    if (!cfg->connectaddr) {
        return NULL;
    }
    if (!cfg->connectport) {
        connectport = FS_DEFAULT_PORT;
    }
    CONSOLE("Connecting to [%s]:%s", connectaddr, connectport);
    if ((s = tcp_connect(connectaddr, connectport)) < 0) {
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

bool fs_initialize(fs_t *fs, const fs_cfg_t *cfg) {
    bool rt = false;

    if (!fs || !cfg) {
        TRACE_ERROR("Invalid arguments: %m");
        return false;
    }

    fs->cfg = *cfg;

    switch (cfg->type) {
        case fs_type_local: {
            break;
        }
        case fs_type_tcp_server: {
            int server = -1;
            if ((server = fs_tcp_listen(cfg)) < 0) {
                goto error;
            }
            if (!(fs->socket = fs_tcp_accept(server, cfg))) {
                close(server);
                goto error;
            }
            close(server);
            break;
        }
        case fs_type_tcp_client: {
            if (!(fs->socket = fs_tcp_connect(cfg))) {
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

bool fs_server_initialize(fs_server_t *fs, const fs_cfg_t *cfg) {
    bool rt = false;

    if (!fs || !cfg) {
        TRACE_ERROR("Invalid arguments: %m");
        return false;
    }

    fs->cfg = *cfg;

    switch (cfg->type) {
        case fs_type_tcp_server:
            if ((fs->server = fs_tcp_listen(cfg)) < 0) {
                goto error;
            }
            break;
        case fs_type_tcp_client:
            if (!(fs->socket = fs_tcp_connect(cfg))) {
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

bool fs_server_serve(fs_server_t *fs) {
    bool rt = true;

    while (true) {
        if (fs->cfg.type == fs_type_tcp_server) {
            if (!fs->socket) {
                if (!(fs->socket = fs_tcp_accept(fs->server, &fs->cfg))) {
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

