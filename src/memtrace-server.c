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
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "evlp.h"
#include "bus.h"
#include "net.h"
#include "addr2line.h"
#include "strlist.h"
#include "log.h"

typedef struct {
    evlp_t *evlp;
    bus_t bus;
    strlist_t directories;
    strlist_t files;
    strlist_t acls;
    bus_topic_t report_topic;
} memtrace_server_t;

__attribute__((aligned)) char g_buff[G_BUFF_SIZE];

/** Return true if path is allowed by ACLs */
bool host_path_is_allowed(const char *path, strlist_t *acls) {
    strlist_iterator_t *it = NULL;

    if (path[0] == 0) {
        return true;
    }

    strlist_for_each(it, acls) {
        const char *acl = strlist_iterator_value(it);
        if (!strncmp(acl, path, strlen(acl))) {
            return true;
        }
    }

    return false;
}

/** Return true if path is safe (and does not contains "/../"in path */
static bool host_path_is_safe(const char *_path) {
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

/** Return the host path of the file */
static char *target2host_path(const char *sysroot, strlist_t *files, strlist_t *directories, strlist_t *acls, const char *path) {
    const char *filename = NULL;
    strlist_iterator_t *it = NULL;

    if (!host_path_is_safe(path)) {
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

        free(realpath);
    }

    return NULL;
}

static bool server_report_parseline(memtrace_server_t *server, bus_connection_t *connection, char *line, const char *sysroot) {
    const char topic[] = "[addr]";
    char *sep = NULL;
    const char *tgtpath = NULL;
    const char *hostpath = NULL;
    size_t address = 0;

    if (strncmp(line, topic, strlen(topic)) != 0) {
        bus_connection_printf(connection, "%s", line);
        goto exit;
    }
    if ((sep = strstr(line, " | "))) {
        *sep = 0;
    }

    tgtpath = line + strlen(topic);
    if ((sep = strchr(line, '+'))) {
        *sep = 0;
        sscanf(sep+1, "0x%zx", &address);
    }

    if (!(hostpath = target2host_path(sysroot, &server->files, &server->directories, &server->acls, tgtpath))) {
        TRACE_ERROR("%s: not found", tgtpath);
        bus_connection_printf(connection, "%s", line);
        goto exit;
    }
    addr2line_print(hostpath, address, bus_connection_writer(connection));

exit:
    return true;
}

static bool server_report_cmd(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {
    char line[4096];
    memtrace_server_t *server = container_of(bus, memtrace_server_t, bus);
    bool rt = false;
    const char *sysroot = NULL;
    const char *toolchain = NULL;
    char *addr2line = NULL;

    when_null(sysroot = strmap_get(options, "sysroot"), error);
    when_null(toolchain = strmap_get(options, "toolchain"), error);
    when_true(asprintf(&addr2line, "%saddr2line", toolchain) <= 0, error);

    if (!host_path_is_allowed(sysroot, &server->acls)) {
        TRACE_ERROR("sysroot path '%s' is not allowed by ACLs", sysroot);
        goto error;
    }

    if (!host_path_is_allowed(toolchain, &server->acls)) {
        TRACE_ERROR("toolchain path '%s' is not allowed by ACLs", toolchain);
        goto error;
    }

    addr2line_initialize(addr2line);
    while (bus_connection_readline(connection, line, sizeof(line))) {
        server_report_parseline(server, connection, line, sysroot);
        if (!strcmp(line, "[cmd_done]\n")) {
            break;
        }
    }
    bus_connection_printf(connection, "[cmd_done]", line);
    bus_connection_flush(connection);
    addr2line_cleanup();
    rt = true;

error:
    return rt;
}

static void help() {
    CONSOLE("Usage: memtrace-server [OPTION].. [PATH]..");
    CONSOLE("A simple file-server for serving shared library with debug symbols to memtrace");
    CONSOLE("File server is listening on [::0]:3002 by default and annouces itself through multicast");
    CONSOLE("");
    CONSOLE("Options:");
    CONSOLE("   -c, --connect=HOST[:PORT]   Connect to specified HOST");
    CONSOLE("   -l, --listen=HOST[:PORT]    Listen on the specified HOST");
    CONSOLE("   -p, --port=VALUE            Use the specified port");
    CONSOLE("   -a, --acl=PATH              Add this directory to ACL");
    CONSOLE("   -h, --help                  Display this help");
    CONSOLE("   -V, --version               Display the version");
}

static void version() {
    CONSOLE("memtrace-server " VERSION);
}

int main(int argc, char *argv[]) {
    const char *short_options = "+c:l:a:s:vhV";
    const struct option long_options[] = {
        {"connect",     required_argument,  0, 'c'},
        {"listen",      required_argument,  0, 'l'},
        {"acl",         required_argument,  0, 'a'},
        {"socket",      required_argument,  0, 's'},
        {"verbose",     no_argument,        0, 'v'},
        {"help",        no_argument,        0, 'h'},
        {"version",     no_argument,        0, 'V'},
        {0}
    };
    int i = 0;
    int opt = -1;
    const char *hostname = "0.0.0.0";
    const char *port = "3002";
    bool client = false;
    int ipc_socket = -1;
    memtrace_server_t server = {0};

    strlist_insert(&server.directories, "");
    strlist_insert(&server.directories, ".");

    strlist_insert(&server.acls, "/usr/");
    strlist_insert(&server.acls, "/lib/");
    strlist_insert(&server.acls, "/lib32/");
    strlist_insert(&server.acls, "/lib64/");
    strlist_insert(&server.acls, "/bin/");
    strlist_insert(&server.acls, "/sbin/");
    strlist_insert(&server.acls, "/opt/");

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                hostname = strtok(optarg, ":");
                port = strtok(NULL, ":");
                client = true;
                break;
            case 'l':
                hostname = strtok(optarg, ":");
                port = strtok(NULL, ":");
                break;
            case 'a':
                strlist_insert(&server.acls, optarg);
                break;
            case 's':
                ipc_socket = atoi(optarg);
                break;
            case 'v':
                verbose++;
                break;
            case 'h':
                help();
                return 0;
            case 'V':
                version();
                return 0;
            default:
                help();
                return 1;
        }
    }

    signal(SIGPIPE, SIG_IGN);

    for (i = optind; i < argc; i++) {
        struct stat st = {0};
        char *path = argv[i];

        if (stat(path, &st) != 0) {
            CONSOLE("Can not open %s: %m", path);
            return 1;
        }

        if ((st.st_mode & S_IFMT) == S_IFDIR) {
            //CONSOLE("Adding directory %s to search path", path);
            strlist_insert(&server.directories, path);
        }
        else {
            //CONSOLE("Adding file %s to search path", path);
            strlist_insert(&server.files, path);
        }
    }

    server.evlp = evlp_create();
    bus_initialize(&server.bus, server.evlp, "memtrace-server", "memtrace");

    server.report_topic.name = "report";
    server.report_topic.read = server_report_cmd;
    bus_register_topic(&server.bus, &server.report_topic);

    if (ipc_socket >= 0) {
        if (!bus_ipc_socket(&server.bus, ipc_socket)) {
            TRACE_ERROR("Failed to connect to ipc socket %d", ipc_socket);
        }
    }
    else if (client) {
        CONSOLE("Connecting to [%s]:%s", hostname, port);
        if (!bus_tcp_connect(&server.bus, hostname, port)) {
            TRACE_ERROR("Failed to connect to %s:%s", hostname, port);
        }
    }
    else {
        CONSOLE("Listening on [%s]:%s", hostname, port);
        if (!bus_tcp_listen(&server.bus, hostname, port)) {
            TRACE_ERROR("Failed to listen on %s:%s", hostname, port);
        }
    }
    evlp_main(server.evlp);

    strlist_cleanup(&server.directories);
    strlist_cleanup(&server.files);
    strlist_cleanup(&server.acls);
    bus_cleanup(&server.bus);
    evlp_destroy(server.evlp);

    return 0;
}

