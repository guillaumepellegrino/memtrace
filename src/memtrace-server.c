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

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/un.h>
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

static const char *skip_whitespace_and_comment(const char *s) {
    for (; *s; s++) {
        if (!isblank(*s) && *s != '#') {
            break;
        }
    }

    return s;
}

static char *get_topic(const char *line, const char *topic) {
    size_t topiclen = strlen(topic);
    char *value = NULL;
    char *sep = NULL;

    line = skip_whitespace_and_comment(line);

    if (!strncmp(line, topic, topiclen)) {
        value = strdup(line + topiclen);
        if ((sep = strchr(value, '\n'))) {
            *sep = 0;
        }
    }

    return value;
}

static bool server_report_parse_addr(memtrace_server_t *server, FILE *out, addr2line_t *addr2line, char *addrstr, const char *sysroot) {
    char *sep = NULL;
    const char *tgtpath = NULL;
    char *hostpath = NULL;
    size_t address = 0;

    tgtpath = addrstr;
    if ((sep = strchr(addrstr, '+'))) {
        *sep = 0;
        sscanf(sep+1, "0x%zx", &address);
    }

    if (!(hostpath = target2host_path(sysroot, &server->files, &server->directories, &server->acls, tgtpath))) {
        TRACE_ERROR("%s: not found", tgtpath);
        fprintf(out, "%s", addrstr);
        goto exit;
    }
    addr2line_print(addr2line, hostpath, address, out);

exit:
    free(hostpath);
    return true;
}

static FILE *server_start_dataviewer(memtrace_server_t *server) {
    struct sockaddr_un connaddr = {
        .sun_family = AF_UNIX,
    };
    int s = -1;

    if (system("dataviewer --stream") != 0) {
        CONSOLE("Failed to start dataviewer: %m");
        CONSOLE("You may need to install it with the following steps:");
        CONSOLE("- Install rust toolchain:");
        CONSOLE("  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh");
        CONSOLE("- Install GTK4 dependency:");
        CONSOLE("  sudo apt install libgtk-4-dev");
        CONSOLE("- Install dataviewer itself from rust package manager:");
        CONSOLE("  cargo install dataviewer --locked'");
        CONSOLE("");
        CONSOLE("");
        goto error;
    }
    if ((s = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0)) < 0) {
        CONSOLE("Failed to create ipc socket: %m\n");
        goto error;
    }
    snprintf(connaddr.sun_path, sizeof(connaddr.sun_path),
        "/tmp/dataviewer.ipc");

    if (connect(s, (struct sockaddr *) &connaddr, sizeof(connaddr)) != 0) {
        CONSOLE("Failed to connext ipc socket to %s: %m\n", connaddr.sun_path);
        goto error;
    }
    CONSOLE("Dataviewer started");

    return fdopen(s, "w");

error:
    close(s);
    return NULL;
}

// This function could benefit some refactoring
static void server_parse_report(memtrace_server_t *server, FILE *in, FILE *out) {
    char line[4096];
    char *cmd_done = NULL;
    char *sysroot = NULL;
    char *toolchain = NULL;
    char *binary = NULL;
    char *dataview = NULL;
    FILE *dataviewer = NULL;
    addr2line_t addr2line = {0};

    while (fgets(line, sizeof(line), in)) {
        bool show2user = true;
        if ((cmd_done = get_topic(line, "[cmd_done]"))) {
            break;
        }
        if (!sysroot) {
            if ((sysroot = get_topic(line, "[sysroot]"))) {
                if (!host_path_is_allowed(sysroot, &server->acls)) {
                    TRACE_ERROR("sysroot path '%s' is not allowed by ACLs", sysroot);
                    free(sysroot);
                    sysroot = NULL;
                }
                show2user = false;
            }
        }
        if (!toolchain) {
            if ((toolchain = get_topic(line, "[toolchain]"))) {
                if (!host_path_is_allowed(toolchain, &server->acls)) {
                    TRACE_ERROR("toolchain path '%s' is not allowed by ACLs", toolchain);
                    free(toolchain);
                    toolchain = NULL;
                }
                if (toolchain) {
                    assert(asprintf(&binary, "%saddr2line", toolchain) > 0);
                    addr2line_initialize(&addr2line, binary);
                }
                show2user = false;
            }
        }
        if (!dataview) {
            dataview = get_topic(line, "[dataview]");
            if (dataview) {
                dataviewer = server_start_dataviewer(server);
                out = dataviewer;
            }
        }
        if (sysroot && toolchain) {
            char *addr = NULL;
            if ((addr = get_topic(line, "[addr]"))) {
                server_report_parse_addr(server, out, &addr2line, addr, sysroot);
                free(addr);
                show2user = false;
            }
        }

        if (show2user) {
            fputs(line, out);
        }
    }

    free(cmd_done);
    free(sysroot);
    free(toolchain);
    free(binary);
    free(dataview);
    if (dataviewer) {
        fputc(0, dataviewer);
        fflush(dataviewer);
        fclose(dataviewer);
    }
    addr2line_cleanup(&addr2line);
}

static bool server_report_cmd(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {
    memtrace_server_t *server = container_of(bus, memtrace_server_t, bus);
    FILE *in = bus_connection_reader(connection);
    FILE *out = bus_connection_writer(connection);
    server_parse_report(server, in, out);
    fprintf(out, "[cmd_done]\n");
    fflush(out);
    return true;
}

static bool server_parse_offline_report(memtrace_server_t *server, const char *report_path) {
    char *output_path = NULL;
    FILE *in = NULL;
    FILE *out = NULL;
    bool rt = false;

    if (!strcmp(report_path, "-")) {
        in = stdin;
        out = stdout;
    }
    else {
        assert(asprintf(&output_path, "%s.decoded", report_path) > 0);
        in = fopen(report_path, "r");
        out = fopen(output_path, "w");
        if (!in) {
            TRACE_ERROR("Failed to open %s: %m", report_path);
            goto error;
        }
        if (!out) {
            TRACE_ERROR("Failed to open %s: %m", output_path);
            goto error;
        }
    }

    printf("Writing report to %s\n", (output_path ? output_path : "console"));
    server_parse_report(server, in, out);
    fflush(out);
    printf("Report written to %s\n", (output_path ? output_path : "console"));
    rt = true;

error:
    free(output_path);
    if (in && in != stdin) {
        fclose(in);
    }
    if (out && out != stdout) {
        fclose(out);
    }
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
    CONSOLE("   -r, --report=PATH           Decode symbols from offline report");
    CONSOLE("   -d, --debug                 Enable debug logs");
    CONSOLE("   -h, --help                  Display this help");
    CONSOLE("   -V, --version               Display the version");
}

static void version() {
    CONSOLE("memtrace-server " VERSION);
}

int main(int argc, char *argv[]) {
    const char *short_options = "+c:l:a:s:r:dhv";
    const struct option long_options[] = {
        {"connect",     required_argument,  0, 'c'},
        {"listen",      required_argument,  0, 'l'},
        {"acl",         required_argument,  0, 'a'},
        {"socket",      required_argument,  0, 's'},
        {"report",      required_argument,  0, 'r'},
        {"debug",       no_argument,        0, 'd'},
        {"help",        no_argument,        0, 'h'},
        {"version",     no_argument,        0, 'v'},
        {0}
    };
    int i = 0;
    int opt = -1;
    const char *hostname = "0.0.0.0";
    const char *port = "3002";
    bool client = false;
    int ipc_socket = -1;
    const char *report_path = NULL;
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
            case 'r':
                report_path = optarg;
                break;
            case 'd':
                log_more_verbose();
                break;
            case 'h':
                help();
                return 0;
            case 'v':
                version();
                return 0;
            default:
                help();
                return 1;
        }
    }

    signal(SIGPIPE, SIG_IGN);
    evlp_exit_onsignal();
    log_set_header("[memtrace-server]");

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

    if (report_path) {
        server_parse_offline_report(&server, report_path);
        goto exit;
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

exit:
    strlist_cleanup(&server.directories);
    strlist_cleanup(&server.files);
    strlist_cleanup(&server.acls);
    bus_cleanup(&server.bus);
    if(server.evlp) {
        evlp_destroy(server.evlp);
    }

    return 0;
}

