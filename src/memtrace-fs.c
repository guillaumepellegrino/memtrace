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
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "net.h"
#include "fs.h"
#include "log.h"

__attribute__((aligned)) char g_buff[G_BUFF_SIZE];

static void help() {
    CONSOLE("Usage: memtrace-fs [OPTION].. [PATH]..");
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
    CONSOLE("memtrace-fs " VERSION);
}

int main(int argc, char *argv[]) {
    const char *short_options = "+c:l:a:vhV";
    const struct option long_options[] = {
        {"connect",     required_argument,  0, 'c'},
        {"listen",      required_argument,  0, 'l'},
        {"acl",         required_argument,  0, 'a'},
        {"verbose",     no_argument,        0, 'v'},
        {"help",        no_argument,        0, 'h'},
        {"version",     no_argument,        0, 'V'},
        {0}
    };
    int i = 0;
    int opt = -1;
    fs_cfg_t fs_cfg = {
        .type = fs_type_tcp_server,
        .me = "memtrace-fs",
        .tgt = "memtrace",
    };
    fs_t fs = {0};
    //gdb_cfg_t gdb_cfg = {0};

    strlist_insert(&fs_cfg.directories, "");
    strlist_insert(&fs_cfg.directories, ".");

    strlist_insert(&fs_cfg.acls, "/usr/");
    strlist_insert(&fs_cfg.acls, "/lib/");
    strlist_insert(&fs_cfg.acls, "/lib32/");
    strlist_insert(&fs_cfg.acls, "/lib64/");
    strlist_insert(&fs_cfg.acls, "/bin/");
    strlist_insert(&fs_cfg.acls, "/sbin/");
    strlist_insert(&fs_cfg.acls, "/opt/");

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                fs_cfg.type = fs_type_tcp_client;
                fs_cfg.hostname = strtok(optarg, ":");
                fs_cfg.port = strtok(NULL, ":");
                break;
            case 'l':
                fs_cfg.hostname = strtok(optarg, ":");
                fs_cfg.port = strtok(NULL, ":");
                break;
            case 'a':
                strlist_insert(&fs_cfg.acls, optarg);
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

    for (i = optind; i < argc; i++) {
        struct stat st = {0};
        char *path = argv[i];

        if (stat(path, &st) != 0) {
            CONSOLE("Can not open %s: %m", path);
            return 1;
        }

        if ((st.st_mode & S_IFMT) == S_IFDIR) {
            CONSOLE("Adding directory %s to search path", path);
            strlist_insert(&fs_cfg.directories, path);
        }
        else {
            CONSOLE("Adding file %s to search path", path);
            strlist_insert(&fs_cfg.files, path);
        }
    }

    if (!fs_initialize(&fs, &fs_cfg)) {
        CONSOLE("Failed to initialize File System Server");
        return 1;
    }

    if (!fs_serve(&fs)) {
        return 1;
    }

    fs_cleanup(&fs);
    strlist_cleanup(&fs_cfg.directories);
    strlist_cleanup(&fs_cfg.files);
    strlist_cleanup(&fs_cfg.acls);

    return 0;
}
