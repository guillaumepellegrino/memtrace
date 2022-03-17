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

#ifndef FS_H
#define FS_H

#include "types.h"
#include "strlist.h"

#define GET_REQUEST "GET/REQUEST/"
#define POST_SYSROOT "POST/SYSROOT/"
#define GET_REPLY "GET/REPLY/"
#define REPORT_REQUEST "REPORT/REQUEST/BEGIN"
#define REPORT_REQUEST_END "REPORT/REQUEST/BEGIN"
#define REPORT_REPLY "REPORT/REQUEST/BEGIN"
#define REPORT_REPLY_END "REPORT/REQUEST/BEGIN"
#define GDB_REQUEST "GDB/REQUEST/"
#define GDB_REPLY "GDB/REPLY/"


enum _fs_type {
    fs_type_local = 0,
    fs_type_tcp_client,
    fs_type_tcp_server,
};

struct _fs_cfg {
    fs_type_t type;
    const char *me;
    const char *tgt;
    const char *hostname;
    const char *mcastaddr;
    const char *port;
    strlist_t directories;
    strlist_t files;
    strlist_t acls;
};

struct _fs {
    fs_cfg_t cfg;
    int mcast;
    int server;
    FILE *socket;
    char *sysroot;
};

/** 
 * Initialize File System according the provided configuration
 */
bool fs_initialize(fs_t *fs, const fs_cfg_t *cfg);
void fs_cleanup(fs_t *fs);

/**
 * Open a file from provided File System
 */
FILE *fs_fopen(fs_t *fs, const char *name, uint64_t size, uint64_t offset);

/**
 * Serve File System
 */
bool fs_serve(fs_t *server);




typedef struct {
    list_t list;
} map_t;

typedef struct _fs_topic fs_topic_t;
struct _fs_topic {
    list_t it;
    const char *topic;
    bool (*read)(fs_topic_t *topic, map_t *options, FILE *fp);
};

void fs_register_topic(fs_topic_t *topic);

FILE *fs_write_request(const char *topic, map_t *options);

/**
 * Simple Message Protocol
 *
 * > POST TOPIC\r\n
 * > $KEY0=$VALUE0\n
 * > $KEY1=$VALUE1\n
 * > \n
 * > $DATA
 *
 * < /REPLY/$TOPIC\n
 * < $KEY2=$VALUE2\n
 * < $KEY3=$VALUE3\n
 * < \n
 * < $DATA
 */
typedef struct _smp smp_t;
typedef struct _smp_topic smp_topic_t;
struct _smp_topic {
    list_t it;
    const char *name;
    bool (*read)(smp_topic_t *topic, map_t *options, FILE *fp);
};

void smp_initialize(smp_t *smp);
void smp_cleanup(smp_t *smp);
void smp_register_topic(smp_t *smp, smp_topic_t *topic);
FILE *smp_write_request(smp_t *smp, const char *topic, map_t *options);



#endif
