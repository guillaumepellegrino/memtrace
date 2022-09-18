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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "inject.h"
#include "libraries.h"
#include "log.h"

__attribute__((aligned)) char g_buff[G_BUFF_SIZE];

#define process_for_each_thread(tid, dir) \
    for (tid = process_first_thread(dir); tid > 0; tid = process_next_thread(dir))

static DIR *process_threads(int pid) {
    char task_path[128];
    DIR *threads = NULL;

    if (pid <= 0) {
        TRACE_ERROR("pid was not provided");
        return false;
    }

    snprintf(task_path, sizeof(task_path), "/proc/%d/task/", pid);

    if (!(threads = opendir(task_path))) {
        TRACE_ERROR("Failed to open %s: %m", task_path);
        return NULL;
    }

    return threads;
}

static int process_next_thread(DIR *threads) {
    struct dirent *task_entry = NULL;

    if (!threads) {
        return 0;
    }

    while ((task_entry = readdir(threads))) {
        int tid = atoi(task_entry->d_name);
        if (tid <= 0) {
            continue;
        }
        return tid;
    }

    return 0;
}

static int process_first_thread(DIR *threads) {
    if (!threads) {
        return 0;
    }

    seekdir(threads, 0);

    return process_next_thread(threads);
}

static bool thread_attach(int tid) {
    int status = 0;

    if (tid <= 0) {
        TRACE_ERROR("tid was not provided");
        return false;
    }
    if (ptrace(PTRACE_SEIZE, tid, 0, 0) != 0) {
        TRACE_ERROR("ptrace(SEIZE, %d, 0, 0) failed: %m", tid);
        return false;
    }
    if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0) {
        TRACE_ERROR("ptrace(INTERRUPT, %d, 0, 0) failed: %m", tid);
        return false;
    }
    if (waitpid(tid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", tid);
        return false;
    }
    if (ptrace(PTRACE_SETOPTIONS, tid, 0, PTRACE_O_TRACESYSGOOD) != 0) {
        TRACE_ERROR("ptrace(SETOPTIONS, %d, 0, TRACESYSGOOD) failed: %m", tid);
        return false;
    }
    return true;
}

static void help() {
    CONSOLE("./target/inject -p $(pidof dummy)");
}

int main(int argc, char *argv[]) {
    static struct {
        const char *name;
        const char *inject;
    } replace_functions[] = {
        {"malloc",          "malloc_hook"},
        {"calloc",          "calloc_hook"},
        {"calloc",          "calloc_hook"},
        {"realloc",         "realloc_hook"},
        {"reallocarray",    "reallocarray_hook"},
        {"free",            "free_hook"},
    };
    const char *short_options = "+p:l:hV";
    const struct option long_options[] = {
        {"pid",         required_argument,  0, 'p'},
        {"library",     required_argument,  0, 'l'},
        {0},
    };
    const char *me = argv[0];
    int rt = 1;
    int opt = -1;
    int pid = -1;
    int tid = -1;
    DIR *threads = NULL;
    const char *libname = "/home/guillaume/Workspace/memtrace/target/memtrace-agent.so";
    injecter_t *injecter = NULL;

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                pid = atoi(optarg);
                break;
            case 'l':
                libname = optarg;
                break;
            case 'h':
                help();
                goto error;
            default:
                help();
                goto error;
        }
    }

    if (pid <= 0) {
        CONSOLE("PID not provided");
        help();
        goto error;
    }
    if (!libname) {
        CONSOLE("Library name not provided");
        help();
        goto error;
    }
    if (!(threads = process_threads(pid))) {
        CONSOLE("Failed to get thread list from pid %d", pid);
        goto error;
    }
    process_for_each_thread(tid, threads) {
        if (!thread_attach(tid)) {
            TRACE_ERROR("Failed to attach to thread %d", tid);
            return false;
        }
        CONSOLE("%s attached to pid:%d/tid:%d", me, pid, tid);
    }

    if (!(injecter = injecter_create(pid))) {
        TRACE_ERROR("Failed to create code injecter");
        goto error;
    }
    if (!injecter_load_library(injecter, libname)) {
        TRACE_ERROR("Failed to load %s inside pid %d", libname, pid);
        goto error;
    }

    CONSOLE("[Replacing functions]");
    for (size_t i = 0; i < sizeof(replace_functions)/sizeof(*replace_functions); i++) {
        injecter_replace_function(injecter, replace_functions[i].name, replace_functions[i].inject);
    }
    rt = 0;

error:
    if (injecter) {
        injecter_destroy(injecter);
    }
    if (threads) {
        process_for_each_thread(tid, threads) {
            if (ptrace(PTRACE_DETACH, tid, NULL, NULL) != 0) {
                TRACE_ERROR("ptrace(DETACH, %d) failed: %m", tid);
            }
        }
        closedir(threads);
    }
    return rt;
}
