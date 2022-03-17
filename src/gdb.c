#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include "gdb.h"
#include "log.h"
#include "process.h"

static process_t gdb_process;

void gdb_cmd(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    vfprintf(gdb_process.input, fmt, ap);
    fflush(gdb_process.input);
    va_end(ap);
}

bool gdb_initialize(const gdb_cfg_t *cfg) {
    const char *argv[] = {cfg->gdb_binary, NULL};

    if (!process_start(&gdb_process, argv)) {
        TRACE_ERROR("Failed to start gdb");
        return false;
    }

    gdb_cmd("set pagination off\n");
    gdb_cmd("directory .\n");
    gdb_cmd("set sysroot %s\n", cfg->sysroot);
    gdb_cmd("set solib-search-path %s\n", cfg->solib_search_path);
    gdb_cmd("set file %s\n", cfg->tgt_binary);
    gdb_cmd("core-file %s\n", cfg->coredump);

    while (fgets(g_buff, sizeof(g_buff), gdb_process.output)) {
        char *sep = NULL;

        if ((sep = strchr(g_buff, '\n'))) {
            *sep = 0;
        }

        CONSOLE("%s", g_buff);
    }

    return true;
}

void gdb_cleanup() {
    process_stop(&gdb_process);
}

void gdb_load(const char *filename) {

}

char *gdb_backtrace() {
    char *backtrace = NULL;

    fprintf(gdb_process.input, "backtrace\n");
    fflush(gdb_process.input);

    return backtrace;
}


