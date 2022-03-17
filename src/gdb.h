#ifndef GDB_H
#define GDB_H

#include "types.h"

typedef struct {
    const char *gdb_binary;
    const char *sysroot;
    const char *solib_search_path;
    const char *tgt_binary;
    const char *coredump;
} gdb_cfg_t;

bool gdb_initialize(const gdb_cfg_t *cfg);
void gdb_cleanup();
void gdb_load(const char *filename);
char *gdb_backtrace();

#endif
