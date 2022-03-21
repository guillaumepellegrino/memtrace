#ifndef GDB_H
#define GDB_H

#include "types.h"
#include "strlist.h"
#include "process.h"

typedef struct {
    const char *gdb_binary;
    const char *sysroot;
    const char *solib_search_path;
    const char *tgt_binary;
    const char *coredump;
    FILE *userin;
    FILE *userout;
} gdb_cfg_t;

typedef struct {
    FILE *userin;
    FILE *userout;
    process_t process;
} gdb_t;

bool gdb_initialize(gdb_t *gdb, const gdb_cfg_t *cfg);
void gdb_cleanup(gdb_t *gdb);
void gdb_backtrace(gdb_t *gdb);
bool gdb_interact(gdb_t *gdb);


#endif
