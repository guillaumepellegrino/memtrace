#pragma once

#include "types.h"

typedef struct _injecter injecter_t;

injecter_t *injecter_create(int pid);
void injecter_destroy(injecter_t *injecter);
bool injecter_load_library(injecter_t *injecter, const char *libname);
bool injecter_replace_function(injecter_t *injecter, const char *program_fname, const char *inject_fname);



bool memtrace_code_injection(int pid, libraries_t *libraries);

