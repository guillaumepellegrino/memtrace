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

#pragma once

#include "types.h"

typedef struct _injecter injecter_t;

injecter_t *injecter_create(int pid);
void injecter_destroy(injecter_t *injecter);
bool injecter_load_library(injecter_t *injecter, const char *libname);
bool injecter_replace_function(injecter_t *injecter, const char *program_fname, const char *inject_fname);



bool memtrace_code_injection(int pid, libraries_t *libraries);

