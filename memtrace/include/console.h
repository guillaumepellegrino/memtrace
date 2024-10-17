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

#ifndef CONSOLE_H
#define CONSOLE_H

#include <termios.h>
#include "types.h"
#include "strlist.h"

struct _console_cmd {
    const char *name;
    const char *help;
    void (*handler)(console_t *console, int argc, char *argv[]);
};

struct _console {
    const console_cmd_t *cmd_list;
    size_t argc;
    char *argv[12];
    size_t bufflen;
    char buff[512];
    struct termios backup;
    size_t cursor;
    strlist_t history;
    strlist_iterator_t *history_iterator;
    bool is_tty;
};

bool console_initiliaze(console_t *console, const console_cmd_t *cmd_list);
void console_cleanup(console_t *console);
bool console_poll(console_t *console);

void console_cmd_help(console_t *console, int argc, char *argv[]);

#endif
