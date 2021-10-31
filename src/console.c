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

#define TRACE_ZONE TRACE_ZONE_CONSOLE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include "console.h"
#include "log.h"

static void console_reset(console_t *console) {
    console->argc = 0;
    console->argv[0] = console->buff;
    console->bufflen = 0;
    CONSOLE_RAW("> ");
}

static void console_addchar(console_t *console, char c) {
    if (console->bufflen >= sizeof(console->buff)) {
        TRACE_LOG("cmdline too long (%zu)", console->bufflen);
        return;
    }

    if (c) {
        assert(write(1, &c, 1) > 0);
    }
    console->buff[console->bufflen] = c;
    console->bufflen++;
}

static void console_delchar(console_t *console) {
    if (console->bufflen <= 0) {
        return;
    }

    CONSOLE_RAW("\b \b");
    console->bufflen--;
}

static void console_separator(console_t *console, char c) {
    if (console->argc >= countof(console->argv)) {
        TRACE_ERROR("command too much arguments");
        return;
    }

    assert(write(1, &c, 1) > 0);
    console_addchar(console, 0);

    console->argc++;
    console->argv[console->argc] = &console->buff[console->bufflen];
}

static void console_eol(console_t *console, int c) {
    size_t i;
    const console_cmd_t *cmd = NULL;

    assert(write(1, &c, 1) > 0);

    if (console->bufflen >= sizeof(console->buff)) {
        TRACE_ERROR("command line too long");
        console_reset(console);
        return;
    }
    console_separator(console, ' ');

    TRACE_DEBUG("cmd: ");
    for (i = 0; i < console->argc; i++) {
        TRACE_DEBUG("  [%zu]=%s", i, console->argv[i]);
    }

    for (cmd = console->cmd_list; cmd->name; cmd++) {
        if (!strcmp(cmd->name, console->argv[0])) {
            if (cmd->handler) {
                cmd->handler(console, console->argc, console->argv);
            }
            break;
        }
    }

    if (!cmd->name && (console->bufflen > 1)) {
        CONSOLE("Unknown command");
    }

    console_reset(console);
}

static void console_autocomplete(console_t *console) {
    const console_cmd_t *cmd = NULL;
    size_t cmd_count = 0;

    TRACE_DEBUG("autocomplete");
    if (console->argc != 0) {
        TRACE_DEBUG("argc!=0");
        return;
    }
    if (console->bufflen >= sizeof(console->buff)) {
        TRACE_LOG("cmdline too long (%zu)", console->bufflen);
        return;
    }
    console->buff[console->bufflen] = 0;

    for (cmd = console->cmd_list; cmd->name; cmd++) {
        if (!strncmp(console->buff, cmd->name, console->bufflen)) {
            cmd_count++;
        }
    }


    if (cmd_count == 1) {
        for (cmd = console->cmd_list; cmd->name; cmd++) {
            if (!strncmp(console->buff, cmd->name, console->bufflen)) {
                size_t i;
                for (i = console->bufflen; i < strlen(cmd->name); i++) {
                    console_addchar(console, cmd->name[i]);
                }
                break;
            }
        }
    }
    else if (cmd_count > 1) {
        CONSOLE("\n");
        for (cmd = console->cmd_list; cmd->name; cmd++) {
            if (!strncmp(console->buff, cmd->name, console->bufflen)) {
                CONSOLE("%s", cmd->name);
            }
        }
        CONSOLE_RAW("> %s", console->argv[0]);
    }
}

bool console_initiliaze(console_t *console, const console_cmd_t *cmd_list) {
    struct termios termios = {0};

    assert(console);
    TRACE_WARNING("init");

    memset(console, 0, sizeof(console_t));
    console->cmd_list = cmd_list;

    if (tcgetattr(0, &termios) < 0) {
        TRACE_ERROR("Failed to get console attr: %m");
        return false;
    }
    console->backup = termios;

    // Read char by char
    termios.c_lflag &= ~(ECHO | ECHONL | ICANON);
    if (tcsetattr(0, 0, &termios) < 0) {
        TRACE_ERROR("Failed to set console attr: %m");
        return false;
    }

    console_reset(console);

    return true;
}

void console_cleanup(console_t *console) {
    assert(console);

    TRACE_WARNING("cleanup");
    if (tcsetattr(0, 0, &console->backup) < 0) {
        TRACE_ERROR("Failed to set console attr: %m");
    }
}

void console_poll(console_t *console) {
    assert(console);

    char c = 0;
    if (read(0, &c, 1) < 0) {
        return;
    }

    switch (c) {
        default:
            console_addchar(console, c);
            break;
        case ' ':
            console_separator(console, c);
            break;
        case 0x7F: //DEL
            console_delchar(console);
            break;
        case '\n':
            console_eol(console, c);
            break;
        case '\t':
            console_autocomplete(console);
            break;
    }
}

void console_cmd_help(console_t *console, int argc, char *argv[]) {
    const console_cmd_t *cmd = NULL;

    CONSOLE("List of commands:");
    for (cmd = console->cmd_list; cmd->name; cmd++) {
        CONSOLE("  %9s: %s", cmd->name, cmd->help);
    }
    CONSOLE("");
}
