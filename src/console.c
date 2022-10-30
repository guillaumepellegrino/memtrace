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
#include <errno.h>
#include "console.h"
#include "log.h"

void console_clear_line(console_t *console) {
    CONSOLE_RAW("\033[2K\r");
}

static void console_reset(console_t *console) {
    console->argc = 0;
    console->argv[0] = console->buff;
    console->buff[0] = 0;
    console->bufflen = 0;
    CONSOLE_RAW("> ");
}

static void console_addchar(console_t *console, char c) {
    if (console->bufflen >= sizeof(console->buff)-1) {
        TRACE_LOG("cmdline too long (%zu)", console->bufflen);
        return;
    }

    if (c) {
        assert(write(1, &c, 1) > 0);
    }
    console->buff[console->bufflen] = c;
    console->bufflen++;
    console->buff[console->bufflen] = 0;
}

static void console_delchar(console_t *console) {
    if (console->bufflen <= 0) {
        return;
    }

    CONSOLE_RAW("\b \b");
    console->bufflen--;
    console->buff[console->bufflen] = 0;
}

static void console_history_restore(console_t *console) {
    const char *cmd = strlist_iterator_value(console->history_iterator);

    console_clear_line(console);
    console_reset(console);

    int i = 0;
    for (i = 0; cmd[i]; i++) {
        console_addchar(console, cmd[i]);
    }
}

static void console_history_prev(console_t *console) {
    if (!console->history_iterator) {
        if ((console->history_iterator = strlist_last(&console->history))) {
            console_history_restore(console);
        }
    }
    else {
        strlist_iterator_t *prev = strlist_iterator_prev(console->history_iterator);
        if (prev) {
            console->history_iterator = prev;
        }
        console_history_restore(console);
    }
}

static void console_history_next(console_t *console) {
    if (!console->history_iterator) {
        if ((console->history_iterator = strlist_last(&console->history))) {
            console_history_restore(console);
        }
    }
    else {
        strlist_iterator_t *next = strlist_iterator_next(console->history_iterator);
        if (next) {
            console->history_iterator = next;
        }
        console_history_restore(console);
    }
}

static void console_add_history(console_t *console, const char *cmd) {
    if (cmd && *cmd) {
        strlist_append(&console->history, cmd);
        console->history_iterator = NULL;
    }
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

    console_add_history(console, console->buff);

    char *it = NULL;
    for (it = strtok(console->buff, " "); it; it = strtok(NULL, " ")) {
        if (console->argc >= countof(console->argv)) {
            break;
        }
        console->argv[console->argc++] = it;
    }

    TRACE_LOG("cmd:");
    for (i = 0; i < console->argc; i++) {
        TRACE_LOG("  [%zu]=%s", i, console->argv[i]);
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
        CONSOLE("Unknown command '%s'", console->argv[0]);
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
    TRACE_LOG("init");

    memset(console, 0, sizeof(console_t));
    console->cmd_list = cmd_list;

    if (tcgetattr(0, &termios) == 0) {
        console->backup = termios;

        // Read char by char
        termios.c_lflag &= ~(ECHO | ECHONL | ICANON);
        if (tcsetattr(0, 0, &termios) < 0) {
            TRACE_ERROR("Failed to set console attr: %m");
            return false;
        }
        console->is_tty = true;
    }
    console_reset(console);

    return true;
}

void console_cleanup(console_t *console) {
    if (!console) {
        return;
    }

    TRACE_LOG("cleanup");
    if (console->is_tty && tcsetattr(0, 0, &console->backup) < 0) {
        TRACE_ERROR("Failed to set console attr: %m");
    }
}

static void console_escape_character(console_t *console) {
    char c = 0;
    if (read(0, &c, 1) < 0) {
        return;
    }

    switch (c) {
        case 0x5B:
            if (read(0, &c, 1) < 0) {
                return;
            }

            switch (c) {
                case 0x41: // UP
                    console_history_prev(console);
                    break;
                case 0x42: // LOW
                    console_history_next(console);
                    break;
                case 0x43: // RIGHT
                    break;
                case 0x44: // LEFT
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
}

bool console_poll(console_t *console) {
    assert(console);

    char c = 0;
    ssize_t len = 0;
    if ((len = read(0, &c, 1)) < 0) {
        return (errno == EINTR) ? true: false;
    }
    if (len == 0) {
        return false;
    }

    switch (c) {
        default:
            console_addchar(console, c);
            break;
        case 0x1B: // ESC (escape)
            console_escape_character(console);
            break;
        case 0x7F: // DEL
            console_delchar(console);
            break;
        case '\n':
            console_eol(console, c);
            break;
        case '\t':
            console_autocomplete(console);
            break;
    }

    return true;
}

void console_cmd_help(console_t *console, int argc, char *argv[]) {
    const console_cmd_t *cmd = NULL;

    CONSOLE("List of commands:");
    for (cmd = console->cmd_list; cmd->name; cmd++) {
        CONSOLE("  %9s: %s", cmd->name, cmd->help);
    }
    CONSOLE("");
}
