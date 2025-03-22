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

#define TRACE_ZONE TRACE_ZONE_CONSOLE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include "console.h"
#include "log.h"

static inline void ESC_SEQ_UP(int value) {CONSOLE_RAW("\x1B[%dA", value);}
static inline void ESC_SEQ_DOWN(int value) {CONSOLE_RAW("\x1B[%dB", value);}
static inline void ESC_SEQ_RIGHT(int value) {CONSOLE_RAW("\x1B[%dC", value);}
static inline void ESC_SEQ_LEFT(int value) {CONSOLE_RAW("\x1B[%dD", value);}
static inline void ESC_SEQ_HORIZONTAL_ABS(int value) {CONSOLE_RAW("\x1B[%dG", value);}
static inline void ESC_SEQ_ERASE_IN_DISPLAY(int value) {CONSOLE_RAW("\x1B[%dJ", value);}
static inline void ESC_SEQ_ERASE_IN_LINE_FROM_CURSOR_TO_END() {CONSOLE_RAW("\x1B[0K");}
static inline void ESC_SEQ_ERASE_IN_LINE_FROM_CURSOR_TO_BEGINING() {CONSOLE_RAW("\x1B[1K");}
static inline void ESC_SEQ_ERASE_IN_LINE_ALL() {CONSOLE_RAW("\x1B[2K");}

void console_clear_line(console_t *console) {
    CONSOLE_RAW("\033[2K\r");
}

static void console_reset(console_t *console) {
    console->argc = 0;
    console->argv[0] = console->buff;
    console->buff[0] = 0;
    console->bufflen = 0;
    console->cursor = 0;
    CONSOLE_RAW("> ");
}

static void console_addchar(console_t *console, char c) {
    if (console->bufflen >= sizeof(console->buff)-1) {
        TRACE_LOG("cmdline too long (%zu)", console->bufflen);
        return;
    }
    const char *right = &console->buff[console->cursor];
    //TRACE_DEBUG("cursor:%d, bufflen:%d", console->cursor, console->bufflen);
    if (console->cursor < console->bufflen) {
        // Rewrite line
        assert(write(1, &c, 1) > 0);
        CONSOLE_RAW("%s", right);
        ESC_SEQ_LEFT(strlen(right));
    }
    else {
        // Append new char at the end of the line
        assert(write(1, &c, 1) > 0);
    }

    // Insert char in the buffer according cursor position
    memmove(&console->buff[console->cursor + 1],
            &console->buff[console->cursor],
            strlen(right));
    console->buff[console->cursor] = c;
    console->bufflen++;
    console->buff[console->bufflen] = 0;
    console->cursor++;
}

static void console_backspace(console_t *console) {
    if (console->bufflen <= 0) {
        return;
    }

    char *right = &console->buff[console->cursor];
    size_t rightlen = strlen(right);

    // Rewrite line
    CONSOLE_RAW("\x08%s ", right);
    ESC_SEQ_LEFT(rightlen + 1);

    // Delete char from internal buffer at the specified cursor position
    memmove(right-1, right, rightlen);
    console->cursor--;
    console->bufflen--;
    console->buff[console->bufflen] = 0;
}

static void console_suppr(console_t *console) {
    char c = 0;
    if (read(0, &c, 1) < 0) {
        return;
    }
    if (c != '~') {
        CONSOLE("Unexpected character '%c'", c);
        return;
    }

    TRACE_DEBUG("SUPPR cursor:%zu, bufflen:%zu", console->cursor, console->bufflen);
    if (console->cursor < console->bufflen) {
        TRACE_DEBUG("DO SUPPR");
        char *right = &console->buff[console->cursor];
        size_t rightlen = strlen(right);

        // Rewrite line
        CONSOLE_RAW("%s ", right+1);
        ESC_SEQ_LEFT(rightlen);

        // Delete char from internal buffer at the specified cursor position
        memmove(right, right+1, rightlen-1);
        console->bufflen--;
        console->buff[console->bufflen] = 0;
    }
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

static void console_eol(console_t *console) {
    size_t i;
    const console_cmd_t *cmd = NULL;

    assert(write(1, "\r\n", 2) > 0);

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
    if (console->argc == 0) {
        console_reset(console);
        return;
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

    TRACE_DEBUG("cmd_count=%zu", cmd_count);

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
        if (tcsetattr(0, TCSANOW, &termios) < 0) {
            TRACE_ERROR("Failed to set console attributes 0x%x: %m", termios.c_lflag);
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
    if (console->is_tty && tcsetattr(0, TCSANOW, &console->backup) < 0) {
        TRACE_ERROR("Failed to set console attributes 0x%x: %m", console->backup.c_lflag);
    }
    strlist_cleanup(&console->history);
}

static void console_cursor_reset(console_t *console) {
    ESC_SEQ_LEFT(console->cursor);
    console->cursor = 0;
}

static void console_cursor_left(console_t *console) {
    if (console->cursor > 0) {
        ESC_SEQ_LEFT(1);
        console->cursor--;
    }
}

static void console_cursor_right(console_t *console) {
    if (console->cursor < console->bufflen) {
        ESC_SEQ_RIGHT(1);
        console->cursor++;
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
                case 0x33: // SUPPR
                    console_suppr(console);
                    break;
                case 0x41: // UP
                    console_history_prev(console);
                    break;
                case 0x42: // LOW
                    console_history_next(console);
                    break;
                case 0x43: // RIGHT
                    console_cursor_right(console);
                    break;
                case 0x44: // LEFT
                    console_cursor_left(console);
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
        case 0x01:
        case 0x02:
            console_cursor_reset(console);
            break;
        case 0x1B: // ESC (escape)
            console_escape_character(console);
            break;
        case 0x7F: // DEL
            console_backspace(console);
            break;
        case '\n':
            console_eol(console);
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
        CONSOLE("  %10s %s", cmd->name, cmd->help);
    }
    CONSOLE("");
}
