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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include "ftrace.h"
#include "log.h"

typedef enum {
    action_read_input = 0,
    action_continue,
    action_step,
    action_quit,
} action_t;

typedef struct _app app_t;
typedef struct _cmd cmd_t;
typedef action_t (*cmd_handler_t)(app_t *app, int argc, char* argv[]);

struct _app {
    ftrace_t ftrace;
    const cmd_t *cmd_list;
    FILE *in;
};

struct _cmd {
    const char *name;
    cmd_handler_t handler;
    const char *help;
};

static bool breakpoint_handler(const ftrace_fcall_t *fcall, void *userdata) {
    size_t callstack[16] = {0};
    app_t *app = userdata;

    CONSOLE("break at %s", ftrace_fcall_name(fcall));
    ftrace_fcall_dump(fcall);

    if (!ftrace_backtrace(&app->ftrace, callstack, sizeof(callstack)/sizeof(*callstack))) {
        CONSOLE("backtrace failed");
    }
    return false;
}

static action_t quit_cmd(app_t *app, int argc, char* argv[]) {

    return action_quit;
}

static action_t help_cmd(app_t *app, int argc, char* argv[]) {
    const cmd_t *cmd = NULL;

    CONSOLE("help");
    CONSOLE("command list:");
    for (cmd = app->cmd_list; cmd->name; cmd++) {
        if (cmd->help) {
            CONSOLE("    %s: %s", cmd->name, cmd->help);
        }

    }

    return action_read_input;
}

static action_t breakpoint_cmd(app_t *app, int argc, char* argv[]) {
    if (argc != 2) {
        CONSOLE("Missing argument");
        return action_read_input;
    }

    size_t address = atoi(argv[1]);
    if (!address) {
        if (sscanf(argv[1], "0x%zx", &address) != 1) {
            if (!ftrace_set_function_breakpoint(&app->ftrace, argv[1], breakpoint_handler, app)) {
                CONSOLE("Failed to set breakpoint on %s", argv[1]);
            }
            return action_read_input;
        }
    }

    if (!ftrace_set_breakpoint(&app->ftrace, argv[1], address, breakpoint_handler, app)) {
        CONSOLE("Failed to set breakpoint at address 0x%zx", address);
    }

    return action_read_input;
}

static action_t clear_cmd(app_t *app, int argc, char* argv[]) {
    return action_read_input;
}

static action_t continue_cmd(app_t *app, int argc, char* argv[]) {
    return action_continue;
}

static action_t step_cmd(app_t *app, int argc, char* argv[]) {
    return action_step;
}

static action_t print_cmd(app_t *app, int argc, char* argv[]) {
    if (argc != 2) {
        CONSOLE("Missing argument");
        return action_read_input;
    }

    size_t address = ftrace_function_address(&app->ftrace, argv[1]);
    CONSOLE("%s = 0x%zx", argv[1], address);

    return action_read_input;
}

static action_t backtrace_cmd(app_t *app, int argc, char* argv[]) {
    size_t callstack[16] = {0};

    if (!ftrace_backtrace(&app->ftrace, callstack, sizeof(callstack)/sizeof(*callstack))) {
        CONSOLE("backtrace failed");
    }

    return action_read_input;
}

static action_t registers_cmd(app_t *app, int argc, char* argv[]) {
    ftrace_fcall_t fcall = {0};

    if (!ftrace_get_registers(&app->ftrace, &fcall)) {
        CONSOLE("Failed to get registers");
        return action_read_input;
    }

    ftrace_fcall_dump(&fcall);

    return action_read_input;
}

static bool read_input(app_t *app) {
    static const cmd_t cmd_list[] = {
        {.name = "help",        .handler = help_cmd,        .help = "Display this help"},
        {.name = "quit",        .handler = quit_cmd,        .help = "Exit this program (quit, exit)"},
        {.name = "q",           .handler = quit_cmd,},
        {.name = "exit",        .handler = quit_cmd},
        {.name = "breakpoint",  .handler = breakpoint_cmd,
         .help = "Set a breakpoint (breakpoint, break, bp, b)\n"
                 "                Usage:\n"
                 "                - breakpoint $function\n"
                 "                - breakpoint $address\n"
        },
        {.name = "break",       .handler = breakpoint_cmd},
        {.name = "bp",          .handler = breakpoint_cmd},
        {.name = "b",           .handler = breakpoint_cmd},
        {.name = "clear",       .handler = clear_cmd,       .help = "Clear breakpoints"},
        {.name = "continue",    .handler = continue_cmd,    .help = "Continue execution (continue, c)"},
        {.name = "c",           .handler = continue_cmd},
        {.name = "step",        .handler = step_cmd,        .help = "Step of one instruction (step, s)"},
        {.name = "s",           .handler = step_cmd},
        {.name = "print",       .handler = print_cmd,       .help = "Print function address (print, p)"},
        {.name = "p",           .handler = print_cmd},
        {.name = "backtrace",   .handler = backtrace_cmd,   .help = "Display the backtrace (backtrace, bt)"},
        {.name = "bt",          .handler = backtrace_cmd},
        {.name = "registers",   .handler = registers_cmd,   .help = "Display registers (registers, regs, r)"},
        {.name = "regs",        .handler = registers_cmd},
        {.name = "r",           .handler = registers_cmd},
        {.name = "",            .handler = help_cmd},
        {.name = NULL},
    };

    char line[512];
    char *argv[16];

    app->cmd_list = cmd_list;

    while (true) {
        const char *sep = " \t\r\n";
        const cmd_t *cmd = NULL;
        size_t argc = 0;

        printf("\n> ");

        if (!fgets(line, sizeof(line), app->in)) {
            return false;
        }

        if (!(argv[argc++] = strtok(line, sep))) {
            help_cmd(app, 0, NULL);
            continue;
        }

        for(; argc < sizeof(argv)/sizeof(*argv); argc++) {
            if (!(argv[argc] = strtok(NULL, sep))) {
                break;
            }
        }


        for (cmd = cmd_list; cmd->name; cmd++) {
            if (!strcmp(argv[0], cmd->name)) {
                switch (cmd->handler(app, argc, argv)) {
                    case action_quit:
                        return false;
                    case action_continue:
                        return true;
                    case action_step:
                        ftrace_step(&app->ftrace);
                        break;
                    case action_read_input:
                        break;
                }
                break;
            }
        }
    }

    return false;
}

static void signal_interrupt_handler(int sig) {
    CONSOLE("\nInterrupted");
}

int main(int argc, char* argv[]) {
    pid_t pid = 0;
    app_t app = {
        .in = stdin,
    };

    if (argc == 1) {
        return 1;
    }

    if (!(pid = atoi(argv[1]))) {
        pid = fork();
        if (pid == 0) {
            setpgid(0, 0);
            return execvp(argv[1], &argv[1]);
        }
        else if (pid < 0) {
            TRACE_ERROR("fork failed: %m");
            return 1;
        }
    }

    struct sigaction sa = {
        .sa_handler = signal_interrupt_handler,
        .sa_flags = 0,
    };

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("sigaction");
        return 1;
    }

    if (!ftrace_attach(&app.ftrace, pid)) {
        TRACE_ERROR("ftrace_initialize() failed");
        return 1;
    }
    if (!ftrace_continue(&app.ftrace)) {
        TRACE_ERROR("ftrace_continue() failed");
        return 1;
    }

    while (read_input(&app)) {
        while (ftrace_poll(&app.ftrace));
    }

    ftrace_detach(&app.ftrace);

    return 0;
}

