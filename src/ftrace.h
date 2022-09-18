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

#ifndef _FTRACE_FTRACE_H
#define _FTRACE_FTRACE_H

/**
 * The ftrace API (Function Trace) is intended to track
 * the function calls and syscall of a remote process
 * by setting breakpoints with linux ptrace.
 */

#ifndef FTRACE_PRIVATE
#define FTRACE_PRIVATE __attribute__((deprecated))
#endif

#include <stddef.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include "types.h"
#include "list.h"

struct _cpu_registers {
    size_t r[32];
};

/**
 * The state of CPU registers when stopped at a function call or a syscall
 **/
struct _ftrace_fcall {
    ftrace_t *ftrace;   // Reference on ftrace
    breakpoint_t *bp;   // Reference on breakpoint
    long pc;            // Program Counter Register
    long nextpc;        // Next PC
    size_t sp;          // Stack Pointer Register
    size_t ra;          // Return Address Register
    size_t syscall;     // Syscall number (in case of a syscall)

    // Function arguments
    size_t arg1;
    size_t arg2;
    size_t arg3;
    size_t arg4;
    size_t arg5;
    size_t arg6;
    size_t arg7;
    size_t retval;

    // raw registers
    cpu_registers_t registers;
};

struct _ftrace {
    ftrace_fcall_t fcall    FTRACE_PRIVATE;
    list_t syscalls         FTRACE_PRIVATE;
    list_t breakpoints;
    int pid                 FTRACE_PRIVATE;
    int epfd                FTRACE_PRIVATE;
    int sigfd               FTRACE_PRIVATE;
    int memfd               FTRACE_PRIVATE;
    size_t syscall_count    FTRACE_PRIVATE;
    int depth               FTRACE_PRIVATE;
    bool exited             FTRACE_PRIVATE;
};

/** Attach ftrace to the process with specified pid */
bool ftrace_attach(ftrace_t *ftrace, int pid);

/** Detach ftrace from the target process */
void ftrace_detach(ftrace_t *ftrace);

bool ftrace_set_fd_handler(ftrace_t *ftrace, epoll_handler_t *handler, int fd, int events);

bool ftrace_continue(ftrace_t *ftrace);

bool ftrace_step(ftrace_t *ftrace);

/** Return the target process pid */
int ftrace_pid(ftrace_t *ftrace);

/** Return a file descriptor on /proc/$pid/mem */
int ftrace_memfd(ftrace_t *ftrace);

/** Return true if the target process exited */
bool ftrace_exited(ftrace_t *ftrace);

/** Return the address of this function */
size_t ftrace_function_address(ftrace_t *ftrace, const char *function);

/** Set a breakpoint for this address */
breakpoint_t *ftrace_set_breakpoint(ftrace_t *ftrace, const char *name, size_t address, ftrace_handler_t handler, void *userdata);

/** Set a breakpoint for this function */
breakpoint_t *ftrace_set_function_breakpoint(ftrace_t *ftrace, const char *function, ftrace_handler_t handler, void *userdata);

/** Set a breakpoint for this syscall */
bool ftrace_set_syscall_breakpoint(ftrace_t *ftrace, int syscall, ftrace_handler_t handler, void *userdata);

/** Wait for an ftrace event */
bool ftrace_poll(ftrace_t *ftrace);

/** Get CPU registers of target process */
bool ftrace_get_registers(ftrace_t *ftrace, ftrace_fcall_t *fcall);

/** Read a word at the given address */
bool ftrace_read_word(ftrace_t *ftrace, size_t addr, size_t *word);

/** Read a string at the given address */
bool ftrace_read_string(ftrace_t *ftrace, size_t addr, char *str, size_t size);

/** Continue the function call until it returns a value (in rtfcall->rv) */
bool ftrace_fcall_get_rv(const ftrace_fcall_t *fcall, ftrace_fcall_t *rtfcall);

/** Friendly name for breakpoint or syscall */
const char *ftrace_fcall_name(const ftrace_fcall_t *fcall);

/** Dump the function call context */
void ftrace_fcall_dump(const ftrace_fcall_t *fcall);

/** Get the callstack of the target process */
bool ftrace_backtrace(const ftrace_t *ftrace, size_t callstack[], size_t size);

/** How deep ftrace_poll() is nested */
int ftrace_depth(ftrace_t *ftrace);

bool ftrace_inject_code(ftrace_t *ftrace, libraries_t *libraries);
#endif
