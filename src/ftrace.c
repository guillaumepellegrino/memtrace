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

#define FTRACE_PRIVATE
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <fcntl.h>
#include <syscall.h>
#include <dlfcn.h>
#include "ftrace.h"
#include "syscall.h"
#include "arch.h"
#include "breakpoint.h"
#include "ptrace.h"
#include "log.h"

bool ftrace_wait(ftrace_t *ftrace, int *status) {
    struct epoll_event event = {0};
    struct signalfd_siginfo fdsi;


    while (true) {
        int cnt = 0;
        if ((cnt = epoll_wait(ftrace->epfd, &event, 1, 1000)) < 0) {
            TRACE_ERROR("epoll_wait() error: %m");
            return false;
        }

        if (cnt == 0) {
            continue;
        }
        if (event.data.ptr == ftrace) {
            break;
        }

        epoll_handler_t *handler = event.data.ptr;
        handler->fn(handler, event.events);
    }

    assert(read(ftrace->sigfd, &fdsi, sizeof(fdsi)) > 0);
    return ptrace_wait(ftrace->pid, status);
}

bool ftrace_attach(ftrace_t *ftrace, int pid) {
    int status = 1;
    sigset_t sigmask;
    struct epoll_event event;

    TRACE_DEBUG("ftrace_intialize %d IN", pid);

    list_initialize(&ftrace->syscalls);
    list_initialize(&ftrace->breakpoints);
    ftrace->pid = pid;
    ftrace->syscall_count = 0;

    if ((ftrace->epfd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
        TRACE_ERROR("epoll_create1() error: %m");
        return false;
    }

    snprintf(g_buff, sizeof(g_buff), "/proc/%d/mem", pid);
    if ((ftrace->memfd = open(g_buff, O_RDONLY|O_LARGEFILE)) <= 0) {
        TRACE_ERROR("Failed to open %s: %m", g_buff);
        return false;
    }

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGCHLD);

    if (sigprocmask(SIG_BLOCK, &sigmask, NULL) < 0) {
        TRACE_ERROR("sigprocmask() error: %m");
        return false;
    }

    if ((ftrace->sigfd = signalfd(-1, &sigmask, SFD_NONBLOCK|SFD_CLOEXEC)) < 0) {
        TRACE_ERROR("signalfd() error: %m");
        return false;
    }

    event.events = EPOLLIN|EPOLLET;
    event.data.ptr = ftrace;
    if (epoll_ctl(ftrace->epfd, EPOLL_CTL_ADD, ftrace->sigfd, &event) < 0) {
        TRACE_ERROR("epoll_ctl() add sigfd error: %m");
        return false;
    }

    if (ptrace(PTRACE_SEIZE, pid, 0, 0) != 0) {
        TRACE_ERROR("ptrace(SEIZE, %d, 0, 0) failed: %m", pid);
        return false;
    }

    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) != 0) {
        TRACE_ERROR("ptrace(INTERRUPT, %d, 0, 0) failed: %m", pid);
        return false;
    }

    //if (!ptrace_wait(ftrace->pid, &status)) {
    if (!ftrace_wait(ftrace, &status)) {
        return false;
    }

    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) != 0) {
        TRACE_ERROR("ptrace(SETOPTIONS, %d, 0, TRACESYSGOOD) failed: %m", pid);
        return false;
    }

    TRACE_DEBUG("ftrace_attach %d OUT", pid);
    return true;
}

void ftrace_detach(ftrace_t *ftrace) {
    list_iterator_t *it = NULL;
    bool running = kill(ftrace->pid, 0) == 0;

    if (list_first(&ftrace->breakpoints) && running) {
        // interrupt the program to cleanup breakpoints
        if (ptrace(PTRACE_INTERRUPT, ftrace->pid, NULL, NULL) != 0) {
            TRACE_ERROR("ptrace(INTERRUPT) failed: %m");
        }

        int status = 0;
        //if (!ptrace_wait(ftrace->pid, &status)) {
        if (!ftrace_wait(ftrace, &status)) {
            TRACE_ERROR("ptrace wait failed: %m");
        }
    }

    while ((it = list_first(&ftrace->breakpoints))) {
        breakpoint_t *bp = breakpoint_from_iterator(it);
        breakpoint_cleanup(bp);
        free(bp);
    }

    while ((it = list_first(&ftrace->syscalls))) {
        syscall_t *syscall = syscall_from_iterator(it);
        syscall_cleanup(syscall);
        free(syscall);
    }

    close(ftrace->memfd);

    if (running && ptrace(PTRACE_DETACH, ftrace->pid, NULL, NULL) != 0) {
        TRACE_ERROR("ptrace(DETACH) failed: %m");
    }
}

bool ftrace_set_fd_handler(ftrace_t *ftrace, epoll_handler_t *handler, int fd, int events) {
    struct epoll_event event;

    event.events = events;
    event.data.ptr = handler;
    if (epoll_ctl(ftrace->epfd, EPOLL_CTL_ADD, fd, &event) < 0) {
        TRACE_ERROR("epoll_ctl() add fd:%d error: %m", fd);
        return false;
    }

    return true;
}

bool ftrace_continue(ftrace_t *ftrace) {
    if (ptrace(PTRACE_SYSCALL, ftrace->pid, NULL, NULL) != 0) {
        TRACE_ERROR("ptrace(SYSCALL, %d) failed: %m", ftrace->pid);
        return false;
    }

    return true;
}

bool ftrace_step(ftrace_t *ftrace) {
    return ptrace_step(ftrace->pid);
}

int ftrace_pid(ftrace_t *ftrace) {
    return ftrace->pid;
}

int ftrace_memfd(ftrace_t *ftrace) {
    return ftrace->memfd;
}

bool ftrace_exited(ftrace_t *ftrace) {
    return ftrace->exited;
}

breakpoint_t *ftrace_set_breakpoint(ftrace_t *ftrace, const char *name, size_t address, ftrace_handler_t handler, void *userdata) {
    breakpoint_t *bp = NULL;

    assert((bp = calloc(1, sizeof(breakpoint_t))));
    if (!breakpoint_initialize(bp, ftrace, name, address)) {
        TRACE_ERROR("Failed to set breapoint at address 0x%zx", address);
        free(bp);
        return NULL;
    }
    breakpoint_set_handler(bp, handler, userdata);

    return bp;
}
/*
size_t ftrace_function_address(ftrace_t *ftrace, const char *function) {
    struct library mylibc = {0};
    struct library childlibc = {0};
    void *la = dlsym(NULL, function);

    if (!la) {
        TRACE_ERROR("Failed to resolve function %s: %s", function, dlerror());
        return 0;
    }
    if (getlibrary(&mylibc, getpid(), "libc-") != 0 && getlibrary(&mylibc, getpid(), "libc.") != 0) {
        TRACE_ERROR("Failed to get my libc library");
        return 0;
    }
    if (getlibrary(&childlibc, ftrace->pid, "libc-") != 0 && getlibrary(&childlibc, ftrace->pid, "libc.") != 0) {
        TRACE_ERROR("Failed to get child libc library");
        return 0;
    }
    size_t ra = relative_addr(&mylibc, la);
    size_t aa = absolute_addr(&childlibc, ra);

    TRACE_WARNING("%s=libc+0x%zx=0x%zx", function, ra, aa);

    return aa;
}
*/
/*
breakpoint_t *ftrace_set_function_breakpoint(ftrace_t *ftrace, const char *function, ftrace_handler_t handler, void *userdata) {

    breakpoint_t *bp = NULL;
    size_t aa = ftrace_function_address(ftrace, function);

    if (!aa) {
        return NULL;
    }

    TRACE_WARNING("Set breakpoint for %s at address 0x%zx", function, aa);
    if (!(bp = ftrace_set_breakpoint(ftrace, function, aa, handler, userdata))) {
        return NULL;
    }

    breakpoint_set_name(bp, function);

    return bp;
}
*/
bool ftrace_set_syscall_breakpoint(ftrace_t *ftrace, int syscallnumber, ftrace_handler_t handler, void *userdata) {
    syscall_t *syscall = calloc(1, sizeof(syscall_t));

    if (!syscall) {
        TRACE_ERROR("calloc failed: %m");
        return false;
    }

    syscall_initialize(syscall, syscallnumber);
    syscall_set_handler(syscall, handler, userdata);
    list_insert(&ftrace->syscalls, syscall_iterator(syscall));

    return true;
}

bool ftrace_poll(ftrace_t *ftrace) {
    bool rt = false;
    int status = -1;

    if (!ftrace) {
        return false;
    }

    ftrace->depth++;

    if (ftrace->depth > 10) {
        TRACE_ERROR("Recursive call depth larger than 10 !");
        return false;
    }

    list_iterator_t *it;
    list_for_each(it, &ftrace->breakpoints) {
        breakpoint_t *bp = breakpoint_from_iterator(it);
        if (breakpoint_state(bp) == breakpoint_state_disabled) {
            if (!breakpoint_stopped(bp, &ftrace->fcall)) {
                // Enable back breakpoint
                if (!breakpoint_enable(bp)) {
                    TRACE_ERROR("breakpoint_enable(%d, %s) failed\n", ftrace->pid, breakpoint_name(bp));
                    goto exit;
                }
            }
            break;
        }
    }

    // continue execution until next syscall or interuption
    int ptracecont = ftrace->syscalls.first ? PTRACE_SYSCALL : PTRACE_CONT;
    //int ptracecont = PTRACE_SYSCALL;
    if (ptrace(ptracecont, ftrace->pid, NULL, NULL) != 0) {
        TRACE_ERROR("ptrace(SYSCALL, %d) failed: %m", ftrace->pid);
        goto exit;
    }

    //if (!ptrace_wait(ftrace->pid, &status)) {
    if (!ftrace_wait(ftrace, &status)) {
        if (errno == EINTR) {
            // ptrace_wait() was interrupted
            // interrupt child process and exit poll function
            if (ptrace(PTRACE_INTERRUPT, ftrace->pid, NULL, NULL) != 0) {
                TRACE_ERROR("ptrace(INTERRUPT, %d) failed: %m", ftrace->pid);
            }
        }
        ftrace->exited = WIFEXITED(status);
        goto exit;
    }

    if (!arch.ftrace_fcall_fill(&ftrace->fcall, ftrace->pid)) {
        goto exit;
    }
    ftrace->fcall.ftrace = ftrace;


    if (ptrace_terminated(status)) {
        TRACE_WARNING("Process terminated");
        if (WIFSTOPPED(status)) {
            ftrace_fcall_dump(&ftrace->fcall);
        }
        goto exit;
    }
    else if (ptrace_stopped_by_syscall(status)) {
        bool in = (ftrace->syscall_count % 2) == 0;
        ftrace->syscall_count += 1;
        if (in) {
            list_iterator_t *it = NULL;
            list_for_each(it, &ftrace->syscalls) {
                syscall_t *syscall = syscall_from_iterator(it);
                if (ftrace->fcall.syscall == syscall_number(syscall)) {
                    ftrace_fcall_t fcall = ftrace->fcall;
                    if (!syscall_call(syscall, &fcall)) {
                        goto exit;
                    }
                }
            }
        }
    }
    else {
        TRACE_DEBUG("Process %d stopped by interrupt at 0x%lx", ftrace->pid, ftrace->fcall.pc);
        list_iterator_t *it;
        list_for_each(it, &ftrace->breakpoints) {
            breakpoint_t *bp = breakpoint_from_iterator(it);
            if (breakpoint_stopped(bp, &ftrace->fcall)) {
                ftrace->fcall.bp = bp;
                if (!breakpoint_handle_interrupt(bp)) {
                    goto exit;
                }
                // bp may be destroyed by user in the callback
                ftrace_fcall_t fcall = ftrace->fcall;
                if (!breakpoint_call(bp, &fcall)) {
                    goto exit;
                }
                break;
            }
        }
    }

    rt = true;

exit:
    ftrace->depth--;
    return rt;
}

bool ftrace_get_registers(ftrace_t *ftrace, ftrace_fcall_t *fcall) {
    memset(fcall, 0, sizeof(ftrace_fcall_t));

    if (!arch.ftrace_fcall_fill(fcall, ftrace->pid)) {
        return false;
    }
    fcall->ftrace = ftrace;

    return true;
}

bool ftrace_read_word(ftrace_t *ftrace, size_t addr, size_t *word) {
    errno = 0;
    *word = ptrace(PTRACE_PEEKDATA, ftrace->pid, addr, NULL);
    return errno == 0;
}

bool ftrace_read_string(ftrace_t *ftrace, size_t addr, char *str, size_t size) {
    size_t rdlen = 0;

    while (true) {
        size_t i;
        union {
            long word;
            char u8[0];
        } value;

        value.word  = ptrace(PTRACE_PEEKDATA, ftrace->pid, addr+rdlen, NULL);
        for (i = 0; i < sizeof(value); i++, rdlen++) {
            str[rdlen] = value.u8[i];

            if (str[rdlen] == 0) {
                return true;
            }
            if (rdlen+1 >= size) {
                str[rdlen] = 0;
                return true;
            }
        }
    }

    str[0] = 0;

    return true;
}

bool ftrace_syscall_get_rv(const ftrace_fcall_t *fcall, ftrace_fcall_t *rtfcall) {
    ftrace_t *ftrace = fcall->ftrace;
    int status = 0;


    // continue execution until next syscall or interuption
    if (ptrace(PTRACE_SYSCALL, ftrace->pid, NULL, NULL) != 0) {
        TRACE_ERROR("ptrace(SYSCALL, %d) failed: %m", ftrace->pid);
        return false;
    }
    //if (!ptrace_wait(ftrace->pid, &status)) {
    if (!ftrace_wait(ftrace, &status)) {
        TRACE_ERROR("ptrace_wait(%d) failed: %m", ftrace->pid);
        return false;
    }

    if (ptrace_terminated(status)) {
        TRACE_ERROR("process(%d) terminated", ftrace->pid);
        return false;
    }
    else if (!ptrace_stopped_by_syscall(status)) {
        TRACE_ERROR("process(%d) not stopped by syscall", ftrace->pid);
        return false;
    }

    ftrace->syscall_count += 1;

    if (!arch.ftrace_fcall_fill(rtfcall, ftrace->pid)) {
        TRACE_ERROR("arch.ftrace_fcall_fill(pid:%d)", ftrace->pid);
        return false;
    }
    rtfcall->ftrace = ftrace;

    return true;
}

typedef struct _ftrace_breakpoint_rv ftrace_breakpoint_rv_t;
struct _ftrace_breakpoint_rv {
    bool done;
    ftrace_fcall_t *rtfcall;
    size_t *rv;
};

static bool ftrace_breakpoint_rv_handler(const ftrace_fcall_t *fcall, void *userdata) {
    ftrace_breakpoint_rv_t *ctx = userdata;

    ctx->done = true;
    *ctx->rtfcall = *fcall;

    return true;
}

static bool ftrace_breakpoint_get_rv(const ftrace_fcall_t *fcall, ftrace_fcall_t *rtfcall) {
    breakpoint_t bp = {0};
    ftrace_t *ftrace = fcall->ftrace;
    ftrace_breakpoint_rv_t ctx = {
        .done = false,
        .rtfcall = rtfcall,
    };

    // Set a breakpoint on RA (Return Address)
    char name[16];
    snprintf(name, sizeof(name), "return@%s", breakpoint_name(fcall->bp));

    if (!breakpoint_initialize(&bp, ftrace, name, fcall->ra)) {
        TRACE_ERROR("Failed to set breakpoint for %s return value", breakpoint_name(fcall->bp));
        return false;
    }

    // rtfcall will be set in handler
    breakpoint_set_handler(&bp, ftrace_breakpoint_rv_handler, &ctx);

    // Wait for breakpoint to be triggered
    while (ftrace_poll(ftrace) && !ctx.done);

    breakpoint_cleanup(&bp);

    return ctx.done;
}

bool ftrace_fcall_get_rv(const ftrace_fcall_t *fcall, ftrace_fcall_t *rtfcall) {
    if (fcall->bp) {
        return ftrace_breakpoint_get_rv(fcall, rtfcall);
    }
    else {
        return ftrace_syscall_get_rv(fcall, rtfcall);
    }
}

const char *ftrace_fcall_name(const ftrace_fcall_t *fcall) {
    if (fcall->bp) {
        return breakpoint_name(fcall->bp);
    }
    else {
        return "Unknown";
    }
}

void ftrace_fcall_dump(const ftrace_fcall_t *fcall) {
    CONSOLE("[%s]", ftrace_fcall_name(fcall));
    CONSOLE("PC:    0x%lx", fcall->pc);
    CONSOLE("RA:    0x%zx", fcall->ra);
    CONSOLE("SP:    0x%zx", fcall->sp);
    CONSOLE("arg1:  0x%zx", fcall->arg1);
    CONSOLE("arg2:  0x%zx", fcall->arg2);
    CONSOLE("arg3:  0x%zx", fcall->arg3);
    CONSOLE("arg4:  0x%zx", fcall->arg4);
    CONSOLE("arg5:  0x%zx", fcall->arg5);
    CONSOLE("arg6:  0x%zx", fcall->arg6);
    CONSOLE("arg7:  0x%zx", fcall->arg7);
    CONSOLE("");
}

bool ftrace_backtrace(const ftrace_t *ftrace, size_t callstack[], size_t size) {
    return true;
}

int ftrace_depth(ftrace_t *ftrace) {
    return ftrace->depth;
}
