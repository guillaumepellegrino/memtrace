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

#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <fcntl.h>
#include <syscall.h>
#include "ptrace.h"
#include "arch.h"
#include "log.h"

bool ptrace_wait(pid_t pid, int *status) {
    if (waitpid(pid, status, 0) < 0) {
        if (errno != EINTR) {
            TRACE_ERROR("waitpid(%d) failed: %m", pid);
        }
        return false;
    }

    if (WIFEXITED(*status)) {
        TRACE_WARNING("process %d exited with status:%d", pid, WEXITSTATUS(*status));
        errno = ECHILD;
        return false;
    }

    return true;
}

bool ptrace_terminated(int status) {
    int signal = -1;

    if (WIFSIGNALED(status)) {
        signal = WTERMSIG(status);
        TRACE_WARNING("process terminated by signal:%d", signal);
        return true;
    }

    if (WIFSTOPPED(status)) {
        signal = WSTOPSIG(status);
        if (signal != SIGTRAP && signal != (SIGTRAP|0x80)) {

            switch (signal) {
                case SIGTRAP:
                case SIGABRT:
                case SIGBUS:
                case SIGFPE:
                case SIGILL:
                case SIGSEGV:
                    TRACE_WARNING("process crashed with signal:%d", signal);
                    return true;
                case SIGKILL:
                    TRACE_WARNING("process was killed by SIGKILL");
                    return true;
                default:
                    TRACE_LOG("process stopped by signal:%d (ignore)", signal);
                    return false;
            }
        }
    }

    return false;
}

bool ptrace_stopped_by_syscall(int status) {
    return WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP|0x80);
}

bool ptrace_step(pid_t pid) {
    int status = -1;
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) != 0) {
        TRACE_ERROR("singlestep failed for process %d: %m", pid);
        return false;
    }
    if (!ptrace_wait(pid, &status)) {
        return false;
    }
    if (ptrace_terminated(status)) {
        return false;
    }
    return true;
}
