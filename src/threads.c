#include "threads.h"
#include "log.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

DIR *process_threads(int pid) {
    char task_path[128];
    DIR *threads = NULL;

    if (pid <= 0) {
        TRACE_ERROR("pid was not provided");
        return false;
    }

    snprintf(task_path, sizeof(task_path), "/proc/%d/task/", pid);

    if (!(threads = opendir(task_path))) {
        TRACE_ERROR("Failed to open %s: %m", task_path);
        return NULL;
    }

    return threads;
}

int threads_next(DIR *threads) {
    struct dirent *task_entry = NULL;

    if (!threads) {
        return 0;
    }

    while ((task_entry = readdir(threads))) {
        int tid = atoi(task_entry->d_name);
        if (tid <= 0) {
            continue;
        }
        return tid;
    }

    return 0;
}

int threads_first(DIR *threads) {
    if (!threads) {
        return 0;
    }

    seekdir(threads, 0);

    return threads_next(threads);
}

static bool thread_attach(int tid) {
    int status = 0;

    if (tid <= 0) {
        TRACE_ERROR("tid was not provided");
        return false;
    }
    if (ptrace(PTRACE_SEIZE, tid, 0, 0) != 0) {
        TRACE_ERROR("ptrace(SEIZE, %d, 0, 0) failed: %m", tid);
        return false;
    }
    if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0) {
        TRACE_ERROR("ptrace(INTERRUPT, %d, 0, 0) failed: %m", tid);
        return false;
    }
    if (waitpid(tid, &status, 0) < 0) {
        TRACE_ERROR("waitpid(%d) failed: %m", tid);
        return false;
    }
    if (ptrace(PTRACE_SETOPTIONS, tid, 0, PTRACE_O_TRACESYSGOOD) != 0) {
        TRACE_ERROR("ptrace(SETOPTIONS, %d, 0, TRACESYSGOOD) failed: %m", tid);
        return false;
    }
    return true;
}


DIR *threads_attach(int pid) {
    DIR *threads = NULL;
    int tid = 0;

    if (!(threads = process_threads(pid))) {
        CONSOLE("Failed to get thread list from pid %d", pid);
        return NULL;
    }
    threads_for_each(tid, threads) {
        if (!thread_attach(tid)) {
            TRACE_ERROR("Failed to attach to thread %d", tid);
            closedir(threads);
            return NULL;
        }
        CONSOLE("memtrace attached to pid:%d/tid:%d", pid, tid);
    }
    return threads;
}

void threads_detach(DIR *threads) {
    int tid = 0;

    if (threads) {
        threads_for_each(tid, threads) {
            if (ptrace(PTRACE_DETACH, tid, NULL, NULL) != 0) {
                TRACE_ERROR("ptrace(DETACH, %d) failed: %m", tid);
            }
        }
        closedir(threads);
    }
}

bool threads_interrupt_except(DIR *threads, int exception) {
    int tid = 0;
    int status = 0;
    bool rt = true;

    threads_for_each(tid, threads) {
        if (tid == exception) {
            continue;
        }
        if (ptrace(PTRACE_INTERRUPT, tid, NULL, NULL) != 0) {
            TRACE_ERROR("ptrace(INTERRUPT, %d) failed: %m", tid);
            rt = false;
        }
        if (waitpid(tid, &status, 0) < 0) {
            TRACE_ERROR("wait(%d) failed: %m", tid);
            rt = false;
        }
    }

    return rt;
}

bool threads_continue(DIR *threads) {
    int tid = 0;
    bool rt = true;

    threads_for_each(tid, threads) {
        if (ptrace(PTRACE_CONT, tid, NULL, NULL) != 0) {
            TRACE_ERROR("ptrace(CONT, %d) failed: %m", tid);
            rt = false;
        }
    }
    return rt;
}

