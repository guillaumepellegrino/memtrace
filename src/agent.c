#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include "agent.h"
#include "agent_hooks.h"
#include "hashmap.h"
#include "log.h"

typedef struct {
    hashmap_iterator_t it;
    ssize_t count;
    ssize_t size;
    size_t *callstack;
    size_t *big_callstack;
    size_t number;
    size_t do_coredump : 1;
    size_t do_gdb : 1;
} block_t;

typedef struct {
    hashmap_iterator_t it;
    size_t ptr_size;
    void *ptr;
    block_t *block;
} allocation_t;

static int ipc_socket() {
    struct sockaddr_un bindaddr = {
        .sun_family = AF_UNIX,
    };
    int s = -1;

    if ((s = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0)) < 0) {
        printf("Failed to create ipc socket: %m\n");
        return -1;
    }

    snprintf(bindaddr.sun_path, sizeof(bindaddr.sun_path),
        "/tmp/memtrace-agent-%d", getpid());

    if (bind(s, (struct sockaddr *) &bindaddr, sizeof(bindaddr)) != 0) {
        printf("Failed to bind ipc socket to %s: %m\n", bindaddr.sun_path);
        return -1;
    }
    if (listen(s, 10) != 0) {
        printf("Failed to listen ipc socket: %m\n");
        return -1;
    }

    return s;
}

static void ipc_socket_close(int ipc) {
    struct sockaddr_un bindaddr = {
        .sun_family = AF_UNIX,
    };

    close(ipc);
    snprintf(bindaddr.sun_path, sizeof(bindaddr.sun_path),
        "/tmp/memtrace-agent-%d", getpid());
    unlink(bindaddr.sun_path);
}

static void cmd_help(agent_t *agent, FILE *fp, char *cmd) {
    fprintf(fp,
        "Command list:\n"
        " - help:           Display this help\n"
        " - status:         Display a short memory status\n"
        " - report $1:      Display full memory report\n"
        " - clear:          Clear the tracked memory\n"
        " - coredump $1 $2: Generate a coredump\n"
        "\n");
}

static void cmd_status(agent_t *agent, FILE *fp, char *cmd) {

}

static void cmd_report(agent_t *agent, FILE *fp, char *cmd) {

}

static void cmd_clear(agent_t *agent, FILE *fp, char *cmd) {

}

static void cmd_coredump(agent_t *agent, FILE *fp, char *cmd) {

}

void ipc_connection_loop(agent_t *agent, FILE *fp) {
    static char line[4096];
    struct {
        const char *name;
        void (*function)(agent_t *agent, FILE *fp, char *cmd);
    } cmd_list[] = {
        {"help\n", cmd_help},
        {"status\n", cmd_status},
        {"report\n", cmd_report},
        {"clear\n", cmd_clear},
        {"coredump\n", cmd_coredump},
    };

    while (fgets(line, sizeof(line), fp)) {
        for (size_t i = 0; i < sizeof(cmd_list)/sizeof(*cmd_list); i++) {
            if (!strcmp(line, cmd_list[i].name)) {
                if (cmd_list[i].function) {
                    // Lock memory accesses for this thread
                    bool lock = hooks_lock();
                    cmd_list[i].function(agent, fp, line);
                    hooks_unlock(lock);
                }
            }
            break;
        }
    }
}

void *ipc_accept_loop(void *arg) {
    agent_t *agent = arg;

    (void) agent;

    printf("Entered event loop\n");

    while (true) {
        int s = -1;
        FILE *fp = NULL;

        if ((s = accept4(agent->ipc, NULL, NULL, SOCK_CLOEXEC)) < 0) {
            printf("accept error: %m\n");
            continue;
        }

        if (!(fp = fdopen(s, "w+"))) {
            printf("fdopen error: %m\n");
            close(s);
            continue;
        }

        printf("ipc connection accepted\n");
        ipc_connection_loop(agent, fp);
        close(s);
        printf("ipc connection closed\n");
    }

    printf("Exiting event loop\n");

    return NULL;
}

bool agent_initialize(agent_t *agent) {
    if ((agent->ipc = ipc_socket()) < 0) {
        return false;
    }

    printf("ipc: %d\n", agent->ipc);

    if (pthread_create(&agent->thread, NULL, ipc_accept_loop, agent) != 0) {
        printf("Failed to create thread");
        return false;
    }

    return true;
}

void agent_cleanup(agent_t *agent) {
    ipc_socket_close(agent->ipc);
}

void agent_malloc(agent_t *agent, void *sp, void *lr, size_t size, void *newptr) {
    printf("malloc(%zu) -> %p\n", size, newptr);
}

void agent_calloc(agent_t *agent, void *sp, void *lr, size_t nmemb, size_t size, void *newptr) {
    printf("calloc(%zu, %zu) -> %p\n", nmemb, size, newptr);
}

void agent_realloc(agent_t *agent, void *sp, void *lr, void *ptr, size_t size, void *newptr) {
    printf("realloc(%p, %zu) -> %p\n", ptr, size, newptr);
}

void agent_reallocarray(agent_t *agent, void *sp, void *lr, void *ptr, size_t nmemb, size_t size, void *newptr) {
    printf("reallocarray(%p, %zu, %zu) -> %p\n", ptr, nmemb, size, newptr);
}

void agent_free(agent_t *agent, void *sp, void *lr, void *ptr) {
    printf("free(%p)\n", ptr);
}

