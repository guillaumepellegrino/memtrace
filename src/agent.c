#define _GNU_SOURCE
#define _DEFAULT_SOURCE
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <pthread.h>
#include "agent.h"
#include "agent_hooks.h"
#include "libraries.h"
#include "elf.h"
#include "elf_file.h"
#include "coredump.h"
#include "evlp.h"
#include "bus.h"
#include "arch.h"
#include "log.h"

typedef struct {
    hashmap_iterator_t it;
    ssize_t count;
    ssize_t size;
    void **callstack;
    size_t number;
    int do_coredump;
} block_t;

typedef struct {
    hashmap_iterator_t it;
    size_t ptr_size;
    void *ptr;
    block_t *block;
} allocation_t;

__attribute__((aligned)) char g_buff[G_BUFF_SIZE];

static uint32_t allocations_maps_hash(hashmap_t *hashmap, void *key) {
    size_t addr = (size_t) key;
    return addr >> 2;
}

static bool allocations_maps_match(hashmap_t *hashmap, void *lkey, void *rkey) {
    size_t laddr = (size_t) lkey;
    size_t raddr = (size_t) rkey;

    return laddr == raddr;
}

static void allocations_maps_destroy(hashmap_t *hashmap, void *key, hashmap_iterator_t *it) {
    agent_t *agent = container_of(hashmap, agent_t, allocations);
    allocation_t *allocation = container_of(it, allocation_t, it);

    block_t *block = allocation->block;
    block->count -= 1;
    block->size -= allocation->ptr_size;
    agent->stats.free_count += 1;
    agent->stats.free_size += allocation->ptr_size;
    agent->stats.byte_inuse -= allocation->ptr_size;
    agent->stats.count_inuse -= 1;
    if (block->count <= 0) {
        hashmap_iterator_destroy(&block->it);
    }

    free(allocation);
}

static uint32_t blocks_maps_hash(hashmap_t *hashmap, void *key) {
    agent_t *agent = container_of(hashmap, agent_t, blocks);
    size_t *callstack = key;
    uint32_t hash = 0;
    size_t i = 0;

    for (i = 0; i < agent->callstack_size && callstack[i]; i++) {
        hash ^= callstack[i];
    }

    return hash;
}

static bool blocks_maps_match(hashmap_t *hashmap, void *lkey, void *rkey) {
    agent_t *agent = container_of(hashmap, agent_t, blocks);
    size_t *lcallstack = lkey;
    size_t *rcallstack = rkey;
    size_t i = 0;

    for (i = 0; i < agent->callstack_size && lcallstack[i]; i++) {
        if (lcallstack[i] != rcallstack[i]) {
            return false;
        }
    }

    return true;
}

static int blocks_map_compar(const hashmap_iterator_t **lval, const hashmap_iterator_t **rval) {
    block_t *lblock = container_of(*lval, block_t, it);
    block_t *rblock = container_of(*rval, block_t, it);

    return rblock->count - lblock->count;
}

static void blocks_maps_destroy(hashmap_t *hashmap, void *key, hashmap_iterator_t *it) {
    agent_t *agent = container_of(hashmap, agent_t, blocks);
    block_t *block = container_of(it, block_t, it);
    agent->stats.block_inuse -= 1;
    free(block->callstack);
    free(block);
}


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

static bool agent_status(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {
    bool lock = hooks_lock();
    agent_t *agent = container_of(topic, agent_t, status_topic);
    //time_t now = time(NULL);
    fprintf(fp, "HEAP SUMMARY\n"/*, asctime(localtime(&now))*/);
    fprintf(fp, "    in use: %zu allocs, %zu bytes in %zu contexts\n",
        agent->stats.count_inuse, agent->stats.byte_inuse, agent->stats.block_inuse);
    fprintf(fp, "    total heap usage: %zu allocs, %zu frees, %zu bytes allocated\n",
        agent->stats.alloc_count, agent->stats.free_count, agent->stats.alloc_size);
    fprintf(fp, "[cmd_done]\n");
    fflush(fp);
    hooks_unlock(lock);

    return true;
}

static bool agent_report(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {
    bool lock = hooks_lock();
    agent_t *agent = container_of(topic, agent_t, report_topic);
    size_t i = 0;
    size_t max = 10;
    hashmap_iterator_t *it = NULL;

    if (strmap_get(options, "count")) {
        max = atoi(strmap_get(options, "count"));
    }

    hashmap_qsort(&agent->blocks, blocks_map_compar);
    hashmap_for_each(it, &agent->blocks) {
        block_t *block = container_of(it, block_t, it);

        if (max > 0 && i >= max) {
            break;
        }

        fprintf(fp, "Memory allocation context n°%zu\n", i);
        fprintf(fp, "%zd allocs, %zd bytes were not free\n", block->count, block->size);
        libraries_backtrace_print(agent->libraries, block->callstack, agent->callstack_size, fp);
        fprintf(fp, "\n");

        i++;
    }

    fprintf(fp, "HEAP SUMMARY\n"/*, asctime(localtime(&now))*/);
    fprintf(fp, "    in use: %zu allocs, %zu bytes in %zu contexts\n",
        agent->stats.count_inuse, agent->stats.byte_inuse, agent->stats.block_inuse);
    fprintf(fp, "    total heap usage: %zu allocs, %zu frees, %zu bytes allocated\n",
        agent->stats.alloc_count, agent->stats.free_count, agent->stats.alloc_size);
    fprintf(fp, "[cmd_done]\n");
    fflush(fp);
    hooks_unlock(lock);

    return true;
}

static bool agent_clear(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {
    bool lock = hooks_lock();
    agent_t *agent = container_of(topic, agent_t, clear_topic);
    hashmap_clear(&agent->allocations);
    agent->stats.alloc_count = 0;
    agent->stats.alloc_size = 0;
    agent->stats.free_count = 0;
    agent->stats.free_size = 0;
    agent->stats.byte_inuse = 0;
    agent->stats.count_inuse = 0;
    agent->stats.block_inuse = 0;

    fprintf(fp, "List of allocations clear\n");
    fprintf(fp, "[cmd_done]\n");
    fflush(fp);
    hooks_unlock(lock);

    return true;
}

static bool agent_coredump(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *fp) {

    return true;
}

static void cmd_coredump(agent_t *agent, FILE *fp, int argc, char *argv[]) {
    int i = 0;
    int num = 0;
    hashmap_iterator_t *it = NULL;
    block_t *block = NULL;
    bool lock = hooks_lock();

    if (argc >= 2) {
        num = atoi(argv[1]);
    }

    // Lookup for context number 'num'
    hashmap_qsort(&agent->blocks, blocks_map_compar);
    hashmap_for_each(it, &agent->blocks) {
        if (i == num) {
            block = container_of(it, block_t, it);
            break;
        }
        i++;
    }

    if (!block) {
        fprintf(fp, "Memory allocation context n°%d not found\n", num);
        goto error;
    }

    if (block->do_coredump > 0) {
        fprintf(fp, "Memory allocation context n°%d already marked for coredump\n", num);
        goto error;
    }

    fprintf(fp, "Waiting to hit memory allocation context n°%d:\n", num);
    libraries_backtrace_print(agent->libraries, block->callstack, agent->callstack_size, fp);
    fprintf(fp, "\n");
    fflush(fp);
    block->do_coredump = fileno(fp);
error:
    hooks_unlock(lock);
}

static void ipc_connection_disconnect(agent_t *agent, FILE *fp) {
    bool lock = hooks_lock();
    hashmap_iterator_t *it = NULL;

    // Remove reference
    hashmap_for_each(it, &agent->blocks) {
        block_t *block = container_of(it, block_t, it);
        if (block->do_coredump == fileno(fp)) {
            CONSOLE("Cancel coredump %p", fp);
            block->do_coredump = -1;
        }
    }
    hooks_unlock(lock);
}

void ipc_connection_loop(agent_t *agent, FILE *fp) {
    char line[512];
    static const struct {
        const char *name;
        void (*function)(agent_t *agent, FILE *fp, int argc, char *argv[]);
    } cmd_list[] = {
        {"coredump", cmd_coredump},
    };

    while (fgets(line, sizeof(line), fp)) {
        char *argv[12] = {0};
        size_t argc = 0;
        char *it = NULL;
        bool rt = false;

        for (it = strtok(line, " \n"); it; it = strtok(NULL, " \n")) {
            if (argc >= countof(argv)) {
                break;
            }
            argv[argc++] = it;
        }

        if (!argv[0]) {
            continue;
        }

        for (size_t i = 0; i < sizeof(cmd_list)/sizeof(*cmd_list); i++) {
            if (!strcmp(argv[0], cmd_list[i].name)) {
                if (cmd_list[i].function) {
                    // Lock memory accesses for this thread
                    cmd_list[i].function(agent, fp, argc, argv);
                    fprintf(fp, "[cmd_done]\n");
                    fflush(fp);
                    rt = true;
                }
                break;
            }
        }

        if (!rt) {
            fprintf(fp, "[cmd_unknown]\n");
            fflush(fp);
        }
    }

    ipc_connection_disconnect(agent, fp);
}

void *ipc_accept_loop(void *arg) {
    agent_t *agent = arg;

    signal(SIGPIPE, SIG_IGN);

    printf("Entered event loop\n");
    if (!bus_ipc_listen(&agent->bus, agent->ipc)) {
        printf("Failed to listen on ipc socket\n");
        return NULL;
    }
    evlp_main(agent->evlp);
    printf("Exiting event loop\n");

    return NULL;
}

bool agent_initialize(agent_t *agent) {
    if (!(agent->libraries = libraries_create(getpid()))) {
        printf("Failed to create libraries");
        return false;
    }
    const hashmap_cfg_t allocations_maps_cfg = {
        .size       = 4000,
        .hash       = allocations_maps_hash,
        .match      = allocations_maps_match,
        .destroy    = allocations_maps_destroy,
    };
    const hashmap_cfg_t blocks_maps_cfg = {
        .size       = allocations_maps_cfg.size,
        .hash       = blocks_maps_hash,
        .match      = blocks_maps_match,
        .destroy    = blocks_maps_destroy,
    };
    agent->callstack_size = 10;
    hashmap_initialize(&agent->allocations, &allocations_maps_cfg);
    hashmap_initialize(&agent->blocks, &blocks_maps_cfg);

    libraries_print(agent->libraries, stdout);

    if ((agent->ipc = ipc_socket()) < 0) {
        return false;
    }

    if (pthread_create(&agent->thread, NULL, ipc_accept_loop, agent) != 0) {
        printf("Failed to create thread");
        return false;
    }

    agent->follow_allocs = true;


    agent->evlp = evlp_create();
    bus_initialize(&agent->bus, agent->evlp, "memtrace-agent", "memtrace");
    agent->status_topic.name = "status";
    agent->status_topic.read = agent_status;
    bus_register_topic(&agent->bus, &agent->status_topic);
    agent->report_topic.name = "report";
    agent->report_topic.read = agent_report;
    bus_register_topic(&agent->bus, &agent->report_topic);
    agent->clear_topic.name = "clear";
    agent->clear_topic.read = agent_clear;
    bus_register_topic(&agent->bus, &agent->clear_topic);
    agent->coredump_topic.name = "coredump";
    agent->coredump_topic.read = agent_coredump;
    bus_register_topic(&agent->bus, &agent->coredump_topic);

    return true;
}

void agent_cleanup(agent_t *agent) {
    bus_cleanup(&agent->bus);
    evlp_destroy(agent->evlp);
    libraries_destroy(agent->libraries);
    ipc_socket_close(agent->ipc);
    agent->follow_allocs = false;
}

void agent_unfollow_allocs(agent_t *agent) {
    agent->follow_allocs = false;
}

static void agent_notifify_do_coredump(block_t *block, cpu_registers_t *regs) {
    char buff[128] = {0};
    ssize_t len = 0;
    int tid = syscall(SYS_gettid);

    len = snprintf(buff, sizeof(buff), "notify do_coredump %d 0x%zx 0x%zx 0x%zx 0x%zx 0x%zx 0x%zx 0x%zx\n",
        tid,
        cpu_register_get(regs, cpu_register_pc),
        cpu_register_get(regs, cpu_register_sp),
        cpu_register_get(regs, cpu_register_fp),
        cpu_register_get(regs, cpu_register_ra),
        cpu_register_get(regs, cpu_register_arg1),
        cpu_register_get(regs, cpu_register_arg2),
        cpu_register_get(regs, cpu_register_arg3));

    if (write(block->do_coredump, buff, len) < 0) {
        CONSOLE("write failed: %m");
    }

    CONSOLE("Do coredump for %d", tid);
    if (read(block->do_coredump, buff, sizeof(buff)) < 0) {
        CONSOLE("read failed: %m");
    }
    CONSOLE("Do coredump done");
    block->do_coredump = -1;
}

void agent_alloc(agent_t *agent, cpu_registers_t *regs, size_t size, void *newptr) {
    hashmap_iterator_t *it = NULL;
    void **callstack = NULL;
    block_t *block = NULL;
    allocation_t *allocation = NULL;

    if (!agent->follow_allocs) {
        return;
    }
    if (pthread_self() == agent->thread) {
        // ignore allocation from the agent itself
        return;
    }

    assert((callstack = calloc(agent->callstack_size, sizeof(size_t))));
    libraries_backtrace(agent->libraries, regs, callstack, agent->callstack_size);


    //if (agent->dump_all) {
    //    libraries_backtrace_print(agent->libraries, callstack, agent->callstack_size, stdout);
    //}

    if ((it = hashmap_get(&agent->blocks, callstack))) {
        block = container_of(it, block_t, it);
        free(callstack);

        if (block->do_coredump > 0) {
            agent_notifify_do_coredump(block, regs);
        }
    }
    else {
        block = calloc(1, sizeof(block_t));
        assert(block);
        block->callstack = callstack;
        hashmap_add(&agent->blocks, block->callstack, &block->it);
        agent->stats.block_inuse += 1;
    }

    // create allocation
    assert((allocation = calloc(1, sizeof(allocation_t))));
    assert(allocation);
    allocation->ptr_size = size;
    allocation->ptr = newptr;
    allocation->block = block;
    hashmap_add(&agent->allocations, newptr, &allocation->it);

    // increment statistics
    block->count += 1;
    block->size += size;
    agent->stats.alloc_count += 1;
    agent->stats.alloc_size += size;
    agent->stats.byte_inuse += size;
    agent->stats.count_inuse += 1;
}

void agent_dealloc(agent_t *agent, void *ptr) {
    hashmap_iterator_t *it = NULL;

    if (!agent->follow_allocs) {
        return;
    }
    if (pthread_self() == agent->thread) {
        // ignore allocation from the agent itself
        return;
    }

    if (ptr && (it = hashmap_get(&agent->allocations, ptr))) {
        allocation_t *allocation = container_of(it, allocation_t, it);
        hashmap_iterator_destroy(&allocation->it);
    }
}
