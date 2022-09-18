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

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include "log.h"
#include "selftest.h"
#include "process.h"

#define selftest_assert(st, rt, fmt, ...) \
    do { \
        if (!(rt)) {CONSOLE("[%2zu][scenario:%s][test:" fmt "] FAILED", st->idx, st->scenario, ##__VA_ARGS__); st->count++;} \
        else {CONSOLE("[%2zu][scenario:%s][test:" fmt "] OK", st->idx, st->scenario, ##__VA_ARGS__); st->success++; st->count++;} \
    } while (0)

typedef struct {
    const char *scenario;
    process_t process;
    size_t idx;
    size_t success;
    size_t count;
} selftest_t;

typedef struct {
    const char *name;
    bool (*action)();
    void (*test)(selftest_t *st);
} test_scenario_t;

typedef struct {
    size_t inuse_bytes;
    size_t inuse_blocks;
    size_t alloc_count;
    size_t free_count;
    size_t alloc_bytes;
} selftest_heap_summary_t;

static char *me;
static const char *connectarg;

static char *selftest_readline(process_t *process) {
    static char line[4096];
    char *sep = NULL;

    if (!fgets(line, sizeof(line), process->output)) {
        return NULL;
    }

    if ((sep = strchr(line, '\n'))) {
        *sep = 0;
    }

    CONSOLE("[memtrace:%d] %s", process->pid, line);

    return line;
}

static char *selftest_strstr(process_t *process, const char *needle) {
    char *line = NULL;
    while ((line = selftest_readline(process))) {
        if (strstr(line, needle)) {
            return line;
        }
    }

    return NULL;
}

static bool selftest_memtrace_report_summary(process_t *process, selftest_heap_summary_t *summary) {
    char *line = NULL;

    memset(summary, 0, sizeof(*summary));

    if (!selftest_strstr(process, "HEAP SUMMARY:")) {
        TRACE_ERROR("memtrace report not generated");
        return false;
    }

    if (!(line = selftest_readline(process))) {
        TRACE_ERROR("memtrace report sumarry not generated");
        return false;
    }

    if (sscanf(line, "    in use at exit: %zu bytes in %zu blocks", &summary->inuse_bytes, &summary->inuse_blocks) != 2) {
        TRACE_ERROR("Failed to parse memtrace report");
        return false;
    }

    if (!(line = selftest_readline(process))) {
        TRACE_ERROR("memtrace report sumarry not generated");
        return false;
    }

    if (sscanf(line, "    total heap usage: %zu allocs, %zu frees, %zu bytes allocated", &summary->alloc_count, &summary->free_count, &summary->alloc_bytes) != 3) {
        TRACE_ERROR("Failed to parse memtrace report");
        return false;
    }

    return true;
}

static void selftest_summary_assert(selftest_t *st, const selftest_heap_summary_t *expected) {
    selftest_heap_summary_t summary = {0};
    selftest_assert(st, selftest_memtrace_report_summary(&st->process, &summary), "summary.parse()");
    selftest_assert(st, summary.inuse_bytes == expected->inuse_bytes, "summary.inuse_bytes");
    selftest_assert(st, summary.inuse_blocks == expected->inuse_blocks, "summary.inuse_blocks");
    selftest_assert(st, summary.alloc_count == expected->alloc_count, "summary.alloc_count");
    selftest_assert(st, summary.free_count == expected->free_count, "summary.free_count");
    selftest_assert(st, summary.alloc_bytes == expected->alloc_bytes, "summary.alloc_bytes");
}

static bool action_calloc() {
    int *ptr = calloc(7*3, 11);
    TRACE_DEBUG("%p", ptr);
    return ptr != NULL;
}

static void test_calloc(selftest_t *st) {
    selftest_heap_summary_t summary = {
        .inuse_bytes = 231,
        .inuse_blocks = 1,
        .alloc_count = 1,
        .free_count = 0,
        .alloc_bytes = 231,
    };
    selftest_summary_assert(st, &summary);
}

static bool action_malloc() {
    TRACE_DEBUG("do_malloc");
    int *ptr = malloc(7*3*13);
    TRACE_DEBUG("malloc=%p", malloc);
    TRACE_DEBUG("ptr=%p", ptr);
    return ptr != NULL;
}

static void test_malloc(selftest_t *st) {
    selftest_heap_summary_t summary = {
        .inuse_bytes = 273,
        .inuse_blocks = 1,
        .alloc_count = 1,
        .free_count = 0,
        .alloc_bytes = 273,
    };
    selftest_summary_assert(st, &summary);
}

static bool action_strdup() {
    TRACE_DEBUG("do_strdup");
    char *ptr = strdup("test");
    TRACE_DEBUG("ptr=%p", ptr);
    TRACE_DEBUG("malloc=%p", malloc);
    TRACE_DEBUG("strdup=%p", strdup);
    return ptr != NULL;
}

static void test_strdup(selftest_t *st) {
    selftest_heap_summary_t summary = {
        .inuse_bytes = 5,
        .inuse_blocks = 1,
        .alloc_count = 1,
        .free_count = 0,
        .alloc_bytes = 5,
    };
    selftest_summary_assert(st, &summary);
}

static bool action_free() {
    int *ptr = malloc(7*3*13);
    TRACE_DEBUG("%p", ptr);
    free(ptr);
    return ptr;
}

static void test_free(selftest_t *st) {
    selftest_heap_summary_t summary = {
        .inuse_bytes = 0,
        .inuse_blocks = 0,
        .alloc_count = 1,
        .free_count = 1,
        .alloc_bytes = 273,
    };
    selftest_summary_assert(st, &summary);
}

static bool action_realloc() {
    int *ptr = malloc(138);
    TRACE_DEBUG("%p", ptr);
    ptr = realloc(ptr, 67);
    TRACE_DEBUG("%p", ptr);
    return true;
}

static void test_realloc(selftest_t *st) {
    selftest_heap_summary_t summary = {
        .inuse_bytes = 67,
        .inuse_blocks = 1,
        .alloc_count = 2,
        .free_count = 1,
        .alloc_bytes = 138+67,
    };
    selftest_summary_assert(st, &summary);
}

static bool action_reallocarray() {
    int *ptr = calloc(138, 3);
    TRACE_DEBUG("%p", ptr);
    ptr = reallocarray(ptr, 138, 7);
    TRACE_DEBUG("%p", ptr);
    return true;
}

static void test_reallocarray(selftest_t *st) {
    selftest_heap_summary_t summary = {
        .inuse_bytes = 138*7,
        .inuse_blocks = 1,
        .alloc_count = 2,
        .free_count = 1,
        .alloc_bytes = 138*(3+7),
    };
    selftest_summary_assert(st, &summary);
}

void *action_do_alloc_1(size_t size) {
    return malloc(size);
}

void *action_do_alloc_2(size_t size) {
    return calloc(1, size);
}

static bool action_multimalloc() {
    int i = 0;

    for (i = 0; i < 10; i++) {
        int *ptr = action_do_alloc_1(53);
        TRACE_DEBUG("%p", ptr);

        if (i % 2) {
            free(ptr);
        }
    }

    for (i = 0; i < 100; i++) {
        int *ptr = action_do_alloc_2(3);
        TRACE_DEBUG("%p", ptr);
        if (i % 2) {
            free(ptr);
        }
    }

    int *ptr = malloc(137);
    TRACE_DEBUG("%p", ptr);

    return ptr;
}

static void test_multimalloc(selftest_t *st) {
    selftest_heap_summary_t summary = {
        .inuse_bytes = (5*53) + (50*3) + 137,
        .inuse_blocks = 5+50+1,
        .alloc_count = 10+100+1,
        .free_count = 5+50,
        .alloc_bytes = (10*53) + (100*3) + 137,
    };
    selftest_summary_assert(st, &summary);
}

static inline void timespec_sub(struct timespec *a, struct timespec *b, struct timespec *result) {
    result->tv_sec  = a->tv_sec  - b->tv_sec;
    result->tv_nsec = a->tv_nsec - b->tv_nsec;
    if (result->tv_nsec < 0) {
        --result->tv_sec;
        result->tv_nsec += 1000000000L;
    }
}

static bool action_hugecalloc() {
    int i = 0;

    struct timespec start = {0};
    struct timespec stop  = {0};
    struct timespec diff  = {0};

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (i = 0; i < 5000; i++) {
        int *ptr = calloc(1, 10);
        TRACE_DEBUG("%p", ptr);
        if (i != 0) {
            free(ptr);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &stop);
    timespec_sub(&stop, &start, &diff);

    CONSOLE("hugecalloc done in %lld.%06lldms", (long long) diff.tv_sec, (long long) diff.tv_nsec);

    return true;
}

static void test_hugecalloc(selftest_t *st) {
    /*
    selftest_heap_summary_t summary = {
        .inuse_bytes = (5*53) + (50*3) + 137,
        .inuse_blocks = 5+50+1,
        .alloc_count = 10+100+1,
        .free_count = 5+50,
        .alloc_bytes = (10*53) + (100*3) + 137,
    };
    selftest_summary_assert(st, &summary);
    */
}

static bool action_loop() {
    CONSOLE("malloc=%p", malloc);
    while (true) {
        size_t i = 0;
        for (i = 0; i < 3; i++) {
            int *ptr = action_do_alloc_2(4);
            TRACE_DEBUG("%p", ptr);
        }
        sleep(1);
        int *ptr = malloc(8);
        TRACE_DEBUG("%p", ptr);
    }
    return true;
}



static test_scenario_t test_scenarios[] = {
    {"calloc", action_calloc, test_calloc},
    {"malloc", action_malloc, test_malloc},
    {"strdup", action_strdup, test_strdup},
    {"free", action_free, test_free},
    {"realloc", action_realloc, test_realloc},
    {"reallocarray", action_reallocarray, test_reallocarray},
    {"multimalloc", action_multimalloc, test_multimalloc},
    {"hugecalloc", action_hugecalloc, test_hugecalloc},
    {"loop", action_loop, NULL},
};

static bool run_action(const char *action) {
    size_t i = 0;
    test_scenario_t *scenario = NULL;

    for (i = 0; i < countof(test_scenarios); i++) {
        scenario = &test_scenarios[i];

        if (!strcmp(scenario->name, action)) {
            return scenario->action();
        }
    }

    TRACE_ERROR("Unknown action %s", action);
    return false;
}

static bool selftest_run_scenario(selftest_t *st, test_scenario_t *scenario) {
    bool rt = false;
   /* 
    const char *cmd[] = {
        me,
        //(verbose>1?"-v":""),
        //(verbose>2?"-v":""),
        me, "--selftest", "--action", scenario->name, NULL};
    */

    const char *cmd[16];
    const char **arg = cmd;
    *arg++ = me;
    if (verbose >= 1) {
        *arg++ = "-v";
    }
    if (verbose >= 2) {
        *arg++ = "-v";
    }
    if (connectarg) {
        *arg++ = "--connect";
        *arg++ = connectarg;
    }
    *arg++ = me;
    *arg++ = "--selftest";
    *arg++ = "--action";
    *arg++ = scenario->name;
    *arg++ = NULL;

    if (!process_start(&st->process, cmd)) {
        TRACE_ERROR("Failed to start process");
        return false;
    }

    st->scenario = scenario->name;

    size_t p_success = st->success;
    size_t p_count = st->count;

    scenario->test(st);

    size_t success = st->success - p_success;
    size_t count = st->count - p_count;
    rt = (success == count);

    while (selftest_readline(&st->process));

    process_stop(&st->process);

    return rt;
}

static bool selftest(const char *scenario_name) {
    selftest_t st = {0};

    CONSOLE("Running selftest");


    for (st.idx = 0; st.idx < countof(test_scenarios); st.idx++) {
        test_scenario_t *scenario = &test_scenarios[st.idx];

        if (scenario_name && strcmp(scenario->name, scenario_name)) {
            continue;
        }
        if (!scenario->action || !scenario->test) {
            continue;
        }

        CONSOLE("[%2zu] Run scenario %s", st.idx, scenario->name);

        if (selftest_run_scenario(&st, scenario)) {
            CONSOLE("[%2zu] Scenario %s: SUCCESS", st.idx, scenario->name);
        }
        else {
            CONSOLE("[%2zu] Scenario %s: FAILURE", st.idx, scenario->name);
        }
    }

    CONSOLE("self tests run: %zu/%zu", st.success, st.count);

    return st.success == st.count;
}

static void help() {
    CONSOLE("Usage: memtrace --selftest [OPTION]...");
    CONSOLE("Run memtrace self test");
    CONSOLE("");
    CONSOLE("Options:");
    CONSOLE("   -c, --connect=HOST[:PORT]   Connect to specified HOST and PORT");
    CONSOLE("   -s, --scenario=VALUE        Run specified scenario");
    CONSOLE("   -a, --action=VALUE          Run specified action");
    CONSOLE("   -v, --verbose               Increase logging verbosity");
    CONSOLE("   -h, --help                  Display this help");
}

int selftest_main(int argc, char *argv[]) {
    const char *short_options = "+sacvhV";
    const struct option long_options[] = {
        {"scenario",    required_argument,  0, 's'},
        {"action",      required_argument,  0, 'a'},
        {"connect",     required_argument,  0, 'c'},
        {"verbose",     no_argument,        0, 'v'},
        {"help",        no_argument,        0, 'h'},
        {0}
    };
    int opt = -1;
    const char *action = NULL;
    const char *scenario = NULL;

    me = argv[0];

    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
            case 'a':
                action = optarg;
                break;
            case 's':
                scenario = optarg;
                break;
            case 'c':
                connectarg = optarg;
                break;
            case 'v':
                verbose++;
                break;
            default:
                help();
                return 1;
        }
    }

    if (action) {
        return run_action(action) ? 0 : 1;
    }
    else {
        return selftest(scenario) ? 0 : 1;
    }

    return 0;
}
