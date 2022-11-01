/*
 * Copyright (C) 2022 Guillaume Pellegrino
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

static volatile int exit_loop = 0;

void *thread_loop(void *arg) {
    (void) arg;

    printf("thread_loop(): pid: %d\n", getpid());

    while (!exit_loop) {
        char *toto = strdup("thread");
        printf("thread: strdup() -> %s (%p)\n", toto, toto);
        free(toto);
        sleep(1);
    }

    return NULL;
}

int getmagicnumber(int count) {
    return count;
}

void sigint_handler(int s) {
    exit_loop = 1;
}

void free_hook(void *ptr);

int main(int argc, char *argv[]) {
    int loop = 1;
    pthread_t thread;

    printf("main(): pid: %d\n", getpid());

    if (argc <= 1) {
        if (pthread_create(&thread, NULL, thread_loop, NULL) != 0) {
            printf("Failed to create thread");
            return 1;
        }
        pthread_detach(thread);
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    while (!exit_loop) {
        int *num = calloc(1, sizeof(num));
        *num = getmagicnumber(loop);
        printf("magic number = %d (%p)\n", *num, num);
        free_hook(num);
        fflush(stdout);

        char *toto = strdup("toto");
        printf("strdup() -> %s (%p)\n", toto, toto);
        free(toto);
        sleep(1);
        loop++;
    }

    printf("Exit main()\n");

    return 0;
}
