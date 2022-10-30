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

char *alloc_toto() {
    return strdup("toto");
}

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
        /*
        int *num = calloc(1, sizeof(num));
        if (num) {
            *num = getmagicnumber(loop);
            //printf("magic number = %d (%p)\n", *num, num);
            free(num);
        }
        else {
            printf("num is NULL\n");
        }
        fflush(stdout);
        */

        //char *toto = alloc_toto();
        //printf("strdup() -> %s (%p)\n", toto, toto);
        time_t now = time(NULL);
        printf("sleep() IN @%s", asctime(localtime(&now)));
        sleep(1);
        now = time(NULL);
        printf("sleep() OUT @%s", asctime(localtime(&now)));
        loop++;
    }

    printf("Exit main()\n");

    return 0;
}
