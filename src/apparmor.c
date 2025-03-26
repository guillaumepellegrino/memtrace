/*
 * Copyright (C) 2025 Guillaume Pellegrino
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

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include "log.h"

char *apparmor_read_mode() {
    char mode[32];
    int fd = open("/sys/module/apparmor/parameters/mode", O_RDONLY);
    if (fd < 0) {
        return NULL;
    }
    if (read(fd, mode, sizeof(mode) - 1) < 0) {
        close(fd);
        return NULL;
    }
    close(fd);
    return strdup(mode);
}

void apparmor_set_mode(const char *mode) {
    int fd = open("/sys/module/apparmor/parameters/mode", O_WRONLY);
    if (fd < 0) {
        TRACE_ERROR("Could not open apparmor mode for write: %m");
        return;
    }
    if (write(fd, mode, strlen(mode)) < 0) {
        TRACE_ERROR("Could not write apparmor mode=%s: %m", mode);
        close(fd);
        return;
    }
    close(fd);
}

void apparmor_tmp_disable(char **mode) {
    *mode = apparmor_read_mode();

    if (*mode && !strcmp(*mode, "enforce")) {
        apparmor_set_mode("complain");
    }


    if (*mode && !strcmp(*mode, "enforce")) {
        apparmor_set_mode(*mode);
    }
}
