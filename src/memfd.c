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

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include "log.h"
#include "memfd.h"

int memfd_open(int pid) {
    char memfile[64];
    int memfd = -1;

    snprintf(memfile, sizeof(memfile), "/proc/%d/mem", pid);
    if ((memfd = open(memfile, O_RDWR)) < 0) {
        TRACE_ERROR("Failed to open /proc/%d/mem: %m", pid);
        return -1;
    }

    return memfd;
}

bool memfd_write(int memfd, const void *buf, size_t count, off64_t offset) {
    assert(buf);
/*
    if (lseek64(memfd, offset, SEEK_SET) < 0) {
        TRACE_ERROR("Failed lseek %p: %m", offset);
        return false;
    }
    if (write(memfd, buf, count) < 0) {
        TRACE_ERROR("Failed write(memfd) at 0x%zx: %m", offset);
        return false;
    }
*/
    if (pwrite64(memfd, buf, count, offset) < 0) {
        TRACE_ERROR("pwrite64(0x%"PRIx64") failed: %m", offset);
        return false;
    }

    return true;
}

bool memfd_read(int memfd, void *buf, size_t count, off64_t offset) {
    assert(buf);
    if (pread64(memfd, buf, count, offset) < 0) {
        TRACE_ERROR("pread64(0x%"PRIx64") failed: %m", offset);
        return false;
    }
    /*
    if (lseek64(memfd, offset, SEEK_SET) < 0) {
        TRACE_ERROR("Failed lseek %p: %m", offset);
        return false;
    }
    if (read(memfd, buf, count) < 0) {
        TRACE_ERROR("Failed read(memfd) at 0x%zx: %m", offset);
        return false;
    }
    */

    return true;
}

bool memfd_readstr(int memfd, char *buf, size_t count, off64_t offset) {
    assert(buf);
    assert(count > 1);
    ssize_t size = pread64(memfd, buf, count-1, offset);
    if (size < 0) {
        TRACE_ERROR("pread64(0x%"PRIx64") failed: %m", offset);
        buf[0] = 0;
        return false;
    }
    buf[size] = 0;
    return true;
}

uint32_t memfd_read32(int memfd, off64_t offset) {
    uint32_t value = 0;
    memfd_read(memfd, &value, sizeof(value), offset);
    return value;
}
