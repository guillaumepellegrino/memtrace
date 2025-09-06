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
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>
#include <ctype.h>
#include "log.h"
#include "memfd.h"
#include "libraries.h"

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
        //TRACE_ERROR("pread64(0x%"PRIx64") failed: %m", offset);
        buf[0] = 0;
        return false;
    }
    buf[size] = 0;
    return true;
}

bool memfd_readascii(int memfd, char *buf, size_t count, off64_t offset) {
    bool has_num_or_letter = false;

    if (!memfd_readstr(memfd, buf, count, offset)) {
        return false;
    }

    for (int i = 0; buf[i]; i++) {
        if (buf[i] >= '0' && buf[i] <= '9') {
            has_num_or_letter = true;
            continue;
        }
        if (buf[i] >= 'a' && buf[i] <= 'z') {
            has_num_or_letter = true;
            continue;
        }
        if (buf[i] >= 'A' && buf[i] <= 'Z') {
            has_num_or_letter = true;
            continue;
        }
        if (buf[i] >= ' ' && buf[i] <= '~') {
            continue;
        }
        if (buf[i] >= '\t' && buf[i] <= '\r') {
            continue;
        }

        return false;
    }

    return has_num_or_letter;
}

uint32_t memfd_read32(int memfd, off64_t offset) {
    uint32_t value = 0;
    memfd_read(memfd, &value, sizeof(value), offset);
    return value;
}

uint64_t memfd_read64(int memfd, off64_t offset) {
    uint64_t value = 0;
    memfd_read(memfd, &value, sizeof(value), offset);
    return value;
}

size_t memfd_readptr(int memfd, off64_t offset) {
    size_t value = 0;
    memfd_read(memfd, &value, sizeof(value), offset);
    return value;
}

static size_t align(size_t size) {
    size_t len = sizeof(size_t);
    size_t mask = ~(len-1);
    size_t rt = (size & mask) + ((size & 0x3) ? len : 0);
    return rt;
}

void memfd_print_autofmt_v0(FILE *fp, int memfd, off64_t addr, off64_t len) {
    char str[512];
    off64_t base = addr;

    fprintf(fp, "0x%"PRIx64"=", base);
    for (off64_t i = 0; i < len;) {
        addr = base + i;

        if (i != 0) {
            fprintf(fp, " ");
        }

        size_t value = memfd_readptr(memfd, addr);
        if (memfd_readascii(memfd, str, sizeof(str), value)) {
            fprintf(fp, "@0x%zx=\"%s\"", value, str);
            i += align(strlen(str) + 1);
        }
        else if (memfd_readascii(memfd, str, sizeof(str), addr)) {
            fprintf(fp, "\"%s\"", str);
            i += align(strlen(str) + 1);
        }
        else {
            fprintf(fp, "0x%0zx", value);
            i += sizeof(size_t);
        }
    }
    fprintf(fp, "\n");
}

size_t memfd_print_addr(FILE *fp, int memfd, off64_t addr, const char *format) {
    off64_t base = addr;
    for (int i = 0; format[i] != 0; i++) {
        switch (format[i]) {
            case 'd':
                fprintf(fp, "*0x%"PRIx64"=%d\n", addr, memfd_read32(memfd, addr));
                addr += 4;
                break;
            case 'u':
                fprintf(fp, "*0x%"PRIx64"=%u\n", addr, memfd_read32(memfd, addr));
                addr += 4;
                break;
            case 'x':
                fprintf(fp, "*0x%"PRIx64"=0x%x\n", addr, memfd_read32(memfd, addr));
                addr += 4;
                break;
            case 'D':
                fprintf(fp, "*0x%"PRIx64"=%"PRId64"\n", addr, memfd_read64(memfd, addr));
                addr += 8;
                break;
            case 'U':
                fprintf(fp, "*0x%"PRIx64"=%"PRId64"\n", addr, memfd_read64(memfd, addr));
                addr += 8;
                break;
            case 'X':
                fprintf(fp, "*0x%"PRIx64"=0x%"PRId64"\n", addr, memfd_read64(memfd, addr));
                addr += 8;
                break;
            case 's': {
                char str[1024];
                memfd_readstr(memfd, str, sizeof(str), addr);
                fprintf(fp, "*0x%"PRIx64"=\"%s\"\n", addr, str);
                addr += strlen(str) + 1;
                break;
            }
            case 'S': {
                char str[1024];
                size_t pstr = 0;
                memfd_read(memfd, &pstr, sizeof(pstr), addr);
                memfd_readstr(memfd, str, sizeof(str), pstr);
                fprintf(fp, "*0x%"PRIx64"=\"%s\"\n", addr, str);
                addr += sizeof(const char *);
                break;
            }
            /*
            case '/': {
                char *endptr = NULL;
                long addrlen = strtol(format+i+1, &endptr, 10);
                if (addrlen > 0) {
                    memfd_print_autofmt(fp, memfd, addr, addrlen, libraries);
                    i = (endptr - format) - 1;
                }
            }
            */
            default:
                break;
        }
    }

    return addr - base;
}

