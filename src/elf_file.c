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
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include "elf_file.h"
#include "elf.h"
#include "fs.h"
#include "log.h"

#define FS_DEFAULT_BINDADDR "::0"
#define FS_DEFAULT_PORT "3002"
#define GET_REQUEST "GET/REQUEST/"
#define GET_REPLY "GET/REPLY/"

/*
uint16_t elf_file_read_u16(elf_file_t *file) {
    uint16_t value = 0;
    elf_file_read(file , &value, sizeof(value));

    return file->lowendian ?
        le16toh(value) : be16toh(value);
}

uint32_t elf_file_read_u32(elf_file_t *file) {
    uint32_t value = 0;
    elf_file_read(file, &value, sizeof(value));

    return file->lowendian ?
        le32toh(value) : be32toh(value);
}

uint64_t elf_file_read_u64(elf_file_t *file) {
    uint64_t value = 0;
    elf_file_read(file, &value, sizeof(value));

    return file->lowendian ?
        le64toh(value) : be64toh(value);
}

int8_t elf_file_read_i8(elf_file_t *file) {
    return elf_file_read_u8(file);
}

int16_t elf_file_read_i16(elf_file_t *file) {
    return elf_file_read_u16(file);
}

int32_t elf_file_read_i32(elf_file_t *file) {
    return elf_file_read_u32(file);
}

int64_t elf_file_read_i64(elf_file_t *file) {
    return elf_file_read_u64(file);
}

uint64_t elf_file_read_addr(elf_file_t *file) {
    return file->elf64 ?
        elf_file_read_u64(file) : elf_file_read_u32(file);
}

uint64_t elf_file_read_dwarfaddr(elf_file_t *file) {
    return file->dwarf64 ?
        elf_file_read_u64(file) : elf_file_read_u32(file);
}

void elf_file_discard(elf_file_t *file, size_t size) {
    size_t i;
    for (i = 0; i < size; i++) {
        elf_file_getc(file);
    }
}
*/
int32_t elf_file_read_sleb128(elf_file_t *file) {
    int32_t result = 0;
    int32_t shift = 0;
    int32_t byte = 0;

    do {
        if ((byte = elf_file_getc(file)) == EOF) {
            return 0;
        }

        // low-order 7 bits of byte are shifted to the left
        result |= (byte & 0x7F) << shift;
        shift += 7;

    // high-order bit of byte is 0 when finished
    } while (byte & 0x80);

    // sign bit of byte is second high-order bit
    if ((shift < 32) && (byte & 0x40)) {
        // sign extend
        result |= (~0U << shift);
    }

    return result;
}

uint32_t elf_file_read_uleb128(elf_file_t *file) {
    uint32_t result = 0;
    uint32_t shift = 0;
    int32_t byte = 0;

    do {
        if ((byte = elf_file_getc(file)) == EOF) {
            return 0;
        }

        // low-order 7 bits of byte are shifted to the left
        result |= (byte & 0x7F) << shift;
        shift += 7;

    // high-order bit of byte is 0 when finished
    } while (byte & 0x80);

    return result;
}

bool elf_file_read_string(elf_file_t *file, char *buff, size_t size) {
    size_t i = 0;

    while (true) {
        int c = elf_file_getc(file);

        if (c == EOF) {
            return false;
        }
        if (c == 0) {
            break;
        }
        if (i+1 >= size) {
            break;
        }
        buff[i++] = c;
    }

    buff[i] = 0;

    return true;
}

const char *elf_file_read_strp(elf_file_t *file) {
    const char *str = file->buffer + file->offset;

    while (file->offset < file->size) {
        if (file->buffer[file->offset++] == 0) {
            return str;
        }
    }

    return NULL;
}

elf_file_t *elf_file_open(elf_t *elf, uint64_t size, uint64_t offset) {
    elf_file_t *file = NULL;
    fs_t *fs = elf_fs(elf);
    const char *name = NULL;

    if (!elf || !size) {
        errno = EINVAL;
        return NULL;
    }
    if (!(name = elf_name(elf))) {
        errno = EINVAL;
        return NULL;
    }

    if (!fs || fs->cfg.type == fs_type_local) {
        FILE *fp = fopen(name, "r");
        if (!fp) {
            return NULL;
        }
        if (offset && fseek(fp, offset, SEEK_SET) != 0) {
            fclose(fp);
            return NULL;
        }
        if (!(file = calloc(1, sizeof(elf_file_t) + size))) {
            fclose(fp);
            return NULL;
        }
        file->size = size;
        if (fread(file->buffer, file->size, 1, fp) != 1) {
            fclose(fp);
            free(file);
            return NULL;
        }
        fclose(fp);
    }
    else {
        uint64_t retsize = 0;
        TRACE_LOG(GET_REQUEST "size=%"PRIu64"/offset=%"PRIu64":%s", size, offset, name);
        if (fprintf(fs->socket, GET_REQUEST "size=%"PRIu64"/offset=%"PRIu64":%s\n", size, offset, name) <= 0) {
            TRACE_ERROR("fprintf(socket) failed: %m");
            return NULL;
        }
        if (fflush(fs->socket) != 0) {
            TRACE_ERROR("fflush(socket) failed: %m");
            return NULL;
        }

        TRACE_LOG("WAIT FOR GET/REPLY");
        char line[64];
        if (!fgets(line, sizeof(line), fs->socket)) {
            TRACE_ERROR("fgets(socket) failed: %m");
            return NULL;
        }
        if (sscanf(line, GET_REPLY "size=%"PRIu64, &retsize) != 1) {
            TRACE_ERROR("Failed to parse reply from server");
            return NULL;
        }
        if (retsize == 0) {
            TRACE_ERROR("Failed to get %s", name);
            return NULL;
        }
        if (!(file = calloc(1, sizeof(elf_file_t) + retsize))) {
            TRACE_ERROR("calloc(%"PRIu64") failed: %m", retsize);
            return NULL;
        }

        file->size = retsize;

        TRACE_LOG("READ %"PRIu64, file->size);
        if (fread(file->buffer, file->size, 1, fs->socket) != 1) {
            TRACE_ERROR("Failed to read reply from server");
            free(file);
            return NULL;
        }
        TRACE_LOG("READ %"PRIu64" DONE", file->size);
    }

    elf_file_set64bit(file, elf_header(elf)->ei_class == ei_class_64bit);
    elf_file_setlowendian(file, elf_header(elf)->ei_data == ei_data_le);

    return file;
}

elf_file_t *elf_section_open(elf_t *elf, const section_header_t *section) {
    elf_file_t *file = NULL;

    if ((file = elf_file_open(elf, section->sh_size, section->sh_offset))) {
        file->section = section;
    }

    return file;
}

elf_file_t *elf_section_open_from_name(elf_t *elf, const char *name) {
    elf_file_t *file = NULL;
    const section_header_t *section = NULL;

    if ((section = elf_section_header_get(elf, name))) {
        file = elf_section_open(elf, section);
    }

    return file;
}

void elf_file_close(elf_file_t *file) {
    free(file);
}

void elf_file_set64bit(elf_file_t *file, bool elf64) {
    file->elf64 = elf64;
}

bool elf_file_64bit(elf_file_t *file) {
    return file->elf64;
}

void elf_file_setdwarf64(elf_file_t *file, bool dwarf64) {
    file->dwarf64 = dwarf64;
}

void elf_file_setlowendian(elf_file_t *file, bool lowendian) {
    file->lowendian = lowendian;
}

const section_header_t *elf_file_section(elf_file_t *file) {
    return file->section;
}

ssize_t elf_file_read(elf_file_t *file, void *buff, size_t size) {
    ssize_t xbytes = size;

    if (file->offset + size > file->size) {
        xbytes = file->size - file->offset;
    }
    if (xbytes < 0) {
        xbytes = 0;
    }

    memcpy(buff, &file->buffer[file->offset], xbytes);

    file->offset += xbytes;

    return xbytes;
}

