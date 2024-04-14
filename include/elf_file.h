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

#ifndef ELF_FILE_H
#define ELF_FILE_H

#include "types.h"
#include <stdio.h>

struct _elf_file {
    const section_header_t *section;
    uint64_t size; /** buffer size */
    uint64_t offset; /** current offset */
    bool elf64; /** Is it a 64bit elf file ? */
    bool dwarf64;
    bool lowendian; /** Is it a low endianess elf file ? */
    char buffer[];
};


elf_file_t *elf_file_open(elf_t *elf, uint64_t size, uint64_t offset);
elf_file_t *elf_section_open(elf_t *elf, const section_header_t *section);
elf_file_t *elf_section_open_from_name(elf_t *elf, const char *name);
void elf_file_close(elf_file_t *file);
void elf_file_set64bit(elf_file_t *file, bool elf64);
bool elf_file_64bit(elf_file_t *file);
void elf_file_setdwarf64(elf_file_t *file, bool dwarf64);
void elf_file_setlowendian(elf_file_t *file, bool lowendian);
const section_header_t *elf_file_section(elf_file_t *file);

ssize_t elf_file_read(elf_file_t *file, void *buff, size_t size);
//int elf_file_getc(elf_file_t *file);
//void elf_file_seek(elf_file_t *file, uint64_t offset);
//uint64_t elf_file_tell(elf_file_t *file);
//int elf_file_eof(elf_file_t *file);

static inline int elf_file_getc(elf_file_t *file) {
    if (file->offset >= file->size) {
        return EOF;
    }

    return file->buffer[file->offset++];
}

static inline void elf_file_seek(elf_file_t *file, uint64_t offset) {
    file->offset = offset;
}

static inline uint64_t elf_file_tell(elf_file_t *file) {
    return file->offset;
}

static inline int elf_file_eof(elf_file_t *file) {
    return file->offset >= file->size;
}

static inline uint8_t elf_file_read_u8(elf_file_t *file) {
    if (file->offset >= file->size) {
        return 0;
    }

    return file->buffer[file->offset++];
}

static inline uint16_t elf_file_read_u16(elf_file_t *file) {
    union {
        uint8_t b[2];
        uint16_t u16;
    } value = {0};

    if (file->offset + sizeof(value) > file->size) {
        return 0;
    }

    value.b[0] |= file->buffer[file->offset++];
    value.b[1] |= file->buffer[file->offset++];

    return file->lowendian ?
        le16toh(value.u16) : be16toh(value.u16);
}

static inline uint32_t elf_file_read_u32(elf_file_t *file) {
    union {
        uint8_t b[4];
        uint32_t u32;
    } value = {0};

    if (file->offset + sizeof(value) > file->size) {
        return 0;
    }

    value.b[0] |= file->buffer[file->offset++];
    value.b[1] |= file->buffer[file->offset++];
    value.b[2] |= file->buffer[file->offset++];
    value.b[3] |= file->buffer[file->offset++];

    return file->lowendian ?
        le32toh(value.u32) : be32toh(value.u32);
}

static inline uint64_t elf_file_read_u64(elf_file_t *file) {
    union {
        uint8_t b[8];
        uint64_t u64;
    } value = {0};

    if (file->offset + sizeof(value) > file->size) {
        return 0;
    }

    value.b[0] |= file->buffer[file->offset++];
    value.b[1] |= file->buffer[file->offset++];
    value.b[2] |= file->buffer[file->offset++];
    value.b[3] |= file->buffer[file->offset++];
    value.b[4] |= file->buffer[file->offset++];
    value.b[5] |= file->buffer[file->offset++];
    value.b[6] |= file->buffer[file->offset++];
    value.b[7] |= file->buffer[file->offset++];

    return file->lowendian ?
        le64toh(value.u64) : be64toh(value.u64);
}

static inline int8_t elf_file_read_i8(elf_file_t *file) {
    return elf_file_read_u8(file);
}

static inline int16_t elf_file_read_i16(elf_file_t *file) {
    return elf_file_read_u16(file);
}

static inline int32_t elf_file_read_i32(elf_file_t *file) {
    return elf_file_read_u32(file);
}

static inline int64_t elf_file_read_i64(elf_file_t *file) {
    return elf_file_read_u64(file);
}

static inline uint64_t elf_file_read_addr(elf_file_t *file) {
    return file->elf64 ?
        elf_file_read_u64(file) : elf_file_read_u32(file);
}

static inline uint64_t elf_file_read_dwarfaddr(elf_file_t *file) {
    return file->dwarf64 ?
        elf_file_read_u64(file) : elf_file_read_u32(file);
}

static inline void elf_file_discard(elf_file_t *file, size_t size) {
    size_t i;
    for (i = 0; i < size; i++) {
        elf_file_getc(file);
    }
}

//uint16_t elf_file_read_u16(elf_file_t *file) {
//uint32_t elf_file_read_u32(elf_file_t *file);
//uint64_t elf_file_read_u64(elf_file_t *file);
//int8_t elf_file_read_i8(elf_file_t *file);
//int16_t elf_file_read_i16(elf_file_t *file);
//int32_t elf_file_read_i32(elf_file_t *file);
//int64_t elf_file_read_i64(elf_file_t *file);
//uint64_t elf_file_read_addr(elf_file_t *file);
//uint64_t elf_file_read_dwarfaddr(elf_file_t *file);
void elf_file_discard(elf_file_t *file, size_t size);
int32_t elf_file_read_sleb128(elf_file_t *file);
uint32_t elf_file_read_uleb128(elf_file_t *file);
bool elf_file_read_string(elf_file_t *file, char *buff, size_t size);
const char *elf_file_read_strp(elf_file_t *file);



#endif
