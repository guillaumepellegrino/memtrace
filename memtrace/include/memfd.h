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

#ifndef MEMFD_H
#define MEMFD_H

#ifndef off64_t
#define off64_t uint64_t
#endif

/**
 * Open a file descriptor pointing on pid's memory
 * for read and write access.
 */
int memfd_open(int pid);

/**
 * Write buffer at the specified offset in the target's process memory, referenced by memfd.
 */
bool memfd_write(int memfd, const void *buf, size_t count, off64_t offset);

/**
 * Read buffer at the specified offset in the target's process memory, referenced by memfd.
 */
bool memfd_read(int memfd, void *buf, size_t count, off64_t offset);

/**
 * Read string at the specified offset in the target's process memory, referenced by memfd.
 */
bool memfd_readstr(int memfd, char *buf, size_t count, off64_t offset);

uint32_t memfd_read32(int memfd, off64_t offset);

#endif
