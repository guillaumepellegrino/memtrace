#pragma once

#include "types.h"

int syscall_open(int pid, void *path, int flags, mode_t mode);
void *syscall_mmap(int pid, void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int syscall_getpid(int pid);
