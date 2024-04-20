#!/bin/bash
#
#  Copyright (C) 2022 Guillaume Pellegrino
#  This file is part of memtrace <https://github.com/guillaumepellegrino/memtrace>.
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 2 of the License, or
#  (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
#


#
# This script build src/syscall_table.c from syscall.h header
# That's a simple hack to map a syscall name to a syscall number.
#
syscalls="$(egrep -o "SYS_[^ ]+" /usr/include/x86_64-linux-gnu/bits/syscall.h)"

echo "// Auto-generated using './src/syscall_table.sh > src/syscall_table.c'"
echo '#include "syscall.h"'
echo ""
echo "const syscall_table_t syscall_table[] = {"
for syscall in $syscalls; do
    syscallname="${syscall:4}"
    echo "#ifdef $syscall"
    echo "    {\"$syscallname\", $syscall},"
    echo "#endif"
done
echo "    {NULL, 0},"
echo '};'
