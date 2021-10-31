MACHINE=$(shell $(CC) -dumpmachine)
CFLAGS+=-Wall -Wextra -Wno-unused-parameter  -Werror -g -O2 -DVERSION=\"$(shell git describe --tags)\"
#LDFLAGS+=-ldw
#LDFLAGS+=-lunwind -lunwind-ptrace
OBJECTS=ftrace.o breakpoint.o syscall.o ptrace.o hashmap.o libraries.o net.o fs.o log.o selftest.o process.o elf.o elf_file.o elf_sym.o debug_line.o debug_info.o debug_frame.o dwarf_expr.o dwarf_unwind.o strlist.o console.o
#OBJECTS+=backtrace.o
TARGETS=memtrace

ifneq (,$(findstring x86_64,$(MACHINE)))
#LDFLAGS+=-lunwind-x86_64
OBJECTS+=x86_64.o
endif

ifneq (,$(findstring arm,$(MACHINE)))
CFLAGS+=
OBJECTS+=arm.o
endif

all: memtrace

memtrace: memtrace.o $(OBJECTS)
	$(CC) -o $(@) $(^) $(LDFLAGS)

-include $(OBJECTS:.o=.d)

%.o:../src/%.c
	$(CC) -c -MD $(CFLAGS) $(<) -o $(@)

clean:
	rm -f memtrace *.o *.d arch/*.o arch/*.d

.PHONY: all clean
