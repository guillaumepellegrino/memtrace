MACHINE=$(shell $(CC) -dumpmachine)
LD?=$(CC:cc=ld)
OBJCOPY?=$(CC:cc=objcopy)
CFLAGS+=-Wall -Wextra -Wno-unused-parameter -Werror -g -O2 -fPIC -pthread \
	-DVERSION=\"$(shell git describe --all)\" \
	-DSYSROOT=\"$(shell $(CC) -print-sysroot)\" \
	-DCOMPILER=\"$(CC)\"
LDFLAGS+=-pthread

TARGETS=memtrace libmemtrace-agent.so dummy dummy2

ifneq (,$(findstring x86_64,$(MACHINE)))
#LDFLAGS+=-lunwind-x86_64
ARCH_OBJECT=x86_64.o
endif

ifneq (,$(findstring arm,$(MACHINE)))
CFLAGS+=
ARCH_OBJECT=arm.o
endif

all: $(TARGETS)

memtrace: memtrace.o inject.o syscall_hijack.o ptrace.o hashmap.o strlist.o libraries.o log.o elf.o elf_file.o elf_sym.o elf_relocate.o console.o coredump.o $(ARCH_OBJECT)
	$(CC) -o $(@) $(^) $(LDFLAGS)

libmemtrace-agent.so: agent.o agent_hooks.o hashmap.o libraries.o elf.o elf_file.o elf_sym.o coredump.o log.o $(ARCH_OBJECT)
	$(CC) --shared -fPIC -o $(@) $(^) $(LDFLAGS)

dummy: dummy.o
	$(CC) -o $(@) $(^) $(LDFLAGS)

dummy2: dummy2.o libmemtrace-agent.so
	$(CC) -o $(@) $(^) $(LDFLAGS) -L. -lmemtrace-agent -Wl,-rpath,target/

-include $(willdcard *.d)

%.o:../src/%.c
	$(CC) -c -MD $(CFLAGS) $(<) -o $(@)

clean:
	rm -f memtrace inject dummy dummy2 *.so *.o *.d

.PHONY: all clean
