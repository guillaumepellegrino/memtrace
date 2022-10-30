CC_HOST?=cc
CFLAGS_HOST+=-Wall -Wextra -Wno-unused-parameter -Werror -g -O2 \
	-DVERSION=\"$(shell git describe --all)\"
LDFLAGS_HOST+=

all: memtrace-server

install:
	install -m 0755 memtrace-server /usr/bin/

memtrace-server: memtrace-server.o evlp.o bus.o net.o strmap.o strlist.o elf.o elf_file.o process.o addr2line.o gdb.o log.o
	$(CC_HOST) -o $(@) $(^) $(LDFLAGS_HOST)

-include $(OBJECTS:.o=.d)

%.o: ../src/%.c
	$(CC_HOST) -c -MD $(CFLAGS_HOST) $(<) -o $(@)

clean:
	rm -f memtrace-server *.o *.d

.PHONY: all install clean

