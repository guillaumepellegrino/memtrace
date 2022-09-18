SUBDIR=host target

all: $(addsuffix -all, $(SUBDIR))

install: $(addsuffix -install, $(SUBDIR))

clean: $(addsuffix -clean, $(SUBDIR))

%-all:
	$(MAKE) -C ${@:-all=} all

%-install:
	$(MAKE) -C ${@:-install=} install

%-clean:
	$(MAKE) -C ${@:-clean=} clean

.PHONY: all install clean
