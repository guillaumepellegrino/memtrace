SUBMAKE=host target

all: $(addsuffix -all, $(SUBMAKE))

install: $(addsuffix -install, $(SUBMAKE))

clean: $(addsuffix -clean, $(SUBMAKE))

%-all:
	$(MAKE) -f Makefile.${@:-all=} all

%-install:
	$(MAKE) -f Makefile.${@:-install=} install

%-clean:
	$(MAKE) -f Makefile.${@:-clean=} clean

cleanall:
	rm -rf build-*

.PHONY: all install clean cleanall
