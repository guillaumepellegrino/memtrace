
all: host-all target-all

intstall: host-install

clean: host-clean target-clean
	$(MAKE) -C host $(@)
	$(MAKE) -C target $(@)

host-all:
	$(MAKE) -C host all

host-install:
	$(MAKE) -C host install

host-clean:
	$(MAKE) -C host clean

target-all:
	$(MAKE) -C target all

target-clean:
	$(MAKE) -C target clean

.PHONY: all install clean host-all host-install host-clean target-all target-clean
