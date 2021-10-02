
all: host-all target-all

clean: host-clean target-clean
	$(MAKE) -C host $(@)
	$(MAKE) -C target $(@)

host-all:
	$(MAKE) -C host all

host-clean:
	$(MAKE) -C host clean

target-all:
	$(MAKE) -C target all

target-clean:
	$(MAKE) -C target clean

.PHONY: all clean host-all host-clean target-all target-clean
