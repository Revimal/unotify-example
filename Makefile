obj-m := unotify.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	@rm -f $(PWD)/*.ko
	@rm -f $(PWD)/*.mod.*
	@rm -f $(PWD)/.*.cmd
	@rm -f $(PWD)/*.o
	@rm -f $(PWD)/.cache.mk
	@rm -rf $(PWD)/.tmp_versions
	@rm -f $(PWD)/Module.symvers
	@rm -f $(PWD)/modules.order
