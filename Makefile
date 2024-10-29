# Copyright (c) 2025 Intel Corporation.
# SPDX-License-Identifier: GPL-2.0

obj-m += usbio.o
usbio-y := drivers/usb/misc/usbio.o

KERNELRELEASE := $(shell uname -r)
KDIR := /lib/modules/$(KERNELRELEASE)/build
PWD := $(shell pwd)

ccflags-y += -I$(src)/include/

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
