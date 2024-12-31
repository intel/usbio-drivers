# Copyright (c) 2025 Intel Corporation.
# SPDX-License-Identifier: GPL-2.0

obj-m += usbio.o
usbio-y := drivers/usb/misc/usbio.o

obj-m += gpio-usbio.o
gpio-usbio-y := drivers/gpio/gpio-usbio.o

obj-m += i2c-usbio.o
i2c-usbio-y := drivers/i2c/busses/i2c-usbio.o

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
