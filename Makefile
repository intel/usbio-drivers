# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2023 Intel Corporation.

ifeq ($(KERN_VER),$(EMPTY_STR))
KERNELRELEASE ?= $(shell uname -r)
else
KERNELRELEASE ?= $(KERN_VER)
endif

obj-m += usbio.o
usbio-y := drivers/mfd/usbio.o

obj-m += gpio-usbio.o
gpio-usbio-y := drivers/gpio/gpio-usbio.o

obj-m += i2c-usbio.o
i2c-usbio-y := drivers/i2c/busses/i2c-usbio.o

KERNELRELEASE ?= $(shell uname -r)
KERNEL_SRC ?= /lib/modules/$(KERNELRELEASE)/build
PWD := $(shell pwd)

ccflags-y += -I$(src)/include/

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules

modules_install:
	$(MAKE) INSTALL_MOD_DIR=/updates -C $(KERNEL_SRC) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean
