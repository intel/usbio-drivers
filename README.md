# USBIO driver stack

This repository supports USBIO drivers on Intel's Meteor Lake, Arrow Lake, Lunar Lake and Panther Lake platforms.

## Build types
* Kernel module
* Dynamic Kernel module
* Kernel source code

### Kernel Module
Requires 6.8 (or later) kernel's headers installed

* To compile:
```
$cd usbio-drivers
$make -j`nproc`
```
* To install modules
```
$sudo make modules_install
$sudo depmod -a
```

### Dynamic Kernel Module
A dkms.conf is provided to build and install the driver stack

* Prepare dkms:
```
$sudo mkdir /usr/src/usbio-0.1
$sudo cp -R . /usr/src/usbio-0.1/
```
* Build and install dkms
```
$sudo dkms add -m usbio -v 0.1
$sudo dkms build -m usbio -v 0.1
$sudo dkms install -m usbio -v 0.1
```

### Kernel source code
Tested on kernel 6.8, 6.11 and 6.14

* Copy driver into kernel source code
* Update the required Kconfig and Makefile

Add to drivers/usb/misc/Kconfig
```
config USB_USBIO
	tristate "Intel USBIO Bridge support"
	depends on USB && ACPI
	select AUXILIARY_BUS
	help
	  This adds support for Intel USBIO drivers.
	  This enables the USBIO bridge driver module in charge to talk
	  to the USB device. Additional drivers such as GPIO_USBIO and
	  I2C_USBIO must be enabled in order to use the device's full
	  functionality.

	  This driver can also be built as a module. If so, the module
	  will be called usbio.
```

Add to drivers/usb/misc/Makefile
```
obj-$(CONFIG_USB_USBIO)	+= usbio.o
```

Enable driver in .config
```
CONFIG_USB_USBIO=y
```

* Compile and install new kernel
