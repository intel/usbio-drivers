# USBIO driver stack

This repository supports USBIO drivers for IO Extension on Intel's Meteor Lake, Arrow Lake, Lunar Lake and Panther Lake platforms.

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
$sudo mkdir /usr/src/usbio-0.3
$sudo cp -R . /usr/src/usbio-0.3/
```
* Build and install dkms
```
$sudo dkms add -m usbio -v 0.3
$sudo dkms build -m usbio -v 0.3
$sudo dkms install -m usbio -v 0.3
```

### Kernel source code
Tested on kernel 6.8

* Copy drivers into kernel source code
* Update the required Kconfigs and Makefiles

Add to drivers/usb/misc/Kconfig
```
config USB_USBIO
	tristate "Intel USBIO Bridge support"
	help
	  This adds support for IO Extension using Intel USBIO drivers.
	  This enables the USBIO bridge driver module in charge to talk
	  to the USB device. Additional drivers such as I2C_USBIO,
	  GPIO_USBIO and SPI_USBIO must be enabled in order to use the
	  device's full functionality.

	  This driver can also be built as a module. If so, the module
	  will be called usbio.
```

Add to drivers/usb/misc/Makefile
```
obj-$(CONFIG_USB_USBIO)	+= usbio.o
```

Add to drivers/gpio/Kconfig
```
config GPIO_USBIO
	tristate "Intel USBIO GPIO support"
	depends on USB_USBIO
	default USB_USBIO
	help
	  Select this option to enable GPIO driver for the INTEL
	  USBIO driver stack.

	  This driver can also be built as a module. If so, the module
	  will be called gpio_usbio.
```

Add to drivers/gpio/Makefile
```
obj-$(CONFIG_GPIO_USBIO)	+= gpio-usbio.o
```

Add to drivers/i2c/busses/Kconfig
```
config I2C_USBIO
	tristate "Intel USBIO I2C Adapter support"
	depends on USB_USBIO
	default USB_USBIO
	help
	  Select this option to enable I2C driver for the INTEL
	  USBIO driver stack.

	  This driver can also be built as a module.  If so, the module
	  will be called i2c_usbio.
```

Add to drivers/i2c/busses/Makefile
```
obj-$(CONFIG_I2C_USBIO)	+= i2c-usbio.o
```

Enable drivers in .config
```
CONFIG_USB_USBIO=y
CONFIG_GPIO_USBIO=y
CONFIG_I2C_USBIO=y
```

* Compile new kernel
