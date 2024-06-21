# usbio driver stack

This repository supports USBIO Extension drivers on Intel Alder Lake, Raptor Lake, Meteor Lake and Lunar Lake platforms.


## Build instructions:
Three ways are available:
  1. build with kernel source tree
  2. build out of kernel source tree
  3. build with dkms

### build with kernel source tree
* Tested with kernel 6.8
* Check out kernel
* Copy repo content to kernel source
* Modify related Kconfig and Makefile

* Add to drivers/mfd/Kconfig
```
config MFD_USBIO
        tristate "Intel USBIO extension support"
        select MFD_CORE
        depends on USB
        help
          This adds support for Intel USBIO (I2C/SPI/GPIO)
          Extension. Additional drivers such as GPIO_USBIO,
          I2C_USBIO, etc. must be enabled in order to use the
          functionality of the device.
```
* add to drivers/mfd/Makefile
```
obj-$(CONFIG_MFD_USBIO) += usbio.o
```

* Add to drivers/gpio/Kconfig
```
config GPIO_USBIO
        tristate "INTEL USBIO GPIO Extension support"
        depends on MFD_USBIO

        help
          Select this option to enable GPIO driver for the INTEL
          USBIO GPIO Extension.

          This driver can also be built as a module. If so, the module
          will be called gpio-usbio.
```
* Add to drivers/gpio/Makefile
```
obj-$(CONFIG_GPIO_USBIO) += gpio-usbio.o
```

* Add to drivers/i2c/busses/Kconfig
```
config I2C_USBIO
        tristate "INTEL USBIO I2C Extension support"
        depends on MFD_USBIO
        help
         If you say yes to this option, I2C functionality support of INTEL
         USBIO I2C Extension will be included.

         This driver can also be built as a module.  If so, the module
         will be called i2c-usbio.
```
* Add to drivers/i2c/busses/Makefile
```
obj-$(CONFIG_I2C_USBIO) += i2c-usbio.o
```

* Add to drivers/spi/Kconfig
```
config SPI_LJCA
       tristate "INTEL La Jolla Cove Adapter SPI support"
       depends on MFD_LJCA
       help
          Select this option to enable SPI driver for the INTEL
          La Jolla Cove Adapter (LJCA) board.

          This driver can also be built as a module. If so, the module
          will be called spi-ljca.
```
* Add to drivers/spi/Makefile
```
obj-$(CONFIG_SPI_LJCA) += spi-ljca.o
```

* Enable the following settings in .config
```
CONFIG_MFD_USBIO=m
CONFIG_GPIO_USBIO=m
CONFIG_I2C_USBIO=m
CONFIG_SPI_LJCA=m
```

### build out of kernel source tree
* Requires 5.13 or later kernel header installed on compiling machine

* To compile:
```
$cd linux-usbio
$make -j`nproc`
```

* To install and use modules
```
$sudo make modules_install
$sudo depmod -a
```

### Build with dkms
a dkms.conf file is also provided as an example for building with dkms which can be
used by ```dkms``` ```add```, ```build``` and ```install```.


## Deployment:
TBD
