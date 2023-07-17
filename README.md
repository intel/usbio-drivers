# USBIO driver stack

This repository supports USBIO Bridge drivers for Intel MeteoLake platform with Lattice AIC


## Build instructions
Ways to build the USBIO drivers
  1. build out of kernel source tree
  2. build with kernel source tree and build with dkms aren't supported yet

Build was tested on Ubuntu 22.04 system

### Build out of kernel source tree
* Prerequisite: 5.19 (or later), kernel header and build packages on compiling machine. To install  
```
$ sudo apt-get install build-essential linux-headers-`uname -r`
```

* To compile the drivers:
```
$ cd usbio-drivers/drivers
$ make clean
$ make
```

* To install the drivers
```
$ sudo insmod usbio.ko
$ sudo insmod i2c-usbio.ko
$ sudo insmod gpio-usbio.ko
```

* To uninstall the drivers
```
$ sudo rmmod gpio-usbio
$ sudo rmmod i2c-usbio
$ sudo rmmod usbio
```
