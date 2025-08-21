/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Intel Corporation.
 *
 */

#ifndef _LINUX_USBIO_H_
#define _LINUX_USBIO_H_

#include <linux/auxiliary_bus.h>
#include <linux/i2c.h>
#include <linux/types.h>

#define auxiliary_get_usbio_client(auxdev) \
		container_of(auxdev, struct usbio_client, adev)

struct usbio_device;

/**
 * struct usbio_client - represents a usbio client
 *
 * @type: client type
 * @id: client id
 * @auxdev: auxiliary device object
 * @bridge: usbio bridge who service the client
 * @link: usbio bridge clients
 */
struct usbio_client {
	u8 type;
	u8 id;
	struct auxiliary_device adev;
	struct usbio_device *bridge;
	struct list_head link;
};

/***********************
 * USBIO Clients Names *
 ***********************/
#define USBIO_GPIO_CLIENT	"usbio-gpio"
#define USBIO_I2C_CLIENT	"usbio-i2c"

/**************************
 * USBIO Type Definitions *
 **************************/

/* 0-2 Reserved/NA */
#define USBIO_GPIO	3
#define USBIO_I2C	4

/* USBIO GPIO commands */
enum usbio_gpio_cmd {
	USBIO_GPIOCMD_DEINIT,
	USBIO_GPIOCMD_INIT,
	USBIO_GPIOCMD_READ,
	USBIO_GPIOCMD_WRITE,
	USBIO_GPIOCMD_END
};

static inline bool usbio_gpiocmd_valid(u8 cmd)
{
	return cmd >= USBIO_GPIOCMD_DEINIT && cmd < USBIO_GPIOCMD_END;
}

/* USBIO GPIO config */
enum usbio_gpio_pincfg {
	USBIO_GPIO_PINCFG_DEFAULT,
	USBIO_GPIO_PINCFG_PULLUP,
	USBIO_GPIO_PINCFG_PULLDOWN,
	USBIO_GPIO_PINCFG_PUSHPULL
};

#define USBIO_GPIO_PINCFG_SHIFT 2
#define USBIO_GPIO_PINCFG_MASK (0x3 << USBIO_GPIO_PINCFG_SHIFT)
#define USBIO_GPIO_SET_PINCFG(pin) \
	(((pin) << USBIO_GPIO_PINCFG_SHIFT) & USBIO_GPIO_PINCFG_MASK)

enum usbio_gpio_pinmode {
	USBIO_GPIO_PINMOD_INVAL,
	USBIO_GPIO_PINMOD_INPUT,
	USBIO_GPIO_PINMOD_OUTPUT,
	USBIO_GPIO_PINMOD_MAXVAL
};

#define USBIO_GPIO_PINMOD_MASK 0x3
#define USBIO_GPIO_SET_PINMOD(pin) ((pin) & USBIO_GPIO_PINMOD_MASK)

/*************************
 * USBIO GPIO Controller *
 *************************/

#define USBIO_MAX_GPIOBANKS	5
#define USBIO_GPIOSPERBANK	32

struct usbio_gpio_bank {
	u8 config[USBIO_GPIOSPERBANK];
	u32 bitmap;
};

struct usbio_gpio_chip {
	int nbanks;
	struct usbio_gpio_bank banks[] __counted_by(nbanks);
};

struct usbio_gpio_init {
	u8 bankid;
	u8 config;
	u8 pincount;
	u8 pin;
} __packed;

struct usbio_gpio_rw {
	u8 bankid;
	u8 pincount;
	u8 pin;
	u32 value;
} __packed;

/* USBIO I2C commands */
enum usbio_i2c_cmd {
	USBIO_I2CCMD_UNINIT,
	USBIO_I2CCMD_INIT,
	USBIO_I2CCMD_READ,
	USBIO_I2CCMD_WRITE,
	USBIO_I2CCMD_END
};

static inline bool usbio_i2ccmd_valid(u8 cmd)
{
	return cmd >= USBIO_I2CCMD_UNINIT && cmd < USBIO_I2CCMD_END;
}

/************************
 * USBIO I2C Controller *
 ************************/

#define USBIO_MAX_I2CBUSES 5

struct usbio_i2c_bus {
	u8 id;
	u32 speed;
	const struct i2c_adapter_quirks *quirks;
} __packed;

struct usbio_i2c_uninit {
	u8 busid;
	u16 config;
} __packed;

struct usbio_i2c_init {
	u8 busid;
	u16 config;
	u32 speed;
} __packed;

struct usbio_i2c_rw {
	u8 busid;
	u16 config;
	u16 size;
	u8 data[] __counted_by(size);
} __packed;

void usbio_client_acpi_bind(struct auxiliary_device *adev,
			    const struct acpi_device_id *hids);

int usbio_transfer(struct usbio_client *client, u8 cmd,
		   const void *obuf, u16 obuf_len, void *ibuf, u16 ibuf_len);

#endif
