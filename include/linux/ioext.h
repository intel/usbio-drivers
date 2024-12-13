/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Intel Corporation.
 *
 */

#ifndef _IOEXT_H_
#define _IOEXT_H_

#include <linux/types.h>

/**************************
 * IOEXT Type Definitions *
 **************************/

/* 0-2 Reserved/NA */
#define IOEXT_GPIO	3
#define IOEXT_I2C	4
#define IOEXT_SPI	5

/* IOEXT GPIO commands */
enum ioext_gpio_cmd {
	IOEXT_GPIOCMD_DEINIT,
	IOEXT_GPIOCMD_INIT,
	IOEXT_GPIOCMD_READ,
	IOEXT_GPIOCMD_WRITE,
	IOEXT_GPIOCMD_END
};

#define IOEXT_GPIOCMD_VALID(cmd) (IOEXT_GPIOCMD_DEINIT <= cmd && \
			cmd < IOEXT_GPIOCMD_END)

/* IOEXT GPIO config */
enum ioext_gpio_pincfg {
	IOEXT_GPIO_PINCFG_DEFAULT,
	IOEXT_GPIO_PINCFG_PULLUP,
	IOEXT_GPIO_PINCFG_PULLDOWN,
	IOEXT_GPIO_PINCFG_PUSHPULL
};

#define IOEXT_GPIO_PINCFG_SHIFT 2
#define IOEXT_GPIO_PINCFG_MASK (0x3 << IOEXT_GPIO_PINCFG_SHIFT)
#define IOEXT_GPIO_SET_PINCFG(pin) \
	((pin & IOEXT_GPIO_PINCFG_MASK) << IOEXT_GPIO_PINCFG_SHIFT)

enum ioext_gpio_pinmode {
	IOEXT_GPIO_PINMOD_INVAL,
	IOEXT_GPIO_PINMOD_INPUT,
	IOEXT_GPIO_PINMOD_OUTPUT,
	IOEXT_GPIO_PINMOD_MAXVAL
};

#define IOEXT_GPIO_PINMOD_MASK 0x3
#define IOEXT_GPIO_SET_PINMOD(pin) (pin & IOEXT_GPIO_PINMOD_MASK)

/*************************
 * IOEXT GPIO Controller *
 *************************/

#define IOEXT_MAX_GPIOBANKS	5
#define IOEXT_GPIOSPERBANK	32

struct ioext_gpio_bank {
	u8 config[IOEXT_GPIOSPERBANK];
	u32 bitmap;
};

struct ioext_gpio_init {
	u8 bankid;
	u8 config;
	u8 pincount;
	u8 pin;
} __packed;

struct ioext_gpio_rw {
	u8 bankid;
	u8 pincount;
	u8 pin;
	u32 value;
} __packed;

int usbio_gpio_init(struct ioext_gpio_bank *banks, unsigned int len);

int usbio_transfer(u8 type, u8 cmd, const void *obuf,
		u16 obuf_len, void *ibuf, u16 ibuf_len);

#endif
