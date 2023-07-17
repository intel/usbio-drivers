/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LINUX_USB_IO_H
#define __LINUX_USB_IO_H

#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/types.h>

#define MAX_BANK_NUM 5
#define GPIO_PER_BANK 32
#define MAX_GPIO_NUM (MAX_BANK_NUM * GPIO_PER_BANK)

struct usbio_gpio_info {
	int num;
	DECLARE_BITMAP(valid_pin_map, MAX_GPIO_NUM);
};

struct usbio_i2c_info {
	u8 id;
	u8 capacity;
};

struct usbio_spi_info {
	u8 id;
	u8 capacity;
};

struct usbio_platform_data {
	int type;
	union {
		struct usbio_gpio_info gpio_info;
		struct usbio_i2c_info i2c_info;
		struct usbio_spi_info spi_info;
	};
};

typedef void (*usbio_event_cb_t)(struct platform_device *pdev, u8 cmd,
				const void *evt_data, int len);

int usbio_register_event_cb(struct platform_device *pdev,
			   usbio_event_cb_t event_cb);
void usbi_unregister_event_cb(struct platform_device *pdev);
int usbio_transfer(struct platform_device *pdev, u8 cmd, const void *obuf,
		  int obuf_len, void *ibuf, int *ibuf_len);
int usbio_transfer_noack(struct platform_device *pdev, u8 cmd, const void *obuf,
			int obuf_len);

#endif
