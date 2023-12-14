// SPDX-License-Identifier: GPL-2.0-only

/*
 * Intel USBIO-Bridge driver
 *
 * Copyright (c) 2023, Intel Corporation.
 */

#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/mfd/core.h>
#include <linux/mfd/usbio.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/version.h>

#include "bridge.h"


#define USBIO_VERSION "1.1"

static char *gpio_hids[] = {
	"INTC1074", /* TGL */
	"INTC1096", /* ADL */
	"INTC100B", /* RPL */
	"INTC10D1", /* MTL */
};
static struct mfd_cell_acpi_match usbio_acpi_match_gpio;

static char *i2c_hids[] = {
	"INTC1075", /* TGL */
	"INTC1097", /* ADL */
	"INTC100C", /* RPL */
	"INTC10D2", /* MTL */
};
static struct mfd_cell_acpi_match usbio_acpi_match_i2cs;

static char *spi_hids[] = {
	"INTC1091", /* TGL */
	"INTC1098", /* ADL */
	"INTC100D", /* RPL */
	"INTC10D3", /* MTL */
};
static struct mfd_cell_acpi_match usbio_acpi_match_spis;

static int try_match_acpi_hid(struct acpi_device *child,
			      struct mfd_cell_acpi_match *match, char **hids,
			      int hids_num)
{
	struct acpi_device_id ids[2] = {};
	int i;

	for (i = 0; i < hids_num; i++) {
		strlcpy(ids[0].id, hids[i], sizeof(ids[0].id));
		if (!acpi_match_device_ids(child, ids)) {
			match->pnpid = hids[i];
			break;
		}
	}

	return 0;
}

static int match_device_ids(struct acpi_device *adev, void *data)
{
	(void)data;
	try_match_acpi_hid(adev, &usbio_acpi_match_gpio, gpio_hids,
			   ARRAY_SIZE(gpio_hids));
	try_match_acpi_hid(adev, &usbio_acpi_match_i2cs, i2c_hids,
			   ARRAY_SIZE(i2c_hids));
	try_match_acpi_hid(adev, &usbio_acpi_match_spis, spi_hids,
			   ARRAY_SIZE(spi_hids));

	return 0;
}

static int precheck_acpi_hid(struct usb_interface *intf)
{
	struct acpi_device *parent;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
	struct acpi_device *child;
#endif

	parent = ACPI_COMPANION(&intf->dev);
	if (!parent)
		return -ENODEV;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	acpi_dev_for_each_child(parent, match_device_ids, NULL);
#else
	list_for_each_entry (child, &parent->children, node) {
		match_device_ids(child, NULL);
	}
#endif

	return 0;
}

static bool usbio_validate(void *data, u32 data_len)
{
	struct usbio_bmsg *header = (struct usbio_bmsg *)data;

	return (header->len + sizeof(*header) == data_len);
}

void usbio_dump(struct usbio_dev *bridge, void *buf, int len)
{
	int i;
	u8 tmp[256] = { 0 };
	int n = 0;

	if (!len)
		return;

	for (i = 0; i < len; i++)
		n += scnprintf(tmp + n, sizeof(tmp) - n - 1, "%02x ",
			       ((u8 *)buf)[i]);

	dev_dbg(&bridge->intf->dev, "%s\n", tmp);
}

static struct usbio_stub *usbio_stub_alloc(struct usbio_dev *bridge, int priv_size)
{
	struct usbio_stub *stub;

	stub = kzalloc(sizeof(*stub) + priv_size, GFP_KERNEL);
	if (!stub)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&stub->event_cb_lock);
	INIT_LIST_HEAD(&stub->list);
	list_add_tail(&stub->list, &bridge->stubs_list);
	dev_dbg(&bridge->intf->dev, "enuming a stub success\n");
	return stub;
}

static struct usbio_stub *usbio_stub_find(struct usbio_dev *bridge, u8 type)
{
	struct usbio_stub *stub;

	list_for_each_entry (stub, &bridge->stubs_list, list) {
		if (stub->type == type)
			return stub;
	}

	dev_err(&bridge->intf->dev, "usb stub not find, type: %d", type);
	return ERR_PTR(-ENODEV);
}

static void usbio_stub_notify(struct usbio_stub *stub, u8 cmd,
			     const void *evt_data, int len)
{
	unsigned long flags;
	spin_lock_irqsave(&stub->event_cb_lock, flags);
	if (stub->event_entry.notify && stub->event_entry.pdev)
		stub->event_entry.notify(stub->event_entry.pdev, cmd, evt_data,
					 len);
	spin_unlock_irqrestore(&stub->event_cb_lock, flags);
}

static int usbio_parse(struct usbio_dev *bridge, struct usbio_bmsg *header)
{
	struct usbio_stub *stub;

	stub = usbio_stub_find(bridge, header->type);
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	if (!(header->flags & RESP_FLAG)) {
		usbio_stub_notify(stub, header->cmd, header->data, header->len);
		return 0;
	}
	if (stub->cur_cmd != header->cmd) {
		dev_err(&bridge->intf->dev, "header->cmd:%x != stub->cur_cmd:%x",
			header->cmd, stub->cur_cmd);
		return -EINVAL;
	}
	if (header->flags & ERR_FLAG) {
		dev_err(&bridge->intf->dev, "header->cmd %x flag %x (ERR_FLAG)",
			 header->cmd, header->flags);
		return -EINVAL;
	}

	stub->ipacket.ibuf_len = header->len;
	if (stub->ipacket.ibuf)
		memcpy(stub->ipacket.ibuf, header->data, header->len);

	stub->acked = true;
	wake_up(&bridge->ack_wq);

	return 0;
}

static int usbio_control_xfer(struct usbio_stub *stub, u8 cmd, const void *obuf,
			int obuf_len, void *ibuf, int *ibuf_len,
			bool wait_ack, int timeout)
{
	struct usbio_msg *header;
	struct usbio_dev *bridge = usb_get_intfdata(stub->intf);
	int actual, ret;
	u8 flags = CMPL_FLAG;

	if (bridge->state == BRIDGE_STOPPED)
		return -ENODEV;

	if (obuf_len > bridge->cbuf_len)
		return -EINVAL;

	if (wait_ack)
		flags |= ACK_FLAG;

	stub->ipacket.ibuf_len = 0;
	actual = sizeof(header) + obuf_len;
	header = kmalloc(actual, GFP_KERNEL);
	if (!header)
		return -ENOMEM;

	header->type = stub->type;
	header->cmd = cmd;
	header->flags = flags;
	header->len = obuf_len;

	memcpy(header->data, obuf, obuf_len);
	dev_dbg(&bridge->intf->dev,
			"send: type:0x%x cmd:0x%x flags:0x%x len:%d\n",
			header->type, header->cmd, header->flags, header->len);
	usbio_dump(bridge, header->data, header->len);

	mutex_lock(&bridge->mutex);
	stub->cur_cmd = cmd;
	stub->ipacket.ibuf = ibuf;
	stub->acked = false;
	usb_autopm_get_interface(bridge->intf);
	ret = usb_control_msg_send(bridge->udev, bridge->ep0, 0,
			USB_TYPE_VENDOR | USB_RECIP_DEVICE | USB_DIR_OUT, 0, 0,
			header, actual, timeout, GFP_KERNEL);
	if (ret) {
		dev_err(&bridge->intf->dev,
			"bridge write failed ret:%d total_len:%d\n ", ret,
			actual);
		goto error;
	}

	kfree(header);
	header = NULL;
	if (wait_ack) {
		actual = bridge->cbuf_len;
		header = kmalloc(actual, GFP_KERNEL);
		if (!header) {
			ret = -ENOMEM;
			goto error;
		}

		ret = usb_control_msg_recv(bridge->udev, bridge->ep0, 0,
			USB_TYPE_VENDOR | USB_RECIP_DEVICE | USB_DIR_IN, 0, 0,
			header, actual, timeout, GFP_KERNEL);
		if (ret) {
			dev_err(&bridge->intf->dev,
				"bridge read failed ret:%d total_len:%d\n ",
				ret, actual);
			goto error;
		}
	}

	if (ibuf_len && header) {
		*ibuf_len = header->len;
		memcpy(ibuf, header->data, *ibuf_len);
	}

	stub->ipacket.ibuf = NULL;
	stub->ipacket.ibuf_len = 0;
error:
	if(header) {
		kfree(header);
		header = NULL;
	}

	usb_autopm_put_interface(bridge->intf);
	mutex_unlock(&bridge->mutex);
	return ret;
}

static int usbio_bulk_write(struct usbio_stub *stub, u8 cmd, const void *obuf,
			   int obuf_len, void *ibuf, int *ibuf_len,
			   bool wait_ack, int timeout)
{
	struct usbio_bmsg *header;
	struct usbio_dev *bridge = usb_get_intfdata(stub->intf);
	int ret;
	u8 flags = CMPL_FLAG;
	int actual;

	if (bridge->state == BRIDGE_STOPPED)
		return -ENODEV;

	if (obuf_len > MAX_PAYLOAD_SIZE)
		return -EINVAL;

	if (wait_ack)
		flags |= ACK_FLAG;

	stub->ipacket.ibuf_len = 0;
	header = kmalloc(sizeof(*header) + obuf_len, GFP_KERNEL);
	if (!header)
		return -ENOMEM;

	header->type = stub->type;
	header->cmd = cmd;
	header->flags = flags;
	header->len = obuf_len;

	memcpy(header->data, obuf, obuf_len);
	dev_dbg(&bridge->intf->dev, "send: type:0x%x cmd:0x%x flags:0x%x len:%d\n",
		header->type, header->cmd, header->flags, header->len);
	usbio_dump(bridge, header->data, header->len);

	mutex_lock(&bridge->mutex);
	stub->cur_cmd = cmd;
	stub->ipacket.ibuf = ibuf;
	stub->acked = false;
	usb_autopm_get_interface(bridge->intf);
	ret = usb_bulk_msg(bridge->udev,
			   usb_sndbulkpipe(bridge->udev, bridge->out_ep), header,
			   sizeof(*header) + obuf_len, &actual,
			   USB_WRITE_TIMEOUT);
	kfree(header);
	if (ret || actual != sizeof(*header) + obuf_len) {
		dev_err(&bridge->intf->dev,
			"bridge write failed ret:%d total_len:%d\n ", ret,
			actual);
		goto error;
	}

	if (wait_ack) {
		ret = wait_event_timeout(bridge->ack_wq, stub->acked,
					 msecs_to_jiffies(timeout));
		if (!ret || !stub->acked) {
			dev_err(&bridge->intf->dev,
				"acked wait timed out ret:%d timeout:%d ack:%d\n",
				ret, timeout, stub->acked);
			ret = -ETIMEDOUT;
			goto error;
		}
	}

	if (ibuf_len)
		*ibuf_len = stub->ipacket.ibuf_len;

	stub->ipacket.ibuf = NULL;
	stub->ipacket.ibuf_len = 0;
	ret = 0;
error:
	usb_autopm_put_interface(bridge->intf);
	mutex_unlock(&bridge->mutex);
	return ret;
}

static int usbio_transfer_internal(struct platform_device *pdev, u8 cmd,
				  const void *obuf, int obuf_len, void *ibuf,
				  int *ibuf_len, bool wait_ack)
{
	struct usbio_platform_data *usbio_pdata;
	struct usbio_dev *bridge;
	struct usbio_stub *stub;

	if (!pdev)
		return -EINVAL;

	bridge = dev_get_drvdata(pdev->dev.parent);
	usbio_pdata = dev_get_platdata(&pdev->dev);
	stub = usbio_stub_find(bridge, usbio_pdata->type);
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	if (stub->type <= GPIO_STUB)
		return usbio_control_xfer(stub, cmd, obuf, obuf_len,
			ibuf, ibuf_len,	wait_ack, USB_WRITE_ACK_TIMEOUT);
	else
		return usbio_bulk_write(stub, cmd, obuf, obuf_len,
			ibuf, ibuf_len,	wait_ack, USB_WRITE_ACK_TIMEOUT);
	}

int usbio_transfer(struct platform_device *pdev, u8 cmd, const void *obuf,
		  int obuf_len, void *ibuf, int *ibuf_len)
{
	return usbio_transfer_internal(pdev, cmd, obuf, obuf_len, ibuf, ibuf_len,
				      true);
}
EXPORT_SYMBOL_GPL(usbio_transfer);

int usbio_transfer_noack(struct platform_device *pdev, u8 cmd, const void *obuf,
			int obuf_len)
{
	return usbio_transfer_internal(pdev, cmd, obuf, obuf_len, NULL, NULL,
				      false);
}
EXPORT_SYMBOL_GPL(usbio_transfer_noack);

int usbio_register_event_cb(struct platform_device *pdev,
			   usbio_event_cb_t event_cb)
{
	struct usbio_platform_data *usbio_pdata;
	struct usbio_dev *bridge;
	struct usbio_stub *stub;
	unsigned long flags;

	if (!pdev)
		return -EINVAL;

	bridge = dev_get_drvdata(pdev->dev.parent);
	usbio_pdata = dev_get_platdata(&pdev->dev);
	stub = usbio_stub_find(bridge, usbio_pdata->type);
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	spin_lock_irqsave(&stub->event_cb_lock, flags);
	stub->event_entry.notify = event_cb;
	stub->event_entry.pdev = pdev;
	spin_unlock_irqrestore(&stub->event_cb_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(usbio_register_event_cb);

void usbio_unregister_event_cb(struct platform_device *pdev)
{
	struct usbio_platform_data *usbio_pdata;
	struct usbio_dev *bridge;
	struct usbio_stub *stub;
	unsigned long flags;

	bridge = dev_get_drvdata(pdev->dev.parent);
	usbio_pdata = dev_get_platdata(&pdev->dev);
	stub = usbio_stub_find(bridge, usbio_pdata->type);
	if (IS_ERR(stub))
		return;

	spin_lock_irqsave(&stub->event_cb_lock, flags);
	stub->event_entry.notify = NULL;
	stub->event_entry.pdev = NULL;
	spin_unlock_irqrestore(&stub->event_cb_lock, flags);
}
EXPORT_SYMBOL_GPL(usbio_unregister_event_cb);

static void usbio_stub_cleanup(struct usbio_dev *bridge)
{
	struct usbio_stub *stub;
	struct usbio_stub *next;

	list_for_each_entry_safe (stub, next, &bridge->stubs_list, list) {
		list_del_init(&stub->list);
		kfree(stub);
	}
}

static void usbio_read_complete(struct urb *urb)
{
	struct usbio_dev *bridge = urb->context;
	struct usbio_bmsg *header = urb->transfer_buffer;
	int len = urb->actual_length;
	int ret;

	dev_dbg(&bridge->intf->dev,
		"bulk read urb got message from fw, status:%d data_len:%d\n",
		urb->status, urb->actual_length);

	BUG_ON(!bridge);
	BUG_ON(!header);

	if (urb->status) {
		/* sync/async unlink faults aren't errors */
		if (urb->status == -ENOENT || urb->status == -ECONNRESET ||
		    urb->status == -ESHUTDOWN)
			return;

		dev_err(&bridge->intf->dev, "read bulk urb transfer failed: %d\n",
			urb->status);
		goto resubmit;
	}

	dev_dbg(&bridge->intf->dev, "receive: type:%d cmd:%d flags:%d len:%d\n",
		header->type, header->cmd, header->flags, header->len);
	usbio_dump(bridge, header->data, header->len);

	if (!usbio_validate(header, len)) {
		dev_err(&bridge->intf->dev,
			"data not correct header->len:%d payload_len:%d\n ",
			header->len, len);
		goto resubmit;
	}

	ret = usbio_parse(bridge, header);
	if (ret)
		dev_err(&bridge->intf->dev,
			"failed to parse data: ret:%d type:%d len: %d", ret,
			header->type, header->len);

resubmit:
	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (ret)
		dev_err(&bridge->intf->dev,
			"failed submitting read urb, error %d\n", ret);
}

static int usbio_start(struct usbio_dev *bridge)
{
	int ret;

	usb_fill_bulk_urb(bridge->in_urb, bridge->udev,
			  usb_rcvbulkpipe(bridge->udev, bridge->in_ep), bridge->ibuf,
			  bridge->ibuf_len, usbio_read_complete, bridge);

	ret = usb_submit_urb(bridge->in_urb, GFP_KERNEL);
	if (ret) {
		dev_err(&bridge->intf->dev,
			"failed submitting read urb, error %d\n", ret);
	}
	return ret;
}

struct usbio_mng_priv {
	long reset_id;
};

static int usbio_mng_reset_handshake(struct usbio_stub *stub)
{
	int ret;
	int ilen;

	ret = usbio_control_xfer(stub, CTRL_RESET_NOTIFY, 0, 0, 0,
			&ilen, true, USB_WRITE_ACK_TIMEOUT);
	if (ret) {
		dev_err(&stub->intf->dev,
			"CTRL_RESET_NOTIFY failed ret:%d\n", ret);
		return -EIO;
	}

	return 0;
}

static inline int usbio_mng_reset(struct usbio_stub *stub)
{
	return usbio_control_xfer(stub, CTRL_RESET, NULL, 0, NULL, NULL, true,
			       USB_WRITE_ACK_TIMEOUT);
}

static int usbio_add_mfd_cell(struct usbio_dev *bridge, struct mfd_cell *cell)
{
	struct mfd_cell *new_cells;

	/* Enumerate the device even if it does not appear in DSDT */
	if (!cell->acpi_match->pnpid)
		dev_warn(&bridge->intf->dev,
			 "The HID of cell %s does not exist in DSDT\n",
			 cell->name);

	new_cells = krealloc_array(bridge->cells, (bridge->cell_count + 1),
				   sizeof(struct mfd_cell), GFP_KERNEL);
	if (!new_cells)
		return -ENOMEM;

	memcpy(&new_cells[bridge->cell_count], cell, sizeof(*cell));
	bridge->cells = new_cells;
	bridge->cell_count++;

	return 0;
}

static int usbio_gpio_stub_init(struct usbio_dev *bridge,
			       struct usbio_gpio_descriptor *desc)
{
	struct usbio_stub *stub;
	struct mfd_cell cell = { 0 };
	struct usbio_platform_data *pdata;
	int gpio_num = desc->pins_per_bank * desc->banks;
	int i;
	u32 valid_pin[MAX_GPIO_NUM / (sizeof(u32) * BITS_PER_BYTE)];

	if (gpio_num > MAX_GPIO_NUM)
		return -EINVAL;

	stub = usbio_stub_alloc(bridge, sizeof(*pdata));
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	stub->type = GPIO_STUB;
	stub->intf = bridge->intf;

	pdata = usbio_priv(stub);
	pdata->type = stub->type;
	pdata->gpio_info.num = gpio_num;

	for (i = 0; i < desc->banks; i++) {
		valid_pin[i] = desc->bank_desc[i].valid_pins;
		dev_info(&bridge->intf->dev, "bank:%d map:0x%08x\n", i, valid_pin[i]);
	}

	bitmap_from_arr32(pdata->gpio_info.valid_pin_map, valid_pin, gpio_num);

	cell.name = "usbio-gpio";
	cell.platform_data = pdata;
	cell.pdata_size = sizeof(*pdata);
	cell.acpi_match = &usbio_acpi_match_gpio;

	return usbio_add_mfd_cell(bridge, &cell);
}

static int usbio_mng_enum_gpio(struct usbio_stub *stub)
{
	struct usbio_dev *bridge = usb_get_intfdata(stub->intf);
	struct usbio_gpio_descriptor *desc;
	int ret;
	int len;

	desc = kzalloc(MAX_PAYLOAD_SIZE, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	ret = usbio_control_xfer(stub, CTRL_ENUM_GPIO, NULL, 0, desc->bank_desc, &len, true,
			      USB_ENUM_STUB_TIMEOUT);
	if (ret || !len || (len % sizeof(*desc->bank_desc))) {
		dev_err(&stub->intf->dev,
			"enum gpio failed ret:%d len:%d bank_desc:%ld\n", ret,
			len, sizeof(*desc->bank_desc));
		kfree(desc);
		return -EIO;
	}

	desc->pins_per_bank = GPIO_PER_BANK;
	desc->banks = len / sizeof(*desc->bank_desc);
	ret = usbio_gpio_stub_init(bridge, desc);
	kfree(desc);
	if (ret)
		dev_err(&stub->intf->dev, "enum gpio failed ret:%d\n", ret);
	return ret;
}

static int usbio_i2c_stub_init(struct usbio_dev *bridge,
			      struct usbio_i2c_descriptor *desc)
{
	struct usbio_stub *stub;
	struct usbio_platform_data *pdata;
	int i;
	int ret;

	stub = usbio_stub_alloc(bridge, desc->num * sizeof(*pdata));
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	stub->type = I2C_STUB;
	stub->intf = bridge->intf;
	pdata = usbio_priv(stub);

	for (i = 0; i < desc->num; i++) {
		struct mfd_cell cell = { 0 };
		pdata[i].type = stub->type;

		pdata[i].i2c_info.id = desc->info[i].id;
		pdata[i].i2c_info.capacity = desc->info[i].capacity;

		cell.name = "usbio-i2c";
		cell.platform_data = &pdata[i];
		cell.pdata_size = sizeof(pdata[i]);
		cell.acpi_match = &usbio_acpi_match_i2cs;

		ret = usbio_add_mfd_cell(bridge, &cell);
		if (ret)
			return ret;
	}

	return 0;
}

static int usbio_mng_enum_i2c(struct usbio_stub *stub)
{
	struct usbio_dev *bridge = usb_get_intfdata(stub->intf);
	struct usbio_i2c_descriptor *desc;
	int ret;
	int len;

	desc = kzalloc(MAX_PAYLOAD_SIZE, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	ret = usbio_control_xfer(stub, CTRL_ENUM_I2C, NULL, 0, desc->info, &len, true,
			      USB_ENUM_STUB_TIMEOUT);
	if (ret || !len || (len % sizeof(*desc->info))) {
		dev_err(&stub->intf->dev,
			"CTRL_ENUM_I2C failed ret:%d len:%d num:%d\n", ret, len,
			desc->num);
		kfree(desc);
		return -EIO;
	}

	desc->num = len / sizeof(*desc->info);
	ret = usbio_i2c_stub_init(bridge, desc);
	kfree(desc);
	return ret;
}

static int usbio_spi_stub_init(struct usbio_dev *bridge,
			      struct usbio_spi_descriptor *desc)
{
	struct usbio_stub *stub;
	struct usbio_platform_data *pdata;
	int i;
	int ret;

	stub = usbio_stub_alloc(bridge, desc->num * sizeof(*pdata));
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	stub->type = SPI_STUB;
	stub->intf = bridge->intf;
	pdata = usbio_priv(stub);

	for (i = 0; i < desc->num; i++) {
		struct mfd_cell cell = { 0 };
		pdata[i].type = stub->type;

		pdata[i].spi_info.id = desc->info[i].id;
		pdata[i].spi_info.capacity = desc->info[i].capacity;

		cell.name = "usbio-spi";
		cell.platform_data = &pdata[i];
		cell.pdata_size = sizeof(pdata[i]);
		cell.acpi_match = &usbio_acpi_match_spis;

		ret = usbio_add_mfd_cell(bridge, &cell);
		if (ret)
			return ret;
	}

	return 0;
}

static int usbio_mng_enum_spi(struct usbio_stub *stub)
{
	struct usbio_dev *bridge = usb_get_intfdata(stub->intf);
	struct usbio_spi_descriptor *desc;
	int ret;
	int len;

	desc = kzalloc(MAX_PAYLOAD_SIZE, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	ret = usbio_control_xfer(stub, CTRL_ENUM_SPI, NULL, 0, desc, &len, true,
			      USB_ENUM_STUB_TIMEOUT);
	if (ret) {
		dev_err(&stub->intf->dev,
			"CTRL_ENUM_SPI failed ret:%d len:%d num:%d\n", ret, len,
			desc->num);
		kfree(desc);
		return -EIO;
	}

	ret = usbio_spi_stub_init(bridge, desc);
	kfree(desc);
	return ret;
}

static int usbio_mng_get_version(struct usbio_stub *stub, char *buf)
{
	struct fw_version version = { 0 };
	int ret;
	int len;

	if (!buf)
		return -EINVAL;

	ret = usbio_control_xfer(stub, CTRL_FW_VERSION, NULL, 0, &version, &len,
			      true, USB_WRITE_ACK_TIMEOUT);
	if (ret || len < sizeof(struct fw_version)) {
		dev_err(&stub->intf->dev,
			"CTRL_GET_VERSION failed ret:%d len:%d\n", ret, len);
		return ret;
	}

	return sysfs_emit(buf, "%d.%d.%d.%d\n", version.major, version.minor,
			  le16_to_cpu(version.patch),
			  le16_to_cpu(version.build));
}

static inline int usbio_mng_set_dfu_mode(struct usbio_stub *stub)
{
	return usbio_control_xfer(stub, CTRL_SET_DFU_MODE, NULL, 0, NULL, NULL,
			       true, USB_WRITE_ACK_TIMEOUT);
}

static int usbio_mng_link(struct usbio_dev *bridge, struct usbio_stub *stub)
{
	int ret;

	ret = usbio_mng_reset_handshake(stub);
	if (ret)
		return ret;

	bridge->state = BRIDGE_RESET_SYNCED;

	/* workaround for FW limitation, ignore return value of enum result */
	usbio_mng_enum_gpio(stub);
	bridge->state = BRIDGE_ENUM_GPIO_COMPLETE;

	usbio_mng_enum_i2c(stub);
	bridge->state = BRIDGE_ENUM_I2C_COMPLETE;

	usbio_mng_enum_spi(stub);
	bridge->state = BRIDGE_ENUM_SPI_COMPLETE;

	return 0;
}

static int usbio_mng_init(struct usbio_dev *bridge)
{
	struct usbio_stub *stub;
	struct usbio_mng_priv *priv;
	int ret;

	stub = usbio_stub_alloc(bridge, sizeof(*priv));
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	priv = usbio_priv(stub);
	if (!priv)
		return -ENOMEM;

	priv->reset_id = 0;
	stub->type = CTRL_STUB;
	stub->intf = bridge->intf;

	ret = usbio_mng_link(bridge, stub);
	if (ret)
		dev_err(&bridge->intf->dev,
			"mng stub link done ret:%d state:%d\n", ret,
			bridge->state);

	return ret;
}

static inline int usbio_diag_get_fw_log(struct usbio_stub *stub, void *buf)
{
	int ret;
	int len;

	if (!buf)
		return -EINVAL;

	ret = usbio_control_xfer(stub, DIAG_GET_FW_LOG, NULL, 0, buf, &len, true,
			      USB_WRITE_ACK_TIMEOUT);
	if (ret)
		return ret;

	return len;
}

static inline int usbio_diag_get_coredump(struct usbio_stub *stub, void *buf)
{
	int ret;
	int len;

	if (!buf)
		return -EINVAL;

	ret = usbio_control_xfer(stub, DIAG_GET_FW_COREDUMP, NULL, 0, buf, &len,
			      true, USB_WRITE_ACK_TIMEOUT);
	if (ret)
		return ret;

	return len;
}

static inline int usbio_diag_set_trace_level(struct usbio_stub *stub, u8 level)
{
	return usbio_control_xfer(stub, DIAG_SET_TRACE_LEVEL, &level,
			       sizeof(level), NULL, NULL, true,
			       USB_WRITE_ACK_TIMEOUT);
}

static int usbio_diag_init(struct usbio_dev *bridge)
{
	struct usbio_stub *stub;

	stub = usbio_stub_alloc(bridge, 0);
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	stub->type = DIAG_STUB;
	stub->intf = bridge->intf;
	return 0;
}

static void usbio_delete(struct usbio_dev *bridge)
{
	mutex_destroy(&bridge->mutex);
	usb_free_urb(bridge->in_urb);
	usb_put_intf(bridge->intf);
	usb_put_dev(bridge->udev);
	kfree(bridge->ibuf);
	kfree(bridge->cells);
	kfree(bridge);
}

static int usbio_init(struct usbio_dev *bridge)
{
	mutex_init(&bridge->mutex);
	init_waitqueue_head(&bridge->ack_wq);
	INIT_LIST_HEAD(&bridge->stubs_list);

	bridge->state = BRIDGE_INITED;

	return 0;
}

static void usbio_stop(struct usbio_dev *bridge)
{
	usb_kill_urb(bridge->in_urb);
}

static ssize_t cmd_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct usbio_dev *bridge = usb_get_intfdata(intf);
	struct usbio_stub *mng_stub = usbio_stub_find(bridge, CTRL_STUB);
	struct usbio_stub *diag_stub = usbio_stub_find(bridge, DIAG_STUB);

	if (sysfs_streq(buf, "dfu"))
		usbio_mng_set_dfu_mode(mng_stub);
	else if (sysfs_streq(buf, "reset"))
		usbio_mng_reset(mng_stub);
	else if (sysfs_streq(buf, "debug"))
		usbio_diag_set_trace_level(diag_stub, 3);

	return count;
}

static ssize_t cmd_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	return sysfs_emit(buf, "%s\n", "supported cmd: [reset, debug]");
}
static DEVICE_ATTR_RW(cmd);

static ssize_t version_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct usbio_dev *bridge = usb_get_intfdata(intf);
	struct usbio_stub *stub = usbio_stub_find(bridge, CTRL_STUB);

	return usbio_mng_get_version(stub, buf);
}
static DEVICE_ATTR_RO(version);

static ssize_t log_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct usbio_dev *bridge = usb_get_intfdata(intf);
	struct usbio_stub *diag_stub = usbio_stub_find(bridge, DIAG_STUB);
	memcpy(buf, "USBIO log: TBD\n", 15);

	return usbio_diag_get_fw_log(diag_stub, buf);
}
static DEVICE_ATTR_RO(log);

static ssize_t coredump_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct usbio_dev *bridge = usb_get_intfdata(intf);
	struct usbio_stub *diag_stub = usbio_stub_find(bridge, DIAG_STUB);

	return usbio_diag_get_coredump(diag_stub, buf);
}
static DEVICE_ATTR_RO(coredump);

static struct attribute *usbio_attrs[] = {
	&dev_attr_version.attr,
	&dev_attr_cmd.attr,
	&dev_attr_log.attr,
	&dev_attr_coredump.attr,
	NULL,
};
ATTRIBUTE_GROUPS(usbio);

static int usbio_probe(struct usb_interface *intf,
		      const struct usb_device_id *id)
{
	struct usbio_dev *bridge;
	struct usb_endpoint_descriptor *ep0, *bulk_in, *bulk_out;
	int ret;

	ret = precheck_acpi_hid(intf);
	if (ret)
		return ret;

	/* allocate memory for our device state and initialize it */
	bridge = kzalloc(sizeof(*bridge), GFP_KERNEL);
	if (!bridge)
		return -ENOMEM;

	usbio_init(bridge);
	bridge->udev = usb_get_dev(interface_to_usbdev(intf));
	bridge->intf = usb_get_intf(intf);

	/* control transfer enpoint information */
	if (!&bridge->udev->ep0) {
		dev_err(&intf->dev,
			"Could not find control endpoint\n");
		goto error;
	}

	ep0 = &bridge->udev->ep0.desc;
	if (!ep0) {
		dev_err(&intf->dev,
			"Could not find control endpoint descriptor\n");
		goto error;
	}

	bridge->ep0 = ep0->bEndpointAddress;
	bridge->cbuf_len = usb_endpoint_maxp(ep0);
	bridge->cbuf = kzalloc(bridge->cbuf_len, GFP_KERNEL);
	if (!bridge->cbuf) {
		ret = -ENOMEM;
		goto error;
	}

	dev_dbg(&intf->dev, "ep0 addr:%d size:%u\n",
		bridge->ep0, bridge->cbuf_len);

	/* set up the endpoint information use only the first bulk-in and bulk-out endpoints */
	ret = usb_find_common_endpoints(intf->cur_altsetting, &bulk_in,
					&bulk_out, NULL, NULL);
	if (ret) {
		dev_err(&intf->dev,
			"Could not find both bulk-in and bulk-out endpoints\n");
		goto error;
	}

	bridge->in_ep = bulk_in->bEndpointAddress;
	bridge->ibuf_len = usb_endpoint_maxp(bulk_in);
	bridge->ibuf = kzalloc(bridge->ibuf_len, GFP_KERNEL);
	if (!bridge->ibuf) {
		ret = -ENOMEM;
		goto error;
	}

	bridge->in_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!bridge->in_urb) {
		ret = -ENOMEM;
		goto error;
	}

	bridge->out_ep = bulk_out->bEndpointAddress;
	dev_dbg(&intf->dev, "bulk_in addr:%d bulk_out addr:%d size:%u\n",
		bridge->in_ep, bridge->out_ep, bridge->ibuf_len);

	/* save our data pointer in this intf device */
	usb_set_intfdata(intf, bridge);
	ret = usbio_start(bridge);
	if (ret) {
		dev_err(&intf->dev, "bridge read start failed ret %d\n", ret);
		goto error;
	}

	ret = usbio_mng_init(bridge);
	if (ret) {
		dev_err(&intf->dev, "register mng stub failed ret %d\n", ret);
		goto error_stop;
	}

	ret = usbio_diag_init(bridge);
	if (ret) {
		dev_err(&intf->dev, "register diag stub failed ret %d\n", ret);
		goto error_stop;
	}

	ret = mfd_add_hotplug_devices(&intf->dev, bridge->cells,
				      bridge->cell_count);
	if (ret) {
		dev_err(&intf->dev, "failed to add mfd devices to core %d\n",
			bridge->cell_count);
		goto error_stop;
	}

	bridge->state = BRIDGE_STARTED;
	dev_info(&intf->dev, "USB Bridge device init success\n");
	return 0;
error_stop:
	usbio_stop(bridge);
error:
	dev_err(&intf->dev, "USB Bridge device init failed\n");
	/* this frees allocated memory */
	usbio_stub_cleanup(bridge);
	usbio_delete(bridge);
	return ret;
}

static void usbio_disconnect(struct usb_interface *intf)
{
	struct usbio_dev *bridge;

	bridge = usb_get_intfdata(intf);

	usbio_stop(bridge);
	bridge->state = BRIDGE_STOPPED;
	mfd_remove_devices(&intf->dev);
	usbio_stub_cleanup(bridge);
	usb_set_intfdata(intf, NULL);
	usbio_delete(bridge);
	dev_info(&intf->dev, "USB Bridge disconnected\n");
}

static int usbio_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct usbio_dev *bridge = usb_get_intfdata(intf);

	usbio_stop(bridge);
	bridge->state = BRIDGE_SUSPEND;

	dev_dbg(&intf->dev, "USB Bridge suspend\n");
	return 0;
}

static int usbio_resume(struct usb_interface *intf)
{
	struct usbio_dev *bridge = usb_get_intfdata(intf);

	bridge->state = BRIDGE_STARTED;
	dev_dbg(&intf->dev, "USB Bridge resume\n");
	return usbio_start(bridge);
}

static const struct usb_device_id usbio_table[] = {
	{USB_DEVICE(0x2AC1, 0x20C1)}, /* Lattice NX40 */
	{USB_DEVICE(0x2AC1, 0x20C9)}, /* Lattice NX33 */
	{USB_DEVICE(0x2AC1, 0x20CB)}, /* Lattice NX33U */
	{}
};
MODULE_DEVICE_TABLE(usb, usbio_table);

static struct usb_driver usbbridge_driver = {
	.name = "usbio-bridge",
	.probe = usbio_probe,
	.disconnect = usbio_disconnect,
	.suspend = usbio_suspend,
	.resume = usbio_resume,
	.id_table = usbio_table,
	.dev_groups = usbio_groups,
	.supports_autosuspend = 1,
};

module_usb_driver(usbbridge_driver);

MODULE_AUTHOR("Ye Xiang <xiang.ye@intel.com>");
MODULE_AUTHOR("Zhang Lixu <lixu.zhang@intel.com>");
MODULE_AUTHOR("Israel Cepeda <israel.a.cepeda.lopez@intel.com>");
MODULE_AUTHOR("Lifu Wang <lifu.wang@intel.com>");
MODULE_DESCRIPTION("Intel USBIO Bridge driver");
MODULE_VERSION(USBIO_VERSION);
MODULE_LICENSE("GPL v2");
