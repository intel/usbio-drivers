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
static struct mfd_cell_acpi_match usbio_acpi_match_i2cs[2];

static char *spi_hids[] = {
	"INTC1091", /* TGL */
	"INTC1098", /* ADL */
	"INTC100D", /* RPL */
	"INTC10D3", /* MTL */
};
static struct mfd_cell_acpi_match usbio_acpi_match_spis[1];

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
	try_match_acpi_hid(adev, &usbio_acpi_match_i2cs[0], i2c_hids,
			   ARRAY_SIZE(i2c_hids));
	try_match_acpi_hid(adev, &usbio_acpi_match_i2cs[1], i2c_hids,
			   ARRAY_SIZE(i2c_hids));
	try_match_acpi_hid(adev, &usbio_acpi_match_spis[0], spi_hids,
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
	struct usbio_msg *header = (struct usbio_msg *)data;

	return (header->len + sizeof(*header) == data_len);
}

void usbio_dump(struct usbio_dev *ljca, void *buf, int len)
{
	int i;
	u8 tmp[256] = { 0 };
	int n = 0;

	if (!len)
		return;

	for (i = 0; i < len; i++)
		n += scnprintf(tmp + n, sizeof(tmp) - n - 1, "%02x ",
			       ((u8 *)buf)[i]);

	dev_dbg(&ljca->intf->dev, "%s\n", tmp);
}

static struct usbio_stub *usbio_stub_alloc(struct usbio_dev *ljca, int priv_size)
{
	struct usbio_stub *stub;

	stub = kzalloc(sizeof(*stub) + priv_size, GFP_KERNEL);
	if (!stub)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&stub->event_cb_lock);
	INIT_LIST_HEAD(&stub->list);
	list_add_tail(&stub->list, &ljca->stubs_list);
	dev_dbg(&ljca->intf->dev, "enuming a stub success\n");
	return stub;
}

static struct usbio_stub *usbio_stub_find(struct usbio_dev *ljca, u8 type)
{
	struct usbio_stub *stub;

	list_for_each_entry (stub, &ljca->stubs_list, list) {
		if (stub->type == type)
			return stub;
	}

	dev_err(&ljca->intf->dev, "usb stub not find, type: %d", type);
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

static int usbio_parse(struct usbio_dev *ljca, struct usbio_msg *header)
{
	struct usbio_stub *stub;

	stub = usbio_stub_find(ljca, header->type);
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	if (!(header->flags & ACK_FLAG)) {
		usbio_stub_notify(stub, header->cmd, header->data, header->len);
		return 0;
	}

	if (stub->cur_cmd != header->cmd) {
		dev_err(&ljca->intf->dev, "header->cmd:%x != stub->cur_cmd:%x",
			header->cmd, stub->cur_cmd);
		return -EINVAL;
	}

	stub->ipacket.ibuf_len = header->len;
	if (stub->ipacket.ibuf)
		memcpy(stub->ipacket.ibuf, header->data, header->len);

	stub->acked = true;
	wake_up(&ljca->ack_wq);

	return 0;
}

static int usbio_stub_write(struct usbio_stub *stub, u8 cmd, const void *obuf,
			   int obuf_len, void *ibuf, int *ibuf_len,
			   bool wait_ack, int timeout)
{
	struct usbio_msg *header;
	struct usbio_dev *ljca = usb_get_intfdata(stub->intf);
	int ret;
	u8 flags = CMPL_FLAG;
	int actual;

	if (ljca->state == BRIDGE_STOPPED)
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
	dev_dbg(&ljca->intf->dev, "send: type:%d cmd:%d flags:%d len:%d\n",
		header->type, header->cmd, header->flags, header->len);
	usbio_dump(ljca, header->data, header->len);

	mutex_lock(&ljca->mutex);
	stub->cur_cmd = cmd;
	stub->ipacket.ibuf = ibuf;
	stub->acked = false;
	usb_autopm_get_interface(ljca->intf);
	ret = usb_bulk_msg(ljca->udev,
			   usb_sndbulkpipe(ljca->udev, ljca->out_ep), header,
			   sizeof(struct usbio_msg) + obuf_len, &actual,
			   USB_WRITE_TIMEOUT);
	kfree(header);
	if (ret || actual != sizeof(struct usbio_msg) + obuf_len) {
		dev_err(&ljca->intf->dev,
			"bridge write failed ret:%d total_len:%d\n ", ret,
			actual);
		goto error;
	}

	if (wait_ack) {
		ret = wait_event_timeout(ljca->ack_wq, stub->acked,
					 msecs_to_jiffies(timeout));
		if (!ret || !stub->acked) {
			dev_err(&ljca->intf->dev,
				"acked sem wait timed out ret:%d timeout:%d ack:%d\n",
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
	usb_autopm_put_interface(ljca->intf);
	mutex_unlock(&ljca->mutex);
	return ret;
}

static int usbio_transfer_internal(struct platform_device *pdev, u8 cmd,
				  const void *obuf, int obuf_len, void *ibuf,
				  int *ibuf_len, bool wait_ack)
{
	struct usbio_platform_data *usbio_pdata;
	struct usbio_dev *ljca;
	struct usbio_stub *stub;

	if (!pdev)
		return -EINVAL;

	ljca = dev_get_drvdata(pdev->dev.parent);
	usbio_pdata = dev_get_platdata(&pdev->dev);
	stub = usbio_stub_find(ljca, usbio_pdata->type);
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	return usbio_stub_write(stub, cmd, obuf, obuf_len, ibuf, ibuf_len,
			       wait_ack, USB_WRITE_ACK_TIMEOUT);
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
	struct usbio_dev *ljca;
	struct usbio_stub *stub;
	unsigned long flags;

	if (!pdev)
		return -EINVAL;

	ljca = dev_get_drvdata(pdev->dev.parent);
	usbio_pdata = dev_get_platdata(&pdev->dev);
	stub = usbio_stub_find(ljca, usbio_pdata->type);
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
	struct usbio_dev *ljca;
	struct usbio_stub *stub;
	unsigned long flags;

	ljca = dev_get_drvdata(pdev->dev.parent);
	usbio_pdata = dev_get_platdata(&pdev->dev);
	stub = usbio_stub_find(ljca, usbio_pdata->type);
	if (IS_ERR(stub))
		return;

	spin_lock_irqsave(&stub->event_cb_lock, flags);
	stub->event_entry.notify = NULL;
	stub->event_entry.pdev = NULL;
	spin_unlock_irqrestore(&stub->event_cb_lock, flags);
}
EXPORT_SYMBOL_GPL(usbio_unregister_event_cb);

static void usbio_stub_cleanup(struct usbio_dev *ljca)
{
	struct usbio_stub *stub;
	struct usbio_stub *next;

	list_for_each_entry_safe (stub, next, &ljca->stubs_list, list) {
		list_del_init(&stub->list);
		kfree(stub);
	}
}

static void usbio_read_complete(struct urb *urb)
{
	struct usbio_dev *ljca = urb->context;
	struct usbio_msg *header = urb->transfer_buffer;
	int len = urb->actual_length;
	int ret;

	dev_dbg(&ljca->intf->dev,
		"bulk read urb got message from fw, status:%d data_len:%d\n",
		urb->status, urb->actual_length);

	BUG_ON(!ljca);
	BUG_ON(!header);

	if (urb->status) {
		/* sync/async unlink faults aren't errors */
		if (urb->status == -ENOENT || urb->status == -ECONNRESET ||
		    urb->status == -ESHUTDOWN)
			return;

		dev_err(&ljca->intf->dev, "read bulk urb transfer failed: %d\n",
			urb->status);
		goto resubmit;
	}

	dev_dbg(&ljca->intf->dev, "receive: type:%d cmd:%d flags:%d len:%d\n",
		header->type, header->cmd, header->flags, header->len);
	usbio_dump(ljca, header->data, header->len);

	if (!usbio_validate(header, len)) {
		dev_err(&ljca->intf->dev,
			"data not correct header->len:%d payload_len:%d\n ",
			header->len, len);
		goto resubmit;
	}

	ret = usbio_parse(ljca, header);
	if (ret)
		dev_err(&ljca->intf->dev,
			"failed to parse data: ret:%d type:%d len: %d", ret,
			header->type, header->len);

resubmit:
	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (ret)
		dev_err(&ljca->intf->dev,
			"failed submitting read urb, error %d\n", ret);
}

static int usbio_start(struct usbio_dev *ljca)
{
	int ret;

	usb_fill_bulk_urb(ljca->in_urb, ljca->udev,
			  usb_rcvbulkpipe(ljca->udev, ljca->in_ep), ljca->ibuf,
			  ljca->ibuf_len, usbio_read_complete, ljca);

	ret = usb_submit_urb(ljca->in_urb, GFP_KERNEL);
	if (ret) {
		dev_err(&ljca->intf->dev,
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
	struct usbio_mng_priv *priv;
	__le32 reset_id;
	__le32 reset_id_ret = 0;
	int ilen;

	priv = usbio_priv(stub);
	reset_id = cpu_to_le32(priv->reset_id++);
	ret = usbio_stub_write(stub, CTRL_RESET_NOTIFY, &reset_id,
			      sizeof(reset_id), &reset_id_ret, &ilen, true,
			      USB_WRITE_ACK_TIMEOUT);
	if (ret || ilen != sizeof(reset_id_ret) || reset_id_ret != reset_id) {
		dev_err(&stub->intf->dev,
			"CTRL_RESET_NOTIFY failed reset_id:%d/%d ret:%d\n",
			le32_to_cpu(reset_id_ret), le32_to_cpu(reset_id), ret);
		return -EIO;
	}

	return 0;
}

static inline int usbio_mng_reset(struct usbio_stub *stub)
{
	return usbio_stub_write(stub, CTRL_RESET, NULL, 0, NULL, NULL, true,
			       USB_WRITE_ACK_TIMEOUT);
}

static int usbio_add_mfd_cell(struct usbio_dev *ljca, struct mfd_cell *cell)
{
	struct mfd_cell *new_cells;

	/* Enumerate the device even if it does not appear in DSDT */
	if (!cell->acpi_match->pnpid)
		dev_warn(&ljca->intf->dev,
			 "The HID of cell %s does not exist in DSDT\n",
			 cell->name);

	new_cells = krealloc_array(ljca->cells, (ljca->cell_count + 1),
				   sizeof(struct mfd_cell), GFP_KERNEL);
	if (!new_cells)
		return -ENOMEM;

	memcpy(&new_cells[ljca->cell_count], cell, sizeof(*cell));
	ljca->cells = new_cells;
	ljca->cell_count++;

	return 0;
}

static int usbio_gpio_stub_init(struct usbio_dev *ljca,
			       struct usbio_gpio_descriptor *desc)
{
	struct usbio_stub *stub;
	struct mfd_cell cell = { 0 };
	struct usbio_platform_data *pdata;
	int gpio_num = desc->pins_per_bank * desc->bank_num;
	int i;
	u32 valid_pin[MAX_GPIO_NUM / (sizeof(u32) * BITS_PER_BYTE)];

	if (gpio_num > MAX_GPIO_NUM)
		return -EINVAL;

	stub = usbio_stub_alloc(ljca, sizeof(*pdata));
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	stub->type = GPIO_STUB;
	stub->intf = ljca->intf;

	pdata = usbio_priv(stub);
	pdata->type = stub->type;
	pdata->gpio_info.num = gpio_num;

	for (i = 0; i < desc->bank_num; i++)
		valid_pin[i] = desc->bank_desc[i].valid_pins;

	bitmap_from_arr32(pdata->gpio_info.valid_pin_map, valid_pin, gpio_num);

	cell.name = "ljca-gpio";
	cell.platform_data = pdata;
	cell.pdata_size = sizeof(*pdata);
	cell.acpi_match = &usbio_acpi_match_gpio;

	return usbio_add_mfd_cell(ljca, &cell);
}

static int usbio_mng_enum_gpio(struct usbio_stub *stub)
{
	struct usbio_dev *ljca = usb_get_intfdata(stub->intf);
	struct usbio_gpio_descriptor *desc;
	int ret;
	int len;

	desc = kzalloc(MAX_PAYLOAD_SIZE, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	ret = usbio_stub_write(stub, CTRL_ENUM_GPIO, NULL, 0, desc, &len, true,
			      USB_ENUM_STUB_TIMEOUT);
	if (ret || len != sizeof(*desc) + desc->bank_num *
						  sizeof(desc->bank_desc[0])) {
		dev_err(&stub->intf->dev,
			"enum gpio failed ret:%d len:%d bank_num:%d\n", ret,
			len, desc->bank_num);
		kfree(desc);
		return -EIO;
	}

	ret = usbio_gpio_stub_init(ljca, desc);
	kfree(desc);
	return ret;
}

static int usbio_i2c_stub_init(struct usbio_dev *ljca,
			      struct usbio_i2c_descriptor *desc)
{
	struct usbio_stub *stub;
	struct usbio_platform_data *pdata;
	int i;
	int ret;

	stub = usbio_stub_alloc(ljca, desc->num * sizeof(*pdata));
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	stub->type = I2C_STUB;
	stub->intf = ljca->intf;
	pdata = usbio_priv(stub);

	for (i = 0; i < desc->num; i++) {
		struct mfd_cell cell = { 0 };
		pdata[i].type = stub->type;

		pdata[i].i2c_info.id = desc->info[i].id;
		pdata[i].i2c_info.capacity = desc->info[i].capacity;
		pdata[i].i2c_info.intr_pin = desc->info[i].intr_pin;

		cell.name = "ljca-i2c";
		cell.platform_data = &pdata[i];
		cell.pdata_size = sizeof(pdata[i]);
		if (i < ARRAY_SIZE(usbio_acpi_match_i2cs))
			cell.acpi_match = &usbio_acpi_match_i2cs[i];

		ret = usbio_add_mfd_cell(ljca, &cell);
		if (ret)
			return ret;
	}

	return 0;
}

static int usbio_mng_enum_i2c(struct usbio_stub *stub)
{
	struct usbio_dev *ljca = usb_get_intfdata(stub->intf);
	struct usbio_i2c_descriptor *desc;
	int ret;
	int len;

	desc = kzalloc(MAX_PAYLOAD_SIZE, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	ret = usbio_stub_write(stub, CTRL_ENUM_I2C, NULL, 0, desc, &len, true,
			      USB_ENUM_STUB_TIMEOUT);
	if (ret) {
		dev_err(&stub->intf->dev,
			"CTRL_ENUM_I2C failed ret:%d len:%d num:%d\n", ret, len,
			desc->num);
		kfree(desc);
		return -EIO;
	}

	ret = usbio_i2c_stub_init(ljca, desc);
	kfree(desc);
	return ret;
}

static int usbio_spi_stub_init(struct usbio_dev *ljca,
			      struct usbio_spi_descriptor *desc)
{
	struct usbio_stub *stub;
	struct usbio_platform_data *pdata;
	int i;
	int ret;

	stub = usbio_stub_alloc(ljca, desc->num * sizeof(*pdata));
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	stub->type = SPI_STUB;
	stub->intf = ljca->intf;
	pdata = usbio_priv(stub);

	for (i = 0; i < desc->num; i++) {
		struct mfd_cell cell = { 0 };
		pdata[i].type = stub->type;

		pdata[i].spi_info.id = desc->info[i].id;
		pdata[i].spi_info.capacity = desc->info[i].capacity;

		cell.name = "ljca-spi";
		cell.platform_data = &pdata[i];
		cell.pdata_size = sizeof(pdata[i]);
		if (i < ARRAY_SIZE(usbio_acpi_match_spis))
			cell.acpi_match = &usbio_acpi_match_spis[i];

		ret = usbio_add_mfd_cell(ljca, &cell);
		if (ret)
			return ret;
	}

	return 0;
}

static int usbio_mng_enum_spi(struct usbio_stub *stub)
{
	struct usbio_dev *ljca = usb_get_intfdata(stub->intf);
	struct usbio_spi_descriptor *desc;
	int ret;
	int len;

	desc = kzalloc(MAX_PAYLOAD_SIZE, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	ret = usbio_stub_write(stub, CTRL_ENUM_SPI, NULL, 0, desc, &len, true,
			      USB_ENUM_STUB_TIMEOUT);
	if (ret) {
		dev_err(&stub->intf->dev,
			"CTRL_ENUM_SPI failed ret:%d len:%d num:%d\n", ret, len,
			desc->num);
		kfree(desc);
		return -EIO;
	}

	ret = usbio_spi_stub_init(ljca, desc);
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

	ret = usbio_stub_write(stub, CTRL_GET_VERSION, NULL, 0, &version, &len,
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
	return usbio_stub_write(stub, CTRL_SET_DFU_MODE, NULL, 0, NULL, NULL,
			       true, USB_WRITE_ACK_TIMEOUT);
}

static int usbio_mng_link(struct usbio_dev *ljca, struct usbio_stub *stub)
{
	int ret;

	ret = usbio_mng_reset_handshake(stub);
	if (ret)
		return ret;

	ljca->state = BRIDGE_RESET_SYNCED;

	/* workaround for FW limitation, ignore return value of enum result */
	usbio_mng_enum_gpio(stub);
	ljca->state = BRIDGE_ENUM_GPIO_COMPLETE;

	usbio_mng_enum_i2c(stub);
	ljca->state = BRIDGE_ENUM_I2C_COMPLETE;

	usbio_mng_enum_spi(stub);
	ljca->state = BRIDGE_ENUM_SPI_COMPLETE;

	return 0;
}

static int usbio_mng_init(struct usbio_dev *ljca)
{
	struct usbio_stub *stub;
	struct usbio_mng_priv *priv;
	int ret;

	stub = usbio_stub_alloc(ljca, sizeof(*priv));
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	priv = usbio_priv(stub);
	if (!priv)
		return -ENOMEM;

	priv->reset_id = 0;
	stub->type = CTRL_STUB;
	stub->intf = ljca->intf;

	ret = usbio_mng_link(ljca, stub);
	if (ret)
		dev_err(&ljca->intf->dev,
			"mng stub link done ret:%d state:%d\n", ret,
			ljca->state);

	return ret;
}

static inline int usbio_diag_get_fw_log(struct usbio_stub *stub, void *buf)
{
	int ret;
	int len;

	if (!buf)
		return -EINVAL;

	ret = usbio_stub_write(stub, DIAG_GET_FW_LOG, NULL, 0, buf, &len, true,
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

	ret = usbio_stub_write(stub, DIAG_GET_FW_COREDUMP, NULL, 0, buf, &len,
			      true, USB_WRITE_ACK_TIMEOUT);
	if (ret)
		return ret;

	return len;
}

static inline int usbio_diag_set_trace_level(struct usbio_stub *stub, u8 level)
{
	return usbio_stub_write(stub, DIAG_SET_TRACE_LEVEL, &level,
			       sizeof(level), NULL, NULL, true,
			       USB_WRITE_ACK_TIMEOUT);
}

static int usbio_diag_init(struct usbio_dev *ljca)
{
	struct usbio_stub *stub;

	stub = usbio_stub_alloc(ljca, 0);
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	stub->type = DIAG_STUB;
	stub->intf = ljca->intf;
	return 0;
}

static void usbio_delete(struct usbio_dev *ljca)
{
	mutex_destroy(&ljca->mutex);
	usb_free_urb(ljca->in_urb);
	usb_put_intf(ljca->intf);
	usb_put_dev(ljca->udev);
	kfree(ljca->ibuf);
	kfree(ljca->cells);
	kfree(ljca);
}

static int usbio_init(struct usbio_dev *ljca)
{
	mutex_init(&ljca->mutex);
	init_waitqueue_head(&ljca->ack_wq);
	INIT_LIST_HEAD(&ljca->stubs_list);

	ljca->state = BRIDGE_INITED;

	return 0;
}

static void usbio_stop(struct usbio_dev *ljca)
{
	usb_kill_urb(ljca->in_urb);
}

static ssize_t cmd_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct usbio_dev *ljca = usb_get_intfdata(intf);
	struct usbio_stub *mng_stub = usbio_stub_find(ljca, CTRL_STUB);
	struct usbio_stub *diag_stub = usbio_stub_find(ljca, DIAG_STUB);

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
	return sysfs_emit(buf, "%s\n", "supported cmd: [dfu, reset, debug]");
}
static DEVICE_ATTR_RW(cmd);

static ssize_t version_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct usbio_dev *ljca = usb_get_intfdata(intf);
	struct usbio_stub *stub = usbio_stub_find(ljca, CTRL_STUB);

	return usbio_mng_get_version(stub, buf);
}
static DEVICE_ATTR_RO(version);

static ssize_t log_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct usbio_dev *ljca = usb_get_intfdata(intf);
	struct usbio_stub *diag_stub = usbio_stub_find(ljca, DIAG_STUB);

	return usbio_diag_get_fw_log(diag_stub, buf);
}
static DEVICE_ATTR_RO(log);

static ssize_t coredump_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct usbio_dev *ljca = usb_get_intfdata(intf);
	struct usbio_stub *diag_stub = usbio_stub_find(ljca, DIAG_STUB);

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
	struct usbio_dev *ljca;
	struct usb_endpoint_descriptor *bulk_in, *bulk_out;
	int ret;

	ret = precheck_acpi_hid(intf);
	if (ret)
		return ret;

	/* allocate memory for our device state and initialize it */
	ljca = kzalloc(sizeof(*ljca), GFP_KERNEL);
	if (!ljca)
		return -ENOMEM;

	/* TODO: Get device descriptor and buffer size */

	usbio_init(ljca);
	ljca->udev = usb_get_dev(interface_to_usbdev(intf));
	ljca->intf = usb_get_intf(intf);

	/* set up the endpoint information use only the first bulk-in and bulk-out endpoints */
	ret = usb_find_common_endpoints(intf->cur_altsetting, &bulk_in,
					&bulk_out, NULL, NULL);
	if (ret) {
		dev_err(&intf->dev,
			"Could not find both bulk-in and bulk-out endpoints\n");
		goto error;
	}

	ljca->ibuf_len = usb_endpoint_maxp(bulk_in);
	ljca->in_ep = bulk_in->bEndpointAddress;
	ljca->ibuf = kzalloc(ljca->ibuf_len, GFP_KERNEL);
	if (!ljca->ibuf) {
		ret = -ENOMEM;
		goto error;
	}

	ljca->in_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!ljca->in_urb) {
		ret = -ENOMEM;
		goto error;
	}

	ljca->out_ep = bulk_out->bEndpointAddress;
	dev_dbg(&intf->dev, "bulk_in size:%zu addr:%d bulk_out addr:%d\n",
		ljca->ibuf_len, ljca->in_ep, ljca->out_ep);

	/* save our data pointer in this intf device */
	usb_set_intfdata(intf, ljca);
	ret = usbio_start(ljca);
	if (ret) {
		dev_err(&intf->dev, "bridge read start failed ret %d\n", ret);
		goto error;
	}

	ret = usbio_mng_init(ljca);
	if (ret) {
		dev_err(&intf->dev, "register mng stub failed ret %d\n", ret);
		goto error_stop;
	}

	ret = usbio_diag_init(ljca);
	if (ret) {
		dev_err(&intf->dev, "register diag stub failed ret %d\n", ret);
		goto error_stop;
	}

	ret = mfd_add_hotplug_devices(&intf->dev, ljca->cells,
				      ljca->cell_count);
	if (ret) {
		dev_err(&intf->dev, "failed to add mfd devices to core %d\n",
			ljca->cell_count);
		goto error_stop;
	}

	ljca->state = BRIDGE_STARTED;
	dev_info(&intf->dev, "LJCA USB device init success\n");
	return 0;
error_stop:
	usbio_stop(ljca);
error:
	dev_err(&intf->dev, "LJCA USB device init failed\n");
	/* this frees allocated memory */
	usbio_stub_cleanup(ljca);
	usbio_delete(ljca);
	return ret;
}

static void usbio_disconnect(struct usb_interface *intf)
{
	struct usbio_dev *ljca;

	ljca = usb_get_intfdata(intf);

	usbio_stop(ljca);
	ljca->state = BRIDGE_STOPPED;
	mfd_remove_devices(&intf->dev);
	usbio_stub_cleanup(ljca);
	usb_set_intfdata(intf, NULL);
	usbio_delete(ljca);
	dev_info(&intf->dev, "LJCA disconnected\n");
}

static int usbio_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct usbio_dev *ljca = usb_get_intfdata(intf);

	usbio_stop(ljca);
	ljca->state = BRIDGE_SUSPEND;

	dev_dbg(&intf->dev, "LJCA suspend\n");
	return 0;
}

static int usbio_resume(struct usb_interface *intf)
{
	struct usbio_dev *ljca = usb_get_intfdata(intf);

	ljca->state = BRIDGE_STARTED;
	dev_dbg(&intf->dev, "LJCA resume\n");
	return usbio_start(ljca);
}

static const struct usb_device_id usbio_table[] = {
	{USB_DEVICE(0x2AC1, 0x20C0)}, /* Lattice NX40 */
	{USB_DEVICE(0x2AC1, 0x20C9)}, /* Lattice NX33U */
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
MODULE_DESCRIPTION("Intel USBIO Bridge driver");
MODULE_LICENSE("GPL v2");
