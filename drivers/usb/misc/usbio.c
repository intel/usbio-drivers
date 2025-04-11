// SPDX-License-Identifier: GPL-2.0
/*
 * Intel USBIO Bridge driver
 *
 * Copyright (c) 2025 Intel Corporation.
 */

#include <linux/acpi.h>
#include <linux/auxiliary_bus.h>
#include <linux/bits.h>
#include <linux/completion.h>
#include <linux/dev_printk.h>
#include <linux/device.h>
#include <linux/i2c.h>
#include <linux/list.h>
#include <linux/math.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/usb.h>
#include <linux/usbio.h>
#include <linux/version.h>

/*************************************
 * USBIO Bridge Protocol Definitions *
 *************************************/

/* USBIO Packet Type */
#define USBIO_PKTTYPE_CTRL	1
#define USBIO_PKTTYPE_DBG	2
#define USBIO_PKTTYPE_GPIO	USBIO_GPIO
#define USBIO_PKTTYPE_I2C	USBIO_I2C

/* USBIO Control Commands */
#define USBIO_CTRLCMD_PROTVER	0
#define USBIO_CTRLCMD_FWVER	1
#define USBIO_CTRLCMD_HS	2
#define USBIO_CTRLCMD_ENUMGPIO	16
#define USBIO_CTRLCMD_ENUMI2C	17

/* USBIO Packet Flags */
#define USBIO_PKTFLAG_ACK	BIT(0)
#define USBIO_PKTFLAG_RSP	BIT(1)
#define USBIO_PKTFLAG_CMP	BIT(2)
#define USBIO_PKTFLAG_ERR	BIT(3)

#define USBIO_PKTFLAGS_REQRESP	(USBIO_PKTFLAG_CMP | USBIO_PKTFLAG_ACK)
#define USBIO_PKTFLAGS_ISRSP	(USBIO_PKTFLAG_CMP | USBIO_PKTFLAG_RSP)

/* USBIO Packet Header */
struct usbio_packet_header {
	u8 type;
	u8 cmd;
	u8 flags;
} __packed;

#define USBIO_CTRLXFER_TIMEOUT 0
#define USBIO_BULKXFER_TIMEOUT 80

/* USBIO Control Transfer Packet */
struct usbio_ctrl_packet {
	struct usbio_packet_header header;
	u8 len;
	u8 data[] __counted_by(len);
} __packed;

/* USBIO Bulk Transfer Packet */
struct usbio_bulk_packet {
	struct usbio_packet_header header;
	u16 len;
	u8 data[] __counted_by(len);
} __packed;

struct usbio_protver {
	u8 ver;
} __packed;

struct usbio_fwver {
	u8 major;
	u8 minor;
	u16 patch;
	u16 build;
} __packed;

struct usbio_gpio_bank_desc {
	u8 id;
	u8 pins;
	u32 bmap;
} __packed;

#define USBIO_I2C_BUS_ADDR_CAP_10B	BIT(3) /* 10bit address support */
#define USBIO_I2C_BUS_MODE_CAP_MASK	0x3
#define USBIO_I2C_BUS_MODE_CAP_SM	0 /* Standard Mode */
#define USBIO_I2C_BUS_MODE_CAP_FM	1 /* Fast Mode */
#define USBIO_I2C_BUS_MODE_CAP_FMP	2 /* Fast Mode+ */
#define USBIO_I2C_BUS_MODE_CAP_HSM	3 /* High-Speed Mode */

struct usbio_i2c_bus_desc {
	u8 id;
	u8 caps;
} __packed;

u32 usbio_i2c_speeds[] = {
	I2C_MAX_STANDARD_MODE_FREQ,
	I2C_MAX_FAST_MODE_FREQ,
	I2C_MAX_FAST_MODE_PLUS_FREQ,
	I2C_MAX_HIGH_SPEED_MODE_FREQ
};

/***********************************
 * USBIO Bridge Device Definitions *
 ***********************************/
struct usbio_dev_info {
	struct usbio_protver protver;
	struct usbio_fwver fwver;
};

/**
 * struct usbio_device - the usb device exposing IOs
 *
 * @dev: the device in the usb interface
 * @udev: the detected usb device
 * @intf: the usb interface
 * @ctrl_pipe: the control transfer pipe
 * @ctrlbuf_len: the size of the control transfer pipe
 * @ctrlbuf: the buffer used for control transfers
 * @txpipe: the bulk out pipe
 * @txbuf_len: the size of the bulk out pipe
 * @txbuf: the buffer used for bulk out transfers
 * @urb: the urb to read bulk pipe
 * @rxpipe: the bulk in pipe
 * @rxbuf_len: the size of the bulk in pipe
 * @rxdat_len: the data length at rx buffer
 * @rxbuf: the buffer used for bulk in transfers
 * @info: the device's protocol and firmware information
 * @ctllock: protection against access concurrency for control transfers
 * @done: completion object as request is done
 * @blklock: protection against access concurrency for bulk transfers
 * @cli_list: device's client list
 * @nr_gpio_banks: the number of gpio banks
 * @gpios: the gpio banks array
 * @chip: the usbio gpio chip data
 * @nr_i2c_buses: the number of i2c buses
 * @i2cs: the i2c buses array
 * @i2cbus: the usbio i2c bus data
 */
struct usbio_device {
	struct device *dev;
	struct usb_device *udev;
	struct usb_interface *intf;

	unsigned int ctrl_pipe;
	u16 ctrlbuf_len;
	void *ctrlbuf;

	unsigned int txpipe;
	u16 txbuf_len;
	void *txbuf;

	struct urb *urb;
	unsigned int rxpipe;
	u16 rxbuf_len;
	u16 rxdat_len;
	void *rxbuf;

	struct usbio_dev_info info;
	/* Control transfer concurrency lock */
	struct mutex ctllock;

	struct completion done;
	/* Bulk transfer concurrency lock */
	struct mutex blklock;

	struct list_head cli_list;

	unsigned int nr_gpio_banks;
	struct usbio_gpio_bank_desc gpios[USBIO_MAX_GPIOBANKS];
	struct usbio_gpio_chip *chip;

	unsigned int nr_i2c_buses;
	struct usbio_i2c_bus_desc i2cs[USBIO_MAX_I2CBUSES];
	struct usbio_i2c_bus *i2cbus;
};

/**
 * struct usbio_match_ids_walk_data - used to find matching ACPI hids and uids
 *
 * @adev: store the matching acpi device
 * @hids: the list of acpi device ids to match
 * @id: the usbio client id to match
 */
struct usbio_match_ids_walk_data {
	struct acpi_device *adev;
	const struct acpi_device_id *hids;
	const u32 id;
};

static int usbio_control_msg(struct usbio_device *usbio,
			     struct usbio_packet_header *pkt, const void *obuf,
			     u16 obuf_len, void *ibuf, u16 ibuf_len)
{
	struct usbio_ctrl_packet *cpkt;
	unsigned int pipe;
	u16 cpkt_len = sizeof(*cpkt) + obuf_len;
	u8 request = USB_TYPE_VENDOR | USB_RECIP_DEVICE;
	int ret;

	ret = usb_autopm_get_interface(usbio->intf);
	if (ret)
		return ret;

	if (cpkt_len > usbio->ctrlbuf_len) {
		ret = -EMSGSIZE;
		goto exit;
	}

	/* Prepare Control Packet Header */
	cpkt = usbio->ctrlbuf;
	cpkt->header.type = pkt->type;
	cpkt->header.cmd = pkt->cmd;
	cpkt->header.flags = pkt->flags;
	cpkt->len = obuf_len;

	/* Copy the data */
	memcpy(cpkt->data, obuf, obuf_len);

	pipe = usb_sndctrlpipe(usbio->udev, usbio->ctrl_pipe);
	ret = usb_control_msg(usbio->udev, pipe, 0, request | USB_DIR_OUT,
			      0, 0, (void *)cpkt, cpkt_len,
			      USBIO_CTRLXFER_TIMEOUT);
	if (ret < 0) {
		dev_err(usbio->dev, "Write CTRLXFER failed: %d", ret);
		goto exit;
	}

	/* Check for protocol error */
	if (ret != cpkt_len) {
		ret = -EPROTO;
		goto exit;
	}

	if (pkt->flags & USBIO_PKTFLAG_ACK) {
		cpkt_len = sizeof(*cpkt) + ibuf_len;

		if (cpkt_len > usbio->ctrlbuf_len) {
			ret = -EMSGSIZE;
			goto exit;
		}

		pipe = usb_rcvctrlpipe(usbio->udev, usbio->ctrl_pipe);
		ret = usb_control_msg(usbio->udev, pipe, 0,
				      request | USB_DIR_IN, 0, 0,
				      (void *)cpkt, cpkt_len,
				      USBIO_CTRLXFER_TIMEOUT);
		if (ret < 0) {
			dev_err(usbio->dev, "Read CTRLXFER failed: %d", ret);
			goto exit;
		}

		/* Check for protocol error */
		if (ret < sizeof(*cpkt)) {
			ret = -EPROTO;
			goto exit;
		}

		/* Check for valid reply header */
		if (cpkt->header.type == pkt->type &&
		    cpkt->header.cmd == pkt->cmd &&
		    cpkt->header.flags & USBIO_PKTFLAG_RSP) {
			/* Check the error flag */
			if (cpkt->header.flags & USBIO_PKTFLAG_ERR) {
				ret = -EREMOTEIO;
				goto exit;
			}

			if (ibuf_len < cpkt->len) {
				ret = -ENOBUFS;
				goto exit;
			}

			/* Copy the data */
			memcpy(ibuf, cpkt->data, cpkt->len);
			ret = cpkt->len;
			goto exit;
		}

		dev_err(usbio->dev, "Unexpected reply: %u:%u:%u",
			cpkt->header.type, cpkt->header.cmd,
			cpkt->header.flags);
		ret = -EPROTO;
		goto exit;
	}

	ret = cpkt_len - sizeof(*cpkt);

exit:
	usb_autopm_put_interface(usbio->intf);

	return ret;
}

static void usbio_bulk_recv(struct urb *urb)
{
	struct usbio_bulk_packet *bpkt = urb->transfer_buffer;
	struct usbio_device *usbio = urb->context;

	if (urb->status) {
		/* URB Error */
		if (urb->status != -ENOENT)
			dev_err(usbio->dev, "URB status:%d", urb->status);

		goto exit;
	}

	/* Verify the received packet is a response */
	if (bpkt->header.flags & USBIO_PKTFLAG_RSP) {
		usbio->rxdat_len = urb->actual_length;
		complete(&usbio->done);
	}

exit:
	usb_submit_urb(usbio->urb, GFP_ATOMIC);
}

static int usbio_bulk_msg(struct usbio_device *usbio,
			  struct usbio_packet_header *pkt, bool last,
			  const void *obuf, u16 obuf_len, void *ibuf,
			  u16 ibuf_len, int timeout)
{
	struct usbio_bulk_packet *bpkt;
	u16 bpkt_len = sizeof(*bpkt) + obuf_len;
	int ret, act;

	ret = usb_autopm_get_interface(usbio->intf);
	if (ret)
		return ret;

	if (bpkt_len > usbio->txbuf_len) {
		ret = -EMSGSIZE;
		goto exit;
	}

	if (ibuf_len)
		reinit_completion(&usbio->done);

	/* If no data to send, skip to read */
	if (!obuf_len)
		goto read;

	/* Prepare Bulk Packet Header */
	bpkt = (struct usbio_bulk_packet *)usbio->txbuf;
	bpkt->header.type = pkt->type;
	bpkt->header.cmd = pkt->cmd;
	bpkt->header.flags = last ? pkt->flags : 0;
	bpkt->len = obuf_len;

	/* Copy the data */
	memcpy(bpkt->data, obuf, obuf_len);

	ret = usb_bulk_msg(usbio->udev, usbio->txpipe,
			   (void *)bpkt, bpkt_len, &act, timeout);
	if (ret) {
		dev_err(usbio->dev, "Write Bulk transfer failed: %d", ret);
		goto exit;
	}

	/* Check for protocol error */
	if (act != bpkt_len) {
		ret = -EPROTO;
		goto exit;
	}

read:
	if (last && pkt->flags & USBIO_PKTFLAG_ACK) {
		bpkt_len = sizeof(*bpkt) + ibuf_len;

		if (bpkt_len > usbio->txbuf_len) {
			ret = -EMSGSIZE;
			goto exit;
		}

		ret = wait_for_completion_timeout(&usbio->done, timeout);
		if (!ret) {
			/* Timed out */
			dev_err(usbio->dev,
				"Read Bulk transfer timed out: %d", timeout);
			ret = -ETIMEDOUT;
			goto exit;
		}

		act = usbio->rxdat_len;
		bpkt = (struct usbio_bulk_packet *)usbio->rxbuf;
		/* Check protocol error */
		if (act < sizeof(*bpkt)) {
			ret = -EPROTO;
			goto exit;
		}

		/* Check for valid reply header */
		if (bpkt->header.type == pkt->type &&
		    bpkt->header.cmd == pkt->cmd &&
		    bpkt->header.flags & USBIO_PKTFLAG_RSP) {
			/* Check the error flag */
			if (bpkt->header.flags & USBIO_PKTFLAG_ERR) {
				ret = -EREMOTEIO;
				goto exit;
			}

			if (ibuf_len < bpkt->len) {
				ret = -ENOBUFS;
				goto exit;
			}

			/* Copy the data */
			memcpy(ibuf, bpkt->data, bpkt->len);
			ret = bpkt->len;
			goto exit;
		}

		dev_err(usbio->dev, "Unexpected reply: %u:%u",
			bpkt->header.type, bpkt->header.cmd);
		ret = -EPROTO;
		goto exit;
	}

	ret = bpkt_len - sizeof(*bpkt);

exit:
	usb_autopm_put_interface(usbio->intf);

	return ret;
}

static int usbio_ctrl_req(struct usbio_device *usbio,
			  u8 cmd, void *ibuf, u8 len)
{
	struct usbio_packet_header pkt = {
		USBIO_PKTTYPE_CTRL,
		cmd,
		USBIO_PKTFLAGS_REQRESP
	};
	int ret;

	ret = usbio_control_msg(usbio, &pkt, NULL, 0, ibuf, len);
	if (ret < 0)
		return ret;

	if (ret != len)
		return -EPROTO;

	return 0;
}

static int usbio_match_device_ids(struct acpi_device *adev, void *data)
{
	struct usbio_match_ids_walk_data *wd = data;
	char *uid;
	unsigned int id = 0;

	if (!acpi_match_device_ids(adev, wd->hids)) {
		uid = acpi_device_uid(adev);
		if (uid)
			for (int i = 0; i < strlen(uid); i++)
				if (!kstrtouint(&uid[i], 10, &id))
					break;

		if (!uid || wd->id == id) {
			wd->adev = adev;
			return 1;
		}
	}

	return 0;
}

void usbio_client_acpi_bind(struct auxiliary_device *adev,
			    const struct acpi_device_id *hids)
{
	struct device *dev = &adev->dev;
	struct acpi_device *parent;
	struct usbio_match_ids_walk_data wd = {
		.adev = NULL,
		.hids = hids,
		.id = adev->id
	};

	parent = ACPI_COMPANION(dev->parent);
	if (!parent)
		return;

	acpi_dev_for_each_child(parent, usbio_match_device_ids, &wd);
	if (wd.adev)
		ACPI_COMPANION_SET(dev, wd.adev);
}
#if KERNEL_VERSION(6, 13, 0) > LINUX_VERSION_CODE
EXPORT_SYMBOL_NS_GPL(usbio_client_acpi_bind, USBIO);
#else
EXPORT_SYMBOL_NS_GPL(usbio_client_acpi_bind, "USBIO");
#endif

static void usbio_auxdev_release(struct device *dev)
{
	struct auxiliary_device *adev = to_auxiliary_dev(dev);
	struct usbio_client *client = auxiliary_get_usbio_client(adev);

	kfree(client);
}

static void usbio_add_client(struct usbio_device *usbio, char *name,
			     u8 type, u8 id, void *data)
{
	struct usbio_client *client;
	struct auxiliary_device *adev;
	int ret;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client) {
		ret = -ENOMEM;
		goto exit;
	}

	client->type = type;
	client->id = id;
	client->bridge = usbio;
	adev = &client->adev;
	adev->name = name;
	adev->id = id;

	adev->dev.parent = usbio->dev;
	adev->dev.platform_data = data;
	adev->dev.release = usbio_auxdev_release;

	ret = auxiliary_device_init(adev);
	if (ret)
		goto exit;

	ret = auxiliary_device_add(adev);
	if (ret)
		auxiliary_device_uninit(adev);

exit:
	if (ret) {
		dev_warn(usbio->dev,
			 "Client %s.%d add failed: %d", name, id, ret);
		kfree(client);
		return;
	}

	list_add_tail(&client->link, &usbio->cli_list);
}

static int usbio_ctrl_enumgpios(struct usbio_device *usbio)
{
	struct usbio_packet_header pkt = {
		USBIO_PKTTYPE_CTRL,
		USBIO_CTRLCMD_ENUMGPIO,
		USBIO_PKTFLAGS_REQRESP
	};
	struct usbio_gpio_bank_desc *gpio;
	int ret;

	gpio = usbio->gpios;
	ret = usbio_control_msg(usbio, &pkt, 0, 0, gpio, sizeof(usbio->gpios));
	if (ret < 0 || ret % sizeof(*gpio)) {
		dev_err(usbio->dev, "CTRL ENUMGPIO failed: %d", ret);
		return ret;
	}

	usbio->nr_gpio_banks = ret / sizeof(*gpio);
	if (!usbio->nr_gpio_banks)
		return 0;

	if (usbio->nr_gpio_banks > USBIO_MAX_GPIOBANKS) {
		dev_warn(usbio->dev,
			 "MAX GPIO banks: %u", USBIO_MAX_GPIOBANKS);
		usbio->nr_gpio_banks = USBIO_MAX_GPIOBANKS;
	}

	size_t size = sizeof(struct usbio_gpio_chip) +
			usbio->nr_gpio_banks * sizeof(struct usbio_gpio_bank);
	usbio->chip = kzalloc(size, GFP_KERNEL);
	if (!usbio->chip)
		return -ENOMEM;

	usbio->chip->nbanks = usbio->nr_gpio_banks;
	for (int i = 0; i < usbio->chip->nbanks; i++)
		usbio->chip->banks[i].bitmap = gpio[i].bmap;

	usbio_add_client(usbio, USBIO_GPIO_CLIENT, USBIO_GPIO, 0, usbio->chip);

	return 0;
}

static int usbio_ctrl_enumi2cs(struct usbio_device *usbio)
{
	struct usbio_packet_header pkt = {
		USBIO_PKTTYPE_CTRL,
		USBIO_CTRLCMD_ENUMI2C,
		USBIO_PKTFLAGS_REQRESP
	};
	struct usbio_i2c_bus_desc *i2c;
	int ret;

	i2c = usbio->i2cs;
	ret = usbio_control_msg(usbio, &pkt, 0, 0, i2c, sizeof(usbio->i2cs));
	if (ret < 0 || ret % sizeof(*i2c)) {
		dev_err(usbio->dev, "CTRL ENUMI2C failed: %d", ret);
		return ret;
	}

	usbio->nr_i2c_buses = ret / sizeof(*i2c);
	if (!usbio->nr_i2c_buses)
		return 0;

	if (usbio->nr_i2c_buses > USBIO_MAX_I2CBUSES) {
		dev_warn(usbio->dev,
			 "MAX I2C buses: %u", USBIO_MAX_I2CBUSES);
		usbio->nr_i2c_buses = USBIO_MAX_I2CBUSES;
	}

	size_t size = usbio->nr_i2c_buses * sizeof(struct usbio_i2c_bus);

	usbio->i2cbus = kzalloc(size, GFP_KERNEL);
	if (!usbio->i2cbus)
		return -ENOMEM;

	for (int i = 0; i < usbio->nr_i2c_buses; i++) {
		struct usbio_i2c_bus *bus = &usbio->i2cbus[i];

		bus->id = i2c[i].id;
		bus->speed = usbio_i2c_speeds[i2c[i].caps &
					 USBIO_I2C_BUS_MODE_CAP_MASK];
		usbio_add_client(usbio, USBIO_I2C_CLIENT,
				 USBIO_I2C, bus->id, bus);
	}

	return 0;
}

static int usbio_gpio_handler(struct usbio_device *usbio, u8 cmd,
			      const void *obuf, u16 obuf_len,
			      void *ibuf, u16 ibuf_len)
{
	const struct usbio_gpio_init *init = obuf;
	struct usbio_packet_header pkt = {
		USBIO_PKTTYPE_GPIO,
		cmd,
		ibuf_len ? USBIO_PKTFLAGS_REQRESP : USBIO_PKTFLAG_CMP
	};
	int ret;

	if (!init || init->bankid > usbio->nr_gpio_banks)
		return -EINVAL;

	mutex_lock(&usbio->ctllock);
	ret = usbio_control_msg(usbio, &pkt, obuf, obuf_len, ibuf, ibuf_len);
	if (ret > 0)
		ret -= obuf_len;
	mutex_unlock(&usbio->ctllock);

	return ret;
}

#define I2C_RW_OVERHEAD (sizeof(struct usbio_bulk_packet) + \
			sizeof(struct usbio_i2c_rw))

static int usbio_i2c_handler(struct usbio_device *usbio, u8 cmd,
			     const void *obuf, u16 obuf_len,
			     void *ibuf, u16 ibuf_len)
{
	const struct usbio_i2c_init *init = obuf;
	struct usbio_packet_header pkt = {
		USBIO_PKTTYPE_I2C,
		cmd,
		ibuf_len ? USBIO_PKTFLAGS_REQRESP : USBIO_PKTFLAG_CMP
	};
	int ret, timeout = USBIO_BULKXFER_TIMEOUT;

	if (!usbio->txpipe || !usbio->rxpipe)
		return -EPERM;

	if (!init || init->busid > usbio->nr_i2c_buses)
		return -EINVAL;

	u8 bid = init->busid;
	u16 len = 0;

	switch (cmd) {
	case USBIO_I2CCMD_WRITE:
		const struct usbio_i2c_rw *i2cwr = obuf;
		u16 txchunk = usbio->txbuf_len - I2C_RW_OVERHEAD;
		u16 wsize = i2cwr->size;

		if (wsize <= txchunk) {
			timeout += DIV_ROUND_UP(wsize * 1000,
						usbio->i2cbus[bid].speed);
			break;
		}

		/* Need to split the output buffer */
		struct usbio_i2c_rw *wr;

		wr = kzalloc(sizeof(*wr) + txchunk, GFP_KERNEL);
		if (!wr)
			return -ENOMEM;

		/* Copy the header */
		memcpy(wr, i2cwr, sizeof(*wr));
		mutex_lock(&usbio->blklock);
		do {
			/* Copy the data chunk */
			memcpy(wr->data, &i2cwr->data[len], txchunk);
			len += txchunk;

			timeout = USBIO_BULKXFER_TIMEOUT +
				  DIV_ROUND_UP(txchunk * 1000,
					       usbio->i2cbus[bid].speed);
			ret = usbio_bulk_msg(usbio, &pkt, wsize == len,
					     wr, sizeof(*wr) + txchunk,
					     ibuf, ibuf_len, timeout);
			if (ret < 0)
				break;

			if (wsize - len < txchunk)
				txchunk = wsize - len;
		} while (wsize > len);
		mutex_unlock(&usbio->blklock);

		kfree(wr);

		return ret;

	case USBIO_I2CCMD_READ:
		struct usbio_i2c_rw *i2crd = ibuf;
		u16 rxchunk = usbio->rxbuf_len - I2C_RW_OVERHEAD;
		u16 rsize = i2crd->size;

		if (rsize <= rxchunk) {
			timeout += DIV_ROUND_UP(rsize * 1000,
						usbio->i2cbus[bid].speed);
			break;
		}

		/* Need to split the input buffer */
		struct usbio_i2c_rw *rd;

		rd = kzalloc(sizeof(*rd) + rxchunk, GFP_KERNEL);
		if (!rd)
			return -ENOMEM;

		mutex_lock(&usbio->blklock);
		do {
			if (rsize - len < rxchunk)
				rxchunk = rsize - len;

			timeout = USBIO_BULKXFER_TIMEOUT +
				  DIV_ROUND_UP(rxchunk * 1000,
					       usbio->i2cbus[bid].speed);
			ret = usbio_bulk_msg(usbio, &pkt, true, obuf,
					     len == 0 ? obuf_len : 0,
					     rd, sizeof(*rd) + rxchunk,
					     timeout);
			if (ret < 0)
				break;

			memcpy(&i2crd->data[len], rd->data, rxchunk);
			len += rxchunk;
		} while (rsize > len);
		mutex_unlock(&usbio->blklock);

		if (rsize == len)
			i2crd->size = rd->size;

		kfree(rd);

		return ret < 0 ? ret : sizeof(*i2crd) + i2crd->size;
	}

	mutex_lock(&usbio->blklock);
	ret = usbio_bulk_msg(usbio, &pkt, true, obuf, obuf_len,
			     ibuf, ibuf_len, timeout);
	mutex_unlock(&usbio->blklock);

	return ret;
}

int usbio_transfer(struct usbio_client *client, u8 cmd, const void *obuf,
		   u16 obuf_len, void *ibuf, u16 ibuf_len)
{
	struct usbio_device *usbio;
	int ret = -EINVAL;

	if (!client || (!obuf && obuf_len) || (!ibuf && ibuf_len))
		return ret;

	if (!client->bridge)
		return -ENODEV;

	usbio = client->bridge;
	switch (client->type) {
	case USBIO_GPIO:
		if (usbio_gpiocmd_valid(cmd))
			ret = usbio_gpio_handler(usbio, cmd, obuf, obuf_len,
						 ibuf, ibuf_len);
		break;
	case USBIO_I2C:
		if (usbio_i2ccmd_valid(cmd)) {
			ret = usbio_i2c_handler(usbio, cmd, obuf, obuf_len,
						ibuf, ibuf_len);
			if (ret == -EREMOTEIO)
				/* Didn't respond */
				return -ENXIO;
		}
		break;
	}

	return ret;
}
#if KERNEL_VERSION(6, 13, 0) > LINUX_VERSION_CODE
EXPORT_SYMBOL_NS_GPL(usbio_transfer, USBIO);
#else
EXPORT_SYMBOL_NS_GPL(usbio_transfer, "USBIO");
#endif

static ssize_t usbio_devinfo_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct usbio_device *usbio = dev_get_drvdata(dev);
	struct usbio_fwver *fwver = &usbio->info.fwver;
	struct usbio_protver *protver = &usbio->info.protver;
	struct usbio_gpio_bank_desc *gpio = usbio->gpios;
	struct usbio_i2c_bus_desc *i2c = usbio->i2cs;
	unsigned int i;
	int len;

	/* Firmware and Protocol Version */
	len = sysfs_emit(buf, "Firmware Version: %u.%u.%u.%u\n"
			 "Protocol Version(BCD): %02x\n",
			 fwver->major, fwver->minor, fwver->patch,
			 fwver->build, protver->ver);

	/* GPIO Banks */
	len += sysfs_emit_at(buf, len, "GPIO Banks: %u\n",
			     usbio->nr_gpio_banks);
	for (i = 0; i < usbio->nr_gpio_banks; i++) {
		len += sysfs_emit_at(buf, len, "\tBank%u[%u] map: %#08x\n",
				     gpio[i].id, gpio[i].pins, gpio[i].bmap);
	}

	/* I2C Buses */
	len += sysfs_emit_at(buf, len, "I2C Buses: %u\n",
			     usbio->nr_i2c_buses);
	for (i = 0; i < usbio->nr_i2c_buses; i++) {
		len += sysfs_emit_at(buf, len, "\tBus%u caps: %#02x\n",
				     i2c[i].id, i2c[i].caps);
	}

	return len;
}
static DEVICE_ATTR_RO(usbio_devinfo);

static int usbio_suspend(struct usb_interface *intf, pm_message_t msg)
{
	struct usbio_device *usbio = usb_get_intfdata(intf);

	usb_kill_urb(usbio->urb);

	return 0;
}

static int usbio_resume(struct usb_interface *intf)
{
	struct usbio_device *usbio = usb_get_intfdata(intf);

	return usb_submit_urb(usbio->urb, GFP_KERNEL);
}

static void usbio_disconnect(struct usb_interface *intf)
{
	struct device *dev = &intf->dev;
	struct usbio_device *usbio = usb_get_intfdata(intf);
	struct usbio_client *cli, *prev;

	device_remove_file(dev, &dev_attr_usbio_devinfo);

	usb_kill_urb(usbio->urb);

	list_for_each_entry_safe_reverse(cli, prev, &usbio->cli_list, link) {
		/* Remove bridge from client */
		cli->bridge = NULL;

		/* Remove client from the list */
		list_del_init(&cli->link);

		/* Remove auxiliary device */
		auxiliary_device_delete(&cli->adev);
		auxiliary_device_uninit(&cli->adev);
	}

	usb_free_urb(usbio->urb);

	kfree(usbio->i2cbus);
	kfree(usbio->chip);
	kfree(usbio->ctrlbuf);
	kfree(usbio->txbuf);
	kfree(usbio->rxbuf);

	mutex_destroy(&usbio->ctllock);
	mutex_destroy(&usbio->blklock);

	usb_set_intfdata(intf, NULL);
	usb_put_intf(intf);

	devm_kfree(dev, usbio);
}

static int usbio_probe(struct usb_interface *intf,
		       const struct usb_device_id *id)
{
	struct usb_device *udev = interface_to_usbdev(intf);
	struct usb_endpoint_descriptor *epin, *epout;
	struct device *dev = &intf->dev;
	struct usbio_device *usbio;
	int ret = -ENOMEM;

	usbio = devm_kzalloc(dev, sizeof(*usbio), GFP_KERNEL);
	if (!usbio)
		return ret;

	usbio->dev = dev;
	usbio->udev = udev;
	usbio->intf = usb_get_intf(intf);
	usb_set_intfdata(intf, usbio);

	mutex_init(&usbio->ctllock);
	mutex_init(&usbio->blklock);
	init_completion(&usbio->done);
	INIT_LIST_HEAD(&usbio->cli_list);

	usbio->ctrl_pipe = usb_endpoint_num(&udev->ep0.desc);
	usbio->ctrlbuf_len = usb_maxpacket(udev, usbio->ctrl_pipe);
	usbio->ctrlbuf = kzalloc(usbio->ctrlbuf_len, GFP_KERNEL);
	if (!usbio->ctrlbuf)
		goto error;

	/* Find the first bulk-in and bulk-out endpoints */
	if (usb_find_common_endpoints(intf->cur_altsetting,
				      &epin, &epout, NULL, NULL)) {
		dev_warn(dev, "Couldn't find bulk-in and bulk-out endpoints");
		goto no_bulk;
	}

	usbio->txpipe = usb_sndbulkpipe(udev, usb_endpoint_num(epout));
	usbio->txbuf_len = usb_endpoint_maxp(epout);
	usbio->txbuf = kzalloc(usbio->txbuf_len, GFP_KERNEL);
	if (!usbio->txbuf)
		goto error;

	usbio->rxpipe = usb_rcvbulkpipe(udev, usb_endpoint_num(epin));
	usbio->rxbuf_len = usb_endpoint_maxp(epin);
	usbio->rxbuf = kzalloc(usbio->rxbuf_len, GFP_KERNEL);
	if (!usbio->rxbuf)
		goto error;

	usbio->urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!usbio->urb)
		goto error;

	usb_fill_bulk_urb(usbio->urb, udev, usbio->rxpipe,
			  usbio->rxbuf, usbio->rxbuf_len,
			  usbio_bulk_recv, usbio);
	ret = usb_submit_urb(usbio->urb, GFP_KERNEL);
	if (ret) {
		dev_err(dev, "Failed to submit usb urb");
		goto error;
	}

no_bulk:
	/* Init USBIO device */
	ret = usbio_ctrl_req(usbio, USBIO_CTRLCMD_HS, NULL, 0);
	if (ret)
		goto error;

	/* Get protocol version */
	ret = usbio_ctrl_req(usbio, USBIO_CTRLCMD_PROTVER,
			     &usbio->info.protver,
			     sizeof(usbio->info.protver));
	if (ret)
		goto error;

	/* Get firmware version */
	ret = usbio_ctrl_req(usbio, USBIO_CTRLCMD_FWVER,
			     &usbio->info.fwver, sizeof(usbio->info.fwver));
	if (ret)
		goto error;

	/* Enumerate IOs */
	ret = usbio_ctrl_enumgpios(usbio);
	if (ret)
		goto error;

	ret = usbio_ctrl_enumi2cs(usbio);
	if (ret)
		goto error;

	dev_set_drvdata(dev, usbio);
	device_create_file(dev, &dev_attr_usbio_devinfo);

	return 0;

error:
	usbio_disconnect(intf);

	return ret;
}

static const struct usb_device_id usbio_table[] = {
	{ USB_DEVICE(0x2AC1, 0x20C1) }, /* Lattice NX40 */
	{ USB_DEVICE(0x2AC1, 0x20C9) }, /* Lattice NX33 */
	{ USB_DEVICE(0x2AC1, 0x20CB) }, /* Lattice NX33U */
	{ USB_DEVICE(0x06CB, 0x0701) }, /* Synaptics Sabre */
	{ }
};
MODULE_DEVICE_TABLE(usb, usbio_table);

static struct usb_driver usbio_driver = {
	.name = "usbio-bridge",
	.probe = usbio_probe,
	.disconnect = usbio_disconnect,
	.suspend = usbio_suspend,
	.resume = usbio_resume,
	.id_table = usbio_table,
	.supports_autosuspend = 1
};
module_usb_driver(usbio_driver);

MODULE_DESCRIPTION("Intel USBIO Bridge driver");
MODULE_AUTHOR("Israel Cepeda <israel.a.cepeda.lopez@intel.com>");
MODULE_LICENSE("GPL");
