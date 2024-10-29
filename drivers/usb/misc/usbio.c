// SPDX-License-Identifier: GPL-2.0
/*
 * Intel USBIO Extension Bridge driver
 *
 * Copyright (c) 2025 Intel Corporation.
 *
 */

#include "usbio.h"

static int usbio_control_msg(struct usbio_device *bridge,
		struct usbio_packet_header *pkt, const void *obuf,
		u16 obuf_len, void *ibuf, u16 ibuf_len)
{
	struct usbio_ctrl_packet *cpkt;
	unsigned int pipe;
	u16 cpkt_len = sizeof(*cpkt) + obuf_len;
	u8 request = USB_TYPE_VENDOR | USB_RECIP_DEVICE;
	int ret;

	if (!bridge || !pkt || (!obuf && obuf_len) || (!ibuf && ibuf_len))
		return -EINVAL;

	if (cpkt_len > bridge->ctrlbuf_len) {
		dev_err(bridge->dev, "Packet size error: %u > %u",
				cpkt_len, bridge->ctrlbuf_len);
		return -EMSGSIZE;
	}

	/* Prepare Control Packet Header */
	cpkt = bridge->ctrlbuf;
	cpkt->header.type = pkt->type;
	cpkt->header.cmd = pkt->cmd;
	cpkt->header.flags = pkt->flags;
	cpkt->len = obuf_len;

	/* Copy the data */
	memcpy(cpkt->data, obuf, obuf_len);

	pipe = usb_sndctrlpipe(bridge->udev, bridge->ctrl_pipe);
	ret = usb_control_msg(bridge->udev, pipe, 0, request | USB_DIR_OUT, 0, 0,
							(void *)cpkt, cpkt_len, USBIO_CTRLXFER_TIMEOUT);
	dev_dbg(bridge->dev, "usb control sent: %d", ret);
	dev_dbg(bridge->dev, "\thdr: %*phN data: %*phN", (int)sizeof(*cpkt),
			cpkt, (int)cpkt->len, cpkt->data);

	if (ret < 0 || ret != cpkt_len)
		return -EIO;

	if (pkt->flags & USBIO_PKTFLAG_ACK) {
		cpkt_len = sizeof(*cpkt) + ibuf_len;

		if (cpkt_len > bridge->ctrlbuf_len) {
			dev_err(bridge->dev, "Packet size error: %u > %u",
					cpkt_len, bridge->ctrlbuf_len);
			return -EMSGSIZE;
		}

		pipe = usb_rcvctrlpipe(bridge->udev, bridge->ctrl_pipe);
		ret = usb_control_msg(bridge->udev, pipe, 0, request | USB_DIR_IN,
								0, 0, (void *)cpkt, cpkt_len,
								USBIO_CTRLXFER_TIMEOUT);
		dev_dbg(bridge->dev, "usb control received: %d", ret);
		dev_dbg(bridge->dev, "\thdr: %*phN data: %*phN", (int)sizeof(*cpkt),
				cpkt, (int)cpkt->len, cpkt->data);

		if (ret < sizeof(*cpkt))
			return -EIO;

		ret = -EINVAL;
		if (cpkt->header.type == pkt->type &&
				cpkt->header.cmd == pkt->cmd &&
				cpkt->header.flags & USBIO_PKTFLAGS_ISRSP) {
			if (!(cpkt->header.flags & USBIO_PKTFLAG_ERR)) {
				if (ibuf_len < cpkt->len)
					return -ENOBUFS;
				/* Copy the data */
				memcpy(ibuf, cpkt->data, cpkt->len);
				ret = cpkt->len;
			} else
				dev_err(bridge->dev,
						"Packet error type: %u, cmd: %u, flags: %u",
						cpkt->header.type, cpkt->header.cmd,
						cpkt->header.flags);
		} else
			dev_err(bridge->dev,
					"Unexpected reply type: %u, cmd: %u, flags: %u",
					cpkt->header.type, cpkt->header.cmd,
					cpkt->header.flags);
	} else
		ret = cpkt_len - sizeof(*cpkt);

	return ret;
}

static int usbio_ctrl_protver(struct usbio_device *bridge)
{
	struct usbio_packet_header pkt = {
		USBIO_PKTTYPE_CTRL,
		USBIO_CTRLCMD_PROTVER,
		USBIO_PKTFLAGS_REQRESP
	};
	struct usbio_protver *prot;
	int ret;

	prot = &bridge->info.protver;
	ret = usbio_control_msg(bridge, &pkt, 0, 0, &prot->ver, sizeof(*prot));
	if (ret != sizeof(*prot)) {
		dev_err(bridge->dev, "CTRL PROTVER failed: %d", ret);
		return -EIO;
	}

	return 0;
}

static int usbio_ctrl_fwver(struct usbio_device *bridge)
{
	struct usbio_packet_header pkt = {
		USBIO_PKTTYPE_CTRL,
		USBIO_CTRLCMD_FWVER,
		USBIO_PKTFLAGS_REQRESP
	};
	struct usbio_fwver *ver;
	int ret;

	ver = &bridge->info.fwver;
	ret = usbio_control_msg(bridge, &pkt, 0, 0, ver, sizeof(*ver));
	if (ret != sizeof(*ver)) {
		dev_err(bridge->dev, "CTRL FWVER failed: %d", ret);
		return -EIO;
	}

	return 0;
}

static int usbio_ctrl_handshake(struct usbio_device *bridge)
{
	struct usbio_packet_header pkt = {
		USBIO_PKTTYPE_CTRL,
		USBIO_CTRLCMD_HS,
		USBIO_PKTFLAGS_REQRESP
	};
	int ret;

	ret = usbio_control_msg(bridge, &pkt, 0, 0, 0, 0);
	if (ret) {
		dev_err(bridge->dev, "CTRL HANDSHAKE failed: %d", ret);
		return -EIO;
	}

	return 0;
}

static int usbio_ctrl_enumgpios(struct usbio_device *bridge)
{
	struct usbio_packet_header pkt = {
		USBIO_PKTTYPE_CTRL,
		USBIO_CTRLCMD_ENUMGPIO,
		USBIO_PKTFLAGS_REQRESP
	};
	struct usbio_gpio_bank_desc *gpio;
	int ret, i;

	gpio = bridge->gpios;
	ret = usbio_control_msg(bridge, &pkt, 0, 0, gpio, sizeof(bridge->gpios));
	if (ret <= 0 || ret % sizeof(*gpio)) {
		dev_err(bridge->dev, "CTRL ENUMGPIO failed: %d", ret);
		return 0;
	}

	ret /= sizeof(*gpio);
	dev_info(bridge->dev, "GPIO Banks: %d", ret);
	for (i = 0; i < ret; i++)
		dev_info(bridge->dev, "\tBank%d[%d] map: %#08x",
					gpio[i].id, gpio[i].pins, gpio[i].bmap);

	return ret;
}

static int usbio_ctrl_enumi2cs(struct usbio_device *bridge)
{
	struct usbio_packet_header pkt = {
		USBIO_PKTTYPE_CTRL,
		USBIO_CTRLCMD_ENUMI2C,
		USBIO_PKTFLAGS_REQRESP
	};
	struct usbio_i2c_bus_desc *i2c;
	int ret, i;

	i2c = bridge->i2cs;
	ret = usbio_control_msg(bridge, &pkt, 0, 0, i2c, sizeof(bridge->i2cs));
	if (ret <= 0 || ret % sizeof(*i2c)) {
		dev_err(bridge->dev, "CTRL ENUMI2C failed: %d", ret);
		return 0;
	}

	ret /= sizeof(*i2c);
	dev_info(bridge->dev, "I2C Buses: %d", ret);
	for (i = 0; i < ret; i++)
		dev_info(bridge->dev, "\tBus%d caps: %#02x", i2c[i].id, i2c[i].caps);

	return ret;
}

static int usbio_ctrl_enumspis(struct usbio_device *bridge)
{
	struct usbio_packet_header pkt = {
		USBIO_PKTTYPE_CTRL,
		USBIO_CTRLCMD_ENUMSPI,
		USBIO_PKTFLAGS_REQRESP
	};
	struct usbio_spi_bus_desc *spi;
	int ret, i;

	spi = bridge->spis;
	ret = usbio_control_msg(bridge, &pkt, 0, 0, spi, sizeof(bridge->spis));
	if (ret <= 0 || ret % sizeof(*spi)) {
		dev_err(bridge->dev, "CTRL ENUMSPI failed: %d", ret);
		return 0;
	}

	ret /= sizeof(*spi);
	dev_info(bridge->dev, "SPI Buses: %d", ret);
	for (i = 0; i < ret; i++)
		dev_info(bridge->dev, "\tBus%d caps: %#02x", spi[i].id, spi[i].caps);

	return ret;
}

static void usbio_disconnect(struct usb_interface *intf)
{
	struct device *dev = &intf->dev;
	struct usbio_device *bridge = usb_get_intfdata(intf);

	usb_set_intfdata(intf, NULL);
	usb_put_intf(intf);

	kfree(bridge->ctrlbuf);
	kfree(bridge->txbuf);
	kfree(bridge->rxbuf);

	devm_kfree(dev, bridge);
}

static int usbio_probe(struct usb_interface *intf,
						const struct usb_device_id *id)
{
	struct usb_device *udev = interface_to_usbdev(intf);
	struct usb_endpoint_descriptor *ep_in, *ep_out;
	struct device *dev = &intf->dev;
	struct usbio_device *bridge;
	int ret = -ENOMEM;

	bridge = devm_kzalloc(dev, sizeof(*bridge), GFP_KERNEL);
	if (!bridge)
		return ret;

	bridge->dev = dev;
	bridge->udev = udev;
	bridge->intf = usb_get_intf(intf);
	usb_set_intfdata(intf, bridge);

	bridge->ctrl_pipe = usb_endpoint_num(&udev->ep0.desc);
	bridge->ctrlbuf_len = usb_maxpacket(udev, bridge->ctrl_pipe);
	bridge->ctrlbuf = kzalloc(bridge->ctrlbuf_len, GFP_KERNEL);
	if (!bridge->ctrlbuf) {
		dev_err(dev, "Failed to allocate ctrlbuf of %u",
				bridge->ctrlbuf_len);
		goto error;
	}

	dev_dbg(dev, "ep0: %u size: %u\n",
			usb_pipeendpoint(bridge->ctrl_pipe), bridge->ctrlbuf_len);

	/* Find the first bulk-in and bulk-out endpoints */
	ret = usb_find_common_endpoints(intf->cur_altsetting,
									&ep_in, &ep_out, NULL, NULL);
	if (!ret) {
		ret = -ENOMEM;
		bridge->tx_pipe = usb_sndbulkpipe(udev, usb_endpoint_num(ep_out));
		bridge->txbuf_len = usb_endpoint_maxp(ep_out);
		bridge->txbuf = kzalloc(bridge->txbuf_len, GFP_KERNEL);
		if (!bridge->txbuf) {
			dev_err(dev, "Failed to allocate txbuf of %u",
					bridge->txbuf_len);
			goto error;
		}

		bridge->rx_pipe = usb_rcvbulkpipe(udev, usb_endpoint_num(ep_in));
		bridge->rxbuf_len = usb_endpoint_maxp(ep_in);
		bridge->rxbuf = kzalloc(bridge->rxbuf_len, GFP_KERNEL);
		if (!bridge->rxbuf) {
			dev_err(dev, "Failed to allocate rxbuf of %u",
					bridge->rxbuf_len);
			goto error;
		}

		dev_dbg(dev, "ep_out: %#02x size: %u ep_in: %#02x size: %u",
				ep_out->bEndpointAddress, bridge->txbuf_len,
				ep_in->bEndpointAddress, bridge->rxbuf_len);
	} else
		dev_warn(dev, "Couldn't find both bulk-in and bulk-out endpoints");

	ret = usbio_ctrl_handshake(bridge);
	if (ret)
		goto error;

	ret = usbio_ctrl_protver(bridge);
	if (ret)
		goto error;

	ret = usbio_ctrl_fwver(bridge);
	if (ret)
		goto error;

	dev_info(dev, "ProtVer(BCD): %02x FwVer: %d.%d.%d.%d",
				bridge->info.protver.ver, bridge->info.fwver.major,
				bridge->info.fwver.minor, bridge->info.fwver.patch,
				bridge->info.fwver.build);

	bridge->nr_gpio_banks = usbio_ctrl_enumgpios(bridge);
	bridge->nr_i2c_buses = usbio_ctrl_enumi2cs(bridge);
	bridge->nr_spi_buses = usbio_ctrl_enumspis(bridge);

	return 0;

error:
	usbio_disconnect(intf);

	return ret;
}

static const struct usb_device_id usbio_table[] = {
	{ USB_DEVICE(0x8086, 0x1087) }, /* Raspberry Pico */
	{ USB_DEVICE(0x2AC1, 0x20C1) }, /* Lattice NX40 */
	{ USB_DEVICE(0x2AC1, 0x20C9) }, /* Lattice NX33 */
	{ USB_DEVICE(0x2AC1, 0x20CB) }, /* Lattice NX33U */
	{ USB_DEVICE(0x06CB, 0x0701) }, /* Synaptics Sabre */
	{ }
};
MODULE_DEVICE_TABLE(usb, usbio_table);

static struct usb_driver usbbridge_driver = {
	.name = "usbio-bridge",
	.probe = usbio_probe,
	.disconnect = usbio_disconnect,
	.id_table = usbio_table,
	.supports_autosuspend = 1
};
module_usb_driver(usbbridge_driver);

MODULE_DESCRIPTION("Intel USBIO Bridge driver");
MODULE_AUTHOR("Israel Cepeda <israel.a.cepeda.lopez@intel.com>");
MODULE_LICENSE("GPL");
