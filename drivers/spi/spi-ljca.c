// SPDX-License-Identifier: GPL-2.0-only

/*
 * Intel USBIO-SPI driver
 *
 * Copyright (c) 2023, Intel Corporation.
 */

#include <linux/acpi.h>
#include <linux/mfd/usbio.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>

/* SPI commands */
enum usbio_spi_cmd {
	LJCA_SPI_INIT = 1,
	LJCA_SPI_READ,
	LJCA_SPI_WRITE,
	LJCA_SPI_WRITEREAD,
	LJCA_SPI_DEINIT,
};

#define LJCA_SPI_BUS_MAX_HZ 48000000
enum {
	LJCA_SPI_BUS_SPEED_24M,
	LJCA_SPI_BUS_SPEED_12M,
	LJCA_SPI_BUS_SPEED_8M,
	LJCA_SPI_BUS_SPEED_6M,
	LJCA_SPI_BUS_SPEED_4_8M, /*4.8MHz*/
	LJCA_SPI_BUS_SPEED_MIN = LJCA_SPI_BUS_SPEED_4_8M,
};

enum {
	LJCA_SPI_CLOCK_LOW_POLARITY,
	LJCA_SPI_CLOCK_HIGH_POLARITY,
};

enum {
	LJCA_SPI_CLOCK_FIRST_PHASE,
	LJCA_SPI_CLOCK_SECOND_PHASE,
};

#define LJCA_SPI_BUF_SIZE 60
#define LJCA_SPI_MAX_XFER_SIZE                                                 \
	(LJCA_SPI_BUF_SIZE - sizeof(struct spi_xfer_packet))
union spi_clock_mode {
	struct {
		u8 polarity : 1;
		u8 phrase : 1;
		u8 reserved : 6;
	} u;

	u8 mode;
} __packed;

struct spi_init_packet {
	u8 index;
	u8 speed;
	union spi_clock_mode mode;
} __packed;

struct spi_xfer_indicator {
	u8 id : 6;
	u8 cmpl : 1;
	u8 index : 1;
};

struct spi_xfer_packet {
	struct spi_xfer_indicator indicator;
	s8 len;
	u8 data[];
} __packed;

struct usbio_spi_dev {
	struct platform_device *pdev;
	struct usbio_spi_info *ctr_info;
	struct spi_master *master;
	u8 speed;
	u8 mode;

	u8 obuf[LJCA_SPI_BUF_SIZE];
	u8 ibuf[LJCA_SPI_BUF_SIZE];
};

static int usbio_spi_read_write(struct usbio_spi_dev *usbio_spi, const u8 *w_data,
			       u8 *r_data, int len, int id, int complete,
			       int cmd)
{
	struct spi_xfer_packet *w_packet =
		(struct spi_xfer_packet *)usbio_spi->obuf;
	struct spi_xfer_packet *r_packet =
		(struct spi_xfer_packet *)usbio_spi->ibuf;
	int ret;
	int ibuf_len;

	w_packet->indicator.index = usbio_spi->ctr_info->id;
	w_packet->indicator.id = id;
	w_packet->indicator.cmpl = complete;

	if (cmd == LJCA_SPI_READ) {
		w_packet->len = sizeof(u16);
		*(u16 *)&w_packet->data[0] = len;
	} else {
		w_packet->len = len;
		memcpy(w_packet->data, w_data, len);
	}

	ret = usbio_transfer(usbio_spi->pdev, cmd, w_packet,
			    sizeof(*w_packet) + w_packet->len, r_packet,
			    &ibuf_len);
	if (ret)
		return ret;

	if (ibuf_len < sizeof(*r_packet) || r_packet->len <= 0) {
		dev_err(&usbio_spi->pdev->dev, "receive patcket error len %d\n",
			r_packet->len);
		return -EIO;
	}

	if (r_data)
		memcpy(r_data, r_packet->data, r_packet->len);

	return 0;
}

static int usbio_spi_init(struct usbio_spi_dev *usbio_spi, int div, int mode)
{
	struct spi_init_packet w_packet = { 0 };
	int ret;

	if (usbio_spi->mode == mode && usbio_spi->speed == div)
		return 0;

	if (mode & SPI_CPOL)
		w_packet.mode.u.polarity = LJCA_SPI_CLOCK_HIGH_POLARITY;
	else
		w_packet.mode.u.polarity = LJCA_SPI_CLOCK_LOW_POLARITY;

	if (mode & SPI_CPHA)
		w_packet.mode.u.phrase = LJCA_SPI_CLOCK_SECOND_PHASE;
	else
		w_packet.mode.u.phrase = LJCA_SPI_CLOCK_FIRST_PHASE;

	w_packet.index = usbio_spi->ctr_info->id;
	w_packet.speed = div;
	ret = usbio_transfer(usbio_spi->pdev, LJCA_SPI_INIT, &w_packet,
			    sizeof(w_packet), NULL, NULL);
	if (ret)
		return ret;

	usbio_spi->mode = mode;
	usbio_spi->speed = div;
	return 0;
}

static int usbio_spi_deinit(struct usbio_spi_dev *usbio_spi)
{
	struct spi_init_packet w_packet = { 0 };

	w_packet.index = usbio_spi->ctr_info->id;
	return usbio_transfer(usbio_spi->pdev, LJCA_SPI_DEINIT, &w_packet,
			     sizeof(w_packet), NULL, NULL);
}

static int usbio_spi_transfer(struct usbio_spi_dev *usbio_spi, const u8 *tx_data,
			     u8 *rx_data, u16 len)
{
	int ret;
	int remaining = len;
	int offset = 0;
	int cur_len;
	int complete = 0;
	int i;

	for (i = 0; remaining > 0;
	     offset += cur_len, remaining -= cur_len, i++) {
		dev_dbg(&usbio_spi->pdev->dev,
			"fragment %d offset %d remaining %d ret %d\n", i,
			offset, remaining, ret);

		if (remaining > LJCA_SPI_MAX_XFER_SIZE) {
			cur_len = LJCA_SPI_MAX_XFER_SIZE;
		} else {
			cur_len = remaining;
			complete = 1;
		}

		if (tx_data && rx_data)
			ret = usbio_spi_read_write(usbio_spi, tx_data + offset,
						  rx_data + offset, cur_len, i,
						  complete, LJCA_SPI_WRITEREAD);
		else if (tx_data)
			ret = usbio_spi_read_write(usbio_spi, tx_data + offset,
						  NULL, cur_len, i, complete,
						  LJCA_SPI_WRITE);
		else if (rx_data)
			ret = usbio_spi_read_write(usbio_spi, NULL,
						  rx_data + offset, cur_len, i,
						  complete, LJCA_SPI_READ);
		else
			return -EINVAL;

		if (ret)
			return ret;
	}

	return 0;
}

static int usbio_spi_prepare_message(struct spi_master *master,
				    struct spi_message *message)
{
	struct usbio_spi_dev *usbio_spi = spi_master_get_devdata(master);
	struct spi_device *spi = message->spi;

	dev_dbg(&usbio_spi->pdev->dev, "cs %d\n", spi->chip_select);
	return 0;
}

static int usbio_spi_transfer_one(struct spi_master *master,
				 struct spi_device *spi,
				 struct spi_transfer *xfer)
{
	struct usbio_spi_dev *usbio_spi = spi_master_get_devdata(master);
	int ret;
	int div;

	div = DIV_ROUND_UP(master->max_speed_hz, xfer->speed_hz) / 2 - 1;
	if (div > LJCA_SPI_BUS_SPEED_MIN)
		div = LJCA_SPI_BUS_SPEED_MIN;

	ret = usbio_spi_init(usbio_spi, div, spi->mode);
	if (ret < 0) {
		dev_err(&usbio_spi->pdev->dev,
			"cannot initialize transfer ret %d\n", ret);
		return ret;
	}

	ret = usbio_spi_transfer(usbio_spi, xfer->tx_buf, xfer->rx_buf,
				xfer->len);
	if (ret < 0)
		dev_err(&usbio_spi->pdev->dev, "ljca spi transfer failed!\n");

	return ret;
}

static int usbio_spi_probe(struct platform_device *pdev)
{
	struct spi_master *master;
	struct usbio_spi_dev *usbio_spi;
	struct usbio_platform_data *pdata = dev_get_platdata(&pdev->dev);
	int ret;

	master = spi_alloc_master(&pdev->dev, sizeof(*usbio_spi));
	if (!master)
		return -ENOMEM;

	platform_set_drvdata(pdev, master);
	usbio_spi = spi_master_get_devdata(master);

	usbio_spi->ctr_info = &pdata->spi_info;
	usbio_spi->master = master;
	usbio_spi->master->dev.of_node = pdev->dev.of_node;
	usbio_spi->pdev = pdev;

	ACPI_COMPANION_SET(&usbio_spi->master->dev, ACPI_COMPANION(&pdev->dev));

	master->bus_num = -1;
	master->mode_bits = SPI_CPHA | SPI_CPOL;
	master->prepare_message = usbio_spi_prepare_message;
	master->transfer_one = usbio_spi_transfer_one;
	master->auto_runtime_pm = false;
	master->max_speed_hz = LJCA_SPI_BUS_MAX_HZ;

	ret = devm_spi_register_master(&pdev->dev, master);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to register master\n");
		goto exit_free_master;
	}

	return ret;

exit_free_master:
	spi_master_put(master);
	return ret;
}

static int usbio_spi_dev_remove(struct platform_device *pdev)
{
	struct spi_master *master = spi_master_get(platform_get_drvdata(pdev));
	struct usbio_spi_dev *usbio_spi = spi_master_get_devdata(master);

	usbio_spi_deinit(usbio_spi);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int usbio_spi_dev_suspend(struct device *dev)
{
	struct spi_master *master = dev_get_drvdata(dev);

	return spi_master_suspend(master);
}

static int usbio_spi_dev_resume(struct device *dev)
{
	struct spi_master *master = dev_get_drvdata(dev);

	return spi_master_resume(master);
}
#endif /* CONFIG_PM_SLEEP */

static const struct dev_pm_ops usbio_spi_pm = {
	SET_SYSTEM_SLEEP_PM_OPS(usbio_spi_dev_suspend, usbio_spi_dev_resume)
};

static struct platform_driver spi_usbio_driver = {
	.driver = {
		.name	= "usb-spi",
		.pm	= &usbio_spi_pm,
	},
	.probe		= usbio_spi_probe,
	.remove		= usbio_spi_dev_remove,
};

module_platform_driver(spi_usbio_driver);

MODULE_AUTHOR("Ye Xiang <xiang.ye@intel.com>");
MODULE_DESCRIPTION("Intel La Jolla Cove Adapter USB-SPI driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:usb-spi");
