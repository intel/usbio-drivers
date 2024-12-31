// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Intel Corporation.
 *
 */

#include <linux/acpi.h>
#include <linux/platform_device.h>
#include <linux/i2c.h>
#include <linux/ioext.h>

struct usbio_i2c {
	int id;
	uint32_t speed;
	struct i2c_adapter adap;
};

static void usbio_i2c_uninit(struct i2c_adapter *adap, struct i2c_msg *msg)
{
	struct usbio_i2c *i2c = i2c_get_adapdata(adap);
	struct ioext_i2c_uninit ubuf;

	ubuf.busid = i2c->id;
	ubuf.config = msg->addr;
	usbio_transfer(IOEXT_I2C, IOEXT_I2CCMD_UNINIT,
					&ubuf, sizeof(ubuf), NULL, 0);
}

static int usbio_i2c_init(struct i2c_adapter *adap, struct i2c_msg *msg)
{
	struct usbio_i2c *i2c = i2c_get_adapdata(adap);
	struct ioext_i2c_init ibuf;
	int ret;

	ibuf.busid = i2c->id;
	ibuf.config = msg->addr;
	ibuf.speed = i2c->speed;
	ret = usbio_transfer(IOEXT_I2C, IOEXT_I2CCMD_INIT, &ibuf, sizeof(ibuf),
							&ibuf, sizeof(ibuf));
	if (ret >= 0)
		ret = ret != sizeof(ibuf) ? -EIO : 0;

	return ret;
}

static int usbio_i2c_read(struct i2c_adapter *adap, struct i2c_msg *msg)
{
	struct usbio_i2c *i2c = i2c_get_adapdata(adap);
	struct ioext_i2c_rw *rbuf;
	int ret;

	rbuf = kzalloc(sizeof(*rbuf) + msg->len, GFP_KERNEL);
	if (!rbuf)
		return -ENOMEM;

	rbuf->busid = i2c->id;
	rbuf->config = msg->addr;
	rbuf->size = msg->len;

	ret = usbio_transfer(IOEXT_I2C, IOEXT_I2CCMD_READ, rbuf, sizeof(*rbuf),
							rbuf, sizeof(*rbuf) + msg->len);
	if (ret >= 0)
		ret = ret == sizeof(*rbuf) + msg->len ? 0 : -EIO;

	if (!ret)
		memcpy(msg->buf, rbuf->data, msg->len);

	dev_dbg(adap->dev.parent, "RD[%d]:%*phN", msg->len, msg->len, msg->buf);

	kfree(rbuf);

	return ret;
}

static int usbio_i2c_write(struct i2c_adapter *adap, struct i2c_msg *msg)
{
	struct usbio_i2c *i2c = i2c_get_adapdata(adap);
	struct ioext_i2c_rw *wbuf;
	int ret;

	wbuf = kzalloc(sizeof(*wbuf) + msg->len, GFP_KERNEL);
	if (!wbuf)
		return -ENOMEM;

	wbuf->busid = i2c->id;
	wbuf->config = msg->addr;
	wbuf->size = msg->len;
	memcpy(wbuf->data, msg->buf, msg->len);

	dev_dbg(adap->dev.parent, "WR[%d]:%*phN", msg->len, msg->len, msg->buf);
	ret = usbio_transfer(IOEXT_I2C, IOEXT_I2CCMD_WRITE, wbuf,
							sizeof(*wbuf) + msg->len, wbuf, sizeof(*wbuf));
	if (ret >= 0)
		ret = ret + wbuf->size == sizeof(*wbuf) + msg->len ? 0 : -EIO;

	kfree(wbuf);

	return ret;
}

static int usbio_i2c_xfer(struct i2c_adapter *adap, struct i2c_msg *msgs,
		int num)
{
	int ret;

	ret = usbio_i2c_init(adap, msgs);
	if (ret)
		return ret;

	for (int i = 0; i < num; ret = ++i) {
		if (msgs[i].flags & I2C_M_RD)
			ret = usbio_i2c_read(adap, &msgs[i]);
		else
			ret = usbio_i2c_write(adap, &msgs[i]);

		if (ret)
			break;
	}

	usbio_i2c_uninit(adap, msgs);

	return ret;
}

static u32 usbio_i2c_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C;
}

static const struct i2c_adapter_quirks usbio_i2c_quirks = {
	.flags = I2C_AQ_NO_REP_START,
	.max_read_len = SZ_4K,
	.max_write_len = SZ_4K
};

static const struct i2c_algorithm usbio_i2c_algo = {
	.master_xfer = usbio_i2c_xfer,
	.functionality = usbio_i2c_func
};

static int usbio_i2c_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct usbio_i2c *i2c;
	char *uid;
	int ret = -EINVAL;

	i2c = devm_kzalloc(dev, sizeof(*i2c), GFP_KERNEL);
	if (!i2c)
		return -ENOMEM;

	i2c->speed = i2c_acpi_find_bus_speed(dev);
	if (!i2c->speed)
		i2c->speed = I2C_MAX_STANDARD_MODE_FREQ;

	i2c->adap.owner = THIS_MODULE;
	i2c->adap.class = I2C_CLASS_HWMON;
	i2c->adap.dev.parent = dev;
	i2c->adap.algo = &usbio_i2c_algo;
	i2c->adap.quirks = &usbio_i2c_quirks;
	ACPI_COMPANION_SET(&i2c->adap.dev, ACPI_COMPANION(dev));

	uid = acpi_device_uid(ACPI_COMPANION(dev));
	if (uid)
		for (int i = 0; i < strlen(uid); i++) {
			ret = kstrtoint(&uid[i], 10, &i2c->id);
			if (!ret)
				break;
		}
	if (ret) {
		dev_err(dev, "Invalid ACPI UID %s", uid);
		goto exit;
	}

	snprintf(i2c->adap.name, sizeof(i2c->adap.name), "%s.%d",
				"Intel USBIO I2C", i2c->id);

	platform_set_drvdata(pdev, i2c);
	i2c_set_adapdata(&i2c->adap, i2c);

	ret = i2c_add_adapter(&i2c->adap);
	if (ret)
		dev_err(dev, "Failed to add adapter %d", ret);

exit:
	if (ret) {
		devm_kfree(dev, i2c);
		return ret;
	}

	return 0;
}

static int usbio_i2c_remove(struct platform_device *pdev)
{
	struct usbio_i2c *i2c = platform_get_drvdata(pdev);
	struct device *dev = &pdev->dev;

	i2c_del_adapter(&i2c->adap);
	devm_kfree(dev, i2c);

	return 0;
}

static const struct acpi_device_id usbio_i2c_acpi_match[] = {
	{ "INTC1008" }, /* MTL */
	{ "INTC10B3" }, /* ARL */
	{ "INTC10B6" }, /* LNL */
	{ "INTC10E3" }, /* PTL */
	{ }
};
MODULE_DEVICE_TABLE(acpi, usbio_i2c_acpi_match);

static struct platform_driver usbio_i2c_driver = {
	.driver = {
		.name = "usbio-i2c",
		.acpi_match_table = usbio_i2c_acpi_match,
	},
	.probe = usbio_i2c_probe,
	.remove = usbio_i2c_remove
};
module_platform_driver(usbio_i2c_driver);

MODULE_DESCRIPTION("Intel USBIO I2C driver");
MODULE_AUTHOR("Israel Cepeda <israel.a.cepeda.lopez@intel.com>");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(USBIO);
