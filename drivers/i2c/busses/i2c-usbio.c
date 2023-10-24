// SPDX-License-Identifier: GPL-2.0-only

/*
 * Intel USBIO-I2C driver
 *
 * Copyright (c) 2023, Intel Corporation.
 */

#include <linux/acpi.h>
#include <linux/i2c.h>
#include <linux/mfd/usbio.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/version.h>

/* I2C commands */
enum i2c_cmd {
	I2C_DEINIT,
	I2C_INIT,
	I2C_READ,
	I2C_WRITE,
	I2C_XFER
};

enum i2c_address_mode {
	I2C_ADDRESS_MODE_7BIT,
	I2C_ADDRESS_MODE_10BIT,
};

/* Speeds */
#define I2C_400KHZ 400000

/* i2c init flags */
#define I2C_INIT_FLAG_MODE_MASK (0x1 << 0)
#define I2C_INIT_FLAG_MODE_POLLING (0x0 << 0)
#define I2C_INIT_FLAG_MODE_INTERRUPT (0x1 << 0)

#define I2C_FLAG_ADDR_16BIT (0x1 << 0)

#define I2C_INIT_FLAG_FREQ_MASK (0x3 << 1)
#define I2C_FLAG_FREQ_100K (0x0 << 1)
#define I2C_FLAG_FREQ_400K (0x1 << 1)
#define I2C_FLAG_FREQ_1M (0x2 << 1)

/* I2C init commands: Init/Deinit */
struct i2c_init_packet {
	u8 id;
	u16 config;
	u32 speed;
} __packed;

/* I2C RW commands: Read/Write */
struct i2c_rw_packet {
	u8 id;
	u16 config;
	u16 len;
	u8 data[];
} __packed;

/* I2C Transfer */
struct i2c_xfer {
	u8 id;
	u16 config;
	u16 wlen;
	u16 rlen;
	u8 data[];
} __packed;

#define USBIO_I2C_MAX_XFER_SIZE 256
#define USBIO_I2C_BUF_SIZE                                                      \
	(USBIO_I2C_MAX_XFER_SIZE + sizeof(struct i2c_rw_packet))

struct usbio_i2c_dev {
	struct platform_device *pdev;
	struct usbio_i2c_info *ctr_info;
	struct i2c_adapter adap;

	u8 obuf[USBIO_I2C_BUF_SIZE];
	u8 ibuf[USBIO_I2C_BUF_SIZE];
};

static u16 usbio_i2c_format_slave_addr(u8 slave_addr, enum i2c_address_mode mode)
{
	if (mode == I2C_ADDRESS_MODE_7BIT)
		return (u16)slave_addr;

	return 0xFF;
}

static int usbio_i2c_start(struct usbio_i2c_dev *usbio_i2c, u8 slave_addr)
{
	struct i2c_init_packet *w_packet = (struct i2c_init_packet *)usbio_i2c->obuf;
	int ret;

	memset(w_packet, 0, sizeof(*w_packet));
	w_packet->id = usbio_i2c->ctr_info->id;
	/* TODO: Add support for 10Bit address and multiple speeds */
	w_packet->config = usbio_i2c_format_slave_addr(slave_addr, I2C_ADDRESS_MODE_7BIT);
	w_packet->speed = I2C_400KHZ;

	ret = usbio_transfer_noack(usbio_i2c->pdev, I2C_INIT, w_packet,
			    sizeof(*w_packet));

	if (ret) {
		dev_err(&usbio_i2c->adap.dev,
			"i2c start failed ret:%d\n", ret);
		return -EIO;
	}

	return 0;
}

static int usbio_i2c_stop(struct usbio_i2c_dev *usbio_i2c, u8 slave_addr)
{
	struct i2c_init_packet *w_packet = (struct i2c_init_packet *)usbio_i2c->obuf;
	int ret;

	memset(w_packet, 0, sizeof(*w_packet));
	w_packet->id = usbio_i2c->ctr_info->id;
	/* TODO: Add support for 10Bit address */
	w_packet->config = usbio_i2c_format_slave_addr(slave_addr, I2C_ADDRESS_MODE_7BIT);

	ret = usbio_transfer_noack(usbio_i2c->pdev, I2C_DEINIT, w_packet,
			    sizeof(*w_packet));

	if (ret) {
		dev_err(&usbio_i2c->adap.dev,
			"i2c stop failed ret:%d\n", ret);
		return -EIO;
	}

	return 0;
}

static int usbio_i2c_pure_read(struct usbio_i2c_dev *usbio_i2c, u8 slave_addr, u8 *data, int len)
{
	struct i2c_rw_packet *w_packet = (struct i2c_rw_packet *)usbio_i2c->obuf;
	struct i2c_rw_packet *r_packet = (struct i2c_rw_packet *)usbio_i2c->ibuf;
	int ibuf_len;
	int ret;

	if (len > USBIO_I2C_MAX_XFER_SIZE)
		return -EINVAL;

	memset(w_packet, 0, sizeof(*w_packet));
	w_packet->id = usbio_i2c->ctr_info->id;
	/* TODO: Add support for 10Bit address */
	w_packet->config = usbio_i2c_format_slave_addr(slave_addr, I2C_ADDRESS_MODE_7BIT);
	w_packet->len = cpu_to_le16(len);
	ret = usbio_transfer(usbio_i2c->pdev, I2C_READ, w_packet,
			    sizeof(*w_packet) + 1, r_packet, &ibuf_len);
	if (ret) {
		dev_err(&usbio_i2c->adap.dev, "I2C_READ failed ret:%d\n", ret);
		return ret;
	}

	if (ibuf_len < sizeof(*r_packet))
		return -EIO;

	if ((s16)le16_to_cpu(r_packet->len) != len ||
	    r_packet->id != w_packet->id) {
		dev_err(&usbio_i2c->adap.dev,
			"i2c raw read failed len:%d id:%d %d\n",
			(s16)le16_to_cpu(r_packet->len), r_packet->id,
			w_packet->id);
		return -EIO;
	}

	memcpy(data, r_packet->data, len);

	return 0;
}

static int usbio_i2c_read(struct usbio_i2c_dev *usbio_i2c, u8 slave_addr, u8 *data,
			 u8 len)
{
	int ret;

	ret = usbio_i2c_start(usbio_i2c, slave_addr);
	if (ret)
		return ret;

	ret = usbio_i2c_pure_read(usbio_i2c, slave_addr, data, len);
	if (ret) {
		dev_err(&usbio_i2c->adap.dev, "i2c raw read failed ret:%d\n",
			ret);

		return ret;
	}

	return usbio_i2c_stop(usbio_i2c, slave_addr);
}

static int usbio_i2c_pure_write(struct usbio_i2c_dev *usbio_i2c, u8 slave_addr, u8 *data, int len)
{
	struct i2c_rw_packet *w_packet = (struct i2c_rw_packet *)usbio_i2c->obuf;
	struct i2c_rw_packet *r_packet = (struct i2c_rw_packet *)usbio_i2c->ibuf;
	int ret;
	int ibuf_len;

	if (len > USBIO_I2C_MAX_XFER_SIZE)
		return -EINVAL;

	memset(w_packet, 0, sizeof(*w_packet));
	w_packet->id = usbio_i2c->ctr_info->id;
	/* TODO: Add support for 10Bit address */
	w_packet->config = usbio_i2c_format_slave_addr(slave_addr, I2C_ADDRESS_MODE_7BIT);
	w_packet->len = cpu_to_le16(len);
	memcpy(w_packet->data, data, len);

	ret = usbio_transfer(usbio_i2c->pdev, I2C_WRITE, w_packet,
			    sizeof(*w_packet) + w_packet->len, r_packet,
			    &ibuf_len);

	if (ret || ibuf_len < sizeof(*r_packet))
		return -EIO;

	if ((s16)le16_to_cpu(r_packet->len) != len ||
	    r_packet->id != w_packet->id) {
		dev_err(&usbio_i2c->adap.dev,
			"i2c write failed len:%d id:%d/%d\n",
			(s16)le16_to_cpu(r_packet->len), r_packet->id,
			w_packet->id);
		return -EIO;
	}

	return 0;
}

static int usbio_i2c_write(struct usbio_i2c_dev *usbio_i2c, u8 slave_addr,
			  u8 *data, u8 len)
{
	int ret;

	if (!data)
		return -EINVAL;

	ret = usbio_i2c_start(usbio_i2c, slave_addr);
	if (ret)
		return ret;

	ret = usbio_i2c_pure_write(usbio_i2c, slave_addr, data, len);
	if (ret)
		return ret;

	return usbio_i2c_stop(usbio_i2c, slave_addr);
}

static int usbio_i2c_xfer(struct i2c_adapter *adapter, struct i2c_msg *msg,
			 int num)
{
	struct usbio_i2c_dev *usbio_i2c;
	struct i2c_msg *cur_msg;
	int i, ret;

	usbio_i2c = i2c_get_adapdata(adapter);
	if (!usbio_i2c)
		return -EINVAL;

	for (i = 0; i < num; i++) {
		cur_msg = &msg[i];
		dev_dbg(&adapter->dev, "i:%d msg:(%d %d)\n", i, cur_msg->flags,
			cur_msg->len);
		if (cur_msg->flags & I2C_M_RD)
			ret = usbio_i2c_read(usbio_i2c, cur_msg->addr,
					    cur_msg->buf, cur_msg->len);

		else
			ret = usbio_i2c_write(usbio_i2c, cur_msg->addr,
					     cur_msg->buf, cur_msg->len);

		if (ret)
			return ret;
	}

	return num;
}

static u32 usbio_i2c_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_adapter_quirks usbio_i2c_quirks = {
	.max_read_len = USBIO_I2C_MAX_XFER_SIZE,
	.max_write_len = USBIO_I2C_MAX_XFER_SIZE,
};

static const struct i2c_algorithm usbio_i2c_algo = {
	.master_xfer = usbio_i2c_xfer,
	.functionality = usbio_i2c_func,
};

struct match_ids_walk_data {
	struct acpi_device *adev;
	const char *hid1;
	const char *uid2;
	const char *uid2_v2;
};

static int match_device_ids(struct acpi_device *adev, void *data)
{
	struct match_ids_walk_data *wd = data;

	if (acpi_dev_hid_uid_match(adev, wd->hid1, wd->uid2) ||
	    acpi_dev_hid_uid_match(adev, wd->hid1, wd->uid2_v2)) {
		wd->adev = adev;
		return 1;
	}

	return 0;
}

static void try_bind_acpi(struct platform_device *pdev,
			  struct usbio_i2c_dev *usbio_i2c)
{
	struct acpi_device *parent;
	struct acpi_device *cur = ACPI_COMPANION(&pdev->dev);
	const char *hid1;
	const char *uid1;
	char uid2[2] = { 0 };
	char uid2_v2[5] = { 0 };
	struct match_ids_walk_data wd = { 0 };

	if (!cur)
		return;

	hid1 = acpi_device_hid(cur);
	uid1 = acpi_device_uid(cur);
	snprintf(uid2, sizeof(uid2), "%d", usbio_i2c->ctr_info->id);
	snprintf(uid2_v2, sizeof(uid2_v2), "VIC%d", usbio_i2c->ctr_info->id);

	/*
	* If the pdev is bound to the right acpi device, just forward it to the
	* adapter. Otherwise, we find that of current adapter manually.
	*/
	if (!uid1 || !strcmp(uid1, uid2) || !strcmp(uid1, uid2_v2)) {
		ACPI_COMPANION_SET(&usbio_i2c->adap.dev, cur);
		return;
	}

	dev_info(&pdev->dev, "hid %s uid %s new uid%s\n", hid1, uid1, uid2);
	parent = ACPI_COMPANION(pdev->dev.parent);
	if (!parent)
		return;

	wd.hid1 = hid1;
	wd.uid2 = uid2;
	wd.uid2_v2 = uid2_v2;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	acpi_dev_for_each_child(parent, match_device_ids, &wd);
	ACPI_COMPANION_SET(&usbio_i2c->adap.dev, wd.adev);
#else
	list_for_each_entry(wd.adev, &parent->children, node) {
		if (match_device_ids(wd.adev, &wd)) {
			ACPI_COMPANION_SET(&usbio_i2c->adap.dev, wd.adev);
			return;
		}
	}
#endif
}

static int usbio_i2c_probe(struct platform_device *pdev)
{
	struct usbio_i2c_dev *usbio_i2c;
	struct usbio_platform_data *pdata = dev_get_platdata(&pdev->dev);
	int ret;

	usbio_i2c = devm_kzalloc(&pdev->dev, sizeof(*usbio_i2c), GFP_KERNEL);
	if (!usbio_i2c)
		return -ENOMEM;

	usbio_i2c->pdev = pdev;
	usbio_i2c->ctr_info = &pdata->i2c_info;

	usbio_i2c->adap.owner = THIS_MODULE;
	usbio_i2c->adap.class = I2C_CLASS_HWMON;
	usbio_i2c->adap.algo = &usbio_i2c_algo;
	usbio_i2c->adap.dev.parent = &pdev->dev;

	try_bind_acpi(pdev, usbio_i2c);

	usbio_i2c->adap.dev.of_node = pdev->dev.of_node;
	i2c_set_adapdata(&usbio_i2c->adap, usbio_i2c);
	snprintf(usbio_i2c->adap.name, sizeof(usbio_i2c->adap.name), "%s-%s-%d",
		 "usbio-i2c", dev_name(pdev->dev.parent),
		 usbio_i2c->ctr_info->id);

	platform_set_drvdata(pdev, usbio_i2c);

	ret = i2c_add_adapter(&usbio_i2c->adap);
	if (ret)
		return ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	if (has_acpi_companion(&usbio_i2c->adap.dev))
		acpi_dev_clear_dependencies(ACPI_COMPANION(&usbio_i2c->adap.dev));
#endif

	return 0;
}

static int usbio_i2c_remove(struct platform_device *pdev)
{
	struct usbio_i2c_dev *usbio_i2c = platform_get_drvdata(pdev);

	i2c_del_adapter(&usbio_i2c->adap);

	return 0;
}

static struct platform_driver usbio_i2c_driver = {
	.driver.name = "usbio-i2c",
	.probe = usbio_i2c_probe,
	.remove = usbio_i2c_remove,
};

module_platform_driver(usbio_i2c_driver);

MODULE_AUTHOR("Lifu Wang <lifu.wang@intel.com>");
MODULE_AUTHOR("Ye Xiang <xiang.ye@intel.com>");
MODULE_AUTHOR("Zhang Lixu <lixu.zhang@intel.com>");
MODULE_AUTHOR("Israel Cepeda <israel.a.cepeda.lopez@intel.com>");
MODULE_DESCRIPTION("Intel USBIO-I2C driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:usbio-i2c");
