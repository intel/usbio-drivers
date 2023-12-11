// SPDX-License-Identifier: GPL-2.0-only

/*
 * Intel USBIO-GPIO driver
 *
 * Copyright (c) 2023, Intel Corporation.
 */

#include <linux/acpi.h>
#include <linux/gpio/driver.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/mfd/usbio.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/bitops.h>

/* GPIO commands */
#define GPIO_DEINIT 0
#define GPIO_INIT 1
#define GPIO_READ 2
#define GPIO_WRITE 3

/* Deprecated */
#define GPIO_INT_EVENT 4
#define GPIO_INT_MASK 5
#define GPIO_INT_UNMASK 6

/* PinMode */
#define GPIO_CONF_DISABLED	0
#define GPIO_CONF_INPUT		1
#define GPIO_CONF_OUTPUT	2

/* PinConfig */
#define GPIO_CONF_DEFAULT	(0<<2)
#define GPIO_CONF_PULLUP	(1<<2)
#define GPIO_CONF_PULLDOWN	(2<<2)
#define GPIO_CONF_NONE		(3<<2)

/* Deprecated */
#define GPIO_CONF_INTERRUPT BIT(6)
#define GPIO_INT_TYPE BIT(7)

#define GPIO_CONF_EDGE (1 << 7)
#define GPIO_CONF_LEVEL (0 << 7)

#define IRQ_SUPPORT 0

struct gpio_cfg_packet {
	u8 bankid;
	u8 config;
	u8 pincount;
	u8 pins;
} __packed;

struct gpio_rw_packet {
	u8 bankid;
	u8 pincount;
	u8 pins;
	u32 value;
} __packed;

struct usbio_gpio_dev {
	struct platform_device *pdev;
	struct gpio_chip gc;
	struct usbio_gpio_info *ctr_info;
	DECLARE_BITMAP(unmasked_irqs, MAX_GPIO_NUM);
	DECLARE_BITMAP(enabled_irqs, MAX_GPIO_NUM);
	DECLARE_BITMAP(reenable_irqs, MAX_GPIO_NUM);
	u8 *connect_mode;
	struct mutex irq_lock;
	struct work_struct work;
	struct mutex trans_lock;

	u8 obuf[256];
	u8 ibuf[256];
};

static bool usbio_gpio_valid(struct usbio_gpio_dev *usbio_gpio, int gpio_id)
{
	if (gpio_id >= usbio_gpio->ctr_info->num ||
	    !test_bit(gpio_id, usbio_gpio->ctr_info->valid_pin_map)) {
		dev_err(&usbio_gpio->pdev->dev,
			"invalid gpio_id:%d\n", gpio_id);
		return false;
	}

	return true;
}

static int gpio_config(struct usbio_gpio_dev *usbio_gpio, u8 gpio_id, u8 config)
{
	struct gpio_cfg_packet *packet = (struct gpio_cfg_packet *)usbio_gpio->obuf;
	int ret;

	if (!usbio_gpio_valid(usbio_gpio, gpio_id))
		return -EINVAL;

	mutex_lock(&usbio_gpio->trans_lock);
	packet->bankid = gpio_id / GPIO_PER_BANK;
	packet->config = config | usbio_gpio->connect_mode[gpio_id];
	packet->pincount = 1;
	packet->pins = gpio_id % GPIO_PER_BANK;

	ret = usbio_transfer(usbio_gpio->pdev, GPIO_INIT, packet,
			    sizeof(*packet), NULL, NULL);
	mutex_unlock(&usbio_gpio->trans_lock);
	return ret;
}

static int usbio_gpio_read(struct usbio_gpio_dev *usbio_gpio, u8 gpio_id)
{
	struct gpio_rw_packet *packet = (struct gpio_rw_packet *)usbio_gpio->obuf;
	struct gpio_rw_packet *ack_packet;
	int ret;
	int ibuf_len;

	if (!usbio_gpio_valid(usbio_gpio, gpio_id))
		return -EINVAL;

	mutex_lock(&usbio_gpio->trans_lock);
	packet->bankid = gpio_id / GPIO_PER_BANK;
	packet->pincount = 1;
	packet->pins = gpio_id % GPIO_PER_BANK;
	ret = usbio_transfer(usbio_gpio->pdev, GPIO_READ, packet,
			    sizeof(*packet), usbio_gpio->ibuf, &ibuf_len);

	ack_packet = (struct gpio_rw_packet *)usbio_gpio->ibuf;
	if (ret || !ibuf_len || ack_packet->pins != packet->pins) {
		dev_err(&usbio_gpio->pdev->dev, "%s failed gpio_id:%d ret %d %d",
			__func__, gpio_id, ret, ack_packet->pins);
		mutex_unlock(&usbio_gpio->trans_lock);
		return -EIO;
	}

	mutex_unlock(&usbio_gpio->trans_lock);
	return (ack_packet->value & (1 << ack_packet->pins) ? 1 : 0);
}

static int usbio_gpio_write(struct usbio_gpio_dev *usbio_gpio, u8 gpio_id,
			   int value)
{
	struct gpio_rw_packet *packet = (struct gpio_rw_packet *)usbio_gpio->obuf;
	int ret;

	mutex_lock(&usbio_gpio->trans_lock);
	packet->bankid = gpio_id / GPIO_PER_BANK;
	packet->pincount = 1;
	packet->pins = gpio_id % GPIO_PER_BANK;
	packet->value = value << packet->pins;

	ret = usbio_transfer(usbio_gpio->pdev, GPIO_WRITE, packet,
			    sizeof(*packet), NULL, NULL);
	if (ret) {
		dev_err(&usbio_gpio->pdev->dev, "%s failed gpio_id:%d ret %d\n",
			__func__, gpio_id, ret);
		mutex_unlock(&usbio_gpio->trans_lock);
		return -EIO;
	}

	mutex_unlock(&usbio_gpio->trans_lock);
	return ret;
}

static int usbio_gpio_get_value(struct gpio_chip *chip, unsigned int offset)
{
	struct usbio_gpio_dev *usbio_gpio = gpiochip_get_data(chip);

	dev_dbg(chip->parent, "%s: offset %d\n", __func__, offset);
	return usbio_gpio_read(usbio_gpio, offset);
}

static void usbio_gpio_set_value(struct gpio_chip *chip, unsigned int offset,
				int val)
{
	struct usbio_gpio_dev *usbio_gpio = gpiochip_get_data(chip);
	int ret;

	dev_dbg(chip->parent, "%s: offset %d val %d\n", __func__, offset, val);
	ret = usbio_gpio_write(usbio_gpio, offset, val);
	if (ret)
		dev_err(chip->parent,
			"%s offset:%d val:%d set value failed %d\n", __func__,
			offset, val, ret);
}

static int usbio_gpio_direction_input(struct gpio_chip *chip,
				     unsigned int offset)
{
	struct usbio_gpio_dev *usbio_gpio = gpiochip_get_data(chip);
	u8 config = GPIO_CONF_INPUT;

	return gpio_config(usbio_gpio, offset, config);
}

static int usbio_gpio_direction_output(struct gpio_chip *chip,
				      unsigned int offset, int val)
{
	struct usbio_gpio_dev *usbio_gpio = gpiochip_get_data(chip);
	u8 config = GPIO_CONF_OUTPUT;
	int ret;

	ret = gpio_config(usbio_gpio, offset, config);
	if (ret)
		return ret;

	usbio_gpio_set_value(chip, offset, val);
	return 0;
}

static int usbio_gpio_set_config(struct gpio_chip *chip, unsigned int offset,
				unsigned long config)
{
	struct usbio_gpio_dev *usbio_gpio = gpiochip_get_data(chip);

	if (!usbio_gpio_valid(usbio_gpio, offset))
		return -EINVAL;

	usbio_gpio->connect_mode[offset] = 0;
	switch (pinconf_to_config_param(config)) {
	case PIN_CONFIG_BIAS_PULL_UP:
		usbio_gpio->connect_mode[offset] |= GPIO_CONF_PULLUP;
		break;
	case PIN_CONFIG_BIAS_PULL_DOWN:
		usbio_gpio->connect_mode[offset] |= GPIO_CONF_PULLDOWN;
		break;
	case PIN_CONFIG_DRIVE_PUSH_PULL:
	case PIN_CONFIG_PERSIST_STATE:
		usbio_gpio->connect_mode[offset] |= GPIO_CONF_NONE;
		break;
	default:
		usbio_gpio->connect_mode[offset] |= GPIO_CONF_DEFAULT;
		break;
	}

	return 0;
}
#if IRQ_SUPPORT
static int usbio_enable_irq(struct usbio_gpio_dev *usbio_gpio, int gpio_id,
			   bool enable)
{
	struct gpio_packet *packet = (struct gpio_packet *)usbio_gpio->obuf;
	int ret;

	mutex_lock(&usbio_gpio->trans_lock);
	packet->num = 1;
	packet->item[0].index = gpio_id;
	packet->item[0].value = 0;

	dev_dbg(usbio_gpio->gc.parent, "%s %d", __func__, gpio_id);

	ret = usbio_transfer(usbio_gpio->pdev,
			    enable == true ? GPIO_INT_UNMASK : GPIO_INT_MASK,
			    packet, sizeof(*packet), NULL, NULL);
	mutex_unlock(&usbio_gpio->trans_lock);
	return ret;
}

static void usbio_gpio_async(struct work_struct *work)
{
	struct usbio_gpio_dev *usbio_gpio =
		container_of(work, struct usbio_gpio_dev, work);
	int gpio_id;
	int unmasked;

	for_each_set_bit (gpio_id, usbio_gpio->reenable_irqs,
			  usbio_gpio->gc.ngpio) {
		clear_bit(gpio_id, usbio_gpio->reenable_irqs);
		unmasked = test_bit(gpio_id, usbio_gpio->unmasked_irqs);
		if (unmasked)
			usbio_enable_irq(usbio_gpio, gpio_id, true);
	}
}

void usbio_gpio_event_cb(struct platform_device *pdev, u8 cmd,
			const void *evt_data, int len)
{
	const struct gpio_packet *packet = evt_data;
	struct usbio_gpio_dev *usbio_gpio = platform_get_drvdata(pdev);
	int i;
	int irq;

	if (cmd != GPIO_INT_EVENT)
		return;

	for (i = 0; i < packet->num; i++) {
		irq = irq_find_mapping(usbio_gpio->gc.irq.domain,
				       packet->item[i].index);
		if (!irq) {
			dev_err(usbio_gpio->gc.parent,
				"gpio_id %d not mapped to IRQ\n",
				packet->item[i].index);
			return;
		}

		generic_handle_irq(irq);

		set_bit(packet->item[i].index, usbio_gpio->reenable_irqs);
		dev_dbg(usbio_gpio->gc.parent, "%s got one interrupt %d %d %d\n",
			__func__, i, packet->item[i].index,
			packet->item[i].value);
	}

	schedule_work(&usbio_gpio->work);
}

static void usbio_irq_unmask(struct irq_data *irqd)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(irqd);
	struct usbio_gpio_dev *usbio_gpio = gpiochip_get_data(gc);
	int gpio_id = irqd_to_hwirq(irqd);

	dev_dbg(usbio_gpio->gc.parent, "%s %d", __func__, gpio_id);
	set_bit(gpio_id, usbio_gpio->unmasked_irqs);
}

static void usbio_irq_mask(struct irq_data *irqd)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(irqd);
	struct usbio_gpio_dev *usbio_gpio = gpiochip_get_data(gc);
	int gpio_id = irqd_to_hwirq(irqd);

	dev_dbg(usbio_gpio->gc.parent, "%s %d", __func__, gpio_id);
	clear_bit(gpio_id, usbio_gpio->unmasked_irqs);
}

static int usbio_irq_set_type(struct irq_data *irqd, unsigned type)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(irqd);
	struct usbio_gpio_dev *usbio_gpio = gpiochip_get_data(gc);
	int gpio_id = irqd_to_hwirq(irqd);

	usbio_gpio->connect_mode[gpio_id] = GPIO_CONF_INTERRUPT;
	switch (type) {
	case IRQ_TYPE_LEVEL_HIGH:
		usbio_gpio->connect_mode[gpio_id] |=
			GPIO_CONF_LEVEL | GPIO_CONF_PULLUP;
		break;
	case IRQ_TYPE_LEVEL_LOW:
		usbio_gpio->connect_mode[gpio_id] |=
			GPIO_CONF_LEVEL | GPIO_CONF_PULLDOWN;
		break;
	case IRQ_TYPE_EDGE_BOTH:
		break;
	case IRQ_TYPE_EDGE_RISING:
		usbio_gpio->connect_mode[gpio_id] |=
			GPIO_CONF_EDGE | GPIO_CONF_PULLUP;
		break;
	case IRQ_TYPE_EDGE_FALLING:
		usbio_gpio->connect_mode[gpio_id] |=
			GPIO_CONF_EDGE | GPIO_CONF_PULLDOWN;
		break;
	default:
		return -EINVAL;
	}

	dev_dbg(usbio_gpio->gc.parent, "%s %d %x\n", __func__, gpio_id,
		usbio_gpio->connect_mode[gpio_id]);
	return 0;
}

static void usbio_irq_bus_lock(struct irq_data *irqd)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(irqd);
	struct usbio_gpio_dev *usbio_gpio = gpiochip_get_data(gc);

	mutex_lock(&usbio_gpio->irq_lock);
}

static void usbio_irq_bus_unlock(struct irq_data *irqd)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(irqd);
	struct usbio_gpio_dev *usbio_gpio = gpiochip_get_data(gc);
	int gpio_id = irqd_to_hwirq(irqd);
	int enabled;
	int unmasked;

	enabled = test_bit(gpio_id, usbio_gpio->enabled_irqs);
	unmasked = test_bit(gpio_id, usbio_gpio->unmasked_irqs);
	dev_dbg(usbio_gpio->gc.parent, "%s %d %d %d\n", __func__, gpio_id,
		 enabled, unmasked);

	if (enabled != unmasked) {
		if (unmasked) {
			gpio_config(usbio_gpio, gpio_id, 0);
			usbio_enable_irq(usbio_gpio, gpio_id, true);
			set_bit(gpio_id, usbio_gpio->enabled_irqs);
		} else {
			usbio_enable_irq(usbio_gpio, gpio_id, false);
			clear_bit(gpio_id, usbio_gpio->enabled_irqs);
		}
	}

	mutex_unlock(&usbio_gpio->irq_lock);
}

static unsigned int usbio_irq_startup(struct irq_data *irqd)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(irqd);

	return gpiochip_lock_as_irq(gc, irqd_to_hwirq(irqd));
}

static void usbio_irq_shutdown(struct irq_data *irqd)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(irqd);

	gpiochip_unlock_as_irq(gc, irqd_to_hwirq(irqd));
}

static struct irq_chip usbio_gpio_irqchip = {
	.name = "ljca-irq",
	.irq_mask = usbio_irq_mask,
	.irq_unmask = usbio_irq_unmask,
	.irq_set_type = usbio_irq_set_type,
	.irq_bus_lock = usbio_irq_bus_lock,
	.irq_bus_sync_unlock = usbio_irq_bus_unlock,
	.irq_startup = usbio_irq_startup,
	.irq_shutdown = usbio_irq_shutdown,
};
#endif
static int usbio_gpio_probe(struct platform_device *pdev)
{
	struct usbio_gpio_dev *usbio_gpio;
	struct usbio_platform_data *pdata = dev_get_platdata(&pdev->dev);
#if IRQ_SUPPORT
	struct gpio_irq_chip *girq = NULL;
#endif

	usbio_gpio = devm_kzalloc(&pdev->dev, sizeof(*usbio_gpio), GFP_KERNEL);
	if (!usbio_gpio)
		return -ENOMEM;

	usbio_gpio->ctr_info = &pdata->gpio_info;
	usbio_gpio->connect_mode =
		devm_kcalloc(&pdev->dev, usbio_gpio->ctr_info->num,
			     sizeof(*usbio_gpio->connect_mode), GFP_KERNEL);
	if (!usbio_gpio->connect_mode)
		return -ENOMEM;

	mutex_init(&usbio_gpio->irq_lock);
	mutex_init(&usbio_gpio->trans_lock);
	usbio_gpio->pdev = pdev;
	usbio_gpio->gc.direction_input = usbio_gpio_direction_input;
	usbio_gpio->gc.direction_output = usbio_gpio_direction_output;
	usbio_gpio->gc.get = usbio_gpio_get_value;
	usbio_gpio->gc.set = usbio_gpio_set_value;
	usbio_gpio->gc.set_config = usbio_gpio_set_config;
	usbio_gpio->gc.can_sleep = true;
	usbio_gpio->gc.parent = &pdev->dev;

	usbio_gpio->gc.base = -1;
	usbio_gpio->gc.ngpio = usbio_gpio->ctr_info->num;
	usbio_gpio->gc.label = ACPI_COMPANION(&pdev->dev) ?
			      acpi_dev_name(ACPI_COMPANION(&pdev->dev)) :
			      "usbio-gpio";
	usbio_gpio->gc.owner = THIS_MODULE;

	platform_set_drvdata(pdev, usbio_gpio);
#if IRQ_SUPPORT
	usbio_register_event_cb(pdev, usbio_gpio_event_cb);

	girq = &usbio_gpio->gc.irq;
	girq->chip = &usbio_gpio_irqchip;
	girq->parent_handler = NULL;
	girq->num_parents = 0;
	girq->parents = NULL;
	girq->default_type = IRQ_TYPE_NONE;
	girq->handler = handle_simple_irq;
	INIT_WORK(&usbio_gpio->work, usbio_gpio_async);
#endif
	return devm_gpiochip_add_data(&pdev->dev, &usbio_gpio->gc, usbio_gpio);
}

static int usbio_gpio_remove(struct platform_device *pdev)
{
	return 0;
}

static struct platform_driver usbio_gpio_driver = {
	.driver.name = "usbio-gpio",
	.probe = usbio_gpio_probe,
	.remove = usbio_gpio_remove,
};

module_platform_driver(usbio_gpio_driver);

MODULE_AUTHOR("Lifu Wang <lifu.wang@intel.com>");
MODULE_AUTHOR("Zhang Lixu <lixu.zhang@intel.com>");
MODULE_AUTHOR("Israel Cepeda <israel.a.cepeda.lopez@intel.com>");
MODULE_DESCRIPTION("Intel USBIO-GPIO driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:usbio-gpio");
