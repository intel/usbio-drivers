// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Intel Corporation.
 *
 */

#include <linux/acpi.h>
#include <linux/platform_device.h>
#include <linux/gpio/driver.h>
#include <linux/ioext.h>
#include <linux/version.h>

struct usbio_gpio {
	int gpio_banks;
	struct ioext_gpio_bank banks[IOEXT_MAX_GPIOBANKS];
	struct gpio_chip gc;
	struct mutex mutex;
};

static int usbio_gpio_get_direction(struct gpio_chip *gc, unsigned int offset)
{
	struct usbio_gpio *gpio = gpiochip_get_data(gc);
	struct ioext_gpio_bank *bank;
	int pin;
	u8 cfg;

	if (!gpio || (offset >= gc->ngpio))
		return -EINVAL;

	bank = &gpio->banks[offset / IOEXT_GPIOSPERBANK];
	pin = offset % IOEXT_GPIOSPERBANK;
	if (~bank->bitmap & BIT(pin))
		return -EINVAL;

	cfg = bank->config[pin] & IOEXT_GPIO_PINMOD_MASK;
	if (cfg == IOEXT_GPIO_PINMOD_INPUT)
		return GPIO_LINE_DIRECTION_IN;
	else if (cfg == IOEXT_GPIO_PINMOD_OUTPUT)
		return GPIO_LINE_DIRECTION_OUT;

	return GPIO_LINE_DIRECTION_IN;
}

static int usbio_gpio_direction_input(struct gpio_chip *gc,
		unsigned int offset)
{
	struct usbio_gpio *gpio = gpiochip_get_data(gc);
	struct ioext_gpio_bank *bank;
	struct ioext_gpio_init gbuf;
	int pin, ret;

	if (!gpio || (offset >= gc->ngpio))
		return -EINVAL;

	bank = &gpio->banks[offset / IOEXT_GPIOSPERBANK];
	pin = offset % IOEXT_GPIOSPERBANK;
	if (~bank->bitmap & BIT(pin))
		return -EINVAL;

	bank->config[pin] |= IOEXT_GPIO_SET_PINMOD(IOEXT_GPIO_PINMOD_INPUT);

	mutex_lock(&gpio->mutex);
	gbuf.bankid = offset / IOEXT_GPIOSPERBANK;
	gbuf.config = bank->config[pin];
	gbuf.pincount  = 1;
	gbuf.pin = pin;
	ret = usbio_transfer(IOEXT_GPIO, IOEXT_GPIOCMD_INIT,
							&gbuf, sizeof(gbuf), NULL, 0);
	mutex_unlock(&gpio->mutex);

	return ret;
}

static int usbio_gpio_direction_output(struct gpio_chip *gc,
		unsigned int offset, int value)
{
	struct usbio_gpio *gpio = gpiochip_get_data(gc);
	struct ioext_gpio_bank *bank;
	struct ioext_gpio_init gbuf;
	int pin, ret;

	if (!gpio || (offset >= gc->ngpio))
		return -EINVAL;

	bank = &gpio->banks[offset / IOEXT_GPIOSPERBANK];
	pin = offset % IOEXT_GPIOSPERBANK;
	if (~bank->bitmap & BIT(pin))
		return -EINVAL;

	bank->config[pin] |= IOEXT_GPIO_SET_PINMOD(IOEXT_GPIO_PINMOD_OUTPUT);

	mutex_lock(&gpio->mutex);
	gbuf.bankid = offset / IOEXT_GPIOSPERBANK;
	gbuf.config = bank->config[pin];
	gbuf.pincount  = 1;
	gbuf.pin = pin;
	ret = usbio_transfer(IOEXT_GPIO, IOEXT_GPIOCMD_INIT,
							&gbuf, sizeof(gbuf), NULL, 0);
	mutex_unlock(&gpio->mutex);

	return ret;
}

static int usbio_gpio_get(struct gpio_chip *gc, unsigned int offset)
{
	struct usbio_gpio *gpio = gpiochip_get_data(gc);
	struct ioext_gpio_bank *bank;
	struct ioext_gpio_rw gbuf;
	int pin, ret;

	if (!gpio || (offset >= gc->ngpio))
		return -EINVAL;

	bank = &gpio->banks[offset / IOEXT_GPIOSPERBANK];
	pin = offset % IOEXT_GPIOSPERBANK;
	if (~bank->bitmap & BIT(pin))
		return -EINVAL;

	mutex_lock(&gpio->mutex);
	gbuf.bankid = offset / IOEXT_GPIOSPERBANK;
	gbuf.pincount  = 1;
	gbuf.pin = pin;
	ret = usbio_transfer(IOEXT_GPIO, IOEXT_GPIOCMD_READ,
							&gbuf, sizeof(gbuf) - sizeof(gbuf.value),
							&gbuf, sizeof(gbuf));
	ret = ret == sizeof(gbuf.value) ? (gbuf.value >> pin) & 1 : -EINVAL;
	mutex_unlock(&gpio->mutex);

	return ret;
}
#if LINUX_VERSION_CODE >=  KERNEL_VERSION(6, 17, 0)
static int usbio_gpio_set(struct gpio_chip *gc, unsigned int offset,
		int value)
#else
static void usbio_gpio_set(struct gpio_chip *gc, unsigned int offset,
		int value)
#endif
{
	struct usbio_gpio *gpio = gpiochip_get_data(gc);
	struct ioext_gpio_bank *bank;
	struct ioext_gpio_rw gbuf;
	int pin;
#if LINUX_VERSION_CODE >=  KERNEL_VERSION(6, 17, 0)
	int ret;
#endif
	if (!gpio || (offset >= gc->ngpio)) {
#if LINUX_VERSION_CODE >=  KERNEL_VERSION(6, 17, 0)
		return -EINVAL;
#else
		return;
#endif
	}
	bank = &gpio->banks[offset / IOEXT_GPIOSPERBANK];
	pin = offset % IOEXT_GPIOSPERBANK;
	if (~bank->bitmap & BIT(pin)) {
#if LINUX_VERSION_CODE >=  KERNEL_VERSION(6, 17, 0)
		return -EINVAL;
#else
		return;
#endif
	}
	mutex_lock(&gpio->mutex);
	gbuf.bankid = offset / IOEXT_GPIOSPERBANK;
	gbuf.pincount  = 1;
	gbuf.pin = pin;
	gbuf.value = value << pin;
#if LINUX_VERSION_CODE >=  KERNEL_VERSION(6, 17, 0)
	ret = usbio_transfer(IOEXT_GPIO, IOEXT_GPIOCMD_WRITE,
					&gbuf, sizeof(gbuf), NULL, 0);
#else
	usbio_transfer(IOEXT_GPIO, IOEXT_GPIOCMD_WRITE,
					&gbuf, sizeof(gbuf), NULL, 0);
#endif

	mutex_unlock(&gpio->mutex);
#if LINUX_VERSION_CODE >=  KERNEL_VERSION(6, 17, 0)
	return ret;
#endif

}

static int usbio_gpio_set_config(struct gpio_chip *gc, unsigned int offset,
		unsigned long config)
{
	struct usbio_gpio *gpio = gpiochip_get_data(gc);
	struct ioext_gpio_bank *bank;
	int pin;

	if (!gpio || (offset >= gc->ngpio))
		return -EINVAL;

	bank = &gpio->banks[offset / IOEXT_GPIOSPERBANK];
	pin = offset % IOEXT_GPIOSPERBANK;
	if (~bank->bitmap & BIT(pin))
		return -EINVAL;

	bank->config[pin] = IOEXT_GPIO_SET_PINCFG(IOEXT_GPIO_PINCFG_DEFAULT);
	switch (pinconf_to_config_param(config)) {
	case PIN_CONFIG_BIAS_PULL_PIN_DEFAULT:
		break;
	case PIN_CONFIG_BIAS_PULL_UP:
		bank->config[pin] |= IOEXT_GPIO_SET_PINCFG(IOEXT_GPIO_PINCFG_PULLUP);
		break;
	case PIN_CONFIG_BIAS_PULL_DOWN:
		bank->config[pin] |= IOEXT_GPIO_SET_PINCFG(IOEXT_GPIO_PINCFG_PULLDOWN);
		break;
	case PIN_CONFIG_DRIVE_PUSH_PULL:
		bank->config[pin] |= IOEXT_GPIO_SET_PINCFG(IOEXT_GPIO_PINCFG_PUSHPULL);
		break;
	default:
		return -ENOTSUPP;
	}

	return 0;
}

static int usbio_gpio_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct usbio_gpio *gpio;

	gpio = devm_kzalloc(dev, sizeof(*gpio), GFP_KERNEL);
	if (!gpio)
		return -ENOMEM;

	gpio->gpio_banks = usbio_gpio_init(gpio->banks, sizeof(gpio->banks));
	if (gpio->gpio_banks < 0) {
		devm_kfree(dev, gpio);
		return gpio->gpio_banks == -ENODEV ? -EPROBE_DEFER : -EINVAL;
	}

	gpio->gc.label = dev_name(dev);
	gpio->gc.parent = dev;
	gpio->gc.owner = THIS_MODULE;
	gpio->gc.get_direction = usbio_gpio_get_direction;
	gpio->gc.direction_input = usbio_gpio_direction_input;
	gpio->gc.direction_output = usbio_gpio_direction_output;
	gpio->gc.get = usbio_gpio_get;
	gpio->gc.set = usbio_gpio_set;
	gpio->gc.set_config = usbio_gpio_set_config;
	gpio->gc.base = -1;
	gpio->gc.ngpio = gpio->gpio_banks * IOEXT_GPIOSPERBANK;
	gpio->gc.can_sleep = true;
	mutex_init(&gpio->mutex);

	platform_set_drvdata(pdev, gpio);

	return gpiochip_add_data(&gpio->gc, gpio);
}

#if KERNEL_VERSION(6, 11, 0) > LINUX_VERSION_CODE
static int usbio_gpio_remove(struct platform_device *pdev)
#else
static void usbio_gpio_remove(struct platform_device *pdev)
#endif
{
	struct usbio_gpio *gpio = platform_get_drvdata(pdev);
	struct device *dev = &pdev->dev;

	gpiochip_remove(&gpio->gc);

	mutex_destroy(&gpio->mutex);
	devm_kfree(dev, gpio);

#if KERNEL_VERSION(6, 11, 0) > LINUX_VERSION_CODE
	return 0;
#endif
}

static const struct acpi_device_id usbio_gpio_acpi_match[] = {
	{ "INTC1007" }, /* MTL */
	{ "INTC10B2" }, /* ARL */
	{ "INTC10B5" }, /* LNL */
	{ "INTC10E2" }, /* PTL */
	{ }
};
MODULE_DEVICE_TABLE(acpi, usbio_gpio_acpi_match);

static struct platform_driver usbio_gpio_driver = {
	.driver = {
		.name = "usbio-gpio",
		.acpi_match_table = usbio_gpio_acpi_match,
	},
	.probe = usbio_gpio_probe,
	.remove = usbio_gpio_remove
};
module_platform_driver(usbio_gpio_driver);

MODULE_DESCRIPTION("Intel USBIO GPIO driver");
MODULE_AUTHOR("Israel Cepeda <israel.a.cepeda.lopez@intel.com>");
MODULE_LICENSE("GPL");
#if KERNEL_VERSION(6, 13, 0) > LINUX_VERSION_CODE
MODULE_IMPORT_NS(USBIO);
#else
MODULE_IMPORT_NS("USBIO");
#endif
