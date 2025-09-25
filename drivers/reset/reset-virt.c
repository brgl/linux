// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 Linaro Ltd.
 */

#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>

static int notify_dupa(struct notifier_block *nb, unsigned long action, void *data)
{
	printk("BGBG %s %d %lu\n", __func__, __LINE__, action);

	return NOTIFY_DONE;
}

static int notify_foo(struct notifier_block *nb, unsigned long action, void *data)
{
	printk("BGBG %s %d %lu\n", __func__, __LINE__, action);

	return NOTIFY_DONE;
}

static int reset_virt_probe(struct platform_device *pdev)
{
	struct notifier_block dupa_nb, foo_nb;
	struct device *dev = &pdev->dev;
	struct regulator *dupa, *foo;
	int ret;

	dupa = devm_regulator_get(dev, "dupa");
	if (IS_ERR(dupa))
		return dev_err_probe(dev, PTR_ERR(dupa), "BGBG dupa\n");

	foo = devm_regulator_get(dev, "foo");
	if (IS_ERR(foo))
		return dev_err_probe(dev, PTR_ERR(foo), "BGBG foo\n");

	dupa_nb.notifier_call = notify_dupa;
	foo_nb.notifier_call = notify_foo;

	ret = devm_regulator_register_notifier(dupa, &dupa_nb);
	if (ret)
		return dev_err_probe(dev, ret, "BGBG not dupa\n");

	ret = devm_regulator_register_notifier(foo, &foo_nb);
	if (ret)
		return dev_err_probe(dev, ret, "BGBG not foo\n");

	ret = regulator_enable(dupa);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "BGBG dupa\n");

	ret = regulator_enable(foo);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "BGBG foo\n");

	ret = regulator_disable(dupa);
	if (ret)
		return dev_err_probe(dev, ret, "BGBG disabledupa\n");

	dev_info(&pdev->dev, "BGBG good\n");

	return 0;
}

static const struct of_device_id reset_virt_of_match[] = {
	{ .compatible = "virtual-reset" },
	{ }
};
MODULE_DEVICE_TABLE(of, reset_virt_of_match);

static struct platform_driver reset_virt_driver = {
	.driver = {
		.name = "virtual-reset",
		.of_match_table = reset_virt_of_match,
	},
	.probe = reset_virt_probe,
};

module_platform_driver(reset_virt_driver);

MODULE_AUTHOR("Bartosz Golaszewski <bartosz.golaszewski@linaro.org>");
MODULE_DESCRIPTION("Virtual reset consumer module");
MODULE_LICENSE("GPL");
