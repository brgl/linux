// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 Linaro Ltd.
 */

#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/reset.h>

static int reset_virt_probe(struct platform_device *pdev)
{
	struct reset_control *reset;
	int ret;

	reset = devm_reset_control_get_shared(&pdev->dev, NULL);
	if (IS_ERR(reset))
		return PTR_ERR(reset);

	ret = reset_control_acquire(reset);
	if (ret)
		return ret;

	reset_control_release(reset);

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
