// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2026 Qualcomm Technologies, Inc. and/or its subsidiaries
 */

#include <linux/device.h>
#include <linux/nvmem-consumer.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>

static int nvmem_virt_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct nvmem_cell *cell;

	cell = devm_nvmem_cell_get(dev, "foo");
	if (IS_ERR(cell))
		return dev_err_probe(dev, PTR_ERR(cell), "get failed\n");

	return 0;
}

static void nvmem_virt_remove(struct platform_device *pdev)
{
	printk("BGBG %s\n", __func__);
}

static const struct of_device_id nvmem_virt_of_match[] = {
	{ .compatible = "nvmem-virt" },
	{ }
};
MODULE_DEVICE_TABLE(of, nvmem_virt_of_match);

static struct platform_driver nvmem_virt_driver = {
	.driver = {
		.name = "nvmem-virt",
		.of_match_table = nvmem_virt_of_match,
	},
	.probe = nvmem_virt_probe,
	.remove = nvmem_virt_remove,
};
module_platform_driver(nvmem_virt_driver);

MODULE_AUTHOR("Bartosz Golaszewski <bartosz.golaszewski@oss.qualcomm.com>");
MODULE_DESCRIPTION("NVMEM Virtual Consumer Module");
MODULE_LICENSE("GPL");
