// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2026 Qualcomm Technologies, Inc. and/or its subsidiaries
 */

#include <linux/device.h>
#include <linux/nvmem-consumer.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/timer.h>

struct nvmem_virt_data {
	struct timer_list timer;
	struct nvmem_device *nvmem;
	struct nvmem_cell *cell;
};

static void nvmem_virt_on_timer(struct timer_list *timer)
{
	struct nvmem_virt_data *data = container_of(timer, struct nvmem_virt_data, timer);
	char buf[32] = { };
	size_t len;
	int ret;

	ret = nvmem_device_read(data->nvmem, 0, 24, buf);
	if (ret < 0)
		printk("nvmem_device_read failed: %d\n", ret);

	printk("BGBG dev %s %s\n", __func__, buf);

	char *cbuf __free(kfree) = nvmem_cell_read(data->cell, &len);
	if (IS_ERR(cbuf))
		printk("nvmem_cell_read failed: %ld\n", PTR_ERR(cbuf));

	printk("BGBG cell read %lu\n", len);

	mod_timer(&data->timer, jiffies + 5 * HZ);
}

static int nvmem_virt_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct nvmem_virt_data *data;

	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->nvmem = devm_nvmem_device_get(dev, "foo");
	if (IS_ERR(data->nvmem))
		return dev_err_probe(dev, PTR_ERR(data->nvmem), "nvmem dev get failed\n");

	data->cell = devm_nvmem_cell_get(dev, "foo");
	if (IS_ERR(data->cell))
		return dev_err_probe(dev, PTR_ERR(data->cell), "nvmem cell get failed\n");

	timer_setup(&data->timer, nvmem_virt_on_timer, 0);
	mod_timer(&data->timer, jiffies + 5 * HZ);

	platform_set_drvdata(pdev, data);

	return 0;
}

static void nvmem_virt_remove(struct platform_device *pdev)
{
	struct nvmem_virt_data *data = platform_get_drvdata(pdev);

	timer_delete_sync(&data->timer);
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
