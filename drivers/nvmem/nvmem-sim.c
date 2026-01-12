// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NVMEM testing module.
 *
 * Copyright (C) 2026 Qualcomm Technologies, Inc. and/or its subsidiaries
 */

#include <linux/cleanup.h>
#include <linux/device.h>
#include <linux/nvmem-provider.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/slab.h>
#include <linux/string.h>

struct nvmem_sim_data {
	struct mutex lock;
	size_t bufsize;
	char buf[] __counted_by(bufsize);
};

static int nvmem_sim_read(void *priv, unsigned int offset, void *val, size_t bytes)
{
	struct nvmem_sim_data *data = priv;

	guard(mutex)(&data->lock);

	memcpy(val, data->buf + offset, bytes);

	return 0;
}

static int nvmem_sim_write(void *priv, unsigned int offset, void *val, size_t bytes)
{
	struct nvmem_sim_data *data = priv;

	guard(mutex)(&data->lock);

	memcpy(data->buf + offset, val, bytes);

	return 0;
}

static int nvmem_sim_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct nvmem_sim_data *data;
	struct nvmem_device *nvmem;
	u32 bufsize;
	int ret;

	ret = device_property_read_u32(dev, "nvmem-sim,size", &bufsize);
	if (ret)
		return dev_err_probe(dev, ret, "failed to read the nvmem-sim,size property\n");

	data = devm_kzalloc(dev, struct_size(data, buf, bufsize), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->bufsize = bufsize;

	ret = devm_mutex_init(dev, &data->lock);
	if (ret)
		return ret;

	struct nvmem_config *cfg __free(kfree) = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!cfg)
		return -ENOMEM;

	ret = device_property_count_u8(dev, "nvmem-sim,contents");
	if (ret < 0 && ret != -EINVAL)
		return dev_err_probe(dev, ret,
			"failed to count the size of the nvmem-sim,contents property\n");

	if (ret > 0) {
		if (ret > data->bufsize)
			return dev_err_probe(dev, -EINVAL, "size of nvmem-sim,contents is larger than nvmem-sim,size\n");

		ret = device_property_read_u8_array(dev, "nvmem-sim,contents", data->buf, ret);
		if (ret)
			return dev_err_probe(dev, ret,
				     "failed to read the nvmem-sim,contents property\n");
	}

	cfg->dev = dev;
	cfg->name = "nvmem-sim";
	cfg->id = NVMEM_DEVID_AUTO;
	cfg->owner = THIS_MODULE;
	cfg->size = data->bufsize;
	cfg->stride = 1;
	cfg->word_size = 1;
	cfg->reg_read = nvmem_sim_read;
	cfg->reg_write = nvmem_sim_write;
	cfg->ignore_wp = true;
	cfg->priv = data;

	nvmem = devm_nvmem_register(dev, cfg);
	if (IS_ERR(nvmem))
		return dev_err_probe(dev, PTR_ERR(nvmem),
				     "Failed to register simulated nvmem device\n");
	
	return 0;
}

static const struct of_device_id nvmem_sim_of_match[] = {
	{ .compatible = "nvmem-simulator" },
	{ }
};
MODULE_DEVICE_TABLE(of, nvmem_sim_of_match);

static struct platform_driver nvmem_sim_driver = {
	.driver = {
		.name = "nvmem-sim",
		.of_match_table = nvmem_sim_of_match,
	},
	.probe = nvmem_sim_probe,
};
module_platform_driver(nvmem_sim_driver);

MODULE_AUTHOR("Bartosz Golaszewski <bartosz.golaszewski@oss.qualcomm.com>");
MODULE_DESCRIPTION("NVMEM Testing Module");
MODULE_LICENSE("GPL");
