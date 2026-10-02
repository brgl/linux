// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Firmware-managed variant of the Qualcomm DWMAC SGMII SerDes/PHY driver.
 */

#include <linux/device-id/of.h>
#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/phy.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/pm_opp.h>
#include <linux/pm_runtime.h>

static int qcom_dwmac_sgmii_phy_scmi_validate(struct phy *phy, enum phy_mode mode,
					      int submode,
					      union phy_configure_opts *opts)
{
	if (mode != PHY_MODE_ETHERNET)
		return -EINVAL;

	switch (submode) {
	case PHY_INTERFACE_MODE_SGMII:
	case PHY_INTERFACE_MODE_1000BASEX:
	case PHY_INTERFACE_MODE_2500BASEX:
		return 0;
	default:
		return -EINVAL;
	}
}

static int qcom_dwmac_sgmii_phy_scmi_set_mode(struct phy *phy, enum phy_mode mode,
					      int submode)
{
	struct device *dev = phy->dev.parent;
	unsigned int level;
	int ret;

	ret = qcom_dwmac_sgmii_phy_scmi_validate(phy, mode, submode, NULL);
	if (ret)
		return ret;

	level = (submode == PHY_INTERFACE_MODE_2500BASEX) ?
		SPEED_2500 : SPEED_1000;

	/*
	 * The line rate is the only thing we control: firmware exposes it as a
	 * performance level of the SCMI DVFS domain attached to this device.
	 * Request it through the OPP API rather than poking the performance
	 * state directly so that the level is validated against the OPP table
	 * firmware provided at attach time - a domain that doesn't support the
	 * requested rate fails here instead of silently reporting success.
	 */
	return dev_pm_opp_set_level(dev, level);
}

static const struct phy_ops qcom_dwmac_sgmii_phy_scmi_ops = {
	.set_mode	= qcom_dwmac_sgmii_phy_scmi_set_mode,
	.validate	= qcom_dwmac_sgmii_phy_scmi_validate,
	.owner		= THIS_MODULE,
};

static void qcom_dwmac_sgmii_phy_scmi_drop_level(void *data)
{
	struct device *dev = data;

	/*
	 * Drop this device's contribution to the domain's aggregated
	 * performance level so that it doesn't outlive the driver binding.
	 *
	 * Note this doesn't reach firmware: SCMI has no way of releasing a
	 * performance level - 0 is not a valid one - so the SCMI performance
	 * domain ignores it. Nothing is leaked either way: the SerDes supplies
	 * and its reference clock are owned by firmware and tied to the MAC's
	 * SCMI power domains, not to the DVFS domain used here.
	 */
	dev_pm_opp_set_opp(dev, NULL);
}

static int qcom_dwmac_sgmii_phy_scmi_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct phy_provider *provider;
	struct phy *phy;
	int ret;

	/*
	 * The domain attached to this device by the driver core must be an SCMI
	 * DVFS domain: the only knob this driver has is the SerDes line rate,
	 * which firmware exposes as a performance level. The SCMI performance
	 * domain populates our OPP table while attaching, so an empty or
	 * missing table means the device tree points us at something else.
	 */
	ret = dev_pm_opp_get_opp_count(dev);
	if (ret <= 0)
		return dev_err_probe(dev, ret ?: -ENODEV,
				     "no performance levels available\n");

	/*
	 * Enable runtime PM on the provider before creating the PHY so that the
	 * PHY core enables runtime PM on the PHY device too and so that genpd
	 * saves and restores the requested performance level across runtime
	 * suspend. No register or clock access is done here - firmware owns the
	 * SerDes and brings its supplies and reference clock up together with
	 * the MAC's SCMI power domains.
	 */
	ret = devm_pm_runtime_enable(dev);
	if (ret)
		return ret;

	ret = devm_add_action_or_reset(dev, qcom_dwmac_sgmii_phy_scmi_drop_level, dev);
	if (ret)
		return ret;

	phy = devm_phy_create(dev, NULL, &qcom_dwmac_sgmii_phy_scmi_ops);
	if (IS_ERR(phy))
		return dev_err_probe(dev, PTR_ERR(phy), "failed to create the phy\n");

	provider = devm_of_phy_provider_register(dev, of_phy_simple_xlate);
	if (IS_ERR(provider))
		return dev_err_probe(dev, PTR_ERR(provider),
				     "failed to register the PHY provider\n");

	return 0;
}

static const struct of_device_id qcom_dwmac_sgmii_phy_scmi_of_match[] = {
	{ .compatible = "qcom,sa8255p-dwmac-sgmii-phy" },
	{ }
};
MODULE_DEVICE_TABLE(of, qcom_dwmac_sgmii_phy_scmi_of_match);

static struct platform_driver qcom_dwmac_sgmii_phy_scmi_driver = {
	.probe	= qcom_dwmac_sgmii_phy_scmi_probe,
	.driver = {
		.name = "qcom-dwmac-sgmii-phy-scmi",
		.of_match_table = qcom_dwmac_sgmii_phy_scmi_of_match,
	},
};
module_platform_driver(qcom_dwmac_sgmii_phy_scmi_driver);

MODULE_DESCRIPTION("Qualcomm DWMAC SGMII PHY driver (firmware managed)");
MODULE_AUTHOR("Bartosz Golaszewski <bartosz.golaszewski@oss.qualcomm.com>");
MODULE_LICENSE("GPL");
