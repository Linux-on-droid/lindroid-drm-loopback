// SPDX-License-Identifier: GPL-2.0-only
/*
 * Sysfs interface
 */

#include "evdi_drv.h"
#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/platform_device.h>

static struct device *evdi_sysfs_dev;

static ssize_t add_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", atomic_read(&evdi_device_count));
}

static ssize_t add_store(struct device *dev, struct device_attribute *attr,
			const char *buf, size_t count)
{
	struct platform_device *pdev;
	struct device *parent = evdi_sysfs_dev;
	int val, ret;

	ret = kstrtoint(buf, 10, &val);
	if (ret) {
		evdi_err("Invalid input for device creation: %s", buf);
		return ret;
	}

	if (val <= 0) {
		evdi_err("Device count must be positive: %d", val);
		return -EINVAL;
	}

	pdev = platform_device_alloc(DRIVER_NAME, PLATFORM_DEVID_AUTO);
	if (!pdev) {
		evdi_err("Failed to allocate platform device");
		return -ENOMEM;
	}

	pdev->dev.parent = parent;
	ret = platform_device_add(pdev);
	if (ret) {
		evdi_err("Failed to add platform device: %d", ret);
		platform_device_put(pdev);
		return ret;
	}

	evdi_info("Created new device via sysfs (total: %d)",
		 atomic_read(&evdi_device_count));

	return count;
}

static DEVICE_ATTR_RW(add);

static struct attribute *evdi_sysfs_attrs[] = {
	&dev_attr_add.attr,
	NULL,
};

static const struct attribute_group evdi_sysfs_attr_group = {
	.attrs = evdi_sysfs_attrs,
};

static ssize_t stats_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf,
	"EVDI-Lindroid Performance Statistics\n"
	"=====================================\n"
	"IOCTL calls:\n"
	"  CONNECT: %lld\n"
	"  POLL: %lld\n"
	"  ADD_BUFF_CALLBACK: %lld\n"
	"  GET_BUFF_CALLBACK: %lld\n"
	"  DESTROY_BUFF_CALLBACK: %lld\n"
	"  SWAP_CALLBACK: %lld\n"
	"  CREATE_BUFF_CALLBACK: %lld\n"
	"\n"
	"Event system:\n"
	"  Queue operations: %lld\n"
	"  Dequeue operations: %lld\n"
	"  Fast pool allocs: %lld\n"
	"  Slow path allocs: %lld\n"
	"  Wakeups: %lld\n"
	"  Poll cycles: %lld\n",
	(long long)atomic64_read(&evdi_perf.ioctl_calls[0]),
	(long long)atomic64_read(&evdi_perf.ioctl_calls[1]),
	(long long)atomic64_read(&evdi_perf.ioctl_calls[2]),
	(long long)atomic64_read(&evdi_perf.ioctl_calls[3]),
	(long long)atomic64_read(&evdi_perf.ioctl_calls[4]),
	(long long)atomic64_read(&evdi_perf.ioctl_calls[5]),
	(long long)atomic64_read(&evdi_perf.ioctl_calls[6]),
	(long long)atomic64_read(&evdi_perf.event_queue_ops),
	(long long)atomic64_read(&evdi_perf.event_dequeue_ops),
	(long long)atomic64_read(&evdi_perf.pool_alloc_fast),
	(long long)atomic64_read(&evdi_perf.pool_alloc_slow),
	(long long)atomic64_read(&evdi_perf.wakeup_count),
	(long long)atomic64_read(&evdi_perf.poll_cycles));
}

static DEVICE_ATTR_RO(stats);

static struct attribute *evdi_debug_attrs[] = {
	&dev_attr_stats.attr,
	NULL,
};

static const struct attribute_group evdi_debug_attr_group = {
	.name = "debug",
	.attrs = evdi_debug_attrs,
};

static const struct attribute_group *evdi_attr_groups[] = {
	&evdi_sysfs_attr_group,
	&evdi_debug_attr_group,
	NULL,
};

int evdi_sysfs_init(void)
{
	int ret;


	evdi_sysfs_dev = root_device_register(DRIVER_NAME);
	if (IS_ERR(evdi_sysfs_dev)) {
		ret = PTR_ERR(evdi_sysfs_dev);
		evdi_err("Failed to register sysfs device: %d", ret);
		return ret;
	}

	ret = sysfs_create_groups(&evdi_sysfs_dev->kobj, evdi_attr_groups);
	if (ret) {
		evdi_err("Failed to create sysfs attributes: %d", ret);
		goto err_device;
	}

	evdi_info("Sysfs interface created at /sys/devices/%s/", DRIVER_NAME);
	return 0;

err_device:
	root_device_unregister(evdi_sysfs_dev);
	evdi_sysfs_dev = NULL;
	return ret;
}

void evdi_sysfs_cleanup(void)
{
	if (evdi_sysfs_dev) {
		sysfs_remove_groups(&evdi_sysfs_dev->kobj, evdi_attr_groups);
		root_device_unregister(evdi_sysfs_dev);
		evdi_sysfs_dev = NULL;
	}

	evdi_info("Sysfs interface cleaned up");
}
