// SPDX-License-Identifier: GPL-2.0-only
/*
 * Sysfs interface
 */

#include "evdi_drv.h"
#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/platform_device.h>

static struct class *evdi_class;
static struct device *evdi_sysfs_dev;

static ssize_t add_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", atomic_read(&evdi_device_count));
}

static ssize_t add_store(struct device *dev, struct device_attribute *attr,
			const char *buf, size_t count)
{
	struct platform_device *pdev;
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

	evdi_class = class_create(THIS_MODULE, DRIVER_NAME);
	if (IS_ERR(evdi_class)) {
		ret = PTR_ERR(evdi_class);
		evdi_err("Failed to create device class: %d", ret);
		return ret;
	}

	evdi_sysfs_dev = device_create(evdi_class, NULL, MKDEV(0, 0), NULL, DRIVER_NAME);
	if (IS_ERR(evdi_sysfs_dev)) {
		ret = PTR_ERR(evdi_sysfs_dev);
		evdi_err("Failed to create sysfs device: %d", ret);
		goto err_device;
	}

	ret = sysfs_create_groups(&evdi_sysfs_dev->kobj, evdi_attr_groups);
	if (ret) {
		evdi_err("Failed to create sysfs attributes: %d", ret);
		goto err_attrs;
	}

	evdi_info("Sysfs interface created at /sys/devices/%s/", DRIVER_NAME);
	return 0;

err_attrs:
	device_destroy(evdi_class, MKDEV(0, 0));
err_device:
	class_destroy(evdi_class);
	return ret;
}

void evdi_sysfs_cleanup(void)
{
	if (evdi_sysfs_dev) {
		sysfs_remove_groups(&evdi_sysfs_dev->kobj, evdi_attr_groups);
		device_destroy(evdi_class, MKDEV(0, 0));
	}

	if (evdi_class) {
		class_destroy(evdi_class);
	}

	evdi_info("Sysfs interface cleaned up");
}
