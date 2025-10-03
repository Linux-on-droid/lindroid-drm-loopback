// SPDX-License-Identifier: GPL-2.0-only
/*
 * Main driver core
 */

#include "evdi_drv.h"
#include <linux/platform_device.h>
#include <linux/of.h>

extern int evdi_event_system_init(void);
extern void evdi_event_system_cleanup(void);
extern const struct drm_ioctl_desc *evdi_get_ioctls(void);
extern int evdi_get_num_ioctls(void);

atomic_t evdi_device_count = ATOMIC_INIT(0);

static int evdi_driver_open(struct drm_device *dev, struct drm_file *file);
static void evdi_driver_postclose(struct drm_device *dev, struct drm_file *file);

#if EVDI_HAVE_DRM_OPEN_CLOSE
static const struct file_operations evdi_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
	.poll = drm_poll,
	.read = drm_read,
	.llseek = noop_llseek,
#ifdef CONFIG_COMPAT
	.compat_ioctl = drm_compat_ioctl,
#endif
};
#endif

static struct drm_driver evdi_driver = {
	.driver_features = DRIVER_MODESET |
#if EVDI_HAVE_ATOMIC_HELPERS
			  DRIVER_ATOMIC |
#endif
			  DRIVER_GEM,

	.open = evdi_driver_open,
	.postclose = evdi_driver_postclose,

#if EVDI_HAVE_DRM_OPEN_CLOSE
	.fops = &evdi_fops,
#endif

	.ioctls = NULL,
	.num_ioctls = 0,

	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,
};

static int evdi_driver_open(struct drm_device *dev, struct drm_file *file)
{
	return 0;
}

static void evdi_driver_postclose(struct drm_device *dev, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;

	evdi_event_cleanup_file(evdi, file);

	evdi_debug("Device %d closed by process %d", evdi->dev_index, current->pid);
}

int evdi_device_init(struct evdi_device *evdi, struct platform_device *pdev)
{
	int ret;

	evdi->pdev = pdev;
	evdi->dev_index = atomic_inc_return(&evdi_device_count) - 1;
	evdi->connected = false;

	evdi->width = 1920;
	evdi->height = 1080;
	evdi->refresh_rate = 60;

	mutex_init(&evdi->config_mutex);

#ifdef EVDI_HAVE_XARRAY
	xa_init(&evdi->file_xa);
#else
	idr_init(&evdi->file_idr);
	spin_lock_init(&evdi->file_lock);
#endif

	ret = evdi_event_init(evdi);
	if (ret) {
		evdi_err("Failed to initialize event system: %d", ret);
		goto err_event;
	}

	evdi_info("Device %d initialized", evdi->dev_index);
	return 0;

err_event:
#ifdef EVDI_HAVE_XARRAY
	xa_destroy(&evdi->file_xa);
#else
	idr_destroy(&evdi->file_idr);
#endif
	return ret;
}

void evdi_device_cleanup(struct evdi_device *evdi)
{
	evdi_info("Cleaning up device %d", evdi->dev_index);

	evdi_event_cleanup(evdi);

#ifdef EVDI_HAVE_XARRAY
	xa_destroy(&evdi->file_xa);
#else
	idr_destroy(&evdi->file_idr);
#endif

	evdi_info("Device %d cleaned up", evdi->dev_index);
}

static int evdi_platform_probe(struct platform_device *pdev)
{
	struct evdi_device *evdi;
	struct drm_device *ddev;
	int ret;

	evdi = kzalloc(sizeof(*evdi), GFP_KERNEL);
	if (!evdi)
		return -ENOMEM;

	ret = evdi_device_init(evdi, pdev);
	if (ret)
		goto err_init;

#ifdef EVDI_HAVE_DRM_MANAGED
	ddev = drm_dev_alloc(&evdi_driver, &pdev->dev);
#else
	ddev = drm_dev_alloc(&evdi_driver, &pdev->dev);
#endif
	if (IS_ERR(ddev)) {
		ret = PTR_ERR(ddev);
		evdi_err("Failed to allocate DRM device: %d", ret);
		goto err_drm_alloc;
	}

	ddev->dev_private = evdi;
	evdi->ddev = ddev;

	ret = evdi_modeset_init(ddev);
	if (ret) {
		evdi_err("Failed to initialize modeset: %d", ret);
		goto err_modeset;
	}

#if EVDI_HAVE_ATOMIC_HELPERS
	drm_mode_config_reset(ddev);
#endif

	ret = drm_dev_register(ddev, 0);
	if (ret) {
		evdi_err("Failed to register DRM device: %d", ret);
		goto err_register;
	}

	platform_set_drvdata(pdev, evdi);

	evdi_info("Platform device probed successfully, DRM device registered");
	return 0;

err_register:
	evdi_modeset_cleanup(ddev);
err_modeset:
#ifndef EVDI_HAVE_DRM_MANAGED
	drm_dev_put(ddev);
#endif
err_drm_alloc:
	evdi_device_cleanup(evdi);
err_init:
	kfree(evdi);
	return ret;
}

static int evdi_platform_remove(struct platform_device *pdev)
{
	struct evdi_device *evdi = platform_get_drvdata(pdev);
	struct drm_device *ddev = evdi->ddev;

	evdi_info("Removing platform device");

	drm_dev_unregister(ddev);

#if EVDI_HAVE_ATOMIC_HELPERS
	drm_atomic_helper_shutdown(ddev);
#endif

	evdi_modeset_cleanup(ddev);

	evdi_device_cleanup(evdi);

#ifndef EVDI_HAVE_DRM_MANAGED
	drm_dev_put(ddev);
#endif

	kfree(evdi);

	return 0;
}

static struct platform_driver evdi_platform_driver = {
	.probe = evdi_platform_probe,
	.remove = evdi_platform_remove,
	.driver = {
	.name = DRIVER_NAME,
	.owner = THIS_MODULE,
	},
};

static int __init evdi_init(void)
{
	int ret;

	evdi_info("Loading EVDI-Lindroid driver v%d.%d.%d",
		 DRIVER_MAJOR, DRIVER_MINOR, DRIVER_PATCHLEVEL);

	ret = evdi_event_system_init();
	if (ret) {
		evdi_err("Failed to initialize event system: %d", ret);
		return ret;
	}

	evdi_driver.ioctls = evdi_get_ioctls();
	evdi_driver.num_ioctls = evdi_get_num_ioctls();

	ret = platform_driver_register(&evdi_platform_driver);
	if (ret) {
		evdi_err("Failed to register platform driver: %d", ret);
		evdi_event_system_cleanup();
	return ret;
	}

	ret = evdi_sysfs_init();
	if (ret) {
		evdi_err("Failed to initialize sysfs: %d", ret);
		platform_driver_unregister(&evdi_platform_driver);
		evdi_event_system_cleanup();
		return ret;
	}

	evdi_info("Driver loaded successfully");
	return 0;
}

static void __exit evdi_exit(void)
{
	evdi_info("Unloading EVDI-Lindroid driver");

	evdi_sysfs_cleanup();

	platform_driver_unregister(&evdi_platform_driver);

	evdi_event_system_cleanup();

	evdi_info("Driver unloaded");
}

module_init(evdi_init);
module_exit(evdi_exit);

MODULE_AUTHOR("EVDI-Lindroid Project");
MODULE_DESCRIPTION("High-performance virtual display driver for Lindroid");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.0.0");
