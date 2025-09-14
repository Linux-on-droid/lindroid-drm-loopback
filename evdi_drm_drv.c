// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Red Hat
 * Copyright (c) 2015 - 2020 DisplayLink (UK) Ltd.
 *
 * Based on parts on udlfb.c:
 * Copyright (C) 2009 its respective authors
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License v2. See the file COPYING in the main directory of this archive for
 * more details.
 */

#include <linux/slab.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/wait.h>
#include <linux/slab.h>
#if KERNEL_VERSION(5, 16, 0) <= LINUX_VERSION_CODE || defined(EL8) || defined(EL9)
#include <drm/drm_ioctl.h>
#include <drm/drm_file.h>
#include <drm/drm_drv.h>
#include <drm/drm_vblank.h>
#elif KERNEL_VERSION(5, 5, 0) <= LINUX_VERSION_CODE
#else
#include <drm/drmP.h>
#endif
#if KERNEL_VERSION(5, 1, 0) <= LINUX_VERSION_CODE || defined(EL8)
#include <drm/drm_probe_helper.h>
#endif
#if KERNEL_VERSION(5, 8, 0) <= LINUX_VERSION_CODE || defined(EL8)
#include <drm/drm_managed.h>
#endif
#include <drm/drm_atomic_helper.h>
#include "evdi_drm_drv.h"
#include "evdi_platform_drv.h"
#include "evdi_cursor.h"
#include "evdi_debug.h"
#include "evdi_drm.h"

#if KERNEL_VERSION(4, 15, 0) > LINUX_VERSION_CODE
#define drm_dev_put drm_dev_unref
#endif

#if KERNEL_VERSION(6, 8, 0) <= LINUX_VERSION_CODE || defined(EL8)
#define EVDI_DRM_UNLOCKED 0
#else
#define EVDI_DRM_UNLOCKED DRM_UNLOCKED
#endif

static struct drm_driver driver;
int evdi_swap_callback_ioctl(struct drm_device *drm_dev, void *data,
                    struct drm_file *file);
int evdi_add_buff_callback_ioctl(struct drm_device *drm_dev, void *data,
                    struct drm_file *file);

int evdi_destroy_buff_callback_ioctl(struct drm_device *drm_dev, void *data,
                    struct drm_file *file);

int evdi_gbm_add_buf_ioctl(
					struct drm_device *dev,
					void *data,
					struct drm_file *file);

int evdi_get_buff_callback_ioctl(struct drm_device *drm_dev, void *data,
                    struct drm_file *file);

int evdi_gbm_get_buf_ioctl(struct drm_device *dev, void *data,
					struct drm_file *file);

int evdi_gbm_del_buf_ioctl(struct drm_device *dev, void *data,
					struct drm_file *file);

int evdi_gbm_create_buff(struct drm_device *dev, void *data,
					struct drm_file *file);

int evdi_create_buff_callback_ioctl(struct drm_device *drm_dev, void *data,
                    struct drm_file *file);

static struct kmem_cache *evdi_event_cache;
static atomic_t evdi_event_cache_users = ATOMIC_INIT(0);

struct drm_ioctl_desc evdi_painter_ioctls[] = {
	DRM_IOCTL_DEF_DRV(EVDI_CONNECT, evdi_painter_connect_ioctl, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_REQUEST_UPDATE, evdi_painter_request_update_ioctl, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GRABPIX, evdi_painter_grabpix_ioctl, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_ENABLE_CURSOR_EVENTS, evdi_painter_enable_cursor_events_ioctl, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_POLL, evdi_poll_ioctl, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_SWAP_CALLBACK, evdi_swap_callback_ioctl, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_ADD_BUFF_CALLBACK, evdi_add_buff_callback_ioctl, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GET_BUFF_CALLBACK, evdi_get_buff_callback_ioctl, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_DESTROY_BUFF_CALLBACK, evdi_destroy_buff_callback_ioctl, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GBM_ADD_BUFF, evdi_gbm_add_buf_ioctl, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GBM_GET_BUFF, evdi_gbm_get_buf_ioctl, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GBM_DEL_BUFF, evdi_gbm_del_buf_ioctl, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GBM_CREATE_BUFF, evdi_gbm_create_buff, EVDI_DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GBM_CREATE_BUFF_CALLBACK, evdi_create_buff_callback_ioctl, EVDI_DRM_UNLOCKED),
};

#if KERNEL_VERSION(5, 11, 0) <= LINUX_VERSION_CODE || defined(EL8)
#else
static const struct vm_operations_struct evdi_gem_vm_ops = {
	.fault = evdi_gem_fault,
	.open = drm_gem_vm_open,
	.close = drm_gem_vm_close,
};
#endif

static const struct file_operations evdi_driver_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.mmap = evdi_drm_gem_mmap,
	.poll = drm_poll,
	.read = drm_read,
	.unlocked_ioctl = drm_ioctl,
	.release = drm_release,

#ifdef CONFIG_COMPAT
	.compat_ioctl = evdi_compat_ioctl,
#endif

	.llseek = noop_llseek,

#if defined(FOP_UNSIGNED_OFFSET)
	.fop_flags = FOP_UNSIGNED_OFFSET,
#endif
};

#define EVDI_MAX_FDS   32
#define EVDI_MAX_INTS  256

//Handle short copies due to minor faults on big buffers
static inline int evdi_prefault_readable(const void __user *uaddr, size_t len)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0) || defined(EL8) || defined(EL9)
	return fault_in_readable(uaddr, len);
#else
	return 0;
#endif
}

static inline int evdi_prefault_writeable(void __user *uaddr, size_t len)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0) || defined(EL8) || defined(EL9)
	return fault_in_writeable(uaddr, len);
#else
	return 0;
#endif
}

//Allow partial progress; return -EFAULT only if zero progress
static int evdi_copy_from_user_allow_partial(void *dst, const void __user *src, size_t len)
{
	size_t not;
	if (!len)
		return 0;
	memset(dst, 0, len);
	(void)evdi_prefault_readable(src, len);
	not = copy_from_user(dst, src, len);
	if (not == len)
		return -EFAULT;
	return 0;
}

static int evdi_copy_to_user_allow_partial(void __user *dst, const void *src, size_t len)
{
	size_t not;
	if (!len)
		return 0;
	(void)evdi_prefault_writeable(dst, len);
	not = copy_to_user(dst, src, len);
	if (not == len)
		return -EFAULT;
	return 0;
}

#define EVDI_WAIT_TIMEOUT (5*HZ)

#define EVDI_SAFE_KFREE(p) do { kfree(p); (p) = NULL; } while (0)

#if KERNEL_VERSION(5, 11, 0) <= LINUX_VERSION_CODE || defined(EL8)
#else
static int evdi_enable_vblank(__always_unused struct drm_device *dev,
			      __always_unused unsigned int pipe)
{
	return 1;
}

static void evdi_disable_vblank(__always_unused struct drm_device *dev,
				__always_unused unsigned int pipe)
{
}
#endif

static struct drm_driver driver = {
#if KERNEL_VERSION(5, 4, 0) <= LINUX_VERSION_CODE || defined(EL8)
	.driver_features = DRIVER_MODESET | DRIVER_GEM | DRIVER_ATOMIC,
#else
	.driver_features = DRIVER_MODESET | DRIVER_GEM | DRIVER_PRIME
			 | DRIVER_ATOMIC,
#endif

	.open = evdi_driver_open,
	.postclose = evdi_driver_postclose,

	/* gem hooks */
#if KERNEL_VERSION(5, 11, 0) <= LINUX_VERSION_CODE || defined(EL8)
#elif KERNEL_VERSION(5, 9, 0) <= LINUX_VERSION_CODE
	.gem_free_object_unlocked = evdi_gem_free_object,
#else
	.gem_free_object = evdi_gem_free_object,
#endif

#if KERNEL_VERSION(5, 11, 0) <= LINUX_VERSION_CODE || defined(EL8)
#else
	.gem_vm_ops = &evdi_gem_vm_ops,
#endif

	.dumb_create = evdi_dumb_create,
	.dumb_map_offset = evdi_gem_mmap,
#if KERNEL_VERSION(5, 12, 0) <= LINUX_VERSION_CODE || defined(EL8)
#else
	.dumb_destroy = drm_gem_dumb_destroy,
#endif

	.ioctls = evdi_painter_ioctls,
	.num_ioctls = ARRAY_SIZE(evdi_painter_ioctls),

	.fops = &evdi_driver_fops,

	.gem_prime_import = drm_gem_prime_import,
#if KERNEL_VERSION(6, 6, 0) <= LINUX_VERSION_CODE
#else
	.prime_fd_to_handle = drm_gem_prime_fd_to_handle,
	.prime_handle_to_fd = drm_gem_prime_handle_to_fd,
#endif
#if KERNEL_VERSION(5, 11, 0) <= LINUX_VERSION_CODE || defined(EL8)
#else
	.preclose = evdi_driver_preclose,
	.gem_prime_export = drm_gem_prime_export,
	.gem_prime_get_sg_table = evdi_prime_get_sg_table,
	.enable_vblank = evdi_enable_vblank,
	.disable_vblank = evdi_disable_vblank,
#endif
	.gem_prime_import_sg_table = evdi_prime_import_sg_table,

	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCH,
};

struct evdi_event *evdi_create_event(struct evdi_device *evdi, enum poll_event_type type, void *data)
{
	struct evdi_event *event;

	event = kmem_cache_zalloc(evdi_event_cache, GFP_KERNEL);
	if (!event)
		return NULL;

	event->type = type;
	event->data = data;
	init_waitqueue_head(&event->wait);
	event->completed = false;
	event->evdi = evdi;

	idr_preload(GFP_KERNEL);
	mutex_lock(&evdi->event_lock);
	event->poll_id = atomic_fetch_inc(&evdi->next_event_id);
	if (idr_alloc(&evdi->event_idr, event,
		      event->poll_id, event->poll_id + 1, GFP_NOWAIT) < 0) {
		mutex_unlock(&evdi->event_lock);
		idr_preload_end();
		kmem_cache_free(evdi_event_cache, event);
		return NULL;
	}
	list_add_tail(&event->list, &evdi->event_queue);
	mutex_unlock(&evdi->event_lock);
	idr_preload_end();

	return event;
}

void evdi_event_free(struct evdi_event *event)
{
	if (event)
		kmem_cache_free(evdi_event_cache, event);
}

static int evdi_event_cache_get(void)
{
	if (!evdi_event_cache) {
		evdi_event_cache = kmem_cache_create("evdi_event",
						     sizeof(struct evdi_event),
						     0, SLAB_HWCACHE_ALIGN, NULL);
		if (!evdi_event_cache)
			return -ENOMEM;
	}
	atomic_inc(&evdi_event_cache_users);
	return 0;
}

static void evdi_event_cache_put(void)
{
	if (atomic_dec_and_test(&evdi_event_cache_users) && evdi_event_cache) {
		kmem_cache_destroy(evdi_event_cache);
		evdi_event_cache = NULL;
	}
}

int evdi_swap_callback_ioctl(struct drm_device *drm_dev, void *data,
                    struct drm_file *file)
{
	struct evdi_device *evdi = drm_dev->dev_private;
	struct drm_evdi_add_buff_callabck *cmd = data;
	struct evdi_event *event;

	mutex_lock(&evdi->event_lock);
	event = idr_find(&evdi->event_idr, cmd->poll_id);
	mutex_unlock(&evdi->event_lock);

	if (!event)
		return -EINVAL;

	event->result = 0;
	event->completed = true;
	wake_up(&event->wait);
	return 0;
}

int evdi_add_buff_callback_ioctl(struct drm_device *drm_dev, void *data,
                    struct drm_file *file)
{
	struct evdi_device *evdi = drm_dev->dev_private;
	struct drm_evdi_add_buff_callabck *cmd = data;
	struct evdi_event *event;
	int *buff_id_ptr;

	mutex_lock(&evdi->event_lock);
	event = idr_find(&evdi->event_idr, cmd->poll_id);
	mutex_unlock(&evdi->event_lock);

	if (!event)
		return -EINVAL;

	buff_id_ptr = kzalloc(sizeof(int), GFP_KERNEL);
	if (!buff_id_ptr)
		return -ENOMEM;

	*buff_id_ptr = cmd->buff_id;
	event->reply_data = buff_id_ptr;
	event->result = 0;
	event->completed = true;
	wake_up(&event->wait);
	return 0;
}

int evdi_get_buff_callback_ioctl(struct drm_device *drm_dev, void *data,
                     struct drm_file *file)
{
	struct evdi_device *evdi = drm_dev->dev_private;
	struct drm_evdi_get_buff_callabck *cmd = data;
	struct evdi_event *event;
	struct evdi_gralloc_buf *gralloc_buf;
	int *fd_ints = NULL;
	int i;

	mutex_lock(&evdi->event_lock);
	event = idr_find(&evdi->event_idr, cmd->poll_id);
	mutex_unlock(&evdi->event_lock);

	if (!event)
		return -EINVAL;

	if (cmd->numFds < 0 || cmd->numInts < 0 ||
	    cmd->numFds > EVDI_MAX_FDS || cmd->numInts > EVDI_MAX_INTS)
		return -EINVAL;

	gralloc_buf = kzalloc(sizeof(struct evdi_gralloc_buf), GFP_KERNEL);
	if (!gralloc_buf)
		return -ENOMEM;

	gralloc_buf->version = cmd->version;
	gralloc_buf->numFds = cmd->numFds;
	gralloc_buf->numInts = cmd->numInts;

	gralloc_buf->data_ints = kzalloc(sizeof(int) * cmd->numInts, GFP_KERNEL);
	gralloc_buf->data_files = kzalloc(sizeof(struct file *) * cmd->numFds, GFP_KERNEL);
	if ((cmd->numInts && !gralloc_buf->data_ints) ||
	    (cmd->numFds && !gralloc_buf->data_files)) {
		EVDI_SAFE_KFREE(gralloc_buf->data_ints);
		EVDI_SAFE_KFREE(gralloc_buf->data_files);
		kfree(gralloc_buf);
		return -ENOMEM;
	}

	if (evdi_copy_from_user_allow_partial(gralloc_buf->data_ints,
					      (const void __user *)cmd->data_ints,
					      sizeof(int) * cmd->numInts)) {
		EVDI_SAFE_KFREE(gralloc_buf->data_ints);
		EVDI_SAFE_KFREE(gralloc_buf->data_files);
		kfree(gralloc_buf);
		return -EFAULT;
	}


	fd_ints = kzalloc(sizeof(int) * cmd->numFds, GFP_KERNEL);
	if (!fd_ints) {
		EVDI_SAFE_KFREE(gralloc_buf->data_ints);
		EVDI_SAFE_KFREE(gralloc_buf->data_files);
		kfree(gralloc_buf);
		return -ENOMEM;
	}
	if (evdi_copy_from_user_allow_partial(fd_ints,
					      (const void __user *)cmd->fd_ints,
					      sizeof(int) * cmd->numFds)) {
		EVDI_SAFE_KFREE(fd_ints);
		EVDI_SAFE_KFREE(gralloc_buf->data_ints);
		EVDI_SAFE_KFREE(gralloc_buf->data_files);
		kfree(gralloc_buf);
		return -EFAULT;
	}
	
	for (i = 0; i < cmd->numFds; i++) {
		gralloc_buf->data_files[i] = fget(fd_ints[i]);
		if (!gralloc_buf->data_files[i]) {
			EVDI_ERROR("evdi_get_buff_callback_ioctl: Failed to open fake fb %d\n", cmd->fd_ints[i]);
			while (--i >= 0) {
				if (gralloc_buf->data_files[i])
					fput(gralloc_buf->data_files[i]);
			}
			EVDI_SAFE_KFREE(fd_ints);
			EVDI_SAFE_KFREE(gralloc_buf->data_ints);
			EVDI_SAFE_KFREE(gralloc_buf->data_files);
			kfree(gralloc_buf);
			return -EINVAL;
		}
	}
	EVDI_SAFE_KFREE(fd_ints);

	event->reply_data = gralloc_buf;
	event->result = 0;
	event->completed = true;
	wake_up(&event->wait);
	return 0;
}

int evdi_destroy_buff_callback_ioctl(struct drm_device *drm_dev, void *data,
                     struct drm_file *file)
{
	struct evdi_device *evdi = drm_dev->dev_private;
	struct drm_evdi_add_buff_callabck *cmd = data;
	struct evdi_event *event;
	mutex_lock(&evdi->event_lock);
	event = idr_find(&evdi->event_idr, cmd->poll_id);
	mutex_unlock(&evdi->event_lock);
	if (!event) {
		EVDI_ERROR("evdi_destroy_buff_callback_ioctl: event is null\n");
		return -EINVAL;
	}

	event->result = 0;
	event->completed = true;
	wake_up(&event->wait);
	return 0;
}

int evdi_create_buff_callback_ioctl(struct drm_device *drm_dev, void *data,
                    struct drm_file *file)
{
	struct evdi_device *evdi = drm_dev->dev_private;
	struct drm_evdi_create_buff_callabck *cmd = data;
	struct evdi_event *event;
	struct drm_evdi_create_buff_callabck *buf = kzalloc(sizeof(struct drm_evdi_create_buff_callabck), GFP_KERNEL);
	memcpy(buf, data, sizeof(struct drm_evdi_create_buff_callabck));
	mutex_lock(&evdi->event_lock);
	event = idr_find(&evdi->event_idr, cmd->poll_id);
	mutex_unlock(&evdi->event_lock);

	if (!event)
		return -EINVAL;

	event->result = 0;
	event->completed = true;
	event->reply_data = buf;
	wake_up(&event->wait);
	return 0;
}

int evdi_gbm_add_buf_ioctl(struct drm_device *dev, void *data,
					struct drm_file *file)
{
	struct file *memfd_file;
	struct file *fd_file;
	int ret;
	int version, numFds, numInts, fd;
	ssize_t bytes_read;
	struct evdi_gralloc_buf *add_gralloc_buf;
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_gbm_add_buf *cmd = data;
	struct evdi_event *event;
	loff_t pos;
	int i;
	int *installed_fd_tmps = NULL;

	memfd_file = fget(cmd->fd);
	if (!memfd_file) {
		EVDI_ERROR("Failed to open fake fb: %d\n", cmd->fd);
		return -EINVAL;
	}

	pos = 0; /* Initialize offset */
	bytes_read = kernel_read(memfd_file, &version, sizeof(version), &pos);
	if (bytes_read != sizeof(version)) {
		EVDI_ERROR("Failed to read version from memfd, bytes_read=%zd\n", bytes_read);
		fput(memfd_file);
		return -EIO;
	}

	bytes_read = kernel_read(memfd_file, &numFds, sizeof(numFds), &pos);
	if (bytes_read != sizeof(numFds)) {
		EVDI_ERROR("Failed to read numFds from memfd, bytes_read=%zd\n", bytes_read);
		fput(memfd_file);
		return -EIO;
	}

	bytes_read = kernel_read(memfd_file, &numInts, sizeof(numInts), &pos);
	if (bytes_read != sizeof(numInts)) {
		EVDI_ERROR("Failed to read numInts from memfd, bytes_read=%zd\n", bytes_read);
		fput(memfd_file);
		return -EIO;
	}
	add_gralloc_buf = kzalloc(sizeof(struct evdi_gralloc_buf), GFP_KERNEL);
	if (!add_gralloc_buf) {
		fput(memfd_file);
		return -ENOMEM;
	}

	add_gralloc_buf->numFds = numFds;
	add_gralloc_buf->numInts = numInts;
	add_gralloc_buf->data_ints = kzalloc(sizeof(int) * numInts, GFP_KERNEL);
	add_gralloc_buf->data_files = kzalloc(sizeof(struct file *) * numFds, GFP_KERNEL);
	if ((numInts && !add_gralloc_buf->data_ints) ||
	    (numFds && !add_gralloc_buf->data_files)) {
		EVDI_SAFE_KFREE(add_gralloc_buf->data_ints);
		EVDI_SAFE_KFREE(add_gralloc_buf->data_files);
		kfree(add_gralloc_buf);
		fput(memfd_file);
		return -ENOMEM;
	}
	add_gralloc_buf->memfd_file = memfd_file;

	installed_fd_tmps = kcalloc(numFds, sizeof(int), GFP_KERNEL);
	if (numFds && !installed_fd_tmps) {
		EVDI_SAFE_KFREE(add_gralloc_buf->data_ints);
		EVDI_SAFE_KFREE(add_gralloc_buf->data_files);
		kfree(add_gralloc_buf);
		fput(memfd_file);
		return -ENOMEM;
	}

	for (i = 0; i < numFds; i++) {
		installed_fd_tmps[i] = -1;
		bytes_read = kernel_read(memfd_file, &fd, sizeof(fd), &pos);
		if (bytes_read != sizeof(fd)) {
			EVDI_ERROR("Failed to read fd from memfd, bytes_read=%zd\n", bytes_read);
			EVDI_SAFE_KFREE(add_gralloc_buf->data_ints);
			EVDI_SAFE_KFREE(add_gralloc_buf->data_files);
			kfree(add_gralloc_buf);
			fput(memfd_file);
			EVDI_SAFE_KFREE(installed_fd_tmps);
			return -EIO;
		}
		fd_file = fget(fd);
		if (!fd_file) {
			EVDI_ERROR("Failed to open fake fb's %d fd file: %d\n", cmd->fd, fd);
			EVDI_SAFE_KFREE(add_gralloc_buf->data_ints);
			EVDI_SAFE_KFREE(add_gralloc_buf->data_files);
			kfree(add_gralloc_buf);
			fput(memfd_file);
			EVDI_SAFE_KFREE(installed_fd_tmps);
			return -EINVAL;
		}
		add_gralloc_buf->data_files[i] = fd_file;

	}

	bytes_read = kernel_read(memfd_file, add_gralloc_buf->data_ints, sizeof(int) *numInts, &pos);
	if (bytes_read != sizeof(int) *numInts) {
		EVDI_ERROR("Failed to read ints from memfd, bytes_read=%zd\n", bytes_read);
		for (i = 0; i < numFds; i++) {
			if (add_gralloc_buf->data_files[i])
				fput(add_gralloc_buf->data_files[i]);
		}
		EVDI_SAFE_KFREE(add_gralloc_buf->data_ints);
		EVDI_SAFE_KFREE(add_gralloc_buf->data_files);
		kfree(add_gralloc_buf);
		fput(memfd_file);
		EVDI_SAFE_KFREE(installed_fd_tmps);
		return -EIO;
	}

	event = evdi_create_event(evdi, add_buf, add_gralloc_buf);
	if (!event)
		return -ENOMEM;

	wake_up(&evdi->poll_ioct_wq);
	ret = wait_event_interruptible_timeout(event->wait, event->completed, EVDI_WAIT_TIMEOUT);
	if (ret == 0) {
		EVDI_ERROR("evdi_gbm_add_buf_ioctl: wait timed out\n");
		for (i = 0; i < numFds; i++) {
			if (add_gralloc_buf->data_files[i])
				fput(add_gralloc_buf->data_files[i]);
		}
		fput(add_gralloc_buf->memfd_file);
		EVDI_SAFE_KFREE(add_gralloc_buf->data_ints);
		EVDI_SAFE_KFREE(add_gralloc_buf->data_files);
		kfree(add_gralloc_buf);
		goto err_event;
	}
	if (ret < 0){
		EVDI_ERROR("evdi_gbm_add_buf_ioctl: wait_event_interruptible interrupted: %d\n", ret);
		goto err_event;
	}

	ret = event->result;
	if (ret < 0) {
		EVDI_ERROR("evdi_gbm_add_buf_ioctl: user ioctl failled\n");
		goto err_event;
	}

	if (ret)
		goto err_inval;

	if (event->reply_data) {
		cmd->id = *((int *)event->reply_data);
		kfree(event->reply_data);
		event->reply_data = NULL;
	}
	mutex_lock(&evdi->event_lock);
	idr_remove(&evdi->event_idr, event->poll_id);
	mutex_unlock(&evdi->event_lock);
	evdi_event_free(event);
	EVDI_SAFE_KFREE(installed_fd_tmps);
	return 0;

 /* err_no_mem: removed unused label */
 err_inval:
	return -EINVAL;

 err_event:
	mutex_lock(&evdi->event_lock);
	idr_remove(&evdi->event_idr, event->poll_id);
	mutex_unlock(&evdi->event_lock);
	evdi_event_free(event);
	EVDI_SAFE_KFREE(installed_fd_tmps);
	return ret ? ret : -ETIMEDOUT;
}

int evdi_gbm_get_buf_ioctl(struct drm_device *dev, void *data,
					struct drm_file *file)
{
	struct drm_evdi_gbm_get_buff *cmd = data;
	struct evdi_gralloc_buf_user *gralloc_buf = kzalloc(sizeof(struct evdi_gralloc_buf_user), GFP_KERNEL);
	struct evdi_gralloc_buf *gralloc_buf_tmp = NULL;
	struct evdi_device *evdi = dev->dev_private;
	int fd_tmp, ret;
	struct evdi_event *event;
	int i;
	int *installed_fds = NULL;

	event = evdi_create_event(evdi, get_buf, &cmd->id);
	if (!event)
		return -ENOMEM;

	wake_up(&evdi->poll_ioct_wq);
	ret = wait_event_interruptible_timeout(event->wait, event->completed, EVDI_WAIT_TIMEOUT);
	if (ret == 0) {
		EVDI_ERROR("evdi_gbm_get_buf_ioctl: wait timed out\n");
		goto err_event;
	} else if (ret < 0) {
		EVDI_ERROR("evdi_gbm_get_buf_ioctl: wait_event_interruptible interrupted: %d\n", ret);
		goto err_event;
	}

	ret = event->result;
	if (ret < 0) {
		EVDI_ERROR("evdi_gbm_get_buf_ioctl: user ioctl failled\n");
		goto err_event;
	}

	gralloc_buf_tmp = event->reply_data;
	if (!gralloc_buf || !gralloc_buf_tmp) {
		ret = -ENOMEM;
		goto err_event;
	}
	gralloc_buf->version = gralloc_buf_tmp->version;
	gralloc_buf->numFds = gralloc_buf_tmp->numFds;
	gralloc_buf->numInts = gralloc_buf_tmp->numInts;
	memcpy(&gralloc_buf->data[gralloc_buf->numFds], gralloc_buf_tmp->data_ints, sizeof(int)*gralloc_buf->numInts);

	installed_fds = kcalloc(gralloc_buf->numFds, sizeof(int), GFP_KERNEL);
	if (gralloc_buf->numFds && !installed_fds) {
		ret = -ENOMEM;
		goto err_event;
	}
	for (i = 0; i < gralloc_buf->numFds; i++) {
		fd_tmp = get_unused_fd_flags(O_RDWR);
		if (fd_tmp < 0) {
			while (--i >= 0)
				put_unused_fd(installed_fds[i]);
			ret = fd_tmp;
			goto err_event;
		}
		installed_fds[i] = fd_tmp;
		gralloc_buf->data[i] = fd_tmp;
	}

	if (evdi_copy_to_user_allow_partial((void __user *)cmd->native_handle,
					    gralloc_buf,
					    sizeof(int) * (3 + gralloc_buf->numFds + gralloc_buf->numInts))) {
		EVDI_ERROR("Failed to copy file descriptor to userspace\n");
		for (i = 0; i < gralloc_buf->numFds; i++)
			put_unused_fd(installed_fds[i]);
		ret = -EFAULT;
		goto err_event;
	}

	for (i = 0; i < gralloc_buf->numFds; i++)
		fd_install(installed_fds[i], gralloc_buf_tmp->data_files[i]);

	kfree(gralloc_buf);
	if (gralloc_buf_tmp) {
		EVDI_SAFE_KFREE(gralloc_buf_tmp->data_ints);
		EVDI_SAFE_KFREE(gralloc_buf_tmp->data_files);
		kfree(gralloc_buf_tmp);
		event->reply_data = NULL;
	}
	mutex_lock(&evdi->event_lock);
	idr_remove(&evdi->event_idr, event->poll_id);
	mutex_unlock(&evdi->event_lock);
	evdi_event_free(event);
	EVDI_SAFE_KFREE(installed_fds);

	return 0;

err_event:
	kfree(gralloc_buf);
	if (gralloc_buf_tmp) {
		for (i = 0; i < gralloc_buf_tmp->numFds; i++)
			if (gralloc_buf_tmp->data_files[i])
				fput(gralloc_buf_tmp->data_files[i]);

		EVDI_SAFE_KFREE(gralloc_buf_tmp->data_ints);
		EVDI_SAFE_KFREE(gralloc_buf_tmp->data_files);
		kfree(gralloc_buf_tmp);
		event->reply_data = NULL;
	}
	mutex_lock(&evdi->event_lock);
	idr_remove(&evdi->event_idr, event->poll_id);
	mutex_unlock(&evdi->event_lock);
	evdi_event_free(event);
	EVDI_SAFE_KFREE(installed_fds);
	return ret ? ret : -ETIMEDOUT;
}

int evdi_gbm_del_buf_ioctl(struct drm_device *dev, void *data,
					struct drm_file *file)
{
	struct drm_evdi_gbm_del_buff *cmd = data;
	struct evdi_device *evdi = dev->dev_private;
	int ret;
	struct evdi_event *event;

	event = evdi_create_event(evdi, destroy_buf, &cmd->id);
	if (!event)
		return -ENOMEM;

	wake_up(&evdi->poll_ioct_wq);
	ret = wait_event_interruptible_timeout(event->wait, event->completed, EVDI_WAIT_TIMEOUT);
	if (ret == 0) {
		EVDI_ERROR("evdi_gbm_del_buf_ioctl: wait timed out\n");
		ret = -ETIMEDOUT;
	} else if (ret < 0) {
		EVDI_ERROR("evdi_gbm_get_buf_ioctl: wait_event_interruptible interrupted: %d\n", ret);
		/* fallthrough */
	}

	if (ret > 0) {
		ret = event->result;
		if (ret < 0) {
			EVDI_ERROR("evdi_gbm_get_buf_ioctl: user ioctl failled\n");
		}
	}

	mutex_lock(&evdi->event_lock);
	idr_remove(&evdi->event_idr, event->poll_id);
	mutex_unlock(&evdi->event_lock);
	evdi_event_free(event);

	return ret > 0 ? 0 : ret;
}

int evdi_gbm_create_buff (struct drm_device *dev, void *data,
					struct drm_file *file)
{
	struct drm_evdi_gbm_create_buff *cmd = data;
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_create_buff_callabck *cb_cmd;
	int ret;
	struct evdi_event *event = evdi_create_event(evdi, create_buf, cmd);
	if (!event)
		return -ENOMEM;

	wake_up(&evdi->poll_ioct_wq);
	ret = wait_event_interruptible_timeout(event->wait, event->completed, EVDI_WAIT_TIMEOUT);
	if (ret == 0) {
		EVDI_ERROR("evdi_gbm_create_buff: wait timed out\n");
		goto err_event;
	} else if (ret < 0) {
		EVDI_ERROR("evdi_gbm_create_buff: wait_event_interruptible interrupted: %d\n", ret);
		goto err_event;
	}

	ret = event->result;
	if (ret < 0) {
		EVDI_ERROR("evdi_gbm_create_buff: user ioctl failled\n");
		goto err_event;
	}

	cb_cmd = (struct drm_evdi_create_buff_callabck *)event->reply_data;
	if (evdi_copy_to_user_allow_partial((void __user *)cmd->id, &cb_cmd->id, sizeof(int)) ||
	    evdi_copy_to_user_allow_partial((void __user *)cmd->stride, &cb_cmd->stride, sizeof(int))) {
		ret = -EFAULT;
		goto err_event;
	}

	mutex_lock(&evdi->event_lock);
	idr_remove(&evdi->event_idr, event->poll_id);
	mutex_unlock(&evdi->event_lock);
	kfree(cb_cmd);
	evdi_event_free(event);

	return 0;

err_event:
	mutex_lock(&evdi->event_lock);
	idr_remove(&evdi->event_idr, event->poll_id);
	mutex_unlock(&evdi->event_lock);
	if (event->reply_data)
		kfree(event->reply_data);
	evdi_event_free(event);
	return ret ? ret : -ETIMEDOUT;
}

int evdi_poll_ioctl(struct drm_device *drm_dev, void *data,
                    struct drm_file *file)
{
	struct evdi_device *evdi = drm_dev->dev_private;
	struct drm_evdi_poll *cmd = data;
	struct evdi_event *event;
	int fd, fd_tmp, ret;
	ssize_t bytes_write;
	loff_t pos;
	int i;

	EVDI_CHECKPT();

	if (!evdi) {
		EVDI_ERROR("evdi is null\n");
		return -ENODEV;
	}

	ret = wait_event_interruptible(evdi->poll_ioct_wq,
				  atomic_read(&evdi->poll_stopping) ||
				  !list_empty(&evdi->event_queue));
	if (ret < 0) {
		EVDI_ERROR("evdi_poll_ioctl: Wait interrupted by signal\n");
		return ret;
	}

	//If woken when stopping, interrupt
	if (unlikely(atomic_read(&evdi->poll_stopping)))
		return -EINTR;

	mutex_lock(&evdi->event_lock);

	if (list_empty(&evdi->event_queue)) {
		mutex_unlock(&evdi->event_lock);
		return -EAGAIN;
	}

	event = list_first_entry(&evdi->event_queue, struct evdi_event, list);
	list_del(&event->list);

	mutex_unlock(&evdi->event_lock);

	cmd->event = event->type;
	cmd->poll_id = event->poll_id;

	switch(cmd->event) {
		case add_buf:
			{
			struct evdi_gralloc_buf *add_gralloc_buf = event->data;
			int *reserved_fd_tmps = NULL;

			fd = get_unused_fd_flags(O_RDWR);
			if (fd < 0) {
				EVDI_ERROR("Failed to allocate file descriptor\n");
				return fd;
			}

			reserved_fd_tmps = kcalloc(add_gralloc_buf->numFds, sizeof(int), GFP_KERNEL);
			if (add_gralloc_buf->numFds && !reserved_fd_tmps) {
				put_unused_fd(fd);
				return -ENOMEM;
			}
			for (i = 0; i < add_gralloc_buf->numFds; i++) {
				fd_tmp = get_unused_fd_flags(O_RDWR);
				if (fd_tmp < 0) {
					while (--i >= 0)
						put_unused_fd(reserved_fd_tmps[i]);
					put_unused_fd(fd);
					EVDI_SAFE_KFREE(reserved_fd_tmps);
					return fd_tmp;
				}
				reserved_fd_tmps[i] = fd_tmp;
			}

			for (i = 0; i < add_gralloc_buf->numFds; i++) {
				fput(add_gralloc_buf->data_files[i]);
				pos = sizeof(int) * (3 + i);
				bytes_write = kernel_write(add_gralloc_buf->memfd_file,
							   &reserved_fd_tmps[i], sizeof(reserved_fd_tmps[i]), &pos);
				if (bytes_write != sizeof(fd_tmp)) {
					EVDI_ERROR("Failed to write fd\n");
					for (; i >= 0; i--)
						put_unused_fd(reserved_fd_tmps[i]);

					put_unused_fd(fd);
					EVDI_SAFE_KFREE(reserved_fd_tmps);
					EVDI_SAFE_KFREE(add_gralloc_buf->data_ints);
					EVDI_SAFE_KFREE(add_gralloc_buf->data_files);
					kfree(add_gralloc_buf);
					return -EFAULT;
				}
			}

			if (evdi_copy_to_user_allow_partial((void __user *)cmd->data, &fd, sizeof(fd))) {
				EVDI_ERROR("Failed to copy file descriptor to userspace\n");
				for (i = 0; i < add_gralloc_buf->numFds; i++)
					put_unused_fd(reserved_fd_tmps[i]);

				put_unused_fd(fd);
				EVDI_SAFE_KFREE(reserved_fd_tmps);
				EVDI_SAFE_KFREE(add_gralloc_buf->data_ints);
				EVDI_SAFE_KFREE(add_gralloc_buf->data_files);
				kfree(add_gralloc_buf);
				return -EFAULT;
			}
			fd_install(fd, add_gralloc_buf->memfd_file);
			for (i = 0; i < add_gralloc_buf->numFds; i++)
				fd_install(reserved_fd_tmps[i], add_gralloc_buf->data_files[i]);

			EVDI_SAFE_KFREE(reserved_fd_tmps);
			EVDI_SAFE_KFREE(add_gralloc_buf->data_ints);
			EVDI_SAFE_KFREE(add_gralloc_buf->data_files);
			kfree(add_gralloc_buf);
			break;
			}
		case create_buf:
			if (evdi_copy_to_user_allow_partial((void __user *)cmd->data,
							    event->data,
							    sizeof(struct drm_evdi_gbm_create_buff))) {
				return -EFAULT;
			}
			break;
		case get_buf:
		case swap_to:
		case destroy_buf:
			if (evdi_copy_to_user_allow_partial((void __user *)cmd->data,
							    event->data, sizeof(int))) {
				return -EFAULT;
			}
			break;
		default:
			EVDI_ERROR("unknown event: %d\n", cmd->event);
	}

	return 0;
}

static void evdi_drm_device_release_cb(__always_unused struct drm_device *dev,
				       __always_unused void *ptr)
{
	struct evdi_device *evdi = dev->dev_private;

	evdi_cursor_free(evdi->cursor);
	evdi_painter_cleanup(evdi->painter);
	kfree(evdi);
	dev->dev_private = NULL;
	EVDI_INFO("Evdi drm_device removed.\n");
	evdi_event_cache_put();

	EVDI_TEST_HOOK(evdi_testhook_drm_device_destroyed());
}

static int evdi_drm_device_init(struct drm_device *dev)
{
	struct evdi_device *evdi;
	int ret;

	EVDI_CHECKPT();
	evdi = kzalloc(sizeof(struct evdi_device), GFP_KERNEL);
	if (!evdi)
		return -ENOMEM;

	evdi->ddev = dev;
	evdi->dev_index = dev->primary->index;
	evdi->cursor_events_enabled = false;
	dev->dev_private = evdi;
	evdi->poll_event = none;
	init_waitqueue_head (&evdi->poll_ioct_wq);
	init_waitqueue_head (&evdi->poll_response_ioct_wq);
	atomic_set(&evdi->poll_stopping, 0);
	mutex_init(&evdi->poll_lock);
	init_completion(&evdi->poll_completion);
	evdi->poll_data_size = -1;

	ret = evdi_event_cache_get();
	if (ret)
		goto err_free;

	mutex_init(&evdi->event_lock);
	INIT_LIST_HEAD(&evdi->event_queue);
	idr_init(&evdi->event_idr);
	atomic_set(&evdi->next_event_id, 1);

	ret = evdi_painter_init(evdi);
	if (ret)
		goto err_free;
	ret =  evdi_cursor_init(&evdi->cursor);
	if (ret)
		goto err_free;

	evdi_modeset_init(dev);

	ret = drm_vblank_init(dev, 1);
	if (ret)
		goto err_init;
	drm_kms_helper_poll_init(dev);

#if KERNEL_VERSION(5, 8, 0) <= LINUX_VERSION_CODE || defined(EL8)
	ret = drmm_add_action_or_reset(dev, evdi_drm_device_release_cb, NULL);
	if (ret)
		goto err_init;
#endif

	return 0;

err_init:
err_free:
	EVDI_ERROR("Failed to setup drm device %d\n", ret);
	evdi_cursor_free(evdi->cursor);
	kfree(evdi->painter);
	kfree(evdi);
	dev->dev_private = NULL;
	return ret;
}

int evdi_driver_open(struct drm_device *dev, __always_unused struct drm_file *file)
{
	char buf[100];

	evdi_log_process(buf, sizeof(buf));
	if (dev && dev->dev_private) {
		struct evdi_device *evdi = dev->dev_private;
		atomic_set(&evdi->poll_stopping, 0);
	}
	EVDI_INFO("(card%d) Opened by %s\n", dev->primary->index, buf);
	return 0;
}

static void evdi_driver_close(struct drm_device *drm_dev, struct drm_file *file)
{
	struct evdi_device *evdi = drm_dev->dev_private;

	EVDI_CHECKPT();
	if (evdi)
		evdi_painter_close(evdi, file);
}

void evdi_driver_preclose(struct drm_device *drm_dev, struct drm_file *file)
{
	struct evdi_device *evdi = drm_dev->dev_private;
	if (evdi) {
		atomic_set(&evdi->poll_stopping, 1);
		wake_up_all(&evdi->poll_ioct_wq);
		wake_up_all(&evdi->poll_response_ioct_wq);
	}
	evdi_driver_close(drm_dev, file);
}

void evdi_driver_postclose(struct drm_device *dev, struct drm_file *file)
{
	char buf[100];

	evdi_log_process(buf, sizeof(buf));
	evdi_driver_close(dev, file);
	EVDI_INFO("(card%d) Closed by %s\n", dev->primary->index, buf);
}

struct drm_device *evdi_drm_device_create(struct device *parent)
{
	struct drm_device *dev = NULL;
	int ret;

	dev = drm_dev_alloc(&driver, parent);
	if (IS_ERR(dev))
		return dev;

	ret = evdi_drm_device_init(dev);
	if (ret)
		goto err_free;

	ret = drm_dev_register(dev, 0);
	if (ret)
		goto err_free;

	return dev;

err_free:
	drm_dev_put(dev);
	return ERR_PTR(ret);
}

static void evdi_drm_device_deinit(struct drm_device *dev)
{
	drm_kms_helper_poll_fini(dev);
	evdi_modeset_cleanup(dev);
	drm_atomic_helper_shutdown(dev);
}

int evdi_drm_device_remove(struct drm_device *dev)
{
	drm_dev_unplug(dev);
	evdi_drm_device_deinit(dev);
#if KERNEL_VERSION(5, 8, 0) <= LINUX_VERSION_CODE || defined(EL8)
#else
	evdi_drm_device_release_cb(dev, NULL);
#endif
	drm_dev_put(dev);
	return 0;
}
