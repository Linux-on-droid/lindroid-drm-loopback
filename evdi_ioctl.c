// SPDX-License-Identifier: GPL-2.0-only
/*
 * Zero-copy IOCTL handlers
 */

#include "evdi_drv.h"
#include <linux/uaccess.h>
#include <linux/prefetch.h>

int evdi_ioctl_connect(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_connect *cmd = data;

	atomic64_inc(&evdi_perf.ioctl_calls[0]);

	if (!cmd->connected) {
		evdi->connected = false;
		atomic_set(&evdi->events.stopping, 1);

		wake_up_interruptible_all(&evdi->events.wait_queue);

		evdi_info("Device %d disconnected", evdi->dev_index);
		return 0;
	}

	mutex_lock(&evdi->config_mutex);

	evdi->connected = true;
	evdi->width = cmd->width;
	evdi->height = cmd->height;
	evdi->refresh_rate = cmd->refresh_rate;

	atomic_set(&evdi->events.stopping, 0);

	mutex_unlock(&evdi->config_mutex);

	evdi_info("Device %d connected: %ux%u@%uHz",
		 evdi->dev_index, cmd->width, cmd->height, cmd->refresh_rate);

	return 0;
}

int evdi_ioctl_poll(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_poll *cmd = data;
	struct evdi_event *event;
	int ret;

	atomic64_inc(&evdi_perf.ioctl_calls[1]);

	event = evdi_event_dequeue(evdi);
	if (likely(event)) {
		cmd->event = event->type;
		cmd->poll_id = event->poll_id;

		if (event->data && cmd->data) {
			prefetch(cmd->data);
			if (copy_to_user(cmd->data, event->data, event->data_size)) {
				evdi_event_free(event);
				return -EFAULT;
			}
		}
		evdi_event_free(event);
		return 0;
	}

	ret = evdi_event_wait(evdi, file);
	if (ret)
		return ret;

	event = evdi_event_dequeue(evdi);
	if (!event)
		return -EAGAIN;

	cmd->event = event->type;
	cmd->poll_id = event->poll_id;

	if (event->data && cmd->data) {
		if (copy_to_user(cmd->data, event->data, event->data_size)) {
			evdi_event_free(event);
			return -EFAULT;
		}
	}

	evdi_event_free(event);
	return 0;
}

int evdi_ioctl_add_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;

	atomic64_inc(&evdi_perf.ioctl_calls[2]);

	wake_up_interruptible_all(&evdi->events.wait_queue);

	return 0;
}

int evdi_ioctl_get_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;

	atomic64_inc(&evdi_perf.ioctl_calls[3]);

	wake_up_interruptible_all(&evdi->events.wait_queue);

	return 0;
}

int evdi_ioctl_destroy_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;

	atomic64_inc(&evdi_perf.ioctl_calls[4]);

	wake_up_interruptible_all(&evdi->events.wait_queue);

	return 0;
}

int evdi_ioctl_swap_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;

	atomic64_inc(&evdi_perf.ioctl_calls[5]);

	wake_up_interruptible_all(&evdi->events.wait_queue);

	return 0;
}

int evdi_ioctl_create_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;

	atomic64_inc(&evdi_perf.ioctl_calls[6]);

	wake_up_interruptible_all(&evdi->events.wait_queue);

	return 0;
}

static const struct drm_ioctl_desc evdi_ioctls[] = {
	DRM_IOCTL_DEF_DRV(EVDI_CONNECT, evdi_ioctl_connect,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_POLL, evdi_ioctl_poll,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_ADD_BUFF_CALLBACK, evdi_ioctl_add_buff_callback,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GET_BUFF_CALLBACK, evdi_ioctl_get_buff_callback,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_DESTROY_BUFF_CALLBACK, evdi_ioctl_destroy_buff_callback,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_SWAP_CALLBACK, evdi_ioctl_swap_callback,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GBM_CREATE_BUFF_CALLBACK, evdi_ioctl_create_buff_callback,
			 DRM_UNLOCKED),
};

const struct drm_ioctl_desc *evdi_get_ioctls(void)
{
	return evdi_ioctls;
}

int evdi_get_num_ioctls(void)
{
	return ARRAY_SIZE(evdi_ioctls);
}

int evdi_queue_add_buf_event(struct evdi_device *evdi, int fd_data, struct drm_file *owner)
{
	struct evdi_event *event;
	void *data;

	data = kmalloc(sizeof(int), GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	memcpy(data, &fd_data, sizeof(int));

	event = evdi_event_alloc(evdi, add_buf,
				atomic_inc_return(&evdi->events.next_poll_id),
				data, sizeof(int), owner);
	if (!event) {
		kfree(data);
		return -ENOMEM;
	}

	evdi_event_queue(evdi, event);
	return 0;
}

int evdi_queue_get_buf_event(struct evdi_device *evdi, int id, struct drm_file *owner)
{
	struct evdi_event *event;
	void *data;

	data = kmalloc(sizeof(int), GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	memcpy(data, &id, sizeof(int));

	event = evdi_event_alloc(evdi, get_buf,
				atomic_inc_return(&evdi->events.next_poll_id),
				data, sizeof(int), owner);
	if (!event) {
		kfree(data);
		return -ENOMEM;
	}

	evdi_event_queue(evdi, event);
	return 0;
}

int evdi_queue_swap_event(struct evdi_device *evdi, int id, struct drm_file *owner)
{
	struct evdi_event *event;
	void *data;

	data = kmalloc(sizeof(int), GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	memcpy(data, &id, sizeof(int));

	event = evdi_event_alloc(evdi, swap_to,
				atomic_inc_return(&evdi->events.next_poll_id),
				data, sizeof(int), owner);
	if (!event) {
		kfree(data);
		return -ENOMEM;
	}

	evdi_event_queue(evdi, event);
	return 0;
}

int evdi_queue_destroy_event(struct evdi_device *evdi, int id, struct drm_file *owner)
{
	struct evdi_event *event;
	void *data;

	data = kmalloc(sizeof(int), GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	memcpy(data, &id, sizeof(int));

	event = evdi_event_alloc(evdi, destroy_buf,
				atomic_inc_return(&evdi->events.next_poll_id),
				data, sizeof(int), owner);
	if (!event) {
		kfree(data);
		return -ENOMEM;
	}

	evdi_event_queue(evdi, event);
	return 0;
}

int evdi_queue_create_event(struct evdi_device *evdi,
			   struct drm_evdi_gbm_create_buff *params,
			   struct drm_file *owner)
{
	struct evdi_event *event;
	void *data;

	data = kmalloc(sizeof(*params), GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	memcpy(data, params, sizeof(*params));

	event = evdi_event_alloc(evdi, create_buf,
				atomic_inc_return(&evdi->events.next_poll_id),
				data, sizeof(*params), owner);
	if (!event) {
		kfree(data);
		return -ENOMEM;
	}

	evdi_event_queue(evdi, event);
	return 0;
}
