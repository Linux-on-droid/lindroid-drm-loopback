// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOCTL handlers
 */

#include "evdi_drv.h"
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/prefetch.h>
#include <linux/completion.h>
#include <linux/compat.h>
#include <linux/sched/signal.h>
#include <linux/errno.h>

static int evdi_queue_create_event_with_id(struct evdi_device *evdi, struct drm_evdi_gbm_create_buff *params, struct drm_file *owner, int poll_id);
static struct evdi_inflight_req *evdi_inflight_alloc(struct evdi_device *evdi,
						     struct drm_file *owner,
						     int type,
						     int *out_id)
{
	struct evdi_inflight_req *req;
	int id;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return NULL;

	req->type = type;
	req->owner = owner;
	init_completion(&req->done);

#ifdef EVDI_HAVE_XARRAY
	{
		u32 xid = 0;
		int ret = xa_alloc(&evdi->inflight_xa, &xid, req,
				   XA_LIMIT(1, INT_MAX), GFP_KERNEL);
		if (ret) {
			kfree(req);
			return NULL;
		}
		id = (int)xid;
	}
#else
	spin_lock(&evdi->inflight_lock);
	id = idr_alloc(&evdi->inflight_idr, req, 1, 0, GFP_KERNEL);
	spin_unlock(&evdi->inflight_lock);
	if (id < 0) {
		kfree(req);
		return NULL;
	}
#endif
	*out_id = id;
	return req;
}

static struct evdi_inflight_req *evdi_inflight_take(struct evdi_device *evdi, int id)
{
	struct evdi_inflight_req *req = NULL;
#ifdef EVDI_HAVE_XARRAY
	xa_lock(&evdi->inflight_xa);
	req = xa_load(&evdi->inflight_xa, id);
	if (req)
		xa_erase(&evdi->inflight_xa, id);

	xa_unlock(&evdi->inflight_xa);
#else
	spin_lock(&evdi->inflight_lock);
	req = idr_find(&evdi->inflight_idr, id);
	if (req)
		idr_remove(&evdi->inflight_idr, id);

	spin_unlock(&evdi->inflight_lock);
#endif
	return req;
}

void evdi_inflight_discard_owner(struct evdi_device *evdi, struct drm_file *owner)
{
#ifdef EVDI_HAVE_XARRAY
	unsigned long index;
	void *entry;
	xa_for_each(&evdi->inflight_xa, index, entry) {
		struct evdi_inflight_req *req = entry;
		if (req && req->owner == owner) {
			xa_erase(&evdi->inflight_xa, index);
			complete_all(&req->done);
			kfree(req);
		}
	}
#else
	int max = INT_MAX;
	int id;
	for (id = 1; id < max; id++) {
		struct evdi_inflight_req *req;
		spin_lock(&evdi->inflight_lock);
		req = idr_find(&evdi->inflight_idr, id);
		if (req && req->owner == owner) {
			idr_remove(&evdi->inflight_idr, id);
			spin_unlock(&evdi->inflight_lock);
			complete_all(&req->done);
			kfree(req);
			continue;
		}
		spin_unlock(&evdi->inflight_lock);
	}
#endif
}

static int evdi_queue_create_event_with_id(struct evdi_device *evdi,
					   struct drm_evdi_gbm_create_buff *params,
					   struct drm_file *owner,
					   int poll_id)
{
	struct evdi_event *event;
	void *data;

	data = kmalloc(sizeof(*params), GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	memcpy(data, params, sizeof(*params));

	event = evdi_event_alloc(evdi, create_buf,
				 poll_id,
				 data, sizeof(*params), owner);
	if (!event) {
		kfree(data);
		return -ENOMEM;
	}

	evdi_event_queue(evdi, event);
	return 0;
}

static int evdi_queue_get_buf_event_with_id(struct evdi_device *evdi,
					   struct drm_evdi_gbm_get_buff *params,
					   struct drm_file *owner,
					   int poll_id)
{
	struct evdi_event *event;
	void *data;

	data = kmalloc(sizeof(*params), GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	memcpy(data, params, sizeof(*params));

	event = evdi_event_alloc(evdi, get_buf,
				 poll_id,
				 data, sizeof(*params), owner);
	if (!event) {
		kfree(data);
		return -ENOMEM;
	}

	evdi_event_queue(evdi, event);
	return 0;
}

int evdi_ioctl_connect(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_connect *cmd = data;

	atomic64_inc(&evdi_perf.ioctl_calls[0]);

	if (!cmd->connected) {
		evdi->connected = false;
		atomic_set(&evdi->events.stopping, 1);

		wake_up_interruptible(&evdi->events.wait_queue);

		evdi_info("Device %d disconnected", evdi->dev_index);
#ifdef EVDI_HAVE_KMS_HELPER
		drm_kms_helper_hotplug_event(dev);
#else
		drm_helper_hpd_irq_event(dev);
#endif
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

#ifdef EVDI_HAVE_KMS_HELPER
		drm_kms_helper_hotplug_event(dev);
#else
		drm_helper_hpd_irq_event(dev);
#endif
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

//Allow partial progress; return -EFAULT only if zero progress
static int evdi_copy_to_user_allow_partial(void __user *dst, const void *src, size_t len)
{
	size_t not;

	if (!len)
		return 0;

	//prefetch(src);
	not = copy_to_user(dst, src, len);
	if (not == len)
		return -EFAULT;

	return 0;
}

int evdi_ioctl_gbm_get_buff(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_gbm_get_buff *cmd = data;
	struct evdi_inflight_req *req;
	struct drm_evdi_gbm_get_buff evt_params;
	struct evdi_gralloc_buf_user *gralloc_buf;
	int poll_id;
	long ret;
	int fd_tmp;
	int i;
	int installed_fds[EVDI_MAX_FDS];

//     atomic64_inc(&evdi_perf.ioctl_calls[6]);

	req = evdi_inflight_alloc(evdi, file, get_buf, &poll_id);
	if (!req)
		return -ENOMEM;

	memset(&evt_params, 0, sizeof(evt_params));
	evt_params.id = cmd->id;
	evt_params.native_handle = NULL;

	if (evdi_queue_get_buf_event_with_id(evdi, &evt_params, file, poll_id)) {
		struct evdi_inflight_req *tmp = evdi_inflight_take(evdi, poll_id);
		if (tmp)
			kfree(tmp);
		return -ENOMEM;
	}

	ret = wait_for_completion_interruptible_timeout(&req->done, EVDI_WAIT_TIMEOUT);
	if (ret == 0) {
			kfree(req);
			return -ETIMEDOUT;
	}
	if (ret < 0) {
			kfree(req);
			return (int)ret;
	}

	gralloc_buf = kzalloc(sizeof(struct evdi_gralloc_buf_user), GFP_KERNEL);

	gralloc_buf->version = req->reply.get_buf.gralloc_buf.version;
	gralloc_buf->numFds = req->reply.get_buf.gralloc_buf.numFds;
	gralloc_buf->numInts = req->reply.get_buf.gralloc_buf.numInts;
	memcpy(&gralloc_buf->data[gralloc_buf->numFds],
			req->reply.get_buf.gralloc_buf.data_ints,
			sizeof(int) * gralloc_buf->numInts);

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

	if (evdi_copy_to_user_allow_partial(cmd->native_handle,
										gralloc_buf,
										sizeof(int) * (3 + gralloc_buf->numFds + gralloc_buf->numInts))) {
		for (i = 0; i < gralloc_buf->numFds; i++)
			put_unused_fd(installed_fds[i]);
		ret = -EFAULT;
		goto err_event;
	}

	for (i = 0; i < gralloc_buf->numFds; i++)
		fd_install(installed_fds[i], req->reply.get_buf.gralloc_buf.data_files[i]);

err_event:
	for (i = 0; i < gralloc_buf->numFds; i++) {
		if (req->reply.get_buf.gralloc_buf.data_files[i]) {
			fput(req->reply.get_buf.gralloc_buf.data_files[i]);
			req->reply.get_buf.gralloc_buf.data_files[i] = NULL;
		}
	}
	kfree(gralloc_buf);
	kfree(req);
	return ret;
}

int evdi_ioctl_gbm_create_buff(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_gbm_create_buff *cmd = data;
	struct evdi_inflight_req *req;
	struct evdi_inflight_req *tmp;
	struct drm_evdi_gbm_create_buff evt_params;
	int __user *u_id;
	__u32 __user *u_stride;
	int poll_id;
	long wret;

	u_id = cmd->id;
	u_stride = cmd->stride;
	if (u_id && !access_ok(u_id, sizeof(*u_id)))
		return -EFAULT;

	if (u_stride && !access_ok(u_stride, sizeof(*u_stride)))
		return -EFAULT;

	req = evdi_inflight_alloc(evdi, file, create_buf, &poll_id);
	if (!req)
		return -ENOMEM;

	memset(&evt_params, 0, sizeof(evt_params));
	evt_params.format = cmd->format;
	evt_params.width = cmd->width;
	evt_params.height = cmd->height;
	evt_params.id = NULL;
	evt_params.stride = NULL;

	if (evdi_queue_create_event_with_id(evdi, &evt_params, file, poll_id)) {
		tmp = evdi_inflight_take(evdi, poll_id);
		if (tmp)
			kfree(tmp);

		return -ENOMEM;
	}

	wret = wait_for_completion_interruptible_timeout(&req->done, EVDI_WAIT_TIMEOUT);
	if (wret == 0) {
		kfree(req);
		return -ETIMEDOUT;
	}
	if (wret < 0) {
		kfree(req);
		return (int)wret;
	}

	if (u_id) {
		if (evdi_copy_to_user_allow_partial(u_id, &req->reply.create.id, sizeof(*u_id))) {
			kfree(req);
			return -EFAULT;
		}
	}
	if (u_stride) {
		if (evdi_copy_to_user_allow_partial(u_stride, &req->reply.create.stride, sizeof(*u_stride))) {
			kfree(req);
			return -EFAULT;
		}
	}

	kfree(req);
	return 0;
}

int evdi_ioctl_add_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;

	atomic64_inc(&evdi_perf.ioctl_calls[2]);

	wake_up_interruptible(&evdi->events.wait_queue);

	return 0;
}

int evdi_ioctl_get_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_get_buff_callabck *cb = data;
	struct evdi_inflight_req *req;
	int i;

	atomic64_inc(&evdi_perf.ioctl_calls[3]);

	req = evdi_inflight_take(evdi, cb->poll_id);
	if (req) {
		req->reply.get_buf.status = 0;
		if (cb->numFds < 0 || cb->numInts < 0 ||
			cb->numFds > EVDI_MAX_FDS || cb->numInts > EVDI_MAX_INTS) {
			req->reply.get_buf.status = -EINVAL;
			return -EINVAL;
		}

		req->reply.get_buf.gralloc_buf.version = cb->version;
		req->reply.get_buf.gralloc_buf.numFds = cb->numFds;
		req->reply.get_buf.gralloc_buf.numInts = cb->numInts;

		for (i = 0; i < cb->numInts; i++)
			req->reply.get_buf.gralloc_buf.data_ints[i] = cb->data_ints[i];

		for (i = 0; i < cb->numFds; i++) {
			req->reply.get_buf.gralloc_buf.data_files[i] = fget(cb->fd_ints[i]);
			if (!req->reply.get_buf.gralloc_buf.data_files[i]) {
				evdi_err("evdi_ioctl_get_buff_callback: Failed to open fb %d\n", cb->fd_ints[i]);
				req->reply.get_buf.status = -EINVAL;
				return -EINVAL;
			}
		}

		complete_all(&req->done);
	}

	wake_up_interruptible(&evdi->events.wait_queue);

	return 0;
}

int evdi_ioctl_destroy_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;

	atomic64_inc(&evdi_perf.ioctl_calls[4]);

	wake_up_interruptible(&evdi->events.wait_queue);

	return 0;
}

int evdi_ioctl_swap_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;

	atomic64_inc(&evdi_perf.ioctl_calls[5]);

	wake_up_interruptible(&evdi->events.wait_queue);

	return 0;
}

int evdi_ioctl_create_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_create_buff_callabck *cb = data;
	struct evdi_inflight_req *req;

	atomic64_inc(&evdi_perf.ioctl_calls[6]);

	req = evdi_inflight_take(evdi, cb->poll_id);
	if (req) {
		req->reply.create.id = cb->id;
		req->reply.create.stride = cb->stride;
		complete_all(&req->done);
	}

	return 0;
}

int evdi_ioctl_gbm_del_buff(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_gbm_del_buff *cmd = data;
	struct evdi_inflight_req *req;
	int poll_id;
	long ret;

	req = evdi_inflight_alloc(evdi, file, destroy_buf, &poll_id);
	if (unlikely(!req))
		return -ENOMEM;

	ret = evdi_queue_destroy_event(evdi, cmd->id, file);
	if (ret) {
		kfree(req);
		return ret;
	}

	ret = wait_for_completion_interruptible_timeout(&req->done, EVDI_WAIT_TIMEOUT);
	if (ret <= 0) {
		kfree(req);
		return ret == 0 ? -ETIMEDOUT : (int)ret;
	}

	kfree(req);
	return 0;
}

const struct drm_ioctl_desc evdi_ioctls[] = {
	DRM_IOCTL_DEF_DRV(EVDI_CONNECT, evdi_ioctl_connect,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_POLL, evdi_ioctl_poll,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GBM_CREATE_BUFF, evdi_ioctl_gbm_create_buff,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_ADD_BUFF_CALLBACK, evdi_ioctl_add_buff_callback,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GBM_GET_BUFF, evdi_ioctl_gbm_get_buff,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GET_BUFF_CALLBACK, evdi_ioctl_get_buff_callback,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_DESTROY_BUFF_CALLBACK, evdi_ioctl_destroy_buff_callback,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_SWAP_CALLBACK, evdi_ioctl_swap_callback,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GBM_CREATE_BUFF_CALLBACK, evdi_ioctl_create_buff_callback,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_GBM_DEL_BUFF, evdi_ioctl_gbm_del_buff,
			 DRM_UNLOCKED),
};

const int evdi_num_ioctls = ARRAY_SIZE(evdi_ioctls);

const struct drm_ioctl_desc *evdi_get_ioctls(void)
{
	return evdi_ioctls;
}

int evdi_get_num_ioctls(void)
{
	return evdi_num_ioctls;
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
	int poll_id = atomic_inc_return(&evdi->events.next_poll_id);
	return evdi_queue_create_event_with_id(evdi, params, owner, poll_id);
}
