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
int evdi_queue_destroy_event(struct evdi_device *evdi, int id, struct drm_file *owner);

//Handle short copies due to minor faults on big buffers
static inline int evdi_prefault_readable(const void __user *uaddr, size_t len)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
	return fault_in_readable(uaddr, len);
#else
	unsigned long start = 0;
	unsigned long end = 0;
	unsigned long addr = 0;
	unsigned char tmp;

	if (unlikely(__get_user(tmp, (const unsigned char __user *)start)))
		return -EFAULT;

	addr = (start | (PAGE_SIZE - 1)) + 1;
	while (addr <= (end & PAGE_MASK)) {
		if (unlikely(__get_user(tmp, (const unsigned char __user *)addr)))
			return -EFAULT;

	addr += PAGE_SIZE;
	}

	if ((start & PAGE_MASK) != (end & PAGE_MASK)) {
		if (unlikely(__get_user(tmp, (const unsigned char __user *)end)))
			return -EFAULT;
	}
	return 0;
#endif
}

//Allow partial progress; return -EFAULT only if zero progress
static int evdi_copy_from_user_allow_partial(void *dst, const void __user *src, size_t len)
{
	size_t not;

	if (!len)
		return 0;

	(void)evdi_prefault_readable(src, len);
	prefetchw(dst);
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

	prefetch(src);
	not = copy_to_user(dst, src, len);
	if (not == len)
		return -EFAULT;

	return 0;
}

void evdi_send_update_work_func(struct work_struct *work)
{
	struct evdi_device *evdi = container_of(work, struct evdi_device, send_update_work);
	struct evdi_drm_update_ready_event *event;
	struct drm_file *client;
	unsigned long flags;
	bool sent = false;

	client = READ_ONCE(evdi->drm_client);
	if (unlikely(!client || !evdi->ddev))
		return;

	event = evdi_drm_event_alloc();
	if (unlikely(!event)) {
		atomic64_inc(&evdi_perf.drm_events_dropped);
		return;
	}

	event->event.base.type = DRM_EVDI_EVENT_UPDATE_READY;
	event->event.base.length = sizeof(event->event);
	event->base.event = &event->event.base;
	event->base.file_priv = client;

	spin_lock_irqsave(&evdi->ddev->event_lock, flags);
#ifdef EVDI_HAVE_DRM_EVENT_RESERVE
	if (likely(drm_event_reserve_init_locked(evdi->ddev, client,
						 &event->base, &event->event.base) == 0)) {
		drm_send_event_locked(evdi->ddev, &event->base);
		sent = true;
	}
#else
	if (likely(client->event_space >= sizeof(event->event))) {
		client->event_space -= sizeof(event->event);
		list_add_tail(&event->base.link, &client->event_list);
		wake_up_interruptible(&client->event_wait);
		sent = true;
	}
#endif
	spin_unlock_irqrestore(&evdi->ddev->event_lock, flags);

	if (likely(sent)) {
		atomic64_inc(&evdi_perf.drm_events_sent);
	} else {
		evdi_drm_event_free(event);
		atomic64_inc(&evdi_perf.drm_events_dropped);
	}
}

void evdi_send_events_work_func(struct work_struct *work)
{
	struct evdi_device *evdi = container_of(work, struct evdi_device, send_events_work);
	wake_up_interruptible(&evdi->events.wait_queue);
}

void evdi_send_drm_update_ready_async(struct evdi_device *evdi)
{
	if (likely(READ_ONCE(evdi->drm_client) && evdi->high_perf_wq)) {
		queue_work(evdi->high_perf_wq, &evdi->send_update_work);
	}
}

static inline struct evdi_inflight_req *evdi_inflight_alloc(struct evdi_device *evdi,
						     struct drm_file *owner,
						     int type,
						     int *out_id)
{
	struct evdi_inflight_req *req;
	int id;

	req = evdi_inflight_req_alloc();
	if (unlikely(!req))
		return NULL;

	req->type = type;
	req->owner = owner;
	init_completion(&req->done);

#ifdef EVDI_HAVE_XARRAY
	{
		u32 xid;
		int ret;
#ifdef EVDI_HAVE_XA_ALLOC_CYCLIC
		xid = READ_ONCE(evdi->inflight_next_id);
		if (unlikely(!xid))
			xid = 1;

		ret = xa_alloc_cyclic(&evdi->inflight_xa, &xid, req,
				      XA_LIMIT(1, INT_MAX), &evdi->inflight_next_id,
				      GFP_ATOMIC);
		if (ret == -EBUSY) {
			evdi->inflight_next_id = 1;
			ret = xa_alloc(&evdi->inflight_xa, &xid, req,
				       XA_LIMIT(1, EVDI_MAX_INFLIGHT_REQUESTS),
				       GFP_ATOMIC);
		}
		if (ret) {
			evdi_inflight_req_put(req);
			return NULL;
		}
		evdi_inflight_req_get(req);
		id = (int)xid;
#else
		xid = 0;
		u32 start_id = READ_ONCE(evdi->inflight_next_id);
		if (unlikely(!start_id))
			start_id = 1;
		ret = xa_alloc(&evdi->inflight_xa, &xid, req,
			       XA_LIMIT(start_id, INT_MAX), GFP_ATOMIC);
		if (ret == -EBUSY && start_id > 1) {
			ret = xa_alloc(&evdi->inflight_xa, &xid, req,
				       XA_LIMIT(1, EVDI_MAX_INFLIGHT_REQUESTS), GFP_ATOMIC);
		}
		if (ret) {
			evdi_inflight_req_put(req);
			return NULL;
		}
		evdi_inflight_req_get(req);
		id = (int)xid;
#endif
	}
#else
	spin_lock(&evdi->inflight_lock);
	id = idr_alloc(&evdi->inflight_idr, req, 1, EVDI_MAX_INFLIGHT_REQUESTS, GFP_ATOMIC);
	spin_unlock(&evdi->inflight_lock);
	if (id < 0) {
		evdi_inflight_req_put(req);
		return NULL;
	}
	evdi_inflight_req_get(req);
#endif
	*out_id = id;
	return req;
}

static struct evdi_inflight_req *evdi_inflight_take(struct evdi_device *evdi, int id)
{
	struct evdi_inflight_req *req = NULL;
#ifdef EVDI_HAVE_XARRAY
#ifdef EVDI_HAVE_ATOMIC_CMPXCHG_RELAXED
	req = xa_load(&evdi->inflight_xa, id);
	if (req) {
		if (xa_cmpxchg(&evdi->inflight_xa, id, req, NULL, GFP_ATOMIC) != req)
			req = NULL;
	}
#else
	{
		unsigned long flags;
		xa_lock_irqsave(&evdi->inflight_xa, flags);
		req = xa_load(&evdi->inflight_xa, id);
		if (req)
			xa_erase(&evdi->inflight_xa, id);

		xa_unlock_irqrestore(&evdi->inflight_xa, flags);
	}
#endif
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
	struct evdi_inflight_req *taken = NULL;
	struct evdi_inflight_req *req;
#ifdef EVDI_HAVE_XARRAY
	unsigned long index;
	void *entry;
#ifndef EVDI_HAVE_ATOMIC_CMPXCHG_RELAXED
	bool found = false;
	unsigned long flags;
#endif
#else
	int id = 0;
	int victim = -1;
#endif

#ifdef EVDI_HAVE_XARRAY
#ifdef EVDI_HAVE_ATOMIC_CMPXCHG_RELAXED
	for (;;) {
		taken = NULL;
		rcu_read_lock();
		xa_for_each(&evdi->inflight_xa, index, entry) {
			req = entry;
			if (!req || req->owner != owner)
				continue;

			if (xa_cmpxchg(&evdi->inflight_xa, index, req, NULL, GFP_ATOMIC) == req) {
				taken = req;
				break;
			}
		}
		rcu_read_unlock();

		if (!taken)
			break;

		complete_all(&taken->done);
		evdi_inflight_req_put(taken);
		cond_resched();
	}
#else /* !EVDI_HAVE_ATOMIC_CMPXCHG_RELAXED */
	for (;;) {
		found = false;
		taken = NULL;
		xa_lock_irqsave(&evdi->inflight_xa, flags);
		xa_for_each(&evdi->inflight_xa, index, entry) {
			req = entry;
			if (req && req->owner == owner) {
				taken = xa_erase(&evdi->inflight_xa, index);
				found = true;
				break;
			}
		}
		xa_unlock_irqrestore(&evdi->inflight_xa, flags);

		if (!found || !taken)
			break;

		complete_all(&taken->done);
		evdi_inflight_req_put(taken);
		cond_resched();
	}
#endif /* EVDI_HAVE_ATOMIC_CMPXCHG_RELAXED */
#else /* !EVDI_HAVE_XARRAY */
	for (;;) {
		taken = NULL;
		spin_lock(&evdi->inflight_lock);
		for (;;) {
			req = idr_get_next(&evdi->inflight_idr, &id);
			if (!req)
				break;

			if (req->owner == owner) {
				victim = id;
				taken = idr_remove(&evdi->inflight_idr, victim);
				break;
			}
			id++;
		}
		spin_unlock(&evdi->inflight_lock);

		if (!taken)
			break;

		complete_all(&taken->done);
		evdi_inflight_req_put(taken);
		cond_resched();
	}
#endif /* EVDI_HAVE_XARRAY */
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

static int evdi_queue_struct_event_with_id(struct evdi_device *evdi,
	void *params, size_t params_size,
	enum poll_event_type type,
	struct drm_file *owner,
	int poll_id)
{
	struct evdi_event *event;
	void *data;

	data = kmalloc(params_size, GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	memcpy(data, params, params_size);

	event = evdi_event_alloc(evdi, type, poll_id, data, params_size, owner);
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
	return evdi_queue_struct_event_with_id(evdi, params, sizeof(*params),
					       get_buf, owner, poll_id);
}

int evdi_ioctl_connect(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_connect *cmd = data;

	atomic64_inc(&evdi_perf.ioctl_calls[0]);

	if (!cmd->connected) {
		evdi->connected = false;
		atomic_set(&evdi->events.stopping, 1);
		WRITE_ONCE(evdi->drm_client, NULL);

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

	WRITE_ONCE(evdi->drm_client, file);
	atomic_set(&evdi->update_requested, 0);

#ifdef EVDI_HAVE_KMS_HELPER
	drm_kms_helper_hotplug_event(dev);
#else
	drm_helper_hpd_irq_event(dev);
#endif
	return 0;
}

int evdi_ioctl_request_update(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;

	if (unlikely(!evdi_likely_connected(evdi)))
		return -ENODEV;

	atomic_set(&evdi->update_requested, 1);
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
			if (evdi_copy_to_user_allow_partial(cmd->data, event->data, event->data_size)) {
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
		if (evdi_copy_to_user_allow_partial(cmd->data, event->data, event->data_size)) {
			evdi_event_free(event);
			return -EFAULT;
		}
	}

	evdi_event_free(event);
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
			evdi_inflight_req_put(tmp);

		evdi_inflight_req_put(req);
		return -ENOMEM;
	}

	ret = wait_for_completion_interruptible_timeout(&req->done, EVDI_WAIT_TIMEOUT);
	if (ret == 0) {
			evdi_inflight_req_put(req);
			return -ETIMEDOUT;
	}
	if (ret < 0) {
			evdi_inflight_req_put(req);
			return (int)ret;
	}

	gralloc_buf = kzalloc(sizeof(struct evdi_gralloc_buf_user), GFP_KERNEL);
	if (unlikely(!gralloc_buf)) {
		evdi_inflight_req_put(req);
		return -ENOMEM;
	}

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

	ret = 0;
err_event:
	for (i = 0; i < gralloc_buf->numFds; i++) {
		if (req->reply.get_buf.gralloc_buf.data_files[i]) {
			fput(req->reply.get_buf.gralloc_buf.data_files[i]);
			req->reply.get_buf.gralloc_buf.data_files[i] = NULL;
		}
	}
	kfree(gralloc_buf);
	evdi_inflight_req_put(req);
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
			evdi_inflight_req_put(tmp);

		evdi_inflight_req_put(req);

		return -ENOMEM;
	}

	wret = wait_for_completion_interruptible_timeout(&req->done, EVDI_WAIT_TIMEOUT);
	if (wret == 0) {
		evdi_inflight_req_put(req);
		return -ETIMEDOUT;
	}
	if (wret < 0) {
		evdi_inflight_req_put(req);
		return (int)wret;
	}

	if (u_id) {
		if (evdi_copy_to_user_allow_partial(u_id, &req->reply.create.id, sizeof(*u_id))) {
			evdi_inflight_req_put(req);
			return -EFAULT;
		}
	}
	if (u_stride) {
		if (evdi_copy_to_user_allow_partial(u_stride, &req->reply.create.stride, sizeof(*u_stride))) {
			evdi_inflight_req_put(req);
			return -EFAULT;
		}
	}

	evdi_inflight_req_put(req);
	return 0;
}

int evdi_ioctl_add_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_add_buff_callabck *cb = data;
	struct evdi_inflight_req *req;

	atomic64_inc(&evdi_perf.ioctl_calls[2]);
	atomic64_inc(&evdi_perf.callback_completions);

	req = evdi_inflight_take(evdi, cb->poll_id);

	if (req) {
		complete_all(&req->done);
		evdi_inflight_req_put(req);
	} else {
		evdi_warn("add_buff_callback: poll_id %d not found", cb->poll_id);
	}

	wake_up_interruptible(&evdi->events.wait_queue);
	return 0;
}

int evdi_ioctl_get_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_get_buff_callabck *cb = data;
	struct evdi_inflight_req *req;
	int i, j;
	int fds_local[EVDI_MAX_FDS];

	atomic64_inc(&evdi_perf.ioctl_calls[3]);

	req = evdi_inflight_take(evdi, cb->poll_id);
	if (req) {
		if (cb->numFds < 0 || cb->numInts < 0 ||
		    cb->numFds > EVDI_MAX_FDS || cb->numInts > EVDI_MAX_INTS) {
			req->reply.get_buf.gralloc_buf.version = cb->version;
			req->reply.get_buf.gralloc_buf.numFds = 0;
			req->reply.get_buf.gralloc_buf.numInts = 0;
			complete_all(&req->done);
			evdi_inflight_req_put(req);
			wake_up_interruptible(&evdi->events.wait_queue);
			return 0;
		}

		req->reply.get_buf.gralloc_buf.version = cb->version;
		req->reply.get_buf.gralloc_buf.numFds = cb->numFds;
		req->reply.get_buf.gralloc_buf.numInts = cb->numInts;

		if (cb->numInts) {
			if (evdi_copy_from_user_allow_partial(req->reply.get_buf.gralloc_buf.data_ints,
					   cb->data_ints,
					   sizeof(int) * cb->numInts)) {
				req->reply.get_buf.gralloc_buf.numFds = 0;
				req->reply.get_buf.gralloc_buf.numInts = 0;
				complete_all(&req->done);
				evdi_inflight_req_put(req);
				wake_up_interruptible(&evdi->events.wait_queue);
				return 0;
			}
		}

		if (cb->numFds) {
			if (evdi_copy_from_user_allow_partial(fds_local, cb->fd_ints,
					   sizeof(int) * cb->numFds)) {
				req->reply.get_buf.gralloc_buf.numFds = 0;
				complete_all(&req->done);
				evdi_inflight_req_put(req);
				wake_up_interruptible(&evdi->events.wait_queue);
				return 0;
			}

			for (i = 0; i < cb->numFds; i++) {
				req->reply.get_buf.gralloc_buf.data_files[i] = fget(fds_local[i]);
				if (!req->reply.get_buf.gralloc_buf.data_files[i]) {
					for (j = 0; j < i; j++) {
						if (req->reply.get_buf.gralloc_buf.data_files[j]) {
							fput(req->reply.get_buf.gralloc_buf.data_files[j]);
							req->reply.get_buf.gralloc_buf.data_files[j] = NULL;
						}
					}
					evdi_err("evdi_ioctl_get_buff_callback: Failed to fget fd %d\n",
						 fds_local[i]);
					req->reply.get_buf.gralloc_buf.numFds = 0;
					complete_all(&req->done);
					evdi_inflight_req_put(req);
					wake_up_interruptible(&evdi->events.wait_queue);
					return 0;
				}
			}
		}

		complete_all(&req->done);
		evdi_inflight_req_put(req);
	}

	wake_up_interruptible(&evdi->events.wait_queue);
	return 0;
}

int evdi_ioctl_destroy_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_destroy_buff_callback *cb = data;
	struct evdi_inflight_req *req;

	atomic64_inc(&evdi_perf.ioctl_calls[4]);
	atomic64_inc(&evdi_perf.callback_completions);

	req = evdi_inflight_take(evdi, cb->poll_id);
	if (likely(req)) {
		complete_all(&req->done);
		evdi_inflight_req_put(req);
	} else {
		evdi_warn("destroy_buff_callback: poll_id %d not found", cb->poll_id);
	}

	wake_up_interruptible(&evdi->events.wait_queue);

	return 0;
}

int evdi_ioctl_swap_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_swap_callback *cb = data;
	struct evdi_inflight_req *req;

	atomic64_inc(&evdi_perf.ioctl_calls[5]);
	atomic64_inc(&evdi_perf.callback_completions);

	req = evdi_inflight_take(evdi, cb->poll_id);
	if (likely(req)) {
		complete_all(&req->done);
		evdi_inflight_req_put(req);
	} else {
		evdi_warn("swap_callback: poll_id %d not found", cb->poll_id);
	}

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
		if (cb->id < 0 || cb->stride < 0) {
			req->reply.create.id = 0;
			req->reply.create.stride = 0;
		} else {
			req->reply.create.id = cb->id;
			req->reply.create.stride = cb->stride;
		}
		complete_all(&req->done);
		evdi_inflight_req_put(req);
	} else {
		evdi_warn("create_buff_callback: poll_id %d not found", cb->poll_id);
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
		evdi_inflight_req_put(req);
		return ret;
	}

	ret = wait_for_completion_interruptible_timeout(&req->done, EVDI_WAIT_TIMEOUT);
	evdi_inflight_req_put(req);
	return (ret <= 0) ? (ret == 0 ? -ETIMEDOUT : (int)ret) : 0;
}

const struct drm_ioctl_desc evdi_ioctls[] = {
	DRM_IOCTL_DEF_DRV(EVDI_CONNECT, evdi_ioctl_connect,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_POLL, evdi_ioctl_poll,
			 DRM_UNLOCKED),
	DRM_IOCTL_DEF_DRV(EVDI_REQUEST_UPDATE, evdi_ioctl_request_update,
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

static int evdi_queue_int_event(struct evdi_device *evdi,
	enum poll_event_type type, int v, struct drm_file *owner)
{
	struct evdi_event *event;
	void *data;

	data = kmalloc(sizeof(int), GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	memcpy(data, &v, sizeof(int));

	event = evdi_event_alloc(evdi, type,
				 atomic_inc_return(&evdi->events.next_poll_id),
				 data, sizeof(int), owner);

	if (!event) {
		kfree(data);
		return -ENOMEM;
	}

	evdi_event_queue(evdi, event);
	return 0;
}

int evdi_queue_add_buf_event(struct evdi_device *evdi, int fd_data, struct drm_file *owner)
{
	return evdi_queue_int_event(evdi, add_buf, fd_data, owner);
}

int evdi_queue_get_buf_event(struct evdi_device *evdi, int id, struct drm_file *owner)
{
	return evdi_queue_int_event(evdi, get_buf, id, owner);
}

int evdi_queue_swap_event(struct evdi_device *evdi, int id, struct drm_file *owner)
{
	return evdi_queue_int_event(evdi, swap_to, id, owner);
}

int evdi_queue_destroy_event(struct evdi_device *evdi, int id, struct drm_file *owner)
{
	return evdi_queue_int_event(evdi, destroy_buf, id, owner);
}

int evdi_queue_create_event(struct evdi_device *evdi,
			   struct drm_evdi_gbm_create_buff *params,
			   struct drm_file *owner)
{
	int poll_id = atomic_inc_return(&evdi->events.next_poll_id);
	return evdi_queue_create_event_with_id(evdi, params, owner, poll_id);
}
