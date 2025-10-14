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

struct evdi_gralloc_buf_stack {
	struct evdi_gralloc_buf_user buf;
	int installed_fds[EVDI_MAX_FDS];
};

static int evdi_process_gralloc_buffer(struct evdi_inflight_req *req,
					int *installed_fds,
					struct evdi_gralloc_buf_user *gralloc_buf)
{
	struct evdi_gralloc_data *gralloc;
	int i, fd_tmp;

	gralloc = req->reply.get_buf.gralloc_buf.gralloc;
	if (!gralloc)
		return -EINVAL;

	gralloc_buf->version = gralloc->version;
	gralloc_buf->numFds = gralloc->numFds;
	gralloc_buf->numInts = gralloc->numInts;
	if (gralloc->data_ints) {
		memcpy(&gralloc_buf->data[gralloc_buf->numFds],
		       gralloc->data_ints,
		       sizeof(int) * gralloc_buf->numInts);
	}

	for (i = 0; i < gralloc_buf->numFds; i++) {
		fd_tmp = get_unused_fd_flags(O_RDWR);
		if (fd_tmp < 0) {
			while (--i >= 0)
				put_unused_fd(installed_fds[i]);
			return fd_tmp;
		}
		installed_fds[i] = fd_tmp;
		gralloc_buf->data[i] = fd_tmp;
	}

	return 0;
}

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

static inline struct evdi_inflight_req *evdi_inflight_alloc(struct evdi_device *evdi,
						     struct drm_file *owner,
						     int type,
						     int *out_id)
{
	struct evdi_inflight_req *req;
	struct evdi_percpu_inflight *percpu_req;
	bool from_percpu = false;
	int id, i;

	percpu_req = get_cpu_ptr(evdi->percpu_inflight);
	if (likely(percpu_req)) {
		for (i = 0; i < 2; i++) {
			if (atomic_cmpxchg(&percpu_req->in_use[i], 0, 1) == 0) {
				req = &percpu_req->req[i];
				from_percpu = true;
				memset(req, 0, sizeof(*req));
				kref_init(&req->refcount);
				init_completion(&req->done);
				atomic_set(&req->freed, 0);
				atomic_set(&req->from_percpu, 1);
				req->percpu_slot = (u8)i;
				req->reply.get_buf.gralloc_buf.gralloc = NULL;
				atomic64_inc(&evdi_perf.inflight_percpu_hits);
				break;
			}
		}
	}
	put_cpu_ptr(percpu_req);

	// fallback to mempool
	if (!from_percpu) {
		req = evdi_inflight_req_alloc();
		if (likely(req))
			atomic64_inc(&evdi_perf.inflight_percpu_misses);
	}

	if (unlikely(!req))
		return NULL;

	req->type = type;
	req->owner = owner;

#ifdef EVDI_HAVE_XARRAY
	{
		u32 xid;
		int ret;
#ifdef EVDI_HAVE_XA_ALLOC_CYCLIC
		xid = READ_ONCE(evdi->inflight_next_id);
		if (unlikely(!xid))
			xid = 1;

		ret = xa_alloc_cyclic(&evdi->inflight_xa,
				      &xid, req,
				      XA_LIMIT(1, INT_MAX),
				      &evdi->inflight_next_id,
				      GFP_NOWAIT);
		if (ret == -EBUSY || ret == -ENOMEM || ret == -EEXIST) {
			WRITE_ONCE(evdi->inflight_next_id, 1);
			xid = 1;
			ret = xa_alloc_cyclic(&evdi->inflight_xa,
					      &xid, req,
					      XA_LIMIT(1, INT_MAX),
					      &evdi->inflight_next_id,
					      GFP_NOWAIT);
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
			       XA_LIMIT(start_id, INT_MAX), GFP_NOWAIT);
		if (ret == -EBUSY && start_id > 1) {
			ret = xa_alloc(&evdi->inflight_xa, &xid, req,
				       XA_LIMIT(1, EVDI_MAX_INFLIGHT_REQUESTS), GFP_NOWAIT);
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
	if (unlikely(!evdi))
		return NULL;

#ifdef EVDI_HAVE_XARRAY
#ifdef EVDI_HAVE_ATOMIC_CMPXCHG_RELAXED
	req = xa_load(&evdi->inflight_xa, id);
	if (req) {
		if (xa_cmpxchg(&evdi->inflight_xa, id, req, NULL, GFP_NOWAIT) != req)
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
	struct evdi_inflight_req *req;

	if (unlikely(!evdi || !owner))
		return;

#ifdef EVDI_HAVE_XARRAY
	{
		XA_STATE(xas, &evdi->inflight_xa, 0);

		rcu_read_lock();
		xas_for_each(&xas, req, ULONG_MAX) {
			if (req->owner != owner)
				continue;

#ifdef EVDI_HAVE_ATOMIC_CMPXCHG_RELAXED
			if (xa_cmpxchg(&evdi->inflight_xa,
				       xas.xa_index, req, NULL, GFP_NOWAIT) != req)
				continue;
#else
			if (xa_lock_irqsave(&evdi->inflight_xa, flags),
			    xa_for_each(&evdi->inflight_xa, idx, entry),
			    req == entry)
			{
				req = xa_erase(&evdi->inflight_xa, xas.xa_index);
				xa_unlock_irqrestore(&evdi->inflight_xa, flags);
			} else {
				xa_unlock_irqrestore(&evdi->inflight_xa, flags);
				continue;
			}
#endif
			rcu_read_unlock();
			complete_all(&req->done);
			evdi_inflight_req_put(req);
			cond_resched();
			rcu_read_lock();
		}
		rcu_read_unlock();
	}
#else
	{
		struct evdi_inflight_req *batch[16];
		int nr, i, id;

		do {
			nr = 0;
			id = 0;
			spin_lock(&evdi->inflight_lock);
			while (nr < 64) {
				req = idr_get_next(&evdi->inflight_idr, &id);
				if (!req)
					break;
				if (req->owner == owner) {
					idr_remove(&evdi->inflight_idr, id);
					batch[nr++] = req;
				}
				id++;
			}
			spin_unlock(&evdi->inflight_lock);

			for (i = 0; i < nr; i++) {
				complete_all(&batch[i]->done);
				evdi_inflight_req_put(batch[i]);
				cond_resched();
			}
		} while (nr == 16);
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

static inline void evdi_flush_work(struct evdi_device *evdi)
{
	if (unlikely(!evdi))
		return;

	atomic_set(&evdi->events.stopping, 1);
	evdi_smp_wmb();
	wake_up_interruptible(&evdi->events.wait_queue);
}

int evdi_ioctl_connect(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_connect *cmd = data;

	atomic64_inc(&evdi_perf.ioctl_calls[0]);

	if (!cmd->connected) {
		evdi_flush_work(evdi);

		mutex_lock(&evdi->config_mutex);
		evdi->connected = false;
		mutex_unlock(&evdi->config_mutex);

		WRITE_ONCE(evdi->drm_client, NULL);
		evdi_smp_wmb();

		evdi_info("Device %d disconnected", evdi->dev_index);
#ifdef EVDI_HAVE_KMS_HELPER
		drm_kms_helper_hotplug_event(dev);
#else
		drm_helper_hpd_irq_event(dev);
#endif
		return 0;
	}

	if (evdi->drm_client && evdi->drm_client != file) {
		evdi_warn("Device %d forcefully disconnecting previous client", evdi->dev_index);
		atomic_set(&evdi->events.stopping, 1);
		evdi_smp_wmb();
		wake_up_interruptible(&evdi->events.wait_queue);
	}

	mutex_lock(&evdi->config_mutex);
	evdi->connected = true;
	evdi->width = cmd->width;
	evdi->height = cmd->height;
	evdi->refresh_rate = cmd->refresh_rate;
	mutex_unlock(&evdi->config_mutex);

	evdi_smp_wmb();
	WRITE_ONCE(evdi->drm_client, file);

	evdi_smp_wmb();

	evdi_info("Device %d connected: %ux%u@%uHz",
		 evdi->dev_index, cmd->width, cmd->height, cmd->refresh_rate);

	atomic_set(&evdi->events.stopping, 0);

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
	struct evdi_gralloc_buf_stack stack_buf;
	struct evdi_gralloc_buf_user *gralloc_buf;
	struct evdi_gralloc_data *gralloc;
	int poll_id;
	long ret;
	int i, copy_size;

	atomic64_inc(&evdi_perf.ioctl_calls[7]);

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

	gralloc_buf = &stack_buf.buf;

	ret = evdi_process_gralloc_buffer(req, stack_buf.installed_fds, gralloc_buf);
	if (ret) {
		evdi_inflight_req_put(req);
		return ret;
	}

	gralloc = req->reply.get_buf.gralloc_buf.gralloc;
	copy_size = sizeof(int) * (3 + gralloc_buf->numFds + gralloc_buf->numInts);
	if (evdi_copy_to_user_allow_partial(cmd->native_handle, gralloc_buf, copy_size)) {
		for (i = 0; i < gralloc_buf->numFds; i++)
			put_unused_fd(stack_buf.installed_fds[i]);

		ret = -EFAULT;
		goto err_event;
	}

	if (gralloc && gralloc->data_files) {
		for (i = 0; i < gralloc_buf->numFds; i++) {
			if (gralloc->data_files[i])
				fd_install(stack_buf.installed_fds[i], gralloc->data_files[i]);
		}
	}

	ret = 0;
err_event:
	if (gralloc && gralloc->data_files) {
		if (ret) {
			for (i = 0; i < gralloc->numFds; i++) {
				if (gralloc->data_files[i]) {
					fput(gralloc->data_files[i]);
					gralloc->data_files[i] = NULL;
				}
			}
		} else {
			for (i = 0; i < gralloc->numFds; i++) {
				gralloc->data_files[i] = NULL;
			}
		}
	}
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

int evdi_ioctl_get_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;
	struct drm_evdi_get_buff_callabck *cb = data;
	struct evdi_inflight_req *req;
	struct evdi_gralloc_data *gralloc;
	int i, j, nfd, nint;
	int fds_local[EVDI_MAX_FDS];

	atomic64_inc(&evdi_perf.ioctl_calls[3]);

	req = evdi_inflight_take(evdi, cb->poll_id);
	if (!req)
		goto out_wake;

//	if (req->owner != file)
//		evdi_warn("get_buff_callback: poll_id %d owned by different file", cb->poll_id);

	if (cb->numFds < 0 || cb->numInts < 0 ||
	    cb->numFds > EVDI_MAX_FDS || cb->numInts > EVDI_MAX_INTS)
		goto out_complete;

	nfd = cb->numFds;
	nint = cb->numInts;

	{
		size_t ints_bytes = nint > 0 ? sizeof(int) * nint : 0;
		size_t files_bytes = nfd > 0 ? sizeof(struct file *) * nfd : 0;
		size_t total = sizeof(*gralloc) + ints_bytes + files_bytes;
		void *blk = kvzalloc(total, GFP_KERNEL);
		char *p;

		if (!blk)
			goto out_complete;

		gralloc = (struct evdi_gralloc_data *)blk;
		p = (char *)(gralloc + 1);
		gralloc->data_ints = nint ? (int *)p : NULL;
		p += ints_bytes;
		gralloc->data_files = nfd ? (struct file **)p : NULL;
		atomic_set(&gralloc->is_kvblock, 1);
		gralloc->version = cb->version;
		gralloc->numFds = 0;
		gralloc->numInts = 0;

		if (nint) {
			if (evdi_copy_from_user_allow_partial(gralloc->data_ints,
							      cb->data_ints,
							      sizeof(int) * nint)) {
				kvfree(blk);
				goto out_complete;
			}
			gralloc->numInts = nint;
		}

		if (nfd) {
			if (evdi_copy_from_user_allow_partial(fds_local, cb->fd_ints,
							      sizeof(int) * nfd)) {
				kvfree(blk);
				goto out_complete;
			}
			for (i = 0; i < nfd; i++) {
				gralloc->data_files[i] = fget(fds_local[i]);
				if (!gralloc->data_files[i]) {
					for (j = 0; j < i; j++) {
						if (gralloc->data_files[j]) {
							fput(gralloc->data_files[j]);
							gralloc->data_files[j] = NULL;
						}
					}
					kvfree(blk);
					goto out_complete;
				}
			}
			gralloc->numFds = nfd;
		}
		req->reply.get_buf.gralloc_buf.gralloc = gralloc;
	}

out_complete:
	complete_all(&req->done);
	evdi_inflight_req_put(req);
	goto out_wake;

out_wake:
	wake_up_interruptible(&evdi->events.wait_queue);
	return 0;
}

int evdi_ioctl_destroy_buff_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;

	atomic64_inc(&evdi_perf.ioctl_calls[4]);
	atomic64_inc(&evdi_perf.callback_completions);

	wake_up_interruptible(&evdi->events.wait_queue);

	return 0;
}

int evdi_ioctl_swap_callback(struct drm_device *dev, void *data, struct drm_file *file)
{
	struct evdi_device *evdi = dev->dev_private;

	atomic64_inc(&evdi_perf.ioctl_calls[5]);
	atomic64_inc(&evdi_perf.callback_completions);

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
	long ret;

	ret = evdi_queue_destroy_event(evdi, cmd->id, file);
	return ret;
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
