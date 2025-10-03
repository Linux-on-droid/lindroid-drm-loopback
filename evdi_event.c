// SPDX-License-Identifier: GPL-2.0-only
/*
 * Lock-free event system for Lindroid
 */

#include "evdi_drv.h"
#include <linux/sched.h>
#include <linux/prefetch.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>

static struct evdi_event_pool global_event_pool;

struct evdi_perf_counters evdi_perf;

int evdi_event_system_init(void)
{
	global_event_pool.cache = kmem_cache_create("evdi_event",
						   sizeof(struct evdi_event),
						   0, SLAB_HWCACHE_ALIGN,
						   NULL);
	if (!global_event_pool.cache)
		return -ENOMEM;

	atomic_set(&global_event_pool.allocated, 0);
	atomic_set(&global_event_pool.peak_usage, 0);

	memset(&evdi_perf, 0, sizeof(evdi_perf));

	evdi_info("Event system initialized with slab cache");

	/* Pre-warm cache */
	{
		const int prealloc = 256;
		int i;
		void *tmp;
		for (i = 0; i < prealloc; i++) {
			tmp = kmem_cache_alloc(global_event_pool.cache, GFP_NOWAIT);
			if (!tmp)
				break;
			kmem_cache_free(global_event_pool.cache, tmp);
		}
	}

	return 0;
}

void evdi_event_system_cleanup(void)
{
	if (global_event_pool.cache) {
		kmem_cache_destroy(global_event_pool.cache);
		global_event_pool.cache = NULL;
	}

	evdi_info("Event system cleaned up, peak usage: %d events",
		 atomic_read(&global_event_pool.peak_usage));
}

int evdi_event_init(struct evdi_device *evdi)
{
	evdi->events.head = NULL;
	evdi->events.tail = NULL;

	init_waitqueue_head(&evdi->events.wait_queue);

	atomic_set(&evdi->events.queue_size, 0);
	atomic_set(&evdi->events.next_poll_id, 1);
	atomic_set(&evdi->events.stopping, 0);

	atomic64_set(&evdi->events.events_queued, 0);
	atomic64_set(&evdi->events.events_dequeued, 0);
	atomic64_set(&evdi->events.pool_hits, 0);
	atomic64_set(&evdi->events.pool_misses, 0);

	evdi_debug("Event system initialized for device %d", evdi->dev_index);
	return 0;
}

void evdi_event_cleanup(struct evdi_device *evdi)
{
	struct evdi_event *event, *next;

	atomic_set(&evdi->events.stopping, 1);

	wake_up_interruptible(&evdi->events.wait_queue);

	event = evdi->events.head;
	while (event) {
		next = event->next;
		evdi_event_free(event);
		event = next;
	}

	evdi->events.head = NULL;
	evdi->events.tail = NULL;
	atomic_set(&evdi->events.queue_size, 0);

	evdi_debug("Event system cleaned up for device %d", evdi->dev_index);
}

struct evdi_event *evdi_event_alloc(struct evdi_device *evdi,
				   enum poll_event_type type,
				   int poll_id,
				   void *data,
				   size_t data_size,
				   struct drm_file *owner)
{
	struct evdi_event *event;
	int cur_alloc, peak;

	event = kmem_cache_alloc(global_event_pool.cache, GFP_ATOMIC);
	if (likely(event)) {
		atomic64_inc(&evdi->events.pool_hits);
		atomic64_inc(&evdi_perf.pool_alloc_fast);
		event->from_pool = true;
	} else {
		event = kmalloc(sizeof(*event), GFP_KERNEL);
		if (!event) {
			atomic64_inc(&evdi->events.pool_misses);
			return NULL;
		}
		atomic64_inc(&evdi_perf.pool_alloc_slow);
		event->from_pool = false;
	}

	event->type = type;
	event->poll_id = poll_id;
	event->data = data;
	event->data_size = data_size;
	event->next = NULL;
	event->owner = owner;
	event->evdi = evdi;

	cur_alloc = atomic_inc_return(&global_event_pool.allocated);
	peak = atomic_read(&global_event_pool.peak_usage);

	while (cur_alloc > peak) {
		if (atomic_cmpxchg(&global_event_pool.peak_usage, peak, cur_alloc) == peak)
			break;

		peak = atomic_read(&global_event_pool.peak_usage);
	}

	return event;
}

void evdi_event_free(struct evdi_event *event)
{
	if (!event)
		return;

	if (event->data && event->data_size > 0)
		kfree(event->data);

	if (event->from_pool && global_event_pool.cache) {
		kmem_cache_free(global_event_pool.cache, event);
	} else {
		kfree(event);
	}

	atomic_dec(&global_event_pool.allocated);
}

void evdi_event_queue(struct evdi_device *evdi, struct evdi_event *event)
{
	struct evdi_event *tail;

	if (unlikely(atomic_read(&evdi->events.stopping))) {
		evdi_event_free(event);
		return;
	}

	do {
		tail = evdi->events.tail;
		event->next = NULL;

		evdi_smp_wmb();

		if (likely(cmpxchg(&evdi->events.tail, tail, event) == tail)) {
			if (tail) {
				tail->next = event;
			} else {
				evdi->events.head = event;
			}
			break;
		}
		cpu_relax();
	} while (1);

	atomic_inc(&evdi->events.queue_size);
	atomic64_inc(&evdi->events.events_queued);
	atomic64_inc(&evdi_perf.event_queue_ops);

	wake_up_interruptible(&evdi->events.wait_queue);
	atomic64_inc(&evdi_perf.wakeup_count);
}

struct evdi_event *evdi_event_dequeue(struct evdi_device *evdi)
{
	struct evdi_event *head, *next;

	do {
		head = evdi->events.head;
		if (!head)
			return NULL;

		next = head->next;
		if (next)
			prefetch(next);

		evdi_smp_rmb();

		if (likely(cmpxchg(&evdi->events.head, head, next) == head)) {
			if (!next)
				evdi->events.tail = NULL;

			break;
		}
		cpu_relax();
	} while (1);

	atomic_dec(&evdi->events.queue_size);
	atomic64_inc(&evdi->events.events_dequeued);
	atomic64_inc(&evdi_perf.event_dequeue_ops);

	return head;
}

static struct evdi_event *evdi_event_wait_dequeue(struct evdi_device *evdi,
						  struct drm_file *owner)
{
	struct evdi_event *evt;
	long ret;

	evt = evdi_event_dequeue(evdi);
	if (evt)
		return evt;

	ret = wait_event_interruptible_timeout(evdi->events.wait_queue,
					       evdi->events.head ||
					       atomic_read(&evdi->events.stopping),
					       msecs_to_jiffies(16));
	if (ret < 0)
		return NULL;

	if (atomic_read(&evdi->events.stopping))
		return NULL;

	return evdi_event_dequeue(evdi);
}

ssize_t evdi_event_read(struct file *file, char __user *buf, size_t len, loff_t *ppos)
{
	struct drm_file *drmfile = file->private_data;
	struct drm_device *ddev = drmfile->minor->dev;
	struct evdi_device *evdi = ddev->dev_private;
	struct evdi_event *evt;
	size_t copy;

	if (!READ_ONCE(evdi->events.head)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		evt = evdi_event_wait_dequeue(evdi, drmfile);
		if (!evt)
			return -ERESTARTSYS;
	} else {
		evt = evdi_event_dequeue(evdi);
		if (!evt)
			return -EAGAIN;
	}

	copy = evt->data_size < len ? evt->data_size : len;
	if (copy && evt->data) {
		if (copy_to_user(buf, evt->data, copy)) {
			evdi_event_free(evt);
			return -EFAULT;
		}
	}

	evdi_event_free(evt);
	return (ssize_t)copy;
}

unsigned int evdi_event_poll(struct file *file, poll_table *wait)
{
	struct drm_file *drmfile = file->private_data;
	struct drm_device *ddev = drmfile->minor->dev;
	struct evdi_device *evdi = ddev->dev_private;
	unsigned int mask = 0;

	poll_wait(file, &evdi->events.wait_queue, wait);
	if (READ_ONCE(evdi->events.head))
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

void evdi_event_cleanup_file(struct evdi_device *evdi, struct drm_file *file)
{
	struct evdi_event *event, *next;
	struct evdi_event *new_head = NULL, *new_tail = NULL;

	event = evdi->events.head;

	while (event) {
		next = event->next;
		if (event->owner == file) {
			evdi_event_free(event);
			atomic_dec(&evdi->events.queue_size);
		} else {
			event->next = NULL;
			if (!new_head) {
				new_head = event;
				new_tail = event;
			} else {
				new_tail->next = event;
				new_tail = event;
			}
		}
	event = next;
	}

	evdi->events.head = new_head;
	evdi->events.tail = new_tail;

	evdi_debug("Cleaned up events for closed file");
}

int evdi_event_wait(struct evdi_device *evdi, struct drm_file *file)
{
	DEFINE_WAIT(wait);
	int ret = 0;

	atomic64_inc(&evdi_perf.poll_cycles);

	for (;;) {
		prepare_to_wait(&evdi->events.wait_queue, &wait, TASK_INTERRUPTIBLE);
		if (evdi->events.head) {
			ret = 0;
			break;
		}

		if (atomic_read(&evdi->events.stopping)) {
			ret = -ENODEV;
			break;
		}

		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		schedule();
	}

	finish_wait(&evdi->events.wait_queue, &wait);
	return ret;
}
