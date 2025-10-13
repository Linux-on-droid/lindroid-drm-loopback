// SPDX-License-Identifier: GPL-2.0-only
/*
 * Lock-free event system for Lindroid
 */

#include "evdi_drv.h"
#include <linux/sched.h>
#include <linux/prefetch.h>
#include <linux/jiffies.h>
#include <linux/uaccess.h>

struct evdi_event_pool global_event_pool = {0};
static void evdi_inflight_req_release(struct kref *kref);

struct evdi_perf_counters evdi_perf;

#define EVDI_PCPU_EVENT_FREE_MAX 256
struct evdi_pcpu_event_freelist {
	struct llist_head free;
	atomic_t free_count;
};

static struct evdi_pcpu_event_freelist __percpu *evdi_pcpu_event_freelist;

static struct evdi_event *evdi_pcpu_event_pop(void)
{
	struct evdi_pcpu_event_freelist *pc;
	struct llist_node *node;

	if (!evdi_pcpu_event_freelist)
		return NULL;

	pc = this_cpu_ptr(evdi_pcpu_event_freelist);
	node = llist_del_first(&pc->free);
	if (!node)
		return NULL;

	atomic_dec(&pc->free_count);
	return llist_entry(node, struct evdi_event, llist);
}

static bool evdi_pcpu_event_push(struct evdi_event *event)
{
	struct evdi_pcpu_event_freelist *pc;
	if (!evdi_pcpu_event_freelist || !event)
		return false;
	pc = this_cpu_ptr(evdi_pcpu_event_freelist);
	if (atomic_read(&pc->free_count) >= EVDI_PCPU_EVENT_FREE_MAX)
		return false;
	llist_add(&event->llist, &pc->free);
	atomic_inc(&pc->free_count);
	return true;
}

static void *evdi_inflight_req_pool_alloc(gfp_t gfp_mask, void *pool_data)
{
	return kvzalloc(sizeof(struct evdi_inflight_req), gfp_mask);
}

static void evdi_inflight_req_pool_free(void *element, void *pool_data)
{
	kvfree(element);
}

static void *evdi_gralloc_data_alloc(gfp_t gfp_mask, void *pool_data)
{
	return kvzalloc(sizeof(struct evdi_gralloc_data), gfp_mask);
}

static void evdi_gralloc_data_free(void *element, void *pool_data)
{
	kvfree(element);
}

int evdi_event_system_init(void)
{
	int cpu;
	struct evdi_pcpu_event_freelist *pc;
	global_event_pool.cache = kmem_cache_create("evdi_events",
						   sizeof(struct evdi_event),
						   0, SLAB_HWCACHE_ALIGN,
						   NULL);
	if (!global_event_pool.cache)
		return -ENOMEM;

	atomic_set(&global_event_pool.allocated, 0);
	atomic_set(&global_event_pool.inflight_allocated, 0);
	atomic_set(&global_event_pool.peak_usage, 0);

	memset(&evdi_perf, 0, sizeof(evdi_perf));
	evdi_smp_wmb();

	evdi_pcpu_event_freelist = alloc_percpu(struct evdi_pcpu_event_freelist);
	if (evdi_pcpu_event_freelist) {
		for_each_possible_cpu(cpu) {
			pc = per_cpu_ptr(evdi_pcpu_event_freelist, cpu);
			init_llist_head(&pc->free);
			atomic_set(&pc->free_count, 0);
		}
	}

	global_event_pool.inflight_pool = mempool_create(
		EVDI_INFLIGHT_POOL_MIN,
		evdi_inflight_req_pool_alloc,
		evdi_inflight_req_pool_free,
		NULL);
	if (!global_event_pool.inflight_pool)
		goto err;

	global_event_pool.gralloc_data_pool = mempool_create(
		EVDI_GRALLOC_DATA_POOL_MIN,
		evdi_gralloc_data_alloc,
		evdi_gralloc_data_free,
		NULL);
	if (!global_event_pool.gralloc_data_pool)
		goto err;

	evdi_info("Event system initialized");

	/* Pre-warm caches */
	{
		const int prealloc = 64;
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

err:
	if (evdi_pcpu_event_freelist)
		free_percpu(evdi_pcpu_event_freelist);

	mempool_destroy(global_event_pool.inflight_pool);
	if (evdi_pcpu_event_freelist)
		free_percpu(evdi_pcpu_event_freelist);

	kmem_cache_destroy(global_event_pool.cache);
	return -ENOMEM;
}

void evdi_event_system_cleanup(void)
{
	if (global_event_pool.gralloc_data_pool)
		mempool_destroy(global_event_pool.gralloc_data_pool);

	if (global_event_pool.inflight_pool)
		mempool_destroy(global_event_pool.inflight_pool);

	if (global_event_pool.cache) {
		kmem_cache_destroy(global_event_pool.cache);
		global_event_pool.cache = NULL;
	}

	if (evdi_pcpu_event_freelist) {
		free_percpu(evdi_pcpu_event_freelist);
		evdi_pcpu_event_freelist = NULL;
	}

	evdi_info("Event system cleaned up - Peak: %d, Inflight hits: %lld",
		  atomic_read(&global_event_pool.peak_usage),
		  atomic64_read(&evdi_perf.inflight_cache_hits));
}

int evdi_event_init(struct evdi_device *evdi)
{
	if (unlikely(!evdi))
		return -EINVAL;

	evdi->percpu_inflight = alloc_percpu(struct evdi_percpu_inflight);
	if (!evdi->percpu_inflight) {
		evdi_err("Failed to allocate per-CPU inflight buffers");
		return -ENOMEM;
	}

	spin_lock_init(&evdi->events.lock);
	init_waitqueue_head(&evdi->events.wait_queue);
	atomic_set(&evdi->events.cleanup_in_progress, 0);

	evdi->events.head = NULL;
	evdi->events.tail = NULL;
	atomic_set(&evdi->events.queue_size, 0);
	atomic_set(&evdi->events.next_poll_id, 1);
	atomic_set(&evdi->events.stopping, 0);

	init_llist_head(&evdi->events.lockfree_head);

	atomic64_set(&evdi->events.events_queued, 0);
	atomic64_set(&evdi->events.events_dequeued, 0);
	atomic64_set(&evdi->events.pool_hits, 0);
	atomic64_set(&evdi->events.pool_misses, 0);
	atomic_set(&evdi->events.wake_pending, 0);

	evdi_smp_wmb();

	evdi_debug("Event system initialized for device %d", evdi->dev_index);
	return 0;
}

void evdi_event_cleanup(struct evdi_device *evdi)
{
	struct evdi_event *event, *next;

	if (unlikely(!evdi))
		return;

	atomic_set(&evdi->events.cleanup_in_progress, 1);
	atomic_set(&evdi->events.stopping, 1);

	evdi_smp_wmb();

	evdi->percpu_inflight = NULL;

	wake_up_all(&evdi->events.wait_queue);

	spin_lock(&evdi->events.lock);
	event = READ_ONCE(evdi->events.head);
	WRITE_ONCE(evdi->events.head, NULL);
	WRITE_ONCE(evdi->events.tail, NULL);
	atomic_set(&evdi->events.queue_size, 0);
	spin_unlock(&evdi->events.lock);

	while (event) {
		next = READ_ONCE(event->next);
		evdi_event_free(event);
		event = next;
	}

	atomic_set(&evdi->events.cleanup_in_progress, 0);

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
	int cur_alloc, peak, new_peak;

	event = evdi_pcpu_event_pop();
	if (event) {
		atomic64_inc(&evdi->events.pool_hits);
		atomic64_inc(&evdi_perf.pool_alloc_fast);
		atomic64_inc(&evdi_perf.event_freelist_pop_hits);
		goto init_event;
	}
	atomic64_inc(&evdi_perf.event_freelist_pop_misses);

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

init_event:
	event->type = type;
	event->poll_id = poll_id;
	event->data = data;
	event->data_size = data_size;
	event->next = NULL;
	event->owner = owner;
	event->evdi = evdi;
	atomic_set(&event->freed, 0);

	cur_alloc = atomic_inc_return(&global_event_pool.allocated);
#ifdef EVDI_HAVE_ATOMIC_CMPXCHG_RELAXED
	do {
		peak = atomic_read(&global_event_pool.peak_usage);
		new_peak = max(cur_alloc, peak);
	} while (peak != new_peak &&
		 atomic_cmpxchg_relaxed(&global_event_pool.peak_usage, peak, new_peak) != peak);
#else
	peak = atomic_read(&global_event_pool.peak_usage);
	if (cur_alloc > peak)
		atomic_cmpxchg(&global_event_pool.peak_usage, peak, cur_alloc);
#endif

	return event;
}

void evdi_inflight_req_get(struct evdi_inflight_req *req)
{
	if (unlikely(!req))
		return;

	kref_get(&req->refcount);
}

void evdi_inflight_req_put(struct evdi_inflight_req *req)
{
	if (unlikely(!req))
		return;

	kref_put(&req->refcount, evdi_inflight_req_release);
}

static void evdi_inflight_req_release(struct kref *kref)
{
	struct evdi_inflight_req *req =
		container_of(kref, struct evdi_inflight_req, refcount);
	struct evdi_percpu_inflight *percpu_req;
	struct evdi_gralloc_data *gralloc;
	int i, slot;

	if (atomic_xchg(&req->freed, 1))
		return;

	gralloc = req->reply.get_buf.gralloc_buf.gralloc;
	if (gralloc) {
		if (gralloc->data_files) {
			for (i = 0; i < gralloc->numFds; i++) {
				if (gralloc->data_files[i]) {
					fput(gralloc->data_files[i]);
					gralloc->data_files[i] = NULL;
				}
			}
			kvfree(gralloc->data_files);
			gralloc->data_files = NULL;
		}
		if (gralloc->data_ints) {
			kvfree(gralloc->data_ints);
			gralloc->data_ints = NULL;
		}
		mempool_free(gralloc, global_event_pool.gralloc_data_pool);
		req->reply.get_buf.gralloc_buf.gralloc = NULL;
	}
	if (atomic_read(&req->from_percpu)) {
		slot = (int)req->percpu_slot;
		if (slot >= 0 && slot < 2) {
			percpu_req = container_of(req, struct evdi_percpu_inflight, req[0]);
			atomic_set(&percpu_req->in_use[slot], 0);
			evdi_smp_wmb();
		}
	} else {
		mempool_free(req, global_event_pool.inflight_pool);
	}
	atomic_dec(&global_event_pool.inflight_allocated);
}

struct evdi_inflight_req *evdi_inflight_req_alloc(void)
{
	struct evdi_inflight_req *req;

	req = mempool_alloc(global_event_pool.inflight_pool, GFP_ATOMIC);
	if (likely(req)) {
		memset(req, 0, sizeof(*req));
		atomic_inc(&global_event_pool.inflight_allocated);
		atomic64_inc(&evdi_perf.inflight_cache_hits);
		kref_init(&req->refcount);
		init_completion(&req->done);
		atomic_set(&req->from_percpu, 0);
		atomic_set(&req->freed, 0);
		req->reply.get_buf.gralloc_buf.gralloc = NULL;
	}
	return req;
}

void evdi_event_free_immediate(struct evdi_event *event)
{
	if (!event)
		return;

	atomic_dec(&global_event_pool.allocated);

	if (event->from_pool && global_event_pool.cache) {
		if (evdi_pcpu_event_push(event)) {
			atomic64_inc(&evdi_perf.event_freelist_pushes);
			return;
		}
		kmem_cache_free(global_event_pool.cache, event);
	} else {
		kfree(event);
	}
}

void evdi_event_free_rcu(struct rcu_head *head)
{
	struct evdi_event *event = container_of(head, struct evdi_event, rcu);
	
	if (event->data && event->data_size > 0)
		kfree(event->data);

	evdi_event_free_immediate(event);
}

void evdi_event_free(struct evdi_event *event)
{
	if (!event)
		return;

	if (atomic_xchg(&event->freed, 1))
		return;

	call_rcu(&event->rcu, evdi_event_free_rcu);
}

static inline bool evdi_event_queue_lockfree(struct evdi_device *evdi, struct evdi_event *event)
{
	if (unlikely(atomic_read_acquire(&evdi->events.cleanup_in_progress)))
		return false;

	if (unlikely(atomic_read_acquire(&evdi->events.stopping)))
		return false;

	llist_add(&event->llist, &evdi->events.lockfree_head);
	
	atomic_inc(&evdi->events.queue_size);
	atomic64_inc(&evdi->events.events_queued);
	atomic64_inc(&evdi_perf.event_queue_ops);
	
	evdi_smp_wmb();

	if (atomic_cmpxchg(&evdi->events.wake_pending, 0, 1) == 0) {
		wake_up_interruptible(&evdi->events.wait_queue);
		atomic64_inc(&evdi_perf.wakeup_count);
	}
	
	return true;
}

void evdi_event_queue(struct evdi_device *evdi, struct evdi_event *event)
{
	struct evdi_event *tail;

	if (unlikely(!evdi || !event))
		return;

	if (likely(evdi_event_queue_lockfree(evdi, event)))
		return;

	spin_lock(&evdi->events.lock);

	if (unlikely(atomic_read(&evdi->events.stopping))) {
		spin_unlock(&evdi->events.lock);
		evdi_event_free(event);
		return;
	}
	WRITE_ONCE(event->next, NULL);
	evdi_smp_wmb();
	tail = READ_ONCE(evdi->events.tail);
	if (tail) {
		WRITE_ONCE(tail->next, event);
	} else {
		WRITE_ONCE(evdi->events.head, event);
	}

	WRITE_ONCE(evdi->events.tail, event);
	spin_unlock(&evdi->events.lock);

	atomic_inc(&evdi->events.queue_size);
	atomic64_inc(&evdi->events.events_queued);
	atomic64_inc(&evdi_perf.event_queue_ops);
	if (atomic_cmpxchg(&evdi->events.wake_pending, 0, 1) == 0) {
		wake_up_interruptible(&evdi->events.wait_queue);
		atomic64_inc(&evdi_perf.wakeup_count);
	}
}

struct evdi_event *evdi_event_dequeue(struct evdi_device *evdi)
{
	struct evdi_event *head, *next;
	struct llist_node *node;
	struct evdi_event *event;

 	if (unlikely(!evdi))
 		return NULL;

	if (unlikely(atomic_read_acquire(&evdi->events.cleanup_in_progress)))
		goto spinlock_path;

	node = llist_del_first(&evdi->events.lockfree_head);
	if (!node)
		return NULL;


	event = llist_entry(node, struct evdi_event, llist);
	atomic_dec(&evdi->events.queue_size);
	atomic64_inc(&evdi->events.events_dequeued);
	atomic64_inc(&evdi_perf.event_dequeue_ops);

	atomic_set(&evdi->events.wake_pending, 0);
	evdi_smp_wmb();

	return event;

spinlock_path:
	spin_lock(&evdi->events.lock);
	
	head = READ_ONCE(evdi->events.head);
	if (head) {
		next = READ_ONCE(head->next);
		WRITE_ONCE(evdi->events.head, next);
		if (!next)
			WRITE_ONCE(evdi->events.tail, NULL);
		
		atomic_dec(&evdi->events.queue_size);
		atomic64_inc(&evdi->events.events_dequeued);
		atomic64_inc(&evdi_perf.event_dequeue_ops);
		atomic_set(&evdi->events.wake_pending, 0);
		evdi_smp_wmb();
	}
	
	spin_unlock(&evdi->events.lock);
	return head;
}


void evdi_event_cleanup_file(struct evdi_device *evdi, struct drm_file *file)
{
	struct evdi_event *event, *next;
	struct evdi_event *new_head = NULL, *new_tail = NULL;
	struct evdi_event **restore_events = NULL;
	int lf_removed = 0;
	int sp_removed = 0;
	int restore_count = 0;
	int restore_capacity = 0;
	int i;

	if (unlikely(!evdi || !file))
		return;

	if (atomic_read(&evdi->events.queue_size) == 0 &&
	    llist_empty(&evdi->events.lockfree_head))
		return;

	atomic_set(&evdi->events.cleanup_in_progress, 1);

	{
		struct llist_node *llnode, *next_node = NULL;
		int queue_estimate = atomic_read(&evdi->events.queue_size);

		if (queue_estimate > 0) {
			restore_capacity = queue_estimate + 64;
			restore_events = kmalloc_array(restore_capacity, 
						sizeof(struct evdi_event *), GFP_KERNEL);
		}

		llnode = llist_del_all(&evdi->events.lockfree_head);

		while (llnode) {
			event = llist_entry(llnode, struct evdi_event, llist);
			next_node = llnode->next;

			if (event->owner == file) {
				lf_removed++;
				atomic_dec(&evdi->events.queue_size);
				call_rcu(&event->rcu, evdi_event_free_rcu);
			} else if (restore_events && restore_count < restore_capacity) {
				restore_events[restore_count++] = event;
			}
			llnode = next_node;
		}
	}
	if (restore_events) {
		for (i = 0; i < restore_count; i++) {
			llist_add(&restore_events[i]->llist, &evdi->events.lockfree_head);
		}
		kfree(restore_events);
	}
	evdi_smp_wmb();

	spin_lock(&evdi->events.lock);

	event = READ_ONCE(evdi->events.head);
	while (event) {
		next = READ_ONCE(event->next);
		if (event->owner == file) {
			sp_removed++;
			call_rcu(&event->rcu, evdi_event_free_rcu);
		} else {
			WRITE_ONCE(event->next, NULL);
			if (!new_head) {
				new_head = event;
				new_tail = event;
			} else {
				WRITE_ONCE(new_tail->next, event);
				new_tail = event;
			}
		}
		event = next;
	}
	
	WRITE_ONCE(evdi->events.head, new_head);
	WRITE_ONCE(evdi->events.tail, new_tail);
	if (sp_removed)
		atomic_sub(sp_removed, &evdi->events.queue_size);

	spin_unlock(&evdi->events.lock);

	atomic_set(&evdi->events.cleanup_in_progress, 0);
	evdi_smp_wmb();
	wake_up_interruptible(&evdi->events.wait_queue);
	
	if (lf_removed || sp_removed)
		evdi_debug("Cleaned up %d events for closed file (lf:%d sp:%d)",
			   lf_removed + sp_removed, lf_removed, sp_removed);
}

int evdi_event_wait(struct evdi_device *evdi, struct drm_file *file)
{
	DEFINE_WAIT(wait);
	int ret = 0;

	atomic64_inc(&evdi_perf.poll_cycles);

	for (;;) {
		prepare_to_wait(&evdi->events.wait_queue, &wait, TASK_INTERRUPTIBLE);
		atomic_set(&evdi->events.wake_pending, 0);
		evdi_smp_mb();
		if (atomic_read(&evdi->events.queue_size) > 0) {
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
