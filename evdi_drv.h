/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __EVDI_DRV_H__
#define __EVDI_DRV_H__

#include <linux/module.h>
#include <linux/version.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/kref.h>
#include <linux/spinlock.h>

#if KERNEL_VERSION(5, 5, 0) <= LINUX_VERSION_CODE
#include <drm/drm_drv.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_file.h>
#include <drm/drm_gem.h>
#include <drm/drm_vblank.h>
#elif KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE
#include <drm/drm_drv.h>
#include <drm/drmP.h>
#else
#include <drm/drmP.h>
#endif

#include <drm/drm_crtc.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_encoder.h>
#include <drm/drm_connector.h>

#if KERNEL_VERSION(4, 19, 0) <= LINUX_VERSION_CODE
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_probe_helper.h>
#define EVDI_HAVE_KMS_HELPER 1
#else
#undef EVDI_HAVE_KMS_HELPER
#endif

#include <drm/drm_simple_kms_helper.h>

#if KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE
#include <linux/xarray.h>
#define EVDI_HAVE_XARRAY 1
#else
#include <linux/idr.h>
#undef EVDI_HAVE_XARRAY
#endif

#if KERNEL_VERSION(5, 11, 0) <= LINUX_VERSION_CODE
#include <drm/drm_managed.h>
#define EVDI_HAVE_DRM_MANAGED 1
#else
#undef EVDI_HAVE_DRM_MANAGED
#endif

#if KERNEL_VERSION(5, 4, 0) <= LINUX_VERSION_CODE
#define EVDI_HAVE_DRM_EVENT_RESERVE 1
#else
#undef EVDI_HAVE_DRM_EVENT_RESERVE
#endif

#if KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE
#define EVDI_HAVE_WQ_HIGHPRI 1
#define EVDI_HAVE_ATOMIC_CMPXCHG_RELAXED 1
#endif

#if KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE
#define EVDI_HAVE_XA_ALLOC_CYCLIC 1
#endif

#include "uapi/evdi_drm.h"

#define DRIVER_NAME "evdi-lindroid"
#define DRIVER_DESC "Lindroid Virtual Display Interface"
#define DRIVER_DATE   "NEVER"
#define DRIVER_MAJOR 1
#define DRIVER_MINOR 0
#define DRIVER_PATCHLEVEL 0

#define EVDI_WAIT_TIMEOUT	msecs_to_jiffies(5000)

#define EVDI_MAX_FDS   32
#define EVDI_MAX_INTS  256

struct evdi_device;

struct evdi_gralloc_buf {
	int version;
	int numFds;
	int numInts;
	struct file *data_files[EVDI_MAX_FDS];
	int data_ints[EVDI_MAX_INTS];
};

struct evdi_gralloc_buf_user {
	int version;
	int numFds;
	int numInts;
	int data[EVDI_MAX_FDS + EVDI_MAX_INTS];
};

struct evdi_event_pool {
	struct kmem_cache *cache;
	struct kmem_cache *drm_cache;
	struct kmem_cache *inflight_cache;
	atomic_t allocated;
	atomic_t drm_allocated;
	atomic_t inflight_allocated;
	atomic_t peak_usage;
};

struct evdi_event {
	enum poll_event_type type;
	int poll_id;
	void *data;
	size_t data_size;
	struct evdi_event *next;
	bool from_pool;
	struct drm_file *owner;
	struct evdi_device *evdi;
};

struct evdi_drm_update_ready_event {
	struct drm_pending_event base;
	struct drm_evdi_event_update_ready event;
};

struct evdi_inflight_req {
	int type;
	struct completion done;
	struct drm_file *owner;
	struct kref refcount;
	union {
		struct {
			int id;
			u32 stride;
		} create;
		struct {
			struct evdi_gralloc_buf gralloc_buf;
			int status;
		} get_buf;
	} reply;
};

struct evdi_gem_object {
	struct drm_gem_object base;
	struct page **pages;
	atomic_t pages_pin_count;
	struct mutex pages_lock;
	void *vmapping;
#if KERNEL_VERSION(5, 11, 0) <= LINUX_VERSION_CODE
	bool vmap_is_iomem;
#endif
	bool vmap_is_vmram;
	struct sg_table *sg;
};

#define to_evdi_bo(x) container_of(x, struct evdi_gem_object, base)

struct evdi_device {
	struct drm_device *ddev;
	struct drm_connector *connector;
	struct drm_encoder *encoder;
	struct drm_simple_display_pipe pipe;

	int dev_index;

	bool connected;
	uint32_t width;
	uint32_t height;
	uint32_t refresh_rate;

	struct drm_file *drm_client;
	atomic_t update_requested;
	struct workqueue_struct *high_perf_wq;
	struct work_struct send_update_work;
	struct work_struct send_events_work;

	struct {
	spinlock_t lock;
	atomic_t cleanup_in_progress;
	struct evdi_event * volatile head;
	struct evdi_event * volatile tail;
	wait_queue_head_t wait_queue;
	struct evdi_event_pool pool;
	atomic_t queue_size;
	atomic_t next_poll_id;
	atomic_t stopping;
	atomic64_t events_queued;
	atomic64_t events_dequeued;
	atomic64_t pool_hits;
	atomic64_t pool_misses;
	} events;

	struct mutex config_mutex;

	struct platform_device *pdev;

#ifdef EVDI_HAVE_XARRAY
	struct xarray file_xa;
	struct xarray inflight_xa;
	u32 inflight_next_id;
#else
	struct idr file_idr;
	spinlock_t file_lock;
	struct idr inflight_idr;
	spinlock_t inflight_lock;
#endif
};

struct evdi_inflight_req;
void evdi_inflight_req_get(struct evdi_inflight_req *req);
void evdi_inflight_req_put(struct evdi_inflight_req *req);
ssize_t evdi_event_read(struct file *file, char __user *buf, size_t len, loff_t *ppos);
unsigned int evdi_event_poll(struct file *file, poll_table *wait);

extern struct evdi_event_pool *evdi_global_event_pool;
extern atomic_t evdi_device_count;

/* evdi_lindroid_drv.c */
int evdi_device_init(struct evdi_device *evdi, struct platform_device *pdev);
void evdi_device_cleanup(struct evdi_device *evdi);

/* evdi_modeset.c */
int evdi_modeset_init(struct drm_device *dev);
void evdi_modeset_cleanup(struct drm_device *dev);

/* evdi_connector.c */
int evdi_connector_init(struct drm_device *dev, struct evdi_device *evdi);
void evdi_connector_cleanup(struct evdi_device *evdi);

/* evdi_encoder.c */
int evdi_encoder_init(struct drm_device *dev, struct evdi_device *evdi);
void evdi_encoder_cleanup(struct evdi_device *evdi);

/* evdi_ioctl.c */
int evdi_ioctl_connect(struct drm_device *dev, void *data, struct drm_file *file);
int evdi_ioctl_poll(struct drm_device *dev, void *data, struct drm_file *file);
int evdi_ioctl_add_buff_callback(struct drm_device *dev, void *data, struct drm_file *file);
int evdi_ioctl_get_buff_callback(struct drm_device *dev, void *data, struct drm_file *file);
int evdi_ioctl_destroy_buff_callback(struct drm_device *dev, void *data, struct drm_file *file);
int evdi_ioctl_swap_callback(struct drm_device *dev, void *data, struct drm_file *file);
int evdi_ioctl_create_buff_callback(struct drm_device *dev, void *data, struct drm_file *file);
int evdi_ioctl_gbm_create_buff(struct drm_device *dev, void *data, struct drm_file *file);
void evdi_inflight_discard_owner(struct evdi_device *evdi, struct drm_file *owner);
int evdi_ioctl_request_update(struct drm_device *dev, void *data, struct drm_file *file);
void evdi_send_drm_update_ready_async(struct evdi_device *evdi);
void evdi_send_update_work_func(struct work_struct *work);
void evdi_send_events_work_func(struct work_struct *work);
int evdi_ioctl_gbm_del_buff(struct drm_device *dev, void *data, struct drm_file *file);
int evdi_queue_swap_event(struct evdi_device *evdi, int id, struct drm_file *owner);

/* evdi_event.c */
int evdi_event_init(struct evdi_device *evdi);
void evdi_event_cleanup(struct evdi_device *evdi);
struct evdi_event *evdi_event_alloc(struct evdi_device *evdi,
				   enum poll_event_type type,
				   int poll_id,
				   void *data,
				   size_t data_size,
				   struct drm_file *owner);
void evdi_event_free(struct evdi_event *event);
void evdi_event_queue(struct evdi_device *evdi, struct evdi_event *event);
struct evdi_event *evdi_event_dequeue(struct evdi_device *evdi);
void evdi_event_cleanup_file(struct evdi_device *evdi, struct drm_file *file);
int evdi_event_wait(struct evdi_device *evdi, struct drm_file *file);
struct evdi_drm_update_ready_event *evdi_drm_event_alloc(void);
void evdi_drm_event_free(struct evdi_drm_update_ready_event *event);
struct evdi_inflight_req;
struct evdi_inflight_req *evdi_inflight_req_alloc(void);

/* evdi_gem.c */
struct evdi_gem_object *evdi_gem_alloc_object(struct drm_device *dev, size_t size);
int evdi_gem_create(struct drm_file *file, struct drm_device *dev, uint64_t size, uint32_t *handle_p);
int evdi_dumb_create(struct drm_file *file, struct drm_device *dev, struct drm_mode_create_dumb *args);
int evdi_drm_gem_mmap(struct file *filp, struct vm_area_struct *vma);
void evdi_gem_free_object(struct drm_gem_object *gem_obj);
uint32_t evdi_gem_object_handle_lookup(struct drm_file *filp, struct drm_gem_object *obj);
struct sg_table *evdi_prime_get_sg_table(struct drm_gem_object *obj);
struct drm_gem_object *evdi_prime_import_sg_table(struct drm_device *dev,
						  struct dma_buf_attachment *attach,
						  struct sg_table *sg);
int evdi_gem_vmap(struct evdi_gem_object *obj);
void evdi_gem_vunmap(struct evdi_gem_object *obj);
#if KERNEL_VERSION(4, 17, 0) <= LINUX_VERSION_CODE
vm_fault_t evdi_gem_fault(struct vm_fault *vmf);
#else
int evdi_gem_fault(struct vm_fault *vmf);
#endif

/* evdi_sysfs.c */
int evdi_sysfs_init(void);
void evdi_sysfs_cleanup(void);

/* Helpers */
static __always_inline bool evdi_likely_connected(struct evdi_device *evdi)
{
	return likely(evdi->connected);
}

static __always_inline bool evdi_likely_not_stopping(struct evdi_device *evdi)
{
	return likely(!atomic_read(&evdi->events.stopping));
}

/* Memory barriers */
static __always_inline void evdi_smp_wmb(void)
{
	smp_wmb();
}

static __always_inline void evdi_smp_rmb(void)
{
	smp_rmb();
}

/* Macros */
#if KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE
#define EVDI_HAVE_DRM_OPEN_CLOSE 1
#else
#define EVDI_HAVE_DRM_OPEN_CLOSE 0
#endif

#if KERNEL_VERSION(4, 19, 0) <= LINUX_VERSION_CODE
#define EVDI_HAVE_ATOMIC_HELPERS 1
#else
#define EVDI_HAVE_ATOMIC_HELPERS 0
#endif

#if KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE
#define EVDI_HAVE_CONNECTOR_INIT_WITH_DDC 1
#else
#define EVDI_HAVE_CONNECTOR_INIT_WITH_DDC 0
#endif

#define EVDI_MAX_INFLIGHT_REQUESTS 1000

/* Debug and statistics */
#ifdef DEBUG
#define evdi_debug(fmt, ...) \
	pr_debug("[evdi-lindroid] " fmt "\n", ##__VA_ARGS__)
#else
#define evdi_debug(fmt, ...) do { } while (0)
#endif

#define evdi_info(fmt, ...) \
	pr_info("[evdi-lindroid] " fmt "\n", ##__VA_ARGS__)

#define evdi_warn(fmt, ...) \
	pr_warn("[evdi-lindroid] " fmt "\n", ##__VA_ARGS__)

#define evdi_err(fmt, ...) \
	pr_err("[evdi-lindroid] " fmt "\n", ##__VA_ARGS__)

/* Performance counters for monitoring */
struct evdi_perf_counters {
	atomic64_t ioctl_calls[16];
	atomic64_t event_queue_ops;
	atomic64_t event_dequeue_ops;
	atomic64_t pool_alloc_fast;
	atomic64_t pool_alloc_slow;
	atomic64_t wakeup_count;
	atomic64_t poll_cycles;
	atomic64_t drm_events_sent;
	atomic64_t drm_events_dropped;
	atomic64_t inflight_cache_hits;
	atomic64_t callback_completions;
};

extern struct evdi_perf_counters evdi_perf;

/* External vm_ops */
extern const struct vm_operations_struct evdi_gem_vm_ops;

#endif /* __EVDI_DRV_H__ */
