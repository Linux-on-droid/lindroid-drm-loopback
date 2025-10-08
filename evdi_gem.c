// SPDX-License-Identifier: GPL-2.0-only
/*
 * EVDI GEM implementation for lindroid
 */

#include <linux/shmem_fs.h>
#include <linux/dma-buf.h>
#include <drm/drm_cache.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/mm.h>
#if KERNEL_VERSION(5, 18, 0) <= LINUX_VERSION_CODE
#include <linux/iosys-map.h>
#endif

#include <drm/drm_gem.h>
#include <drm/drm_prime.h>

#if defined(MODULE_IMPORT_NS) && defined(DMA_BUF)
MODULE_IMPORT_NS(DMA_BUF);
#endif

#include "evdi_drv.h"

static int evdi_pin_pages(struct evdi_gem_object *obj);
static void evdi_unpin_pages(struct evdi_gem_object *obj);

static void evdi_gem_vm_open(struct vm_area_struct *vma)
{
	struct evdi_gem_object *obj = to_evdi_bo(vma->vm_private_data);
	drm_gem_vm_open(vma);
	evdi_pin_pages(obj);
}

static void evdi_gem_vm_close(struct vm_area_struct *vma)
{
	struct evdi_gem_object *obj = to_evdi_bo(vma->vm_private_data);
	evdi_unpin_pages(obj);
	drm_gem_vm_close(vma);
}

const struct vm_operations_struct evdi_gem_vm_ops = {
	.fault = evdi_gem_fault,
	.open = evdi_gem_vm_open,
	.close = evdi_gem_vm_close,
};

#if KERNEL_VERSION(5, 11, 0) <= LINUX_VERSION_CODE
static int evdi_prime_pin(struct drm_gem_object *obj)
{
	struct evdi_gem_object *bo = to_evdi_bo(obj);
	return evdi_pin_pages(bo);
}

static void evdi_prime_unpin(struct drm_gem_object *obj)
{
	struct evdi_gem_object *bo = to_evdi_bo(obj);
	evdi_unpin_pages(bo);
}

static const struct drm_gem_object_funcs gem_obj_funcs = {
	.free = evdi_gem_free_object,
	.pin = evdi_prime_pin,
	.unpin = evdi_prime_unpin,
	.vm_ops = &evdi_gem_vm_ops,
	.export = drm_gem_prime_export,
	.get_sg_table = evdi_prime_get_sg_table,
};
#endif

static bool evdi_drm_gem_object_use_import_attach(struct drm_gem_object *obj)
{
	if (!obj || !obj->import_attach || !obj->import_attach->dmabuf)
		return false;

	return true;
}

uint32_t evdi_gem_object_handle_lookup(struct drm_file *filp, struct drm_gem_object *obj)
{
	uint32_t it_handle = 0;
	struct drm_gem_object *it_obj = NULL;

	spin_lock(&filp->table_lock);
	idr_for_each_entry(&filp->object_idr, it_obj, it_handle) {
		if (it_obj == obj)
			break;
	}
	spin_unlock(&filp->table_lock);

	if (!it_obj)
		it_handle = 0;

	return it_handle;
}

struct evdi_gem_object *evdi_gem_alloc_object(struct drm_device *dev, size_t size)
{
	struct evdi_gem_object *obj;

	obj = kzalloc(sizeof(*obj), GFP_KERNEL);
	if (obj == NULL)
		return NULL;

	if (drm_gem_object_init(dev, &obj->base, size) != 0) {
		kfree(obj);
		return NULL;
	}

	atomic_set(&obj->pages_pin_count, 0);

#if KERNEL_VERSION(5, 11, 0) <= LINUX_VERSION_CODE
	obj->base.funcs = &gem_obj_funcs;
#endif

	mutex_init(&obj->pages_lock);

	return obj;
}

int evdi_gem_create(struct drm_file *file, struct drm_device *dev,
		    uint64_t size, uint32_t *handle_p)
{
	struct evdi_gem_object *obj;
	int ret;
	u32 handle;

	size = round_up(size, PAGE_SIZE);

	obj = evdi_gem_alloc_object(dev, size);
	if (obj == NULL)
		return -ENOMEM;

	ret = drm_gem_handle_create(file, &obj->base, &handle);
	if (ret) {
		drm_gem_object_release(&obj->base);
		kfree(obj);
		return ret;
	}

#if KERNEL_VERSION(5, 9, 0) <= LINUX_VERSION_CODE
	drm_gem_object_put(&obj->base);
#else
	drm_gem_object_put_unlocked(&obj->base);
#endif

	*handle_p = handle;
	return 0;
}

static int evdi_align_pitch(int width, int cpp)
{
	int aligned = width;
	int pitch_mask = 0;

	switch (cpp) {
	case 1:
		pitch_mask = 255;
		break;
	case 2:
		pitch_mask = 127;
		break;
	case 3:
	case 4:
		pitch_mask = 63;
		break;
	}

	aligned += pitch_mask;
	aligned &= ~pitch_mask;
	return aligned * cpp;
}

int evdi_dumb_create(struct drm_file *file, struct drm_device *dev,
		     struct drm_mode_create_dumb *args)
{
	args->pitch = evdi_align_pitch(args->width, DIV_ROUND_UP(args->bpp, 8));
	args->size = args->pitch * args->height;
	return evdi_gem_create(file, dev, args->size, &args->handle);
}

int evdi_drm_gem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret;

	ret = drm_gem_mmap(filp, vma);
	if (ret)
		return ret;

#if KERNEL_VERSION(6, 1, 0) <= LINUX_VERSION_CODE
	vm_flags_mod(vma, VM_MIXEDMAP | VM_DONTDUMP | VM_DONTEXPAND | VM_DONTCOPY,
		     VM_PFNMAP);
#else
	vma->vm_flags &= ~VM_PFNMAP;
	vma->vm_flags |= VM_MIXEDMAP | VM_DONTDUMP | VM_DONTEXPAND | VM_DONTCOPY;
#endif

#if KERNEL_VERSION(5, 11, 0) > LINUX_VERSION_CODE
	vma->vm_ops = &evdi_gem_vm_ops;
#endif

	return ret;
}

#if KERNEL_VERSION(4, 17, 0) <= LINUX_VERSION_CODE
vm_fault_t evdi_gem_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#else
int evdi_gem_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#endif
	struct evdi_gem_object *obj = to_evdi_bo(vma->vm_private_data);
	struct page *page;
	pgoff_t page_offset;
	loff_t num_pages;
	int ret = 0;

	page_offset = (vmf->address - vma->vm_start) >> PAGE_SHIFT;
	num_pages = obj->base.size >> PAGE_SHIFT;

	if (!obj->pages || page_offset >= num_pages)
		return VM_FAULT_SIGBUS;

	page = obj->pages[page_offset];

#if KERNEL_VERSION(4, 17, 0) <= LINUX_VERSION_CODE
	ret = vmf_insert_page(vma, vmf->address, page);
#else
	ret = vm_insert_page(vma, vmf->address, page);
#endif

	switch (ret) {
	case -EAGAIN:
	case 0:
	case -ERESTARTSYS:
	case -EBUSY:
		return VM_FAULT_NOPAGE;
	case -ENOMEM:
		return VM_FAULT_OOM;
	default:
		return VM_FAULT_SIGBUS;
	}
}

static int evdi_gem_get_pages(struct evdi_gem_object *obj, gfp_t gfpmask)
{
	struct page **pages;

	if (obj->pages)
		return 0;

	pages = drm_gem_get_pages(&obj->base);
	if (IS_ERR(pages))
		return PTR_ERR(pages);

	obj->pages = pages;

#ifdef CONFIG_X86
	drm_clflush_pages(obj->pages, DIV_ROUND_UP(obj->base.size, PAGE_SIZE));
#endif

	return 0;
}

static void evdi_gem_put_pages(struct evdi_gem_object *obj)
{
	if (evdi_drm_gem_object_use_import_attach(&obj->base)) {
		obj->pages = NULL;
		return;
	}

	drm_gem_put_pages(&obj->base, obj->pages, false, true);
	obj->pages = NULL;
}

static int evdi_pin_pages(struct evdi_gem_object *obj)
{
	int ret = 0;

	if (unlikely(!obj))
		return -EINVAL;

	/* Fast path if pinned */
	if (likely(atomic_read(&obj->pages_pin_count) > 0)) {
		atomic_inc(&obj->pages_pin_count);
		return 0;
	}

	/* Slow path */
	mutex_lock(&obj->pages_lock);
	if (atomic_inc_return(&obj->pages_pin_count) == 1) {
		ret = evdi_gem_get_pages(obj, GFP_KERNEL);
		if (ret)
			atomic_dec(&obj->pages_pin_count);
	}
	mutex_unlock(&obj->pages_lock);

	return ret;
}

static void evdi_unpin_pages(struct evdi_gem_object *obj)
{
	int new_cnt = atomic_dec_return(&obj->pages_pin_count);

	if (unlikely(!obj))
		return;

	if (unlikely(new_cnt == 0)) {
		mutex_lock(&obj->pages_lock);
		if (atomic_read(&obj->pages_pin_count) == 0)
			evdi_gem_put_pages(obj);
		mutex_unlock(&obj->pages_lock);
	}
}

int evdi_gem_vmap(struct evdi_gem_object *obj)
{
	int page_count = DIV_ROUND_UP(obj->base.size, PAGE_SIZE);
	int ret;

	if (evdi_drm_gem_object_use_import_attach(&obj->base)) {
#if KERNEL_VERSION(5, 11, 0) <= LINUX_VERSION_CODE
		{
			int retm;
#if KERNEL_VERSION(5, 18, 0) <= LINUX_VERSION_CODE
			struct iosys_map map;
#else
			struct dma_buf_map map = DMA_BUF_MAP_INIT_VADDR(NULL);
#endif
			iosys_map_set_vaddr(&map, NULL);
			retm = dma_buf_vmap(obj->base.import_attach->dmabuf, &map);
			if (retm)
				return -ENOMEM;

#ifdef IOSYS_MAP_IS_IOMEM
			obj->vmap_is_iomem = iosys_map_is_iomem(&map);
			obj->vmapping = obj->vmap_is_iomem ?
				(void __force *)map.vaddr_iomem :
				(void *)map.vaddr;
#else
			obj->vmap_is_iomem = map.is_iomem;
			obj->vmapping = map.vaddr;
#endif
		}
#else
		obj->vmapping = dma_buf_vmap(obj->base.import_attach->dmabuf);
		obj->vmap_is_iomem = false;
		if (!obj->vmapping)
			return -ENOMEM;
#endif
		return 0;
 	}

	ret = evdi_pin_pages(obj);
	if (ret)
		return ret;

#if KERNEL_VERSION(5, 9, 0) <= LINUX_VERSION_CODE
	obj->vmapping = vm_map_ram(obj->pages, page_count, -1);
#else
	obj->vmapping = vm_map_ram(obj->pages, page_count, -1, PAGE_KERNEL);
#endif
	obj->vmap_is_vmram = obj->vmapping != NULL;

	if (!obj->vmapping) {
		obj->vmapping = vmap(obj->pages, page_count, 0, PAGE_KERNEL);
		if (!obj->vmapping)
			return -ENOMEM;
	}

	return 0;
}

void evdi_gem_vunmap(struct evdi_gem_object *obj)
{
	if (evdi_drm_gem_object_use_import_attach(&obj->base)) {
#if KERNEL_VERSION(5, 18, 0) <= LINUX_VERSION_CODE
		{
			struct iosys_map map;
#ifdef IOSYS_MAP_IS_IOMEM
			if (obj->vmap_is_iomem)
				iosys_map_set_vaddr_iomem(&map, (void __iomem *)obj->vmapping);
			else
				iosys_map_set_vaddr(&map, obj->vmapping);
#else
			if (obj->vmap_is_iomem)
				iosys_map_set_vaddr_iomem(&map, (void __iomem *)obj->vmapping);
			else
				iosys_map_set_vaddr(&map, obj->vmapping);
#endif
			dma_buf_vunmap(obj->base.import_attach->dmabuf, &map);
		}
#else
		dma_buf_vunmap(obj->base.import_attach->dmabuf, obj->vmapping);
#endif
		obj->vmap_is_iomem = false;
		obj->vmapping = NULL;
		return;
	}

	if (obj->vmapping) {
		if (obj->vmap_is_vmram)
			vm_unmap_ram(obj->vmapping, DIV_ROUND_UP(obj->base.size, PAGE_SIZE));
		else
			vunmap(obj->vmapping);
		obj->vmapping = NULL;
		obj->vmap_is_vmram = false;
		evdi_unpin_pages(obj);
	}
}

void evdi_gem_free_object(struct drm_gem_object *gem_obj)
{
	struct evdi_gem_object *obj = to_evdi_bo(gem_obj);

	if (obj->vmapping)
		evdi_gem_vunmap(obj);

	if (gem_obj->import_attach) {
		drm_prime_gem_destroy(gem_obj, obj->sg);
	}

	if (obj->pages)
		evdi_gem_put_pages(obj);

	if (gem_obj->dev->vma_offset_manager)
		drm_gem_free_mmap_offset(gem_obj);

	mutex_destroy(&obj->pages_lock);

	drm_gem_object_release(&obj->base);
	kfree(obj);
}

static struct sg_table *evdi_dup_sg_table(const struct sg_table *src)
{
	struct sg_table *dst;
	struct scatterlist *s, *d;
	struct page *page;
	int i, nents;
	unsigned int len = 0;

	if (!src || !src->sgl)
		return ERR_PTR(-EINVAL);

	dst = kzalloc(sizeof(*dst), GFP_KERNEL);
	if (!dst)
		return ERR_PTR(-ENOMEM);

	nents = src->nents;
	if (sg_alloc_table(dst, nents, GFP_KERNEL)) {
		kfree(dst);
		return ERR_PTR(-ENOMEM);
	}

	s = src->sgl;
	d = dst->sgl;
	for (i = 0; i < nents; i++, s = sg_next(s), d = sg_next(d)) {
		page = sg_page(s);
		len = s->length;
		sg_set_page(d, page, len, s->offset);
	}

	return dst;
}

struct sg_table *evdi_prime_get_sg_table(struct drm_gem_object *obj)
{
	struct evdi_gem_object *bo = to_evdi_bo(obj);

	if (bo->sg) {
		return evdi_dup_sg_table(bo->sg);
	}

#if KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE
	return drm_prime_pages_to_sg(obj->dev, bo->pages, bo->base.size >> PAGE_SHIFT);
#else
	return drm_prime_pages_to_sg(bo->pages, bo->base.size >> PAGE_SHIFT);
#endif
}

struct drm_gem_object *evdi_prime_import_sg_table(struct drm_device *dev,
						   struct dma_buf_attachment *attach,
						   struct sg_table *sg)
{
	struct evdi_gem_object *obj;

	obj = evdi_gem_alloc_object(dev, attach->dmabuf->size);
	if (IS_ERR(obj))
		return ERR_CAST(obj);

	obj->sg = sg;
	return &obj->base;
}
