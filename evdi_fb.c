// SPDX-License-Identifier: GPL-2.0-only
/*
 * EVDI minimal framebuffer wrapper for fake dma-bufs
 */

#include "evdi_drv.h"
#include <drm/drm_file.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_gem.h>
#include <linux/overflow.h>

static inline void evdi_gem_object_put_local(struct drm_gem_object *obj)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	drm_gem_object_put(obj);
#else
	drm_gem_object_put_unlocked(obj);
#endif
}

static void evdi_fb_destroy(struct drm_framebuffer *fb)
{
	struct evdi_framebuffer *efb = to_evdi_fb(fb);

	if (efb->obj)
		evdi_gem_object_put_local(&efb->obj->base);

	drm_framebuffer_cleanup(fb);

	kfree(efb);
}

static int evdi_fb_create_handle(struct drm_framebuffer *fb,
				 struct drm_file *file,
				 unsigned int *handle)
{
	struct evdi_framebuffer *efb = to_evdi_fb(fb);
	if (!efb->obj)
		return -EINVAL;
	return drm_gem_handle_create(file, &efb->obj->base, handle);
}

const struct drm_framebuffer_funcs evdifb_funcs = {
	.destroy	= evdi_fb_destroy,
	.create_handle	= evdi_fb_create_handle,
};

static unsigned int evdi_fb_cpp(u32 format)
{
	const struct drm_format_info *info = drm_format_info(format);
	if (!info || info->num_planes != 1)
		return 0;

	return info->cpp[0];
}

static int evdi_fb_calc_size(const struct drm_mode_fb_cmd2 *mode_cmd,
			     u32 *out_pitch, size_t *out_size)
{
	const struct drm_format_info *info = drm_format_info(mode_cmd->pixel_format);
	u32 pitch, cpp;
	size_t last_lines, total, tail;

	if (!info || info->num_planes != 1)
		return -EINVAL;

	cpp = info->cpp[0];
	if (!cpp)
		return -EINVAL;

	if (!mode_cmd->width || !mode_cmd->height)
		return -EINVAL;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0))
	if (mode_cmd->modifier[0] && mode_cmd->modifier[0] != DRM_FORMAT_MOD_LINEAR)
		return -EINVAL;
#endif

	if (mode_cmd->pitches[0]) {
		pitch = mode_cmd->pitches[0];
		if (pitch < mode_cmd->width * cpp)
			return -EINVAL;
	} else {
		pitch = mode_cmd->width * cpp;
	}

	if (mode_cmd->height == 0)
		return -EINVAL;

	if (check_mul_overflow((size_t)(mode_cmd->height - 1), (size_t)pitch, &last_lines))
		return -EOVERFLOW;

	tail = (size_t)mode_cmd->width * cpp;
	if (check_add_overflow((size_t)mode_cmd->offsets[0], last_lines, &total))
		return -EOVERFLOW;

	if (check_add_overflow(total, tail, &total))
		return -EOVERFLOW;

	*out_pitch = pitch;
	*out_size = total;
	return 0;
}

static int evdi_fb_extract_gralloc_id(const struct drm_mode_fb_cmd2 *mode_cmd)
{
#if (KERNEL_VERSION(4, 15, 0) <= LINUX_VERSION_CODE)
	if (mode_cmd->modifier[0])
		return (int)(mode_cmd->modifier[0] & 0x7fffffff);
#endif
	if (mode_cmd->handles[0] > 0xFFFF)
		return (int)mode_cmd->handles[0];

	return 0;
}

static struct evdi_gem_object *evdi_fb_acquire_bo(struct drm_device *dev,
						  struct drm_file *file,
						  const struct drm_mode_fb_cmd2 *mode_cmd)
{
	struct drm_gem_object *gem = NULL;
	size_t size;
	u32 validated_pitch;
	int ret;

	ret = evdi_fb_calc_size(mode_cmd, &validated_pitch, &size);
	if (ret)
		return NULL;

	gem = drm_gem_object_lookup(file, mode_cmd->handles[0]);
	if (gem)
		return to_evdi_bo(gem);

	return evdi_gem_alloc_object(dev, size);
}

static int evdi_fb_init_core(struct drm_device *dev,
			     struct evdi_framebuffer *efb,
			     const struct drm_mode_fb_cmd2 *mode_cmd)
{
	struct drm_framebuffer *fb = &efb->base;
	const struct drm_format_info *info = drm_format_info(mode_cmd->pixel_format);
	int ret;

	if (!info)
		return -EINVAL;

	fb->dev = dev;
	fb->format = info;
	fb->width  = mode_cmd->width;
	fb->height = mode_cmd->height;
	fb->pitches[0] = mode_cmd->pitches[0] ?
			 mode_cmd->pitches[0] :
			 evdi_fb_cpp(mode_cmd->pixel_format) * mode_cmd->width;
	fb->offsets[0] = mode_cmd->offsets[0];
#if defined(DRM_FORMAT_MOD_LINEAR) || (LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0))
	fb->modifier = mode_cmd->modifier[0];
#endif
	fb->flags = 0;
	fb->funcs = &evdifb_funcs;
	fb->obj[0] = &efb->obj->base;

	ret = drm_framebuffer_init(dev, fb, &evdifb_funcs);
	return ret;
}

struct drm_framebuffer *evdi_fb_user_fb_create(struct drm_device *dev,
					       struct drm_file *file,
					       const struct drm_mode_fb_cmd2 *mode_cmd)
{
	struct evdi_framebuffer *efb;
	struct evdi_gem_object *bo;
	int ret;

	bo = evdi_fb_acquire_bo(dev, file, mode_cmd);
	if (!bo)
		return ERR_PTR(-ENOENT);

	efb = kzalloc(sizeof(*efb), GFP_KERNEL);
	if (!efb) {
		evdi_gem_object_put_local(&bo->base);
		return ERR_PTR(-ENOMEM);
	}

	efb->obj = bo;
	efb->owner = file;
	efb->active = true;
	efb->gralloc_buf_id = evdi_fb_extract_gralloc_id(mode_cmd);

	ret = evdi_fb_init_core(dev, efb, mode_cmd);
	if (ret) {
		evdi_gem_object_put_local(&bo->base);
		kfree(efb);
		return ERR_PTR(ret);
	}
	return &efb->base;
}
