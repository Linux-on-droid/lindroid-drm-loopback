// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Red Hat
 * Copyright (c) 2015 - 2020 DisplayLink (UK) Ltd.
 * Copyright (c) 2025 Lindroid Authors
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License v2. See the file COPYING in the main directory of this archive for
 * more details.
 */

#include "evdi_drv.h"
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_atomic_helper.h>

static const struct drm_mode_config_funcs evdi_mode_config_funcs = {
#if EVDI_HAVE_ATOMIC_HELPERS
	.fb_create	= evdi_fb_user_fb_create,
	.atomic_check	= drm_atomic_helper_check,
	.atomic_commit	= drm_atomic_helper_commit,
#else
	.fb_create	= evdi_fb_user_fb_create,
#endif
};

static const uint32_t evdi_formats[] = {
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_ARGB8888,
};

static void evdi_pipe_enable(struct drm_simple_display_pipe *pipe,
			     struct drm_crtc_state *crtc_state,
			     struct drm_plane_state *plane_state)
{
	drm_crtc_vblank_on(&pipe->crtc);
}

static void evdi_pipe_disable(struct drm_simple_display_pipe *pipe)
{
	drm_crtc_vblank_off(&pipe->crtc);
}

static void evdi_pipe_update(struct drm_simple_display_pipe *pipe,
			     struct drm_plane_state *old_state)
{
	struct drm_plane_state *state = pipe->plane.state;
	struct evdi_device *evdi = pipe->plane.dev->dev_private;
	struct drm_framebuffer *fb = state ? state->fb : NULL;
	struct drm_pending_vblank_event *vblank_ev;
	struct drm_device *ddev;
	struct evdi_framebuffer *efb;
	unsigned long flags;

	drm_crtc_handle_vblank(&pipe->crtc);

	if (pipe->crtc.state && pipe->crtc.state->event) {
		ddev = pipe->crtc.dev;
		vblank_ev = pipe->crtc.state->event;
		pipe->crtc.state->event = NULL;
		spin_lock_irqsave(&ddev->event_lock, flags);
		drm_crtc_send_vblank_event(&pipe->crtc, vblank_ev);
		spin_unlock_irqrestore(&ddev->event_lock, flags);
	}

	if (!fb)
		return;

	efb = to_evdi_fb(fb);

	if (efb && efb->owner && efb->gralloc_buf_id)
		evdi_queue_swap_event(evdi,
				      efb->gralloc_buf_id,
				      evdi_connector_slot(evdi, pipe->connector),
				      efb->owner);

	if (unlikely(!READ_ONCE(evdi->drm_client)))
		return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
static void evdi_pipe_enable_compat(struct drm_simple_display_pipe *pipe,
				    struct drm_crtc_state *crtc_state)
{
	evdi_pipe_enable(pipe, crtc_state, NULL);
}
#endif

static const struct drm_simple_display_pipe_funcs evdi_pipe_funcs = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
	.enable 	= evdi_pipe_enable_compat,
#else
	.enable		= evdi_pipe_enable,
#endif
	.disable	= evdi_pipe_disable,
	.update		= evdi_pipe_update,
};

int evdi_modeset_init(struct drm_device *dev)
{
	struct evdi_device *evdi = dev->dev_private;
	int ret = 0;
	int i;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	ret = drm_mode_config_init(dev);
	if (ret) {
		evdi_err("Failed to initialize mode config: %d", ret);
		return ret;
	}
#else
	drm_mode_config_init(dev);
#endif

	dev->mode_config.min_width = 640;
	dev->mode_config.min_height = 480;
	dev->mode_config.max_width = 8192;
	dev->mode_config.max_height = 8192;

	dev->mode_config.preferred_depth = 24;
	dev->mode_config.prefer_shadow = 1;

	dev->mode_config.funcs = &evdi_mode_config_funcs;

	ret = evdi_connector_init(dev, evdi);
	if (ret) {
		evdi_err("Failed to initialize connector: %d", ret);
		goto err_connector;
	}
	for (i = 0; i < LINDROID_MAX_CONNECTORS; i++) {
		ret = drm_simple_display_pipe_init(dev, &evdi->pipe[i], &evdi_pipe_funcs,
						   evdi_formats, ARRAY_SIZE(evdi_formats),
						   NULL, evdi->connector[i]);
		if (ret) {
			evdi_err("Failed to initialize simple display pipe[%d]: %d", i, ret);
			goto err_pipe;
		}
	}

	evdi_info("Modeset initialized for device %d", evdi->dev_index);
	return 0;

err_pipe:
	evdi_connector_cleanup(evdi);
err_connector:
	drm_mode_config_cleanup(dev);
	return ret;
}

void evdi_modeset_cleanup(struct drm_device *dev)
{
	struct evdi_device *evdi = dev->dev_private;

	evdi_connector_cleanup(evdi);

	drm_mode_config_cleanup(dev);

	evdi_debug("Modeset cleaned up for device %d", evdi->dev_index);
}
