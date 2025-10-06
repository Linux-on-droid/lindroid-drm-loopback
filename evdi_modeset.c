// SPDX-License-Identifier: GPL-2.0-only
/*
 * Modeset implementation
 */

#include "evdi_drv.h"
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_atomic_helper.h>

static const struct drm_mode_config_funcs evdi_mode_config_funcs = {
#if EVDI_HAVE_ATOMIC_HELPERS
	.fb_create	= drm_gem_fb_create,
	.atomic_check	= drm_atomic_helper_check,
	.atomic_commit	= drm_atomic_helper_commit,
#else
	.fb_create	= drm_gem_fb_create,
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
	struct drm_framebuffer *old_fb = old_state ? old_state->fb : NULL;
	struct drm_framebuffer *new_fb = state ? state->fb : NULL;
	struct drm_pending_vblank_event *vblank_ev;
	struct drm_device *ddev;
	unsigned long flags;

	if (new_fb && new_fb != old_fb) {
		drm_crtc_handle_vblank(&pipe->crtc);
		if (pipe->crtc.state && pipe->crtc.state->event) {
			ddev = pipe->crtc.dev;
			vblank_ev = pipe->crtc.state->event;
			spin_lock_irqsave(&ddev->event_lock, flags);
			pipe->crtc.state->event = NULL;
			drm_crtc_send_vblank_event(&pipe->crtc, vblank_ev);
			spin_unlock_irqrestore(&ddev->event_lock, flags);
		}
		evdi_queue_swap_event(evdi, 0, NULL);
		if (atomic_xchg(&evdi->update_requested, 0)) {
			evdi_send_drm_update_ready_async(evdi);
		}
	}
}

static const struct drm_simple_display_pipe_funcs evdi_pipe_funcs = {
	.enable		= evdi_pipe_enable,
	.disable	= evdi_pipe_disable,
	.update		= evdi_pipe_update,
};

int evdi_modeset_init(struct drm_device *dev)
{
	struct evdi_device *evdi = dev->dev_private;
	int ret;

	ret = drm_mode_config_init(dev);
	if (ret) {
		evdi_err("Failed to initialize mode config: %d", ret);
		return ret;
	}

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

	ret = evdi_encoder_init(dev, evdi);
	if (ret) {
		evdi_err("Failed to initialize encoder: %d", ret);
		goto err_encoder;
	}

	drm_connector_attach_encoder(evdi->connector, evdi->encoder);
	ret = drm_simple_display_pipe_init(dev, &evdi->pipe, &evdi_pipe_funcs,
					   evdi_formats, ARRAY_SIZE(evdi_formats),
					   NULL, evdi->connector);
	if (ret) {
		evdi_err("Failed to initialize simple display pipe: %d", ret);
		goto err_pipe;
	}

	evdi_info("Modeset initialized for device %d", evdi->dev_index);
	return 0;

err_pipe:
	evdi_encoder_cleanup(evdi);
err_encoder:
	evdi_connector_cleanup(evdi);
err_connector:
	drm_mode_config_cleanup(dev);
	return ret;
}

void evdi_modeset_cleanup(struct drm_device *dev)
{
	struct evdi_device *evdi = dev->dev_private;

	evdi_encoder_cleanup(evdi);

	evdi_connector_cleanup(evdi);

	drm_mode_config_cleanup(dev);

	evdi_debug("Modeset cleaned up for device %d", evdi->dev_index);
}
