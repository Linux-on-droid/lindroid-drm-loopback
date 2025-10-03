// SPDX-License-Identifier: GPL-2.0-only
/*
 * Modeset implementation
 */

#include "evdi_drv.h"
#include <drm/drm_gem_framebuffer_helper.h>

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
}

static void evdi_pipe_disable(struct drm_simple_display_pipe *pipe)
{
}

static const struct drm_simple_display_pipe_funcs evdi_pipe_funcs = {
	.enable		= evdi_pipe_enable,
	.disable	= evdi_pipe_disable,
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
