// SPDX-License-Identifier: GPL-2.0-only
/*
 * Modeset implementation
 */

#include "evdi_drv.h"

int evdi_modeset_init(struct drm_device *dev)
{
	struct evdi_device *evdi = dev->dev_private;
	int ret;

#ifdef EVDI_HAVE_DRM_MANAGED
	ret = drmm_mode_config_init(dev);
#else
	ret = drm_mode_config_init(dev);
#endif
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

#if EVDI_HAVE_ATOMIC_HELPERS
	dev->mode_config.funcs = &(const struct drm_mode_config_funcs) {
		.fb_create = NULL,
		.atomic_check = drm_atomic_helper_check,
		.atomic_commit = drm_atomic_helper_commit,
	};
#else
	dev->mode_config.funcs = &(const struct drm_mode_config_funcs) {
		.fb_create = NULL,  /* Not needed for create-disp */
	};
#endif

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

	ret = evdi_crtc_init(dev, evdi);
	if (ret) {
		evdi_err("Failed to initialize CRTC: %d", ret);
		goto err_crtc;
	}

	drm_connector_attach_encoder(evdi->connector, evdi->encoder);

	evdi_info("Modeset initialized for device %d", evdi->dev_index);
	return 0;

err_crtc:
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

	evdi_connector_cleanup(evdi);
	evdi_encoder_cleanup(evdi);

	drm_mode_config_cleanup(dev);

	evdi_debug("Modeset cleaned up for device %d", evdi->dev_index);
}

static void evdi_crtc_atomic_enable(struct drm_crtc *crtc,
				   struct drm_atomic_state *state)
{
}

static void evdi_crtc_atomic_disable(struct drm_crtc *crtc,
					struct drm_atomic_state *state)
{
}

#if EVDI_HAVE_ATOMIC_HELPERS
static const struct drm_crtc_helper_funcs evdi_crtc_helper_funcs = {
	.atomic_enable = evdi_crtc_atomic_enable,
	.atomic_disable = evdi_crtc_atomic_disable,
};

static const struct drm_crtc_funcs evdi_crtc_funcs = {
	.set_config = drm_atomic_helper_set_config,
	.page_flip = drm_atomic_helper_page_flip,
	.destroy = drm_crtc_cleanup,
	.reset = drm_atomic_helper_crtc_reset,
	.atomic_duplicate_state = drm_atomic_helper_crtc_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_crtc_destroy_state,
};
#else
static const struct drm_crtc_helper_funcs evdi_crtc_helper_funcs = {
};

static const struct drm_crtc_funcs evdi_crtc_funcs = {
	.destroy = drm_crtc_cleanup,
};
#endif

int evdi_crtc_init(struct drm_device *dev, struct evdi_device *evdi)
{
	struct drm_crtc *crtc;
	int ret;

	crtc = kzalloc(sizeof(*crtc), GFP_KERNEL);
	if (!crtc)
		return -ENOMEM;

#if EVDI_HAVE_ATOMIC_HELPERS
	ret = drm_crtc_init_with_planes(dev, crtc, NULL, NULL,
				   &evdi_crtc_funcs, NULL);
#else
	ret = drm_crtc_init(dev, crtc, &evdi_crtc_funcs);
#endif
	if (ret) {
		evdi_err("Failed to initialize CRTC: %d", ret);
		kfree(crtc);
		return ret;
	}

	drm_crtc_helper_add(crtc, &evdi_crtc_helper_funcs);

	evdi->crtc = crtc;

	evdi_debug("CRTC initialized for device %d", evdi->dev_index);
	return 0;
}
