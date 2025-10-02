// SPDX-License-Identifier: GPL-2.0-only
/*
 * Encoder implementation for virtual display
 */

#include "evdi_drv.h"

static void evdi_encoder_atomic_enable(struct drm_encoder *encoder,
					   struct drm_atomic_state *state)
{
}

static void evdi_encoder_atomic_disable(struct drm_encoder *encoder,
					struct drm_atomic_state *state)
{
}

#if EVDI_HAVE_ATOMIC_HELPERS
static const struct drm_encoder_helper_funcs evdi_encoder_helper_funcs = {
	.atomic_enable = evdi_encoder_atomic_enable,
	.atomic_disable = evdi_encoder_atomic_disable,
};
#else
static const struct drm_encoder_helper_funcs evdi_encoder_helper_funcs = {
	.dpms = NULL,
};
#endif

static const struct drm_encoder_funcs evdi_encoder_funcs = {
	.destroy = drm_encoder_cleanup,
};

int evdi_encoder_init(struct drm_device *dev, struct evdi_device *evdi)
{
	struct drm_encoder *encoder;
	int ret;

	encoder = kzalloc(sizeof(*encoder), GFP_KERNEL);
	if (!encoder)
		return -ENOMEM;

	ret = drm_encoder_init(dev, encoder, &evdi_encoder_funcs,
			  DRM_MODE_ENCODER_VIRTUAL, NULL);
	if (ret) {
		evdi_err("Failed to initialize encoder: %d", ret);
		kfree(encoder);
		return ret;
	}

	encoder->possible_crtcs = 1;

	drm_encoder_helper_add(encoder, &evdi_encoder_helper_funcs);

	evdi->encoder = encoder;

	evdi_debug("Encoder initialized for device %d", evdi->dev_index);
	return 0;
}

void evdi_encoder_cleanup(struct evdi_device *evdi)
{
	if (evdi->encoder) {
		drm_encoder_cleanup(evdi->encoder);
		kfree(evdi->encoder);
		evdi->encoder = NULL;
	}
	evdi_debug("Encoder cleaned up for device %d", evdi->dev_index);
}
