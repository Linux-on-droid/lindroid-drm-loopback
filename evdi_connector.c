// SPDX-License-Identifier: GPL-2.0-only
/*
 * Virtual connector implementation
 */

#include "evdi_drv.h"
#include <drm/drm_modes.h>

static enum drm_connector_status
evdi_connector_detect(struct drm_connector *connector, bool force)
{
	struct evdi_device *evdi = connector->dev->dev_private;

	return evdi_likely_connected(evdi) ?
	   connector_status_connected :
	   connector_status_disconnected;
}

static int evdi_connector_get_modes(struct drm_connector *connector)
{
	struct evdi_device *evdi = connector->dev->dev_private;
	struct drm_display_mode *mode;

	if (!evdi_likely_connected(evdi))
	return 0;

	mode = drm_mode_create(connector->dev);
	if (!mode)
		return 0;

	mode->hdisplay = evdi->width;
	mode->vdisplay = evdi->height;

	mode->clock = evdi->width * evdi->height * evdi->refresh_rate / 1000;

	mode->hsync_start = mode->hdisplay + 8;
	mode->hsync_end = mode->hsync_start + 8;
	mode->htotal = mode->hsync_end + 8;

	mode->vsync_start = mode->vdisplay + 1;
	mode->vsync_end = mode->vsync_start + 1;
	mode->vtotal = mode->vsync_end + 1;

	mode->type = DRM_MODE_TYPE_PREFERRED | DRM_MODE_TYPE_DRIVER;

	drm_mode_set_name(mode);
	drm_mode_probed_add(connector, mode);

	evdi_debug("Created mode %ux%u@%uHz for device %d",
		  evdi->width, evdi->height, evdi->refresh_rate, evdi->dev_index);

	return 1;
}

static enum drm_mode_status
evdi_connector_mode_valid(struct drm_connector *connector,
			 struct drm_display_mode *mode)
{
	int vrefresh = drm_mode_vrefresh(mode);
	if (mode->hdisplay < 640 || mode->hdisplay > 8192)
		return MODE_BAD_HVALUE;

	if (mode->vdisplay < 480 || mode->vdisplay > 8192)
		return MODE_BAD_VVALUE;

	if (vrefresh < 30 || vrefresh > 240)
		return MODE_BAD;

	return MODE_OK;
}

static const struct drm_connector_helper_funcs evdi_connector_helper_funcs = {
	.get_modes = evdi_connector_get_modes,
	.mode_valid = evdi_connector_mode_valid,
};

#if EVDI_HAVE_ATOMIC_HELPERS
static const struct drm_connector_funcs evdi_connector_funcs = {
	.detect = evdi_connector_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = drm_connector_cleanup,
	.reset = drm_atomic_helper_connector_reset,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};
#else
static const struct drm_connector_funcs evdi_connector_funcs = {
	.detect = evdi_connector_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = drm_connector_cleanup,
};
#endif

int evdi_connector_init(struct drm_device *dev, struct evdi_device *evdi)
{
	struct drm_connector *connector;
	int ret;

	connector = kzalloc(sizeof(*connector), GFP_KERNEL);
	if (!connector)
		return -ENOMEM;

#if EVDI_HAVE_CONNECTOR_INIT_WITH_DDC
	ret = drm_connector_init_with_ddc(dev, connector, &evdi_connector_funcs,
					 DRM_MODE_CONNECTOR_VIRTUAL, NULL);
#else
	ret = drm_connector_init(dev, connector, &evdi_connector_funcs,
			   DRM_MODE_CONNECTOR_VIRTUAL);
#endif
	if (ret) {
		evdi_err("Failed to initialize connector: %d", ret);
		kfree(connector);
		return ret;
	}

	connector->interlace_allowed = false;
	connector->doublescan_allowed = false;

	drm_connector_helper_add(connector, &evdi_connector_helper_funcs);

	evdi->connector = connector;

	evdi_debug("Connector initialized for device %d", evdi->dev_index);
	return 0;
}

void evdi_connector_cleanup(struct evdi_device *evdi)
{
	if (evdi->connector) {
		drm_connector_cleanup(evdi->connector);
		kfree(evdi->connector);
		evdi->connector = NULL;
	}

	evdi_debug("Connector cleaned up for device %d", evdi->dev_index);
}
