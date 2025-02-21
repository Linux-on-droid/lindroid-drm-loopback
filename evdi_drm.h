/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 *
 * Copyright (c) 2015 - 2020 DisplayLink (UK) Ltd.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License v2. See the file COPYING in the main directory of this archive for
 * more details.
 */

#ifndef __UAPI_EVDI_DRM_H__
#define __UAPI_EVDI_DRM_H__

#ifdef __KERNEL__
#include <linux/types.h>
#include <drm/drm.h>
#else
#include <stdint.h>
#endif

/* Output events sent from driver to evdi lib */
#define DRM_EVDI_EVENT_UPDATE_READY  0x80000000
#define DRM_EVDI_EVENT_DPMS          0x80000001
#define DRM_EVDI_EVENT_MODE_CHANGED  0x80000002
#define DRM_EVDI_EVENT_CRTC_STATE    0x80000003
#define DRM_EVDI_EVENT_CURSOR_SET    0x80000004
#define DRM_EVDI_EVENT_CURSOR_MOVE   0x80000005

enum poll_event_type {
  none,
  add_buf,
  swap_to
};

struct drm_evdi_event_update_ready {
	struct drm_event base;
};

struct drm_evdi_event_dpms {
	struct drm_event base;
	int32_t mode;
};

struct drm_evdi_event_mode_changed {
	struct drm_event base;
	int32_t hdisplay;
	int32_t vdisplay;
	int32_t vrefresh;
	int32_t bits_per_pixel;
	uint32_t pixel_format;
};

struct drm_evdi_event_crtc_state {
	struct drm_event base;
	int32_t state;
};

struct drm_evdi_connect {
	int32_t connected;
	int32_t dev_index;
	uint32_t width;
	uint32_t height;
	uint32_t refresh_rate;
};

struct drm_evdi_request_update {
	int32_t reserved;
};

enum drm_evdi_grabpix_mode {
	EVDI_GRABPIX_MODE_RECTS = 0,
	EVDI_GRABPIX_MODE_DIRTY = 1,
};

struct drm_evdi_grabpix {
	enum drm_evdi_grabpix_mode mode;
	int32_t buf_width;
	int32_t buf_height;
	int32_t buf_byte_stride;
	unsigned char __user *buffer;
	int32_t num_rects;
	struct drm_clip_rect __user *rects;
};

struct drm_evdi_event_cursor_set {
	struct drm_event base;
	int32_t hot_x;
	int32_t hot_y;
	uint32_t width;
	uint32_t height;
	uint8_t enabled;
	uint32_t buffer_handle;
	uint32_t buffer_length;
	uint32_t pixel_format;
	uint32_t stride;
};

struct drm_evdi_event_cursor_move {
	struct drm_event base;
	int32_t x;
	int32_t y;
};

struct drm_evdi_enable_cursor_events {
	struct drm_event base;
	uint8_t enable;
};

struct drm_evdi_poll {
	enum poll_event_type event;
	int poll_id;
	void *data;
};

struct drm_evdi_add_buff_callabck {
	int poll_id;
	int buff_id;
};

struct drm_evdi_swap_callabck {
	int poll_id;
};

/* Input ioctls from evdi lib to driver */
#define DRM_EVDI_CONNECT          0x00
#define DRM_EVDI_REQUEST_UPDATE   0x01
#define DRM_EVDI_GRABPIX          0x02
#define DRM_EVDI_ENABLE_CURSOR_EVENTS 0x04
#define DRM_EVDI_POLL 0x05
#define DRM_EVDI_ADD_BUFF_CALLBACK 0x06
#define DRM_EVDI_SWAP_CALLBACK 0x07
/* LAST_IOCTL 0x5F -- 96 driver specific ioctls to use */

#define DRM_IOCTL_EVDI_CONNECT DRM_IOWR(DRM_COMMAND_BASE +  \
	DRM_EVDI_CONNECT, struct drm_evdi_connect)
#define DRM_IOCTL_EVDI_REQUEST_UPDATE DRM_IOWR(DRM_COMMAND_BASE +  \
	DRM_EVDI_REQUEST_UPDATE, struct drm_evdi_request_update)
#define DRM_IOCTL_EVDI_GRABPIX DRM_IOWR(DRM_COMMAND_BASE +  \
	DRM_EVDI_GRABPIX, struct drm_evdi_grabpix)
#define DRM_IOCTL_EVDI_ENABLE_CURSOR_EVENTS DRM_IOWR(DRM_COMMAND_BASE +  \
	DRM_EVDI_ENABLE_CURSOR_EVENTS, struct drm_evdi_enable_cursor_events)
#define DRM_IOCTL_EVDI_POLL DRM_IOWR(DRM_COMMAND_BASE +  \
	DRM_EVDI_POLL, struct drm_evdi_poll)
#define DRM_IOCTL_EVDI_ADD_BUFF_CALLBACK DRM_IOWR(DRM_COMMAND_BASE +  \
	DRM_EVDI_ADD_BUFF_CALLBACK, struct drm_evdi_add_buff_callabck)
#define DRM_IOCTL_EVDI_SWAP_CALLBACK DRM_IOWR(DRM_COMMAND_BASE +  \
	DRM_EVDI_SWAP_CALLBACK, struct drm_evdi_swap_callabck)

#endif /* __EVDI_UAPI_DRM_H__ */
