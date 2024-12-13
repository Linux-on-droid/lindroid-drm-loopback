# SPDX-License-Identifier: GPL-2.0-only
lindroid_drm-y := \
	vkms_drv.o \
	vkms_plane.o \
	vkms_output.o \
	vkms_formats.o \
	vkms_crtc.o \
	vkms_composer.o \
	vkms_writeback.o

CONFIG_DRM_LINDROID ?= m

obj-$(CONFIG_DRM_LINDROID) += lindroid_drm.o
