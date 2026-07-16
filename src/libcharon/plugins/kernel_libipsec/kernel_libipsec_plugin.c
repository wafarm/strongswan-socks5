/*
 * Copyright (C) 2012-2026 Tobias Brunner
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "kernel_libipsec_plugin.h"
#include "kernel_libipsec_ipsec.h"
#include "kernel_libipsec_router.h"
#include "kernel_libipsec_esp_handler.h"
#include "kernel_libipsec_tun.h"
#ifdef USE_KERNEL_LIBIPSEC_SOCKS
#include "kernel_libipsec_socks.h"
#endif

#include <daemon.h>
#include <ipsec.h>
#include <networking/tun_device.h>

#define TUN_DEFAULT_MTU 1400

typedef struct private_kernel_libipsec_plugin_t private_kernel_libipsec_plugin_t;

struct private_kernel_libipsec_plugin_t {
	kernel_libipsec_plugin_t public;
	tun_device_t *tun;
	kernel_libipsec_router_t *router;
	kernel_libipsec_esp_handler_t *esp_handler;
	bool socks5;
};

METHOD(plugin_t, get_name, char*,
	private_kernel_libipsec_plugin_t *this)
{
	return "kernel-libipsec";
}

static bool create_router(private_kernel_libipsec_plugin_t *this,
						  plugin_feature_t *feature, bool reg, void *arg)
{
	if (reg)
	{
		kernel_libipsec_plain_t *plain = NULL;

		if (this->socks5)
		{
#ifdef USE_KERNEL_LIBIPSEC_SOCKS
			plain = kernel_libipsec_socks_create();
#endif
		}
		else
		{
			plain = kernel_libipsec_tun_create();
		}
		this->router = kernel_libipsec_router_create(plain);
		if (!this->router)
		{
			DESTROY_IF(plain);
			return FALSE;
		}
	}
	else
	{
		DESTROY_IF(this->router);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_kernel_libipsec_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(kernel_ipsec_register, kernel_libipsec_ipsec_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
		PLUGIN_CALLBACK((plugin_feature_callback_t)create_router, NULL),
			PLUGIN_PROVIDE(CUSTOM, "kernel-libipsec-router"),
				PLUGIN_DEPENDS(CUSTOM, "libcharon-receiver"),
#ifdef USE_KERNEL_LIBIPSEC_SOCKS
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
#endif
	};

	*features = f;
#ifdef USE_KERNEL_LIBIPSEC_SOCKS
	/* Keep the existing TUN backend independent of a strong RNG provider. */
	return countof(f) - (this->socks5 ? 0 : 1);
#else
	return countof(f);
#endif
}

METHOD(plugin_t, destroy, void,
	private_kernel_libipsec_plugin_t *this)
{
	if (this->tun)
	{
		lib->set(lib, "kernel-libipsec-tun", NULL);
		this->tun->destroy(this->tun);
	}
	if (this->esp_handler)
	{
		lib->set(lib, "kernel-libipsec-esp-handler", NULL);
		this->esp_handler->destroy(this->esp_handler);
	}
	libipsec_deinit();
	free(this);
}

PLUGIN_DEFINE(kernel_libipsec)
{
	private_kernel_libipsec_plugin_t *this;
	char *data_plane;
	bool socks5;

	data_plane = lib->settings->get_str(lib->settings,
						"%s.plugins.kernel-libipsec.data_plane", "tun", lib->ns);
	if (streq(data_plane, "tun"))
	{
		socks5 = FALSE;
	}
	else if (streq(data_plane, "socks5"))
	{
#ifdef USE_KERNEL_LIBIPSEC_SOCKS
		socks5 = TRUE;
#else
		DBG1(DBG_KNL, "kernel-libipsec SOCKS5 data plane was not enabled "
			 "at build time");
		return NULL;
#endif
	}
	else
	{
		DBG1(DBG_KNL, "unknown kernel-libipsec data plane '%s'", data_plane);
		return NULL;
	}

	if (socks5 &&
		(lib->settings->get_bool(lib->settings, "%s.install_routes", TRUE,
								lib->ns) ||
		 lib->settings->get_bool(lib->settings, "%s.install_virtual_ip", TRUE,
								lib->ns)))
	{
		DBG1(DBG_KNL, "kernel-libipsec SOCKS5 data plane requires "
			 "install_routes=no and install_virtual_ip=no");
		return NULL;
	}

	if (!socks5 && !lib->caps->check(lib->caps, CAP_NET_ADMIN))
	{
		DBG1(DBG_KNL, "kernel-libipsec TUN data plane requires CAP_NET_ADMIN "
			 "capability");
		return NULL;
	}

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
		.socks5 = socks5,
	);

	if (!libipsec_init())
	{
		DBG1(DBG_LIB, "initialization of libipsec failed");
		destroy(this);
		return NULL;
	}

	if (!socks5)
	{
		this->tun = tun_device_create("ipsec%d");
		if (!this->tun)
		{
			DBG1(DBG_KNL, "failed to create TUN device");
			destroy(this);
			return NULL;
		}
		if (!this->tun->set_mtu(this->tun, TUN_DEFAULT_MTU) ||
			!this->tun->up(this->tun))
		{
			DBG1(DBG_KNL, "failed to configure TUN device");
			destroy(this);
			return NULL;
		}
		lib->set(lib, "kernel-libipsec-tun", this->tun);

		/* Set the default TUN device used to install virtual IPs. */
		lib->settings->set_str(lib->settings, "%s.install_virtual_ip_on",
							   this->tun->get_name(this->tun), lib->ns);
	}

	if (lib->settings->get_bool(lib->settings,
					"%s.plugins.kernel-libipsec.raw_esp", FALSE, lib->ns))
	{
		this->esp_handler = kernel_libipsec_esp_handler_create();
		if (!this->esp_handler)
		{
			DBG1(DBG_KNL, "only UDP-encapsulated ESP packets supported by "
				 "kernel-libipsec on this platform");
		}
		lib->set(lib, "kernel-libipsec-esp-handler", this->esp_handler);
	}
	return &this->public.plugin;
}
