/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "dns_over_tls_plugin.h"
#include "dns_over_tls_resolver.h"

#include <daemon.h>

typedef struct private_dns_over_tls_plugin_t private_dns_over_tls_plugin_t;

struct private_dns_over_tls_plugin_t {
	dns_over_tls_plugin_t public;
	dns_over_tls_resolver_t *resolver;
};

METHOD(plugin_t, get_name, char*, private_dns_over_tls_plugin_t *this)
{
	return "dns-over-tls";
}

static bool plugin_cb(private_dns_over_tls_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		if (!lib->hosts->add_provider(lib->hosts, &this->resolver->provider))
		{
			return FALSE;
		}
		this->resolver->reload(this->resolver);
	}
	else
	{
		lib->hosts->remove_provider(lib->hosts, &this->resolver->provider);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int, private_dns_over_tls_plugin_t *this,
	plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "dns-over-tls"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, reload, bool, private_dns_over_tls_plugin_t *this)
{
	return this->resolver->reload(this->resolver);
}

METHOD(plugin_t, destroy, void, private_dns_over_tls_plugin_t *this)
{
	this->resolver->destroy(this->resolver);
	free(this);
}

PLUGIN_DEFINE(dns_over_tls)
{
	private_dns_over_tls_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.reload = _reload,
				.destroy = _destroy,
			},
		},
		.resolver = dns_over_tls_resolver_create(),
	);
	return &this->public.plugin;
}
