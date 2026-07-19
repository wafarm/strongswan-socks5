/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/**
 * @defgroup dns_over_tls dns_over_tls
 * @ingroup cplugins
 *
 * DNS-over-TLS resolver provider for IKE gateway hostnames.
 *
 * @defgroup dns_over_tls_plugin dns_over_tls_plugin
 * @{ @ingroup dns_over_tls
 */

#ifndef DNS_OVER_TLS_PLUGIN_H_
#define DNS_OVER_TLS_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct dns_over_tls_plugin_t dns_over_tls_plugin_t;

struct dns_over_tls_plugin_t {
	plugin_t plugin;
};

#endif /** DNS_OVER_TLS_PLUGIN_H_ @}*/
