/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/**
 * @defgroup dns_over_tls_resolver dns_over_tls_resolver
 * @{ @ingroup dns_over_tls
 */

#ifndef DNS_OVER_TLS_RESOLVER_H_
#define DNS_OVER_TLS_RESOLVER_H_

#include <library.h>
#include <networking/host_resolver.h>

typedef struct dns_over_tls_resolver_t dns_over_tls_resolver_t;
typedef struct dns_over_tls_endpoint_t dns_over_tls_endpoint_t;

/** Parsed tls:// authentication-domain@IP-literal endpoint. */
struct dns_over_tls_endpoint_t {
	identification_t *identity;
	host_t *address;
};

/** DNS-over-TLS resolver provider. */
struct dns_over_tls_resolver_t {

	/** Implements the scheme-based host resolver provider interface. */
	host_resolver_provider_t provider;

	/** Reparse configuration and close the cached connection. */
	bool (*reload)(dns_over_tls_resolver_t *this);

	/** Destroy the resolver. */
	void (*destroy)(dns_over_tls_resolver_t *this);
};

/** Parse a strict DNS-over-TLS resolver URI. */
bool dns_over_tls_endpoint_parse(char *uri, dns_over_tls_endpoint_t *endpoint);

/** Release fields in a parsed endpoint. */
void dns_over_tls_endpoint_clear(dns_over_tls_endpoint_t *endpoint);

/** Create a DNS-over-TLS resolver provider. */
dns_over_tls_resolver_t *dns_over_tls_resolver_create();

#endif /** DNS_OVER_TLS_RESOLVER_H_ @}*/
