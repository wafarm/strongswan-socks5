/*
 * Copyright (C) 2012 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup host_resolver host_resolver
 * @{ @ingroup networking
 */

#ifndef HOST_RESOLVER_H_
#define HOST_RESOLVER_H_

#include "host.h"

typedef struct host_resolver_t host_resolver_t;
typedef struct host_resolver_provider_t host_resolver_provider_t;

/**
 * Resolver provider for URI schemes.
 *
 * Providers are called by one of the resolver's worker threads.  A provider
 * has to remain valid until it is removed from the resolver.
 */
struct host_resolver_provider_t {

	/** URI scheme handled by this provider (without ://). */
	char *scheme;

	/**
	 * Resolve a host using the supplied resolver URI.
	 *
	 * @param uri		complete resolver URI
	 * @param name		name to lookup
	 * @param family	requested address family
	 * @return			resolved host or NULL if the lookup failed
	 */
	host_t *(*resolve)(host_resolver_provider_t *this, char *uri, char *name,
					   int family);
};

/**
 * Resolve hosts by DNS name but do so in a separate thread (calling
 * getaddrinfo(3) directly might block indefinitely, or at least a very long
 * time if no DNS servers are reachable).
 */
struct host_resolver_t {

	/**
	 * Resolve host from the given DNS name.
	 *
	 * @param name		name to lookup
	 * @param family	requested address family
	 * @return			resolved host or NULL if failed or canceled
	 */
	host_t *(*resolve)(host_resolver_t *this, char *name, int family);

	/**
	 * Resolve a host using a provider selected by the resolver URI scheme.
	 *
	 * This never falls back to the system resolver if the URI is invalid, no
	 * provider is registered, or the provider fails.
	 *
	 * @param uri		resolver URI
	 * @param name		name to lookup
	 * @param family	requested address family
	 * @return			resolved host or NULL if failed or canceled
	 */
	host_t *(*resolve_with_uri)(host_resolver_t *this, char *uri, char *name,
							int family);

	/**
	 * Register a scheme-based resolver provider.
	 *
	 * @param provider	provider to register
	 * @return			TRUE if registered, FALSE if invalid/already registered
	 */
	bool (*add_provider)(host_resolver_t *this,
						 host_resolver_provider_t *provider);

	/**
	 * Remove a resolver provider.
	 *
	 * This call waits until all queued or active callbacks for the provider
	 * have completed.
	 *
	 * @param provider	provider to remove
	 */
	void (*remove_provider)(host_resolver_t *this,
						  host_resolver_provider_t *provider);

	/**
	 * Flush the queue of queries. No new queries will be accepted afterwards.
	 */
	void (*flush)(host_resolver_t *this);

	/**
	 * Destroy a host_resolver_t.
	 */
	void (*destroy)(host_resolver_t *this);
};

/**
 * Create a host_resolver_t instance.
 */
host_resolver_t *host_resolver_create();

#endif /** HOST_RESOLVER_H_ @}*/
