/*
 * Copyright (C) 2015 Tobias Brunner
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

#include "test_suite.h"

#include <library.h>
#include <config/ike_cfg.h>
#include <networking/host_resolver.h>

static void assert_family(int expected, char *addr, bool local)
{
	ike_cfg_create_t ike = {
		.version = IKEV2,
		.local = local ? addr : "%any",
		.local_port = 500,
		.remote = local ? "%any" : addr,
		.remote_port = 500,
	};
	ike_cfg_t *cfg;
	int family;

	cfg = ike_cfg_create(&ike);
	family = ike_cfg_get_family(cfg, local);
	ck_assert_msg(expected == family, "expected family %d != %d (addr: '%s')",
				  expected, family, addr);
	cfg->destroy(cfg);
}

START_TEST(test_get_address_family_empty)
{
	assert_family(AF_UNSPEC, "", _i);
}
END_TEST

typedef struct {
	host_resolver_provider_t provider;
	u_int calls;
	char last_name[64];
	int last_family;
} gateway_provider_t;

static host_t *resolve_gateway(host_resolver_provider_t *provider, char *uri,
							   char *name, int family)
{
	gateway_provider_t *this = (gateway_provider_t*)provider;

	this->calls++;
	snprintf(this->last_name, sizeof(this->last_name), "%s", name);
	this->last_family = family;
	if (streq(name, "first.invalid"))
	{
		return NULL;
	}
	return host_create_from_string("203.0.113.8", 0);
}

static ike_cfg_t *create_resolver_cfg(char *local, char *remote)
{
	ike_cfg_create_t ike = {
		.version = IKEV2,
		.local = local,
		.local_port = 500,
		.remote = remote,
		.remote_port = 4500,
	};

	return ike_cfg_create(&ike);
}

static void assert_host(host_t *host, char *address, uint16_t port)
{
	host_t *expected;

	ck_assert(host);
	expected = host_create_from_string(address, port);
	ck_assert(host->equals(host, expected));
	expected->destroy(expected);
	host->destroy(host);
}

START_TEST(test_gateway_resolver_scope)
{
	gateway_provider_t provider = {
		.provider = {
			.scheme = "test-gateway",
			.resolve = resolve_gateway,
		},
	};
	ike_cfg_t *cfg;
	host_t *host;
	char *previous, *saved = NULL;

	previous = lib->settings->get_str(lib->settings,
									 "%s.host_resolver.dot_server", NULL, lib->ns);
	if (previous)
	{
		saved = strdup(previous);
	}
	ck_assert(lib->hosts->add_provider(lib->hosts, &provider.provider));
	lib->settings->set_str(lib->settings, "%s.host_resolver.dot_server",
							  "test-gateway://resolver", lib->ns);

	/* Remote gateway names use the configured provider. */
	cfg = create_resolver_cfg("localhost", "gateway.invalid");
	assert_host(cfg->resolve_other(cfg, AF_INET), "203.0.113.8", 4500);
	ck_assert_int_eq(provider.calls, 1);
	ck_assert_str_eq(provider.last_name, "gateway.invalid");
	ck_assert_int_eq(provider.last_family, AF_INET);

	/* Local hostname resolution keeps using the system resolver. */
	host = cfg->resolve_me(cfg, AF_INET);
	ck_assert(host);
	host->destroy(host);
	ck_assert_int_eq(provider.calls, 1);
	cfg->destroy(cfg);

	/* Numeric gateways bypass the provider. */
	cfg = create_resolver_cfg("%any", "198.51.100.20");
	assert_host(cfg->resolve_other(cfg, AF_INET), "198.51.100.20", 4500);
	ck_assert_int_eq(provider.calls, 1);
	cfg->destroy(cfg);

	/* Each hostname in the fallback list is attempted via the provider. */
	cfg = create_resolver_cfg("%any", "first.invalid,second.invalid");
	assert_host(cfg->resolve_other(cfg, AF_INET), "203.0.113.8", 4500);
	ck_assert_int_eq(provider.calls, 3);
	cfg->destroy(cfg);

	/* An explicitly configured numeric fallback remains usable. */
	cfg = create_resolver_cfg("%any", "first.invalid,198.51.100.21");
	assert_host(cfg->resolve_other(cfg, AF_INET), "198.51.100.21", 4500);
	ck_assert_int_eq(provider.calls, 4);
	cfg->destroy(cfg);

	/* A missing provider fails closed even for an OS-resolvable hostname. */
	lib->hosts->remove_provider(lib->hosts, &provider.provider);
	cfg = create_resolver_cfg("%any", "localhost");
	ck_assert(!cfg->resolve_other(cfg, AF_INET));
	cfg->destroy(cfg);

	/* Unset and empty settings retain the existing system resolver behavior. */
	lib->settings->set_str(lib->settings, "%s.host_resolver.dot_server", NULL,
							  lib->ns);
	cfg = create_resolver_cfg("%any", "localhost");
	host = cfg->resolve_other(cfg, AF_INET);
	ck_assert(host);
	host->destroy(host);
	cfg->destroy(cfg);
	lib->settings->set_str(lib->settings, "%s.host_resolver.dot_server", "",
							  lib->ns);
	cfg = create_resolver_cfg("%any", "localhost");
	host = cfg->resolve_other(cfg, AF_INET);
	ck_assert(host);
	host->destroy(host);
	cfg->destroy(cfg);

	lib->settings->set_str(lib->settings, "%s.host_resolver.dot_server", saved,
							  lib->ns);
	free(saved);
}
END_TEST

START_TEST(test_get_address_family_addr)
{
	assert_family(AF_INET, "192.168.1.1", _i);
	assert_family(AF_INET6, "fec::1", _i);
}
END_TEST

START_TEST(test_get_address_family_multi)
{
	assert_family(AF_INET, "192.168.1.1,192.168.2.2", _i);
	assert_family(AF_INET6, "fec::1,fec::2", _i);

	assert_family(AF_UNSPEC, "192.168.1.1,fec::1", _i);
	assert_family(AF_UNSPEC, "fec::1,192.168.1.1", _i);
}
END_TEST

START_TEST(test_get_address_family_any)
{
	assert_family(AF_UNSPEC, "%any", _i);

	assert_family(AF_INET, "%any4", _i);
	assert_family(AF_INET, "0.0.0.0", _i);

	assert_family(AF_INET6, "%any6", _i);
	assert_family(AF_INET6, "::", _i);

	assert_family(AF_INET, "192.168.1.1,%any", _i);
	assert_family(AF_INET, "192.168.1.1,%any4", _i);
	assert_family(AF_UNSPEC, "192.168.1.1,%any6", _i);

	assert_family(AF_INET6, "fec::1,%any", _i);
	assert_family(AF_UNSPEC, "fec::1,%any4", _i);
	assert_family(AF_INET6, "fec::1,%any6", _i);
}
END_TEST

START_TEST(test_get_address_family_other)
{
	assert_family(AF_INET, "192.168.1.0", _i);
	assert_family(AF_UNSPEC, "192.168.1.0/24", _i);
	assert_family(AF_UNSPEC, "192.168.1.0-192.168.1.10", _i);

	assert_family(AF_INET, "192.168.1.0/24,192.168.2.1", _i);
	assert_family(AF_INET, "192.168.1.0-192.168.1.10,192.168.2.1", _i);
	assert_family(AF_INET6, "192.168.1.0/24,fec::1", _i);
	assert_family(AF_INET6, "192.168.1.0-192.168.1.10,fec::1", _i);

	assert_family(AF_INET6, "fec::", _i);
	assert_family(AF_UNSPEC, "fec::/64", _i);
	assert_family(AF_UNSPEC, "fec::1-fec::10", _i);

	assert_family(AF_INET6, "fec::/64,fed::1", _i);
	assert_family(AF_INET6, "fec::1-fec::10,fec::1", _i);
	assert_family(AF_INET, "fec::/64,192.168.1.1", _i);
	assert_family(AF_INET, "fec::1-fec::10,192.168.1.1", _i);

	assert_family(AF_UNSPEC, "strongswan.org", _i);
	assert_family(AF_INET, "192.168.1.0,strongswan.org", _i);
	assert_family(AF_INET6, "fec::1,strongswan.org", _i);
}
END_TEST

Suite *ike_cfg_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("ike_cfg");

	tc = tcase_create("ike_cfg_get_address_family");
	tcase_add_loop_test(tc, test_get_address_family_empty, 0, 2);
	tcase_add_loop_test(tc, test_get_address_family_addr, 0, 2);
	tcase_add_loop_test(tc, test_get_address_family_multi, 0, 2);
	tcase_add_loop_test(tc, test_get_address_family_any, 0, 2);
	tcase_add_loop_test(tc, test_get_address_family_other, 0, 2);
	suite_add_tcase(s, tc);

	tc = tcase_create("gateway resolver scope");
	tcase_add_test(tc, test_gateway_resolver_scope);
	suite_add_tcase(s, tc);

	return s;
}
