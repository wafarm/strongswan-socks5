/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include <test_suite.h>

#include "dns_over_tls_resolver.h"

typedef struct {
	char *uri;
	char *identity;
	int family;
	uint16_t port;
} valid_uri_t;

static valid_uri_t valid_uris[] = {
	{ "tls://one.one.one.one@1.1.1.1", "one.one.one.one", AF_INET, 853 },
	{ "tls://dns.example@192.0.2.53:8853", "dns.example", AF_INET, 8853 },
	{ "tls://dns.example@[2001:db8::53]", "dns.example", AF_INET6, 853 },
	{ "tls://DNS.Example@[2001:db8::53]:443", "DNS.Example", AF_INET6, 443 },
};

START_TEST(test_valid_uri)
{
	dns_over_tls_endpoint_t endpoint;
	chunk_t identity;

	ck_assert(dns_over_tls_endpoint_parse(valid_uris[_i].uri, &endpoint));
	ck_assert_int_eq(endpoint.address->get_family(endpoint.address),
					 valid_uris[_i].family);
	ck_assert_int_eq(endpoint.address->get_port(endpoint.address),
					 valid_uris[_i].port);
	ck_assert_int_eq(endpoint.identity->get_type(endpoint.identity), ID_FQDN);
	identity = endpoint.identity->get_encoding(endpoint.identity);
	ck_assert_int_eq(identity.len, strlen(valid_uris[_i].identity));
	ck_assert(memeq(identity.ptr, valid_uris[_i].identity, identity.len));
	dns_over_tls_endpoint_clear(&endpoint);
}
END_TEST

static char *invalid_uris[] = {
	NULL,
	"",
	"udp://dns.example@192.0.2.53",
	"tls:/dns.example@192.0.2.53",
	"tls://@192.0.2.53",
	"tls://dns.example@",
	"tls://dns.example",
	"tls://dns.example@resolver.example",
	"tls://dns.example@2001:db8::53",
	"tls://dns.example@[2001:db8::53",
	"tls://dns.example@[]:853",
	"tls://dns.example@192.0.2.53:",
	"tls://dns.example@192.0.2.53:0",
	"tls://dns.example@192.0.2.53:53",
	"tls://dns.example@192.0.2.53:+853",
	"tls://dns.example@192.0.2.53: 853",
	"tls://dns.example@192.0.2.53:65536",
	"tls://dns.example@192.0.2.53:853/path",
	"tls://dns.example@@192.0.2.53",
	"tls://1.1.1.1@192.0.2.53",
	"tls://bad_name.example@192.0.2.53",
	"tls://d\xc3\xb6t.example@192.0.2.53",
	"tls://-dns.example@192.0.2.53",
	"tls://dns-.example@192.0.2.53",
};

START_TEST(test_invalid_uri)
{
	dns_over_tls_endpoint_t endpoint;

	ck_assert(!dns_over_tls_endpoint_parse(invalid_uris[_i], &endpoint));
	dns_over_tls_endpoint_clear(&endpoint);
}
END_TEST

Suite *dns_over_tls_endpoint_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("dns-over-tls endpoint");
	tc = tcase_create("URI parsing");
	tcase_add_loop_test(tc, test_valid_uri, 0, countof(valid_uris));
	tcase_add_loop_test(tc, test_invalid_uri, 0, countof(invalid_uris));
	suite_add_tcase(s, tc);
	return s;
}
