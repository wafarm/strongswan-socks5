/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include <test_suite.h>

#include <collections/linked_list.h>
#include <credentials/certificates/x509.h>

#include "tls_peer.h"

typedef struct {
	x509_t public;
	linked_list_t *sans;
} fake_x509_t;

static certificate_type_t get_type(certificate_t *cert)
{
	return CERT_X509;
}

static id_match_t has_subject(certificate_t *cert, identification_t *subject)
{
	fake_x509_t *this = (fake_x509_t*)cert;
	identification_t *san;
	enumerator_t *enumerator;
	id_match_t current, best = ID_MATCH_NONE;

	enumerator = this->sans->create_enumerator(this->sans);
	while (enumerator->enumerate(enumerator, &san))
	{
		current = san->matches(san, subject);
		best = max(best, current);
	}
	enumerator->destroy(enumerator);
	return best;
}

static enumerator_t *create_san_enumerator(x509_t *cert)
{
	fake_x509_t *this = (fake_x509_t*)cert;

	return this->sans->create_enumerator(this->sans);
}

static fake_x509_t *fake_x509_create(char *san)
{
	fake_x509_t *this;

	INIT(this,
		.public = {
			.interface = {
				.get_type = get_type,
				.has_subject = has_subject,
			},
			.create_subjectAltName_enumerator = create_san_enumerator,
		},
		.sans = linked_list_create(),
	);
	this->sans->insert_last(this->sans,
							 identification_create_from_string(san));
	return this;
}

static void fake_x509_destroy(fake_x509_t *this)
{
	this->sans->destroy_offset(this->sans,
							  offsetof(identification_t, destroy));
	free(this);
}

typedef struct {
	char *presented;
	char *reference;
	bool matches;
} server_match_t;

static server_match_t server_matches[] = {
	{ "dns.example.com", "dns.example.com", TRUE },
	{ "DNS.Example.Com", "dns.example.com", TRUE },
	{ "*.example.com", "dns.example.com", TRUE },
	{ "*.Example.Com", "DNS.example.com", TRUE },
	{ "*.example.com", "a.b.example.com", FALSE },
	{ "*.example.com", "example.com", FALSE },
	{ "*.example.com", "badexample.com", FALSE },
	{ "d*.example.com", "dns.example.com", FALSE },
	{ "*.*.example.com", "a.b.example.com", FALSE },
	{ "dns.*.com", "dns.example.com", FALSE },
	{ "*", "dns.example.com", FALSE },
	{ "*.example.com", "192.0.2.1", FALSE },
};

START_TEST(test_server_matches)
{
	fake_x509_t *cert;
	identification_t *server;

	cert = fake_x509_create(server_matches[_i].presented);
	server = identification_create_from_string(server_matches[_i].reference);
	ck_assert_int_eq(tls_peer_matches_server(&cert->public.interface, server),
					 server_matches[_i].matches);
	server->destroy(server);
	fake_x509_destroy(cert);
}
END_TEST

Suite *peer_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("peer");
	tc = tcase_create("server certificate identity");
	tcase_add_loop_test(tc, test_server_matches, 0, countof(server_matches));
	suite_add_tcase(s, tc);
	return s;
}
