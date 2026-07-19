/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "test_suite.h"

#include <errno.h>
#include <unistd.h>

#include <credentials/sets/mem_cred.h>
#include <networking/host.h>
#include <threading/semaphore.h>
#include <threading/thread.h>
#include <tls_socket.h>

#include "dns_over_tls_resolver.h"

#define SERVER_NAME "moon.d.strongswan.org"
#define SERVER_DIR DOT_TEST_CRED_DIR
#define SERVER_KEY SERVER_DIR "/rsa/moon_key.der"
#define SERVER_CERT SERVER_DIR "/x509/moon_D_cert.der"
#define CA_A SERVER_DIR "/x509ca/ca_A_cert.der"
#define CA_B SERVER_DIR "/x509ca/ca_B_cert.der"
#define CA_C SERVER_DIR "/x509ca/ca_C_cert.der"
#define CA_D SERVER_DIR "/x509ca/ca_D_cert.der"

#define DNS_TYPE_A     1
#define DNS_TYPE_AAAA  28

static mem_cred_t *creds;

static bool add_key(char *path)
{
	private_key_t *key;

	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_ANY,
							 BUILD_FROM_FILE, path, BUILD_END);
	if (!key)
	{
		return FALSE;
	}
	creds->add_key(creds, key);
	return TRUE;
}

static bool add_cert(char *path, bool trusted)
{
	certificate_t *cert;

	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							  BUILD_FROM_FILE, path, BUILD_END);
	if (!cert)
	{
		return FALSE;
	}
	creds->add_cert(creds, trusted, cert);
	return TRUE;
}

static void setup_credentials(bool trusted)
{
	creds = mem_cred_create();
	ck_assert(add_key(SERVER_KEY));
	ck_assert(add_cert(SERVER_CERT, FALSE));
	ck_assert(add_cert(CA_D, FALSE));
	ck_assert(add_cert(CA_C, FALSE));
	ck_assert(add_cert(CA_B, FALSE));
	ck_assert(add_cert(CA_A, trusted));
	lib->credmgr->add_set(lib->credmgr, &creds->set);
}

START_SETUP(setup_trusted)
{
	setup_credentials(TRUE);
}
END_SETUP

START_SETUP(setup_untrusted)
{
	setup_credentials(FALSE);
}
END_SETUP

START_TEARDOWN(teardown_credentials)
{
	lib->credmgr->remove_set(lib->credmgr, &creds->set);
	creds->destroy(creds);
	creds = NULL;
	lib->credmgr->flush_cache(lib->credmgr, CERT_ANY);
	lib->settings->set_str(lib->settings, "%s.host_resolver.dot_server", NULL,
							  lib->ns);
	lib->settings->set_str(lib->settings, "%s.host_resolver.dot_timeout", NULL,
							  lib->ns);
}
END_TEARDOWN

typedef struct {
	int fd;
	uint16_t port;
	thread_t *thread;
	tls_version_t max_version;
	u_int accepts;
	u_int queries;
	u_int close_after;
	bool bad_id;
	bool hold_handshake;
	bool stop;
	bool failed;
	semaphore_t *accepted;
	semaphore_t *continue_handshake;
	uint8_t v4[4];
	uint8_t v6[16];
} dot_server_t;

static uint16_t read_u16(uint8_t *ptr)
{
	return ((uint16_t)ptr[0] << 8) | ptr[1];
}

static void write_u16(uint8_t *ptr, uint16_t value)
{
	ptr[0] = value >> 8;
	ptr[1] = value;
}

static bool tls_read_exact(tls_socket_t *tls, chunk_t data)
{
	ssize_t len;

	while (data.len)
	{
		len = tls->read(tls, data.ptr, data.len, TRUE);
		if (len <= 0)
		{
			return FALSE;
		}
		data = chunk_skip(data, len);
	}
	return TRUE;
}

static bool tls_write_exact(tls_socket_t *tls, chunk_t data)
{
	ssize_t len;

	while (data.len)
	{
		len = tls->write(tls, data.ptr, data.len);
		if (len <= 0)
		{
			return FALSE;
		}
		data = chunk_skip(data, len);
	}
	return TRUE;
}

static chunk_t build_response(dot_server_t *server, chunk_t query)
{
	chunk_t response;
	uint16_t type, rdlen;
	uint8_t *ptr;

	if (query.len < 17 || read_u16(query.ptr + 4) != 1)
	{
		return chunk_empty;
	}
	type = read_u16(query.ptr + query.len - 4);
	if (type != DNS_TYPE_A && type != DNS_TYPE_AAAA)
	{
		return chunk_empty;
	}
	rdlen = type == DNS_TYPE_A ? sizeof(server->v4) : sizeof(server->v6);
	response = chunk_alloc(query.len + 12 + rdlen);
	memcpy(response.ptr, query.ptr, query.len);
	write_u16(response.ptr + 2, 0x8180);
	write_u16(response.ptr + 6, 1);
	write_u16(response.ptr + 8, 0);
	write_u16(response.ptr + 10, 0);
	if (server->bad_id)
	{
		response.ptr[0] ^= 1;
	}
	ptr = response.ptr + query.len;
	*ptr++ = 0xc0;
	*ptr++ = 0x0c;
	write_u16(ptr, type);
	ptr += 2;
	write_u16(ptr, 1);
	ptr += 2;
	memset(ptr, 0, 4);
	ptr += 4;
	write_u16(ptr, rdlen);
	ptr += 2;
	memcpy(ptr, type == DNS_TYPE_A ? server->v4 : server->v6, rdlen);
	return response;
}

static bool serve_query(dot_server_t *server, tls_socket_t *tls)
{
	uint8_t prefix[2];
	chunk_t query, response, frame;
	uint16_t length;
	bool success = FALSE;

	if (!tls_read_exact(tls, chunk_create(prefix, sizeof(prefix))))
	{
		return FALSE;
	}
	length = read_u16(prefix);
	if (length < 12)
	{
		return FALSE;
	}
	query = chunk_alloc(length);
	if (!tls_read_exact(tls, query))
	{
		chunk_free(&query);
		return FALSE;
	}
	response = build_response(server, query);
	chunk_free(&query);
	if (!response.len)
	{
		return FALSE;
	}
	frame = chunk_alloc(response.len + 2);
	write_u16(frame.ptr, response.len);
	memcpy(frame.ptr + 2, response.ptr, response.len);
	chunk_free(&response);
	success = tls_write_exact(tls, frame);
	chunk_free(&frame);
	if (success)
	{
		server->queries++;
	}
	return success;
}

static void *serve_dot(dot_server_t *server)
{
	identification_t *identity;
	tls_socket_t *tls;
	int client;
	u_int queries;

	identity = identification_create_from_string(SERVER_NAME);
	while (!server->stop)
	{
		client = accept(server->fd, NULL, NULL);
		if (client < 0)
		{
			if (!server->stop)
			{
				server->failed = TRUE;
			}
			break;
		}
		server->accepts++;
		if (server->hold_handshake)
		{
			server->accepted->post(server->accepted);
			server->continue_handshake->wait(server->continue_handshake);
		}
		tls = tls_socket_create(TRUE, identity, NULL, client, NULL,
								TLS_1_0, server->max_version, 0);
		if (!tls)
		{
			close(client);
			continue;
		}
		queries = 0;
		while (!server->stop && serve_query(server, tls))
		{
			if (server->close_after && ++queries >= server->close_after)
			{
				break;
			}
		}
		tls->destroy(tls);
		close(client);
	}
	identity->destroy(identity);
	return NULL;
}

static void server_start(dot_server_t *server)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t len = sizeof(address);
	int on = 1;

	server->max_version = server->max_version ?: TLS_1_3;
	if (!server->v4[0] && !server->v4[1] && !server->v4[2] && !server->v4[3])
	{
		server->v4[0] = 192;
		server->v4[1] = 0;
		server->v4[2] = 2;
		server->v4[3] = 55;
	}
	if (!server->v6[0] && !server->v6[15])
	{
		server->v6[0] = 0x20;
		server->v6[1] = 0x01;
		server->v6[2] = 0x0d;
		server->v6[3] = 0xb8;
		server->v6[15] = 0x55;
	}
	server->fd = socket(AF_INET, SOCK_STREAM, 0);
	ck_assert_msg(server->fd >= 0, "%s", strerror(errno));
	ck_assert(setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == 0);
	ck_assert_msg(bind(server->fd, (sockaddr_t*)&address, sizeof(address)) == 0,
				  "%s", strerror(errno));
	ck_assert(listen(server->fd, 4) == 0);
	ck_assert(getsockname(server->fd, (sockaddr_t*)&address, &len) == 0);
	server->port = ntohs(address.sin_port);
	if (server->hold_handshake)
	{
		server->accepted = semaphore_create(0);
		server->continue_handshake = semaphore_create(0);
	}
	server->thread = thread_create((thread_main_t)serve_dot, server);
	ck_assert(server->thread);
}

static void server_stop(dot_server_t *server)
{
	server->stop = TRUE;
	if (server->continue_handshake)
	{
		server->continue_handshake->post(server->continue_handshake);
	}
	shutdown(server->fd, SHUT_RDWR);
	server->thread->join(server->thread);
	close(server->fd);
	DESTROY_IF(server->accepted);
	DESTROY_IF(server->continue_handshake);
	ck_assert(!server->failed);
}

static char *server_uri(dot_server_t *server, char *identity)
{
	char uri[256];

	snprintf(uri, sizeof(uri), "tls://%s@127.0.0.1:%u", identity, server->port);
	return strdup(uri);
}

static uint16_t unused_loopback_port(void)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t len = sizeof(address);
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	ck_assert(fd >= 0);
	ck_assert(bind(fd, (sockaddr_t*)&address, sizeof(address)) == 0);
	ck_assert(getsockname(fd, (sockaddr_t*)&address, &len) == 0);
	close(fd);
	return ntohs(address.sin_port);
}

static void assert_address(host_t *host, char *address)
{
	host_t *expected;

	ck_assert(host);
	expected = host_create_from_string(address, 0);
	ck_assert(host->ip_equals(host, expected));
	expected->destroy(expected);
	host->destroy(host);
}

START_TEST(test_success_reuse_and_families)
{
	dot_server_t server = {};
	dns_over_tls_resolver_t *resolver;
	host_t *host;
	char *uri;

	server_start(&server);
	uri = server_uri(&server, SERVER_NAME);
	resolver = dns_over_tls_resolver_create();
	assert_address(resolver->provider.resolve(&resolver->provider, uri,
											 "vpn.example", AF_INET), "192.0.2.55");
	/* Connections are reused, DNS answers are deliberately not cached. */
	assert_address(resolver->provider.resolve(&resolver->provider, uri,
											 "vpn.example", AF_INET), "192.0.2.55");
	assert_address(resolver->provider.resolve(&resolver->provider, uri,
											 "vpn6.example", AF_INET6), "2001:db8::55");
	host = resolver->provider.resolve(&resolver->provider, uri,
									  "dual.example", AF_UNSPEC);
	assert_address(host, "2001:db8::55");
	resolver->destroy(resolver);
	server_stop(&server);
	ck_assert_int_eq(server.accepts, 1);
	ck_assert_int_eq(server.queries, 5);
	free(uri);
}
END_TEST

START_TEST(test_broken_connection_reconnects_once)
{
	dot_server_t server = { .close_after = 1 };
	dns_over_tls_resolver_t *resolver;
	char *uri;

	server_start(&server);
	uri = server_uri(&server, SERVER_NAME);
	resolver = dns_over_tls_resolver_create();
	assert_address(resolver->provider.resolve(&resolver->provider, uri,
											 "one.example", AF_INET), "192.0.2.55");
	assert_address(resolver->provider.resolve(&resolver->provider, uri,
											 "two.example", AF_INET), "192.0.2.55");
	resolver->destroy(resolver);
	server_stop(&server);
	ck_assert_int_eq(server.accepts, 2);
	ck_assert_int_eq(server.queries, 2);
	free(uri);
}
END_TEST

START_TEST(test_reload_closes_connection)
{
	dot_server_t first = {}, second = { .v4 = { 198, 51, 100, 77 } };
	dns_over_tls_resolver_t *resolver;
	char *uri1, *uri2;

	server_start(&first);
	server_start(&second);
	uri1 = server_uri(&first, SERVER_NAME);
	uri2 = server_uri(&second, SERVER_NAME);
	resolver = dns_over_tls_resolver_create();
	assert_address(resolver->provider.resolve(&resolver->provider, uri1,
											 "one.example", AF_INET), "192.0.2.55");
	lib->settings->set_str(lib->settings, "%s.host_resolver.dot_server", uri2,
							  lib->ns);
	ck_assert(resolver->reload(resolver));
	assert_address(resolver->provider.resolve(&resolver->provider, uri2,
											 "two.example", AF_INET), "198.51.100.77");
	resolver->destroy(resolver);
	server_stop(&first);
	server_stop(&second);
	ck_assert_int_eq(first.accepts, 1);
	ck_assert_int_eq(second.accepts, 1);
	free(uri1);
	free(uri2);
}
END_TEST

START_TEST(test_wrong_identity)
{
	dot_server_t server = {};
	dns_over_tls_resolver_t *resolver;
	char *uri;

	server_start(&server);
	uri = server_uri(&server, "wrong.example");
	resolver = dns_over_tls_resolver_create();
	ck_assert(!resolver->provider.resolve(&resolver->provider, uri,
										  "vpn.example", AF_INET));
	resolver->destroy(resolver);
	server_stop(&server);
	ck_assert_int_eq(server.queries, 0);
	free(uri);
}
END_TEST

START_TEST(test_tls_downgrade)
{
	dot_server_t server = { .max_version = TLS_1_1 };
	dns_over_tls_resolver_t *resolver;
	char *uri;

	server_start(&server);
	uri = server_uri(&server, SERVER_NAME);
	resolver = dns_over_tls_resolver_create();
	ck_assert(!resolver->provider.resolve(&resolver->provider, uri,
										  "vpn.example", AF_INET));
	resolver->destroy(resolver);
	server_stop(&server);
	ck_assert_int_eq(server.queries, 0);
	free(uri);
}
END_TEST

START_TEST(test_malformed_response)
{
	dot_server_t server = { .bad_id = TRUE };
	dns_over_tls_resolver_t *resolver;
	char *uri;

	server_start(&server);
	uri = server_uri(&server, SERVER_NAME);
	resolver = dns_over_tls_resolver_create();
	ck_assert(!resolver->provider.resolve(&resolver->provider, uri,
										  "vpn.example", AF_INET));
	resolver->destroy(resolver);
	server_stop(&server);
	ck_assert_int_eq(server.queries, 1);
	free(uri);
}
END_TEST

START_TEST(test_unavailable_server)
{
	dot_server_t server = { .port = unused_loopback_port() };
	dns_over_tls_resolver_t *resolver;
	char *uri;

	uri = server_uri(&server, SERVER_NAME);
	resolver = dns_over_tls_resolver_create();
	ck_assert(!resolver->provider.resolve(&resolver->provider, uri,
										  "localhost", AF_INET));
	resolver->destroy(resolver);
	free(uri);
}
END_TEST

START_TEST(test_absolute_timeout)
{
	dot_server_t server = { .hold_handshake = TRUE };
	dns_over_tls_resolver_t *resolver;
	timeval_t start, end;
	char *uri;

	server_start(&server);
	uri = server_uri(&server, SERVER_NAME);
	lib->settings->set_time(lib->settings, "%s.host_resolver.dot_timeout", 1,
							   lib->ns);
	resolver = dns_over_tls_resolver_create();
	time_monotonic(&start);
	ck_assert(!resolver->provider.resolve(&resolver->provider, uri,
										  "vpn.example", AF_INET));
	time_monotonic(&end);
	timersub(&end, &start, &end);
	ck_assert(end.tv_sec >= 1 && end.tv_sec < 3);
	resolver->destroy(resolver);
	server_stop(&server);
	free(uri);
}
END_TEST

START_TEST(test_untrusted_certificate)
{
	dot_server_t server = {};
	dns_over_tls_resolver_t *resolver;
	char *uri;

	server_start(&server);
	uri = server_uri(&server, SERVER_NAME);
	resolver = dns_over_tls_resolver_create();
	ck_assert(!resolver->provider.resolve(&resolver->provider, uri,
										  "vpn.example", AF_INET));
	resolver->destroy(resolver);
	server_stop(&server);
	ck_assert_int_eq(server.queries, 0);
	free(uri);
}
END_TEST

Suite *dns_over_tls_transport_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("dns-over-tls transport");
	tc = tcase_create("trusted server");
	tcase_add_checked_fixture(tc, setup_trusted, teardown_credentials);
	tcase_add_test(tc, test_success_reuse_and_families);
	tcase_add_test(tc, test_broken_connection_reconnects_once);
	tcase_add_test(tc, test_reload_closes_connection);
	tcase_add_test(tc, test_wrong_identity);
	tcase_add_test(tc, test_tls_downgrade);
	tcase_add_test(tc, test_malformed_response);
	tcase_add_test(tc, test_unavailable_server);
	tcase_add_test(tc, test_absolute_timeout);
	tcase_set_timeout(tc, 10);
	suite_add_tcase(s, tc);

	tc = tcase_create("untrusted server");
	tcase_add_checked_fixture(tc, setup_untrusted, teardown_credentials);
	tcase_add_test(tc, test_untrusted_certificate);
	tcase_set_timeout(tc, 10);
	suite_add_tcase(s, tc);
	return s;
}
