/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include <test_suite.h>

#include "dns_over_tls_dns.h"

#define TEST_ID 0x1234

static void put_u16(uint8_t *ptr, uint16_t value)
{
	ptr[0] = value >> 8;
	ptr[1] = value;
}

static void append(chunk_t *message, void *data, size_t len)
{
	message->ptr = realloc(message->ptr, message->len + len);
	memcpy(message->ptr + message->len, data, len);
	message->len += len;
}

static chunk_t response_base(char *name, uint16_t type, uint16_t flags,
							 uint16_t answers)
{
	chunk_t response;

	ck_assert(dns_over_tls_build_query(name, type, TEST_ID, &response));
	put_u16(response.ptr + 2, 0x8000 | flags);
	put_u16(response.ptr + 6, answers);
	return response;
}

static void append_address(chunk_t *response, uint16_t owner,
						   uint16_t type, void *address, size_t len)
{
	uint8_t header[12] = {};

	put_u16(header, 0xc000 | owner);
	put_u16(header + 2, type);
	put_u16(header + 4, 1);
	put_u16(header + 10, len);
	append(response, header, sizeof(header));
	append(response, address, len);
}

static size_t append_cname(chunk_t *response, uint16_t owner,
						   void *target, size_t len)
{
	uint8_t header[12] = {};
	size_t offset;

	put_u16(header, 0xc000 | owner);
	put_u16(header + 2, DNS_TYPE_CNAME);
	put_u16(header + 4, 1);
	put_u16(header + 10, len);
	append(response, header, sizeof(header));
	offset = response->len;
	append(response, target, len);
	return offset;
}

static void host_destroy(host_t *host)
{
	host->destroy(host);
}

static void destroy_hosts(linked_list_t *hosts)
{
	if (hosts)
	{
		hosts->destroy_function(hosts, (void*)host_destroy);
	}
}

START_TEST(test_query_encoding)
{
	static uint8_t expected_a[] = {
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x03, 'v', 'p', 'n', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
		0x00, 0x01, 0x00, 0x01,
	};
	chunk_t query;

	ck_assert(dns_over_tls_build_query("vpn.example", DNS_TYPE_A, TEST_ID,
									   &query));
	ck_assert(chunk_equals(query, chunk_from_thing(expected_a)));
	chunk_free(&query);
	ck_assert(dns_over_tls_build_query("vpn.example.", DNS_TYPE_AAAA,
									   TEST_ID, &query));
	ck_assert_int_eq(query.ptr[query.len - 4], 0);
	ck_assert_int_eq(query.ptr[query.len - 3], DNS_TYPE_AAAA);
	chunk_free(&query);
}
END_TEST

START_TEST(test_invalid_query)
{
	char label[66];
	chunk_t query;

	memset(label, 'a', sizeof(label));
	label[64] = '\0';
	ck_assert(!dns_over_tls_build_query(NULL, DNS_TYPE_A, TEST_ID, &query));
	ck_assert(!dns_over_tls_build_query("", DNS_TYPE_A, TEST_ID, &query));
	ck_assert(!dns_over_tls_build_query(".", DNS_TYPE_A, TEST_ID, &query));
	ck_assert(!dns_over_tls_build_query("a..example", DNS_TYPE_A, TEST_ID,
										&query));
	ck_assert(!dns_over_tls_build_query(label, DNS_TYPE_A, TEST_ID, &query));
	ck_assert(!dns_over_tls_build_query("vpn.example", DNS_TYPE_CNAME,
										TEST_ID, &query));
}
END_TEST

START_TEST(test_a_answers)
{
	uint8_t first[] = { 192, 0, 2, 1 }, second[] = { 192, 0, 2, 2 };
	chunk_t response = response_base("vpn.example", DNS_TYPE_A, 0x0180, 2);
	linked_list_t *hosts;
	enumerator_t *enumerator;
	host_t *host;
	u_int i = 0;

	append_address(&response, 12, DNS_TYPE_A, first, sizeof(first));
	append_address(&response, 12, DNS_TYPE_A, second, sizeof(second));
	ck_assert_int_eq(dns_over_tls_parse_response(response, "vpn.example",
					DNS_TYPE_A, TEST_ID, &hosts, NULL), DOT_DNS_SUCCESS);
	ck_assert_int_eq(hosts->get_count(hosts), 2);
	enumerator = hosts->create_enumerator(hosts);
	while (enumerator->enumerate(enumerator, &host))
	{
		ck_assert(chunk_equals(host->get_address(host),
							 i++ ? chunk_from_thing(second) : chunk_from_thing(first)));
	}
	enumerator->destroy(enumerator);
	destroy_hosts(hosts);
	chunk_free(&response);
}
END_TEST

START_TEST(test_aaaa_answer)
{
	uint8_t address[] = {
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	};
	chunk_t response = response_base("vpn.example", DNS_TYPE_AAAA, 0x0180, 1);
	linked_list_t *hosts;
	host_t *host;

	append_address(&response, 12, DNS_TYPE_AAAA, address, sizeof(address));
	ck_assert_int_eq(dns_over_tls_parse_response(response, "vpn.example",
					DNS_TYPE_AAAA, TEST_ID, &hosts, NULL), DOT_DNS_SUCCESS);
	ck_assert_int_eq(hosts->get_count(hosts), 1);
	ck_assert_int_eq(hosts->get_first(hosts, (void**)&host), SUCCESS);
	ck_assert(chunk_equals(host->get_address(host), chunk_from_thing(address)));
	destroy_hosts(hosts);
	chunk_free(&response);
}
END_TEST

START_TEST(test_compressed_cname_chain)
{
	uint8_t alias[] = { 5, 'a', 'l', 'i', 'a', 's', 0xc0, 0x10 };
	uint8_t vpn[] = { 3, 'v', 'p', 'n', 0xc0, 0x10 };
	uint8_t address[] = { 198, 51, 100, 7 };
	chunk_t response = response_base("www.example", DNS_TYPE_A, 0x0180, 3);
	linked_list_t *hosts;
	size_t alias_offset, vpn_offset;
	host_t *host;

	alias_offset = append_cname(&response, 12, alias, sizeof(alias));
	vpn_offset = append_cname(&response, alias_offset, vpn, sizeof(vpn));
	append_address(&response, vpn_offset, DNS_TYPE_A, address, sizeof(address));
	ck_assert_int_eq(dns_over_tls_parse_response(response, "WWW.EXAMPLE.",
					DNS_TYPE_A, TEST_ID, &hosts, NULL), DOT_DNS_SUCCESS);
	ck_assert_int_eq(hosts->get_count(hosts), 1);
	ck_assert_int_eq(hosts->get_first(hosts, (void**)&host), SUCCESS);
	ck_assert(chunk_equals(host->get_address(host), chunk_from_thing(address)));
	destroy_hosts(hosts);
	chunk_free(&response);
}
END_TEST

START_TEST(test_nxdomain_and_nodata)
{
	chunk_t response;
	linked_list_t *hosts;

	response = response_base("missing.example", DNS_TYPE_A, 0x0183, 0);
	ck_assert_int_eq(dns_over_tls_parse_response(response, "missing.example",
					DNS_TYPE_A, TEST_ID, &hosts, NULL), DOT_DNS_NXDOMAIN);
	ck_assert(!hosts);
	chunk_free(&response);

	response = response_base("empty.example", DNS_TYPE_A, 0x0180, 0);
	ck_assert_int_eq(dns_over_tls_parse_response(response, "empty.example",
					DNS_TYPE_A, TEST_ID, &hosts, NULL), DOT_DNS_SUCCESS);
	ck_assert_int_eq(hosts->get_count(hosts), 0);
	destroy_hosts(hosts);
	chunk_free(&response);
}
END_TEST

START_TEST(test_server_error)
{
	uint8_t codes[] = { 1, 2, 4, 5, 15 }, rcode;
	linked_list_t *hosts;
	chunk_t response;

	response = response_base("vpn.example", DNS_TYPE_A,
							 0x0180 | codes[_i], 0);
	ck_assert_int_eq(dns_over_tls_parse_response(response, "vpn.example",
					DNS_TYPE_A, TEST_ID, &hosts, &rcode),
					DOT_DNS_SERVER_ERROR);
	ck_assert_int_eq(rcode, codes[_i]);
	ck_assert(!hosts);
	chunk_free(&response);
}
END_TEST

static void assert_invalid(chunk_t response, char *name, uint16_t type)
{
	linked_list_t *hosts;

	ck_assert_int_eq(dns_over_tls_parse_response(response, name, type,
										 TEST_ID, &hosts, NULL), DOT_DNS_ERROR);
	ck_assert(!hosts);
	chunk_free(&response);
}

START_TEST(test_mismatched_response)
{
	chunk_t response;

	response = response_base("vpn.example", DNS_TYPE_A, 0x0180, 0);
	response.ptr[0] ^= 1;
	assert_invalid(response, "vpn.example", DNS_TYPE_A);

	response = response_base("vpn.example", DNS_TYPE_A, 0x0180, 0);
	response.ptr[response.len - 3] = DNS_TYPE_AAAA;
	assert_invalid(response, "vpn.example", DNS_TYPE_A);

	response = response_base("vpn.example", DNS_TYPE_A, 0x0180, 0);
	response.ptr[13] = 'x';
	assert_invalid(response, "vpn.example", DNS_TYPE_A);
}
END_TEST

START_TEST(test_malformed_response)
{
	uint8_t address[] = { 192, 0, 2, 1 };
	uint8_t bad_record[15] = {};
	chunk_t response;
	size_t offset;

	response = response_base("vpn.example", DNS_TYPE_A, 0x0380, 0);
	assert_invalid(response, "vpn.example", DNS_TYPE_A);

	response = response_base("vpn.example", DNS_TYPE_A, 0x0180, 1);
	offset = response.len;
	put_u16(bad_record, 0xc000 | offset); /* self-referencing pointer */
	put_u16(bad_record + 2, DNS_TYPE_A);
	put_u16(bad_record + 4, 1);
	put_u16(bad_record + 10, sizeof(address));
	memcpy(bad_record + 12, address, 3); /* truncated RDATA */
	append(&response, bad_record, sizeof(bad_record));
	assert_invalid(response, "vpn.example", DNS_TYPE_A);

	response = response_base("vpn.example", DNS_TYPE_A, 0x0180, 1);
	append_address(&response, 12, DNS_TYPE_A, address, sizeof(address));
	response.len--;
	assert_invalid(response, "vpn.example", DNS_TYPE_A);
}
END_TEST

START_TEST(test_cname_loop)
{
	uint8_t alias[] = { 5, 'a', 'l', 'i', 'a', 's', 0xc0, 0x10 };
	uint8_t original[] = { 0xc0, 0x0c };
	chunk_t response = response_base("www.example", DNS_TYPE_A, 0x0180, 2);
	size_t alias_offset;

	alias_offset = append_cname(&response, 12, alias, sizeof(alias));
	append_cname(&response, alias_offset, original, sizeof(original));
	assert_invalid(response, "www.example", DNS_TYPE_A);
}
END_TEST

Suite *dns_over_tls_dns_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("dns-over-tls DNS");
	tc = tcase_create("encoding");
	tcase_add_test(tc, test_query_encoding);
	tcase_add_test(tc, test_invalid_query);
	suite_add_tcase(s, tc);

	tc = tcase_create("parsing");
	tcase_add_test(tc, test_a_answers);
	tcase_add_test(tc, test_aaaa_answer);
	tcase_add_test(tc, test_compressed_cname_chain);
	tcase_add_test(tc, test_nxdomain_and_nodata);
	tcase_add_loop_test(tc, test_server_error, 0, 5);
	tcase_add_test(tc, test_mismatched_response);
	tcase_add_test(tc, test_malformed_response);
	tcase_add_test(tc, test_cname_loop);
	suite_add_tcase(s, tc);
	return s;
}
