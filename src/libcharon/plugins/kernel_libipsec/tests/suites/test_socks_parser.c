/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include <test_suite.h>

#include "kernel_libipsec_socks_parser.h"

START_TEST(test_greeting_fragments)
{
	uint8_t frame[] = { 5, 3, 2, 0, 1, 0xaa };
	uint8_t method = 0xff;
	size_t consumed = 99, i;

	for (i = 0; i < 5; i++)
	{
		ck_assert_int_eq(kernel_libipsec_socks_parse_greeting(frame, i,
									&consumed, &method), SOCKS5_PARSE_MORE);
		ck_assert_int_eq(consumed, 0);
	}
	ck_assert_int_eq(kernel_libipsec_socks_parse_greeting(frame,
									sizeof(frame), &consumed, &method),
					 SOCKS5_PARSE_OK);
	ck_assert_int_eq(consumed, 5);
	ck_assert_int_eq(method, SOCKS5_METHOD_NO_AUTH);
}
END_TEST

START_TEST(test_greeting_rejections)
{
	uint8_t unsupported[] = { 5, 2, 1, 2 };
	uint8_t empty[] = { 5, 0 };
	uint8_t wrong[] = { 4, 1, 0 };
	uint8_t method;
	size_t consumed;

	ck_assert_int_eq(kernel_libipsec_socks_parse_greeting(unsupported,
				sizeof(unsupported), &consumed, &method), SOCKS5_PARSE_OK);
	ck_assert_int_eq(method, SOCKS5_METHOD_UNACCEPTABLE);
	ck_assert_int_eq(kernel_libipsec_socks_parse_greeting(empty, sizeof(empty),
				&consumed, &method), SOCKS5_PARSE_INVALID);
	ck_assert_int_eq(kernel_libipsec_socks_parse_greeting(wrong, sizeof(wrong),
				&consumed, &method), SOCKS5_PARSE_INVALID);
}
END_TEST

static void assert_partial_request(uint8_t *frame, size_t len)
{
	socks5_request_t request;
	size_t consumed, i;

	for (i = 0; i < len; i++)
	{
		ck_assert_int_eq(kernel_libipsec_socks_parse_request(frame, i,
									&consumed, &request), SOCKS5_PARSE_MORE);
		ck_assert_int_eq(consumed, 0);
	}
}

START_TEST(test_ipv4_request_fragments)
{
	uint8_t frame[] = { 5, 1, 0, 1, 192, 0, 2, 7, 0x01, 0xbb, 0xcc };
	socks5_request_t request;
	size_t consumed;

	assert_partial_request(frame, 10);
	ck_assert_int_eq(kernel_libipsec_socks_parse_request(frame, sizeof(frame),
				&consumed, &request), SOCKS5_PARSE_OK);
	ck_assert_int_eq(consumed, 10);
	ck_assert_int_eq(request.command, SOCKS5_CMD_CONNECT);
	ck_assert_int_eq(request.atyp, SOCKS5_ATYP_IPV4);
	ck_assert(memeq(request.address, frame + 4, 4));
	ck_assert_int_eq(request.port, 443);
}
END_TEST

START_TEST(test_ipv6_request)
{
	uint8_t frame[22] = { 5, 1, 0, 4 };
	socks5_request_t request;
	size_t consumed;
	u_int i;

	for (i = 0; i < 16; i++)
	{
		frame[4 + i] = i;
	}
	frame[20] = 0x20;
	frame[21] = 0x01;
	assert_partial_request(frame, sizeof(frame));
	ck_assert_int_eq(kernel_libipsec_socks_parse_request(frame, sizeof(frame),
				&consumed, &request), SOCKS5_PARSE_OK);
	ck_assert_int_eq(consumed, sizeof(frame));
	ck_assert(memeq(request.address, frame + 4, 16));
	ck_assert_int_eq(request.port, 8193);
}
END_TEST

START_TEST(test_domain_request)
{
	uint8_t frame[] = { 5, 1, 0, 3, 11,
		'e','x','a','m','p','l','e','.','o','r','g', 0, 80 };
	socks5_request_t request;
	size_t consumed;

	assert_partial_request(frame, sizeof(frame));
	ck_assert_int_eq(kernel_libipsec_socks_parse_request(frame, sizeof(frame),
				&consumed, &request), SOCKS5_PARSE_OK);
	ck_assert_str_eq(request.domain, "example.org");
	ck_assert_int_eq(request.port, 80);
}
END_TEST

START_TEST(test_request_rejections)
{
	uint8_t unsupported[] = { 5, 1, 0, 9 };
	uint8_t empty_domain[] = { 5, 1, 0, 3, 0, 0, 80 };
	uint8_t nul_domain[] = { 5, 1, 0, 3, 3, 'a', 0, 'b', 0, 80 };
	uint8_t zero_port[] = { 5, 1, 0, 1, 192, 0, 2, 1, 0, 0 };
	uint8_t reserved[] = { 5, 1, 1, 1, 192, 0, 2, 1, 0, 80 };
	socks5_request_t request;
	size_t consumed;

	ck_assert_int_eq(kernel_libipsec_socks_parse_request(unsupported,
				sizeof(unsupported), &consumed, &request),
				SOCKS5_PARSE_UNSUPPORTED_ADDRESS);
	ck_assert_int_eq(consumed, 4);
	ck_assert_int_eq(kernel_libipsec_socks_parse_request(empty_domain,
				sizeof(empty_domain), &consumed, &request), SOCKS5_PARSE_INVALID);
	ck_assert_int_eq(kernel_libipsec_socks_parse_request(nul_domain,
				sizeof(nul_domain), &consumed, &request), SOCKS5_PARSE_INVALID);
	ck_assert_int_eq(kernel_libipsec_socks_parse_request(zero_port,
				sizeof(zero_port), &consumed, &request), SOCKS5_PARSE_INVALID);
	ck_assert_int_eq(kernel_libipsec_socks_parse_request(reserved,
				sizeof(reserved), &consumed, &request), SOCKS5_PARSE_INVALID);
}
END_TEST

Suite *test_socks_parser_suite_create(void)
{
	Suite *suite = suite_create("SOCKS5 parser");
	TCase *tests = tcase_create("incremental frames");

	tcase_add_test(tests, test_greeting_fragments);
	tcase_add_test(tests, test_greeting_rejections);
	tcase_add_test(tests, test_ipv4_request_fragments);
	tcase_add_test(tests, test_ipv6_request);
	tcase_add_test(tests, test_domain_request);
	tcase_add_test(tests, test_request_rejections);
	suite_add_tcase(suite, tests);
	return suite;
}
