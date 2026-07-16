/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#ifndef KERNEL_LIBIPSEC_SOCKS_PARSER_H_
#define KERNEL_LIBIPSEC_SOCKS_PARSER_H_

#include <library.h>

#define SOCKS5_VERSION                  0x05
#define SOCKS5_METHOD_NO_AUTH           0x00
#define SOCKS5_METHOD_UNACCEPTABLE      0xff

#define SOCKS5_CMD_CONNECT              0x01
#define SOCKS5_CMD_BIND                 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE        0x03

#define SOCKS5_ATYP_IPV4                0x01
#define SOCKS5_ATYP_DOMAIN              0x03
#define SOCKS5_ATYP_IPV6                0x04

#define SOCKS5_REP_SUCCESS              0x00
#define SOCKS5_REP_GENERAL_FAILURE      0x01
#define SOCKS5_REP_POLICY_DENIED        0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE  0x03
#define SOCKS5_REP_HOST_UNREACHABLE     0x04
#define SOCKS5_REP_CONNECTION_REFUSED   0x05
#define SOCKS5_REP_TTL_EXPIRED          0x06
#define SOCKS5_REP_COMMAND_UNSUPPORTED  0x07
#define SOCKS5_REP_ADDRESS_UNSUPPORTED  0x08

typedef enum {
	SOCKS5_PARSE_MORE,
	SOCKS5_PARSE_OK,
	SOCKS5_PARSE_INVALID,
	SOCKS5_PARSE_UNSUPPORTED_ADDRESS,
} socks5_parse_status_t;

typedef struct {
	uint8_t command;
	uint8_t atyp;
	uint8_t address[16];
	char domain[256];
	uint16_t port;
} socks5_request_t;

/**
 * Parse a complete SOCKS5 greeting from a possibly partial buffer.
 *
 * On success, method is NO_AUTH if offered or UNACCEPTABLE otherwise.
 */
socks5_parse_status_t kernel_libipsec_socks_parse_greeting(
							const uint8_t *data, size_t len, size_t *consumed,
							uint8_t *method);

/** Parse a complete SOCKS5 request from a possibly partial buffer. */
socks5_parse_status_t kernel_libipsec_socks_parse_request(
							const uint8_t *data, size_t len, size_t *consumed,
							socks5_request_t *request);

#endif /* KERNEL_LIBIPSEC_SOCKS_PARSER_H_ */
