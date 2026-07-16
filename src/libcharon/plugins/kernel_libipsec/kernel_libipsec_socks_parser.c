/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "kernel_libipsec_socks_parser.h"

socks5_parse_status_t kernel_libipsec_socks_parse_greeting(
							const uint8_t *data, size_t len, size_t *consumed,
							uint8_t *method)
{
	size_t i, frame;

	*consumed = 0;
	if (len < 2)
	{
		return SOCKS5_PARSE_MORE;
	}
	if (data[0] != SOCKS5_VERSION || !data[1])
	{
		return SOCKS5_PARSE_INVALID;
	}
	frame = 2 + data[1];
	if (len < frame)
	{
		return SOCKS5_PARSE_MORE;
	}
	*method = SOCKS5_METHOD_UNACCEPTABLE;
	for (i = 2; i < frame; i++)
	{
		if (data[i] == SOCKS5_METHOD_NO_AUTH)
		{
			*method = SOCKS5_METHOD_NO_AUTH;
			break;
		}
	}
	*consumed = frame;
	return SOCKS5_PARSE_OK;
}

socks5_parse_status_t kernel_libipsec_socks_parse_request(
							const uint8_t *data, size_t len, size_t *consumed,
							socks5_request_t *request)
{
	size_t address_offset = 4, address_len, frame;

	*consumed = 0;
	if (len < 4)
	{
		return SOCKS5_PARSE_MORE;
	}
	if (data[0] != SOCKS5_VERSION || data[2] != 0)
	{
		return SOCKS5_PARSE_INVALID;
	}
	memset(request, 0, sizeof(*request));
	request->command = data[1];
	request->atyp = data[3];
	switch (request->atyp)
	{
		case SOCKS5_ATYP_IPV4:
			address_len = 4;
			break;
		case SOCKS5_ATYP_IPV6:
			address_len = 16;
			break;
		case SOCKS5_ATYP_DOMAIN:
			if (len < 5)
			{
				return SOCKS5_PARSE_MORE;
			}
			if (!data[4])
			{
				return SOCKS5_PARSE_INVALID;
			}
			address_len = data[4];
			address_offset++;
			break;
		default:
			*consumed = 4;
			return SOCKS5_PARSE_UNSUPPORTED_ADDRESS;
	}
	frame = address_offset + address_len + 2;
	if (len < frame)
	{
		return SOCKS5_PARSE_MORE;
	}
	if (request->atyp == SOCKS5_ATYP_DOMAIN)
	{
		/* DNS APIs use C strings, so never silently truncate a SOCKS name. */
		if (memchr(data + address_offset, '\0', address_len))
		{
			return SOCKS5_PARSE_INVALID;
		}
		memcpy(request->domain, data + address_offset, address_len);
		request->domain[address_len] = '\0';
	}
	else
	{
		memcpy(request->address, data + address_offset, address_len);
	}
	request->port = ((uint16_t)data[frame - 2] << 8) | data[frame - 1];
	if (!request->port)
	{
		return SOCKS5_PARSE_INVALID;
	}
	*consumed = frame;
	return SOCKS5_PARSE_OK;
}
