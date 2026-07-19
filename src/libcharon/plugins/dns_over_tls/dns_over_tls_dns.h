/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

/**
 * @defgroup dns_over_tls_dns dns_over_tls_dns
 * @{ @ingroup dns_over_tls
 */

#ifndef DNS_OVER_TLS_DNS_H_
#define DNS_OVER_TLS_DNS_H_

#include <library.h>
#include <collections/linked_list.h>

#define DNS_TYPE_A       1
#define DNS_TYPE_CNAME   5
#define DNS_TYPE_AAAA    28

typedef enum dot_dns_status_t dot_dns_status_t;

/** Result of parsing a DNS response. */
enum dot_dns_status_t {
	DOT_DNS_SUCCESS,
	DOT_DNS_NXDOMAIN,
	DOT_DNS_SERVER_ERROR,
	DOT_DNS_ERROR,
};

/**
 * Encode a recursive IN query for a single name and type.
 *
 * @param name	name to encode
 * @param type	DNS_TYPE_A or DNS_TYPE_AAAA
 * @param id	query identifier
 * @param query	allocated DNS message on success
 * @return		TRUE if the name and type were valid
 */
bool dns_over_tls_build_query(char *name, uint16_t type, uint16_t id,
							  chunk_t *query);

/**
 * Parse and authenticate the structure of a DNS response.
 *
 * The response ID, question name, type and class must exactly match the
 * supplied query (DNS names are compared case-insensitively).  Returned hosts
 * are in answer order and owned by the caller.
 *
 * @param response	DNS response message
 * @param name		queried name
 * @param type		queried type
 * @param id			query identifier
 * @param hosts		created list of host_t* on success
 * @param rcode		optional response code, set for valid DNS responses
 * @return			response status
 */
dot_dns_status_t dns_over_tls_parse_response(chunk_t response, char *name,
										 uint16_t type, uint16_t id,
										 linked_list_t **hosts, uint8_t *rcode);

#endif /** DNS_OVER_TLS_DNS_H_ @}*/
