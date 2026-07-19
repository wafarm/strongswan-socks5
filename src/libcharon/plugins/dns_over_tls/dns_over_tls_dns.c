/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "dns_over_tls_dns.h"

#include <ctype.h>

#include <networking/host.h>

#define DNS_HEADER_LEN       12
#define DNS_CLASS_IN         1
#define DNS_MAX_NAME_LEN     255
#define DNS_MAX_POINTERS     128
#define DNS_MAX_RECORDS      4096
#define DNS_MAX_CNAME_DEPTH  16

typedef struct {
	char *owner;
	char *target;
	host_t *address;
	uint16_t type;
} dns_record_t;

static uint16_t read_u16(uint8_t *ptr)
{
	return ((uint16_t)ptr[0] << 8) | ptr[1];
}

static void write_u16(uint8_t *ptr, uint16_t value)
{
	ptr[0] = value >> 8;
	ptr[1] = value;
}

/**
 * Compare a decoded DNS name with a configured name, ignoring a final dot.
 */
static bool name_equals(char *decoded, char *configured)
{
	size_t len;

	if (!configured)
	{
		return FALSE;
	}
	len = strlen(configured);
	while (len && configured[len - 1] == '.')
	{
		len--;
	}
	return strlen(decoded) == len && strncasecmp(decoded, configured, len) == 0;
}

/**
 * Decode a possibly compressed DNS name and advance the original offset.
 */
static bool read_name(chunk_t message, size_t *offset,
					  char name[DNS_MAX_NAME_LEN])
{
	size_t pos = *offset, next = pos, out = 0;
	u_int pointers = 0, labels = 0;
	bool jumped = FALSE;
	uint8_t len;

	while (TRUE)
	{
		if (pos >= message.len)
		{
			return FALSE;
		}
		len = message.ptr[pos];
		if ((len & 0xc0) == 0xc0)
		{
			size_t pointer;

			if (pos + 1 >= message.len || ++pointers > DNS_MAX_POINTERS)
			{
				return FALSE;
			}
			pointer = ((len & 0x3f) << 8) | message.ptr[pos + 1];
			/* RFC 1035 compression pointers refer to a prior occurrence. */
			if (pointer < DNS_HEADER_LEN || pointer >= pos)
			{
				return FALSE;
			}
			if (!jumped)
			{
				next = pos + 2;
				jumped = TRUE;
			}
			pos = pointer;
			continue;
		}
		if (len & 0xc0)
		{
			return FALSE;
		}
		pos++;
		if (!len)
		{
			if (!jumped)
			{
				next = pos;
			}
			if (out)
			{
				out--;
			}
			name[out] = '\0';
			*offset = next;
			return TRUE;
		}
		if (len > 63 || pos + len > message.len ||
			out + len + 1 >= DNS_MAX_NAME_LEN || ++labels > 127)
		{
			return FALSE;
		}
		memcpy(name + out, message.ptr + pos, len);
		out += len;
		name[out++] = '.';
		pos += len;
		if (!jumped)
		{
			next = pos;
		}
	}
}

bool dns_over_tls_build_query(char *name, uint16_t type, uint16_t id,
							  chunk_t *query)
{
	uint8_t buffer[DNS_HEADER_LEN + DNS_MAX_NAME_LEN + 4] = {};
	size_t offset = DNS_HEADER_LEN, start = 0, len, total = 1;

	*query = chunk_empty;
	if (!name || !*name || (type != DNS_TYPE_A && type != DNS_TYPE_AAAA))
	{
		return FALSE;
	}
	len = strlen(name);
	while (len && name[len - 1] == '.')
	{
		len--;
	}
	if (!len)
	{
		return FALSE;
	}
	while (start < len)
	{
		size_t end = start;

		while (end < len && name[end] != '.')
		{
			end++;
		}
		if (end == start || end - start > 63 ||
			total + 1 + end - start > DNS_MAX_NAME_LEN)
		{
			return FALSE;
		}
		buffer[offset++] = end - start;
		memcpy(buffer + offset, name + start, end - start);
		offset += end - start;
		total += 1 + end - start;
		start = end + 1;
	}
	buffer[offset++] = 0;
	write_u16(buffer, id);
	write_u16(buffer + 2, 0x0100); /* recursion desired */
	write_u16(buffer + 4, 1);
	write_u16(buffer + offset, type);
	write_u16(buffer + offset + 2, DNS_CLASS_IN);
	offset += 4;
	*query = chunk_clone(chunk_create(buffer, offset));
	return TRUE;
}

static void record_destroy(dns_record_t *record)
{
	free(record->owner);
	free(record->target);
	DESTROY_IF(record->address);
	free(record);
}

/**
 * Parse all resource records, collecting usable answer records.
 */
static bool parse_records(chunk_t response, size_t *offset, u_int count,
						  u_int answer_count, uint16_t expected_type,
						  linked_list_t *records)
{
	u_int i;

	for (i = 0; i < count; i++)
	{
		char owner[DNS_MAX_NAME_LEN], target[DNS_MAX_NAME_LEN];
		size_t rdata, end, name_offset;
		uint16_t type, class, rdlen;
		dns_record_t *record = NULL;

		if (!read_name(response, offset, owner) ||
			*offset + 10 > response.len)
		{
			return FALSE;
		}
		type = read_u16(response.ptr + *offset);
		class = read_u16(response.ptr + *offset + 2);
		rdlen = read_u16(response.ptr + *offset + 8);
		*offset += 10;
		rdata = *offset;
		end = rdata + rdlen;
		if (end < rdata || end > response.len)
		{
			return FALSE;
		}
		if ((type == DNS_TYPE_A && rdlen != 4) ||
			(type == DNS_TYPE_AAAA && rdlen != 16))
		{
			return FALSE;
		}
		if (type == DNS_TYPE_CNAME)
		{
			name_offset = rdata;
			if (!read_name(response, &name_offset, target) ||
				name_offset != end || !*target)
			{
				return FALSE;
			}
		}
		if (i < answer_count && class == DNS_CLASS_IN &&
			(type == DNS_TYPE_CNAME || type == expected_type))
		{
			INIT(record,
				.owner = strdup(owner),
				.type = type,
			);
			if (type == DNS_TYPE_CNAME)
			{
				record->target = strdup(target);
			}
			else
			{
				record->address = host_create_from_chunk(
						type == DNS_TYPE_A ? AF_INET : AF_INET6,
						chunk_create(response.ptr + rdata, rdlen), 0);
				if (!record->address)
				{
					record_destroy(record);
					return FALSE;
				}
			}
			records->insert_last(records, record);
		}
		*offset = end;
	}
	return TRUE;
}

/**
 * Follow a unique, bounded CNAME chain and return its final owner.
 */
static char *canonical_name(linked_list_t *records, char *name)
{
	char *current = strdup(name), *seen[DNS_MAX_CNAME_DEPTH + 1] = {};
	enumerator_t *enumerator;
	dns_record_t *record;
	char *target;
	u_int depth, i;

	for (depth = 0; depth <= DNS_MAX_CNAME_DEPTH; depth++)
	{
		seen[depth] = current;
		target = NULL;
		enumerator = records->create_enumerator(records);
		while (enumerator->enumerate(enumerator, &record))
		{
			if (record->type == DNS_TYPE_CNAME &&
				strcaseeq(record->owner, current))
			{
				if (target && !strcaseeq(target, record->target))
				{
					target = NULL;
					break;
				}
				target = record->target;
			}
		}
		enumerator->destroy(enumerator);
		if (!target)
		{
			/* No CNAME is a valid final name. Multiple conflicting CNAMEs
			 * were converted to NULL above, detect those separately. */
			u_int matches = 0;
			char *first = NULL;

			enumerator = records->create_enumerator(records);
			while (enumerator->enumerate(enumerator, &record))
			{
				if (record->type == DNS_TYPE_CNAME &&
					strcaseeq(record->owner, current))
				{
					if (!first)
					{
						first = record->target;
					}
					else if (!strcaseeq(first, record->target))
					{
						matches = 2;
						break;
					}
					matches = max(matches, 1);
				}
			}
			enumerator->destroy(enumerator);
			if (matches > 1)
			{
				goto failed;
			}
			for (i = 0; i < depth; i++)
			{
				free(seen[i]);
			}
			return current;
		}
		if (depth == DNS_MAX_CNAME_DEPTH)
		{
			goto failed;
		}
		for (i = 0; i <= depth; i++)
		{
			if (strcaseeq(seen[i], target))
			{
				goto failed;
			}
		}
		current = strdup(target);
	}

failed:
	for (i = 0; i <= depth && i <= DNS_MAX_CNAME_DEPTH; i++)
	{
		free(seen[i]);
	}
	return NULL;
}

dot_dns_status_t dns_over_tls_parse_response(chunk_t response, char *name,
										 uint16_t type, uint16_t id,
										 linked_list_t **hosts, uint8_t *rcode)
{
	linked_list_t *records;
	enumerator_t *enumerator;
	dns_record_t *record;
	char question[DNS_MAX_NAME_LEN], *canonical;
	size_t offset = DNS_HEADER_LEN;
	uint16_t flags, qdcount, ancount, nscount, arcount, qtype, qclass;
	u_int total;

	*hosts = NULL;
	if (rcode)
	{
		*rcode = 0;
	}
	if (response.len < DNS_HEADER_LEN || read_u16(response.ptr) != id)
	{
		return DOT_DNS_ERROR;
	}
	flags = read_u16(response.ptr + 2);
	qdcount = read_u16(response.ptr + 4);
	ancount = read_u16(response.ptr + 6);
	nscount = read_u16(response.ptr + 8);
	arcount = read_u16(response.ptr + 10);
	total = (u_int)ancount + nscount + arcount;
	if (!(flags & 0x8000) || (flags & 0x7800) || (flags & 0x0200) ||
		qdcount != 1 || total > DNS_MAX_RECORDS ||
		(type != DNS_TYPE_A && type != DNS_TYPE_AAAA))
	{
		return DOT_DNS_ERROR;
	}
	if (!read_name(response, &offset, question) || offset + 4 > response.len)
	{
		return DOT_DNS_ERROR;
	}
	qtype = read_u16(response.ptr + offset);
	qclass = read_u16(response.ptr + offset + 2);
	offset += 4;
	if (!name_equals(question, name) || qtype != type || qclass != DNS_CLASS_IN)
	{
		return DOT_DNS_ERROR;
	}
	records = linked_list_create();
	if (!parse_records(response, &offset, total, ancount, type, records) ||
		offset != response.len)
	{
		records->destroy_function(records, (void*)record_destroy);
		return DOT_DNS_ERROR;
	}
	if (rcode)
	{
		*rcode = flags & 0x000f;
	}
	if ((flags & 0x000f) == 3)
	{
		records->destroy_function(records, (void*)record_destroy);
		return DOT_DNS_NXDOMAIN;
	}
	if (flags & 0x000f)
	{
		records->destroy_function(records, (void*)record_destroy);
		return DOT_DNS_SERVER_ERROR;
	}
	canonical = canonical_name(records, question);
	if (!canonical)
	{
		records->destroy_function(records, (void*)record_destroy);
		return DOT_DNS_ERROR;
	}
	*hosts = linked_list_create();
	enumerator = records->create_enumerator(records);
	while (enumerator->enumerate(enumerator, &record))
	{
		if (record->type == type && record->address &&
			strcaseeq(record->owner, canonical))
		{
			(*hosts)->insert_last(*hosts, record->address->clone(record->address));
		}
	}
	enumerator->destroy(enumerator);
	free(canonical);
	records->destroy_function(records, (void*)record_destroy);
	return DOT_DNS_SUCCESS;
}
