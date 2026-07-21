/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#define _GNU_SOURCE

#include "kernel_libipsec_socks.h"
#include "kernel_libipsec_socks_parser.h"
#include "kernel_libipsec_lwip_port.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <daemon.h>
#include <ipsec.h>
#include <attributes/attribute_handler.h>
#include <bus/listeners/listener.h>
#include <collections/linked_list.h>
#include <threading/condvar.h>
#include <threading/mutex.h>
#include <threading/thread.h>
#include <utils/utils/time.h>

#include <lwip/dns.h>
#include <lwip/init.h>
#include <lwip/ip.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define SOCKS5_DEFAULT_LISTEN "tcp://127.0.0.1:1080"
#define SOCKS5_DEFAULT_MTU 1400
#define SOCKS5_DEFAULT_MAX_CONNECTIONS 128
#define SOCKS5_DEFAULT_HANDSHAKE_TIMEOUT 10
#define SOCKS5_DEFAULT_CONNECT_TIMEOUT 30
#define SOCKS5_BUFFER_LIMIT 65535
#define SOCKS5_IO_CHUNK 4096
#define SOCKS5_PACKET_QUEUE_LIMIT 1024

typedef struct private_kernel_libipsec_socks_t private_kernel_libipsec_socks_t;
typedef struct socks_client_t socks_client_t;
typedef struct tunnel_t tunnel_t;

typedef struct {
	listener_t public;
	private_kernel_libipsec_socks_t *owner;
} socks_bus_listener_t;

typedef struct {
	attribute_handler_t public;
	private_kernel_libipsec_socks_t *owner;
} socks_attribute_handler_t;

typedef struct {
	uint8_t *ptr;
	size_t offset;
	size_t len;
	size_t capacity;
	size_t limit;
} byte_buffer_t;

typedef enum {
	CLIENT_GREETING,
	CLIENT_REQUEST,
	CLIENT_RESOLVING,
	CLIENT_CONNECTING,
	CLIENT_RELAY,
	CLIENT_FAILED,
	CLIENT_CLOSING,
	CLIENT_DEAD,
} client_state_t;

struct socks_client_t {
	private_kernel_libipsec_socks_t *backend;
	uint64_t id;
	int fd;
	client_state_t state;
	uint64_t deadline;
	byte_buffer_t upstream;
	byte_buffer_t control;
	byte_buffer_t downstream;
	bool close_after_write;
	bool local_eof;
	bool remote_eof;
	bool tcp_write_shutdown;
	bool socket_write_shutdown;
	bool dns_pending;
	struct tcp_pcb *pcb;
	uint32_t reqid;
	socks5_request_t request;
	host_t *destination;
};

struct tunnel_t {
	uint32_t ike_id;
	uint32_t child_id;
	uint32_t reqid;
	char *ike_name;
	char *child_name;
	linked_list_t *local_ts;
	linked_list_t *remote_ts;
	linked_list_t *vips;
};

typedef struct {
	uint32_t ike_id;
	host_t *server;
	u_int refs;
} dns_entry_t;

typedef enum {
	EVENT_PACKET,
	EVENT_TUNNEL_UP,
	EVENT_TUNNEL_DOWN,
	EVENT_IKE_REKEY,
	EVENT_IKE_DOWN,
	EVENT_DNS_ADD,
	EVENT_DNS_REMOVE,
	EVENT_STOP,
} event_type_t;

typedef struct {
	event_type_t type;
	union {
		ip_packet_t *packet;
		tunnel_t *tunnel;
		struct {
			uint32_t ike_id;
			uint32_t child_id;
		} down;
		struct {
			uint32_t old_ike_id;
			uint32_t new_ike_id;
		} rekey;
		uint32_t ike_id;
		struct {
			uint32_t ike_id;
			host_t *server;
		} dns;
	};
} socks_event_t;

struct private_kernel_libipsec_socks_t {
	kernel_libipsec_plain_t public;
	socks_bus_listener_t bus;
	socks_attribute_handler_t attribute;

	struct sockaddr_storage listen_addr;
	socklen_t listen_len;
	int listener;
	int notify[2];
	thread_t *thread;
	mutex_t *mutex;
	condvar_t *condvar;
	linked_list_t *events;
	u_int queued_packets;
	bool started;
	bool start_success;

	char *ike_name;
	char *child_name;
	host_t *source4;
	host_t *source6;
	linked_list_t *configured_dns;
	uint16_t mtu;
	u_int max_connections;
	uint32_t handshake_timeout;
	uint32_t connect_timeout;

	/* The following state is owned exclusively by the event thread. */
	struct netif netif;
	rng_t *rng;
	u8_t tcp_ext_id;
	linked_list_t *clients;
	linked_list_t *tunnels;
	linked_list_t *dns;
	uint64_t next_client_id;
	tunnel_t *selected;
	uint32_t selected_reqid;
	uint32_t selected_ike_id;
	host_t *selected_source4;
	host_t *selected_source6;
	bool selected_ready;
	u_int dns_server_count;
};

static uint64_t now_ms(void)
{
	timeval_t now;

	time_monotonic(&now);
	return (uint64_t)now.tv_sec * 1000 + now.tv_usec / 1000;
}

static bool buffer_reserve(byte_buffer_t *buffer, size_t additional)
{
	size_t capacity;
	uint8_t *ptr;

	if (additional > buffer->limit - buffer->len)
	{
		return FALSE;
	}
	if (buffer->offset &&
		buffer->capacity - buffer->offset - buffer->len < additional)
	{
		memmove(buffer->ptr, buffer->ptr + buffer->offset, buffer->len);
		buffer->offset = 0;
	}
	if (buffer->capacity - buffer->offset - buffer->len >= additional)
	{
		return TRUE;
	}
	capacity = buffer->capacity ? buffer->capacity : 256;
	while (capacity - buffer->len < additional && capacity < buffer->limit)
	{
		capacity = min(capacity * 2, buffer->limit);
	}
	if (capacity - buffer->len < additional)
	{
		return FALSE;
	}
	ptr = realloc(buffer->ptr, capacity);
	if (!ptr)
	{
		return FALSE;
	}
	buffer->ptr = ptr;
	buffer->capacity = capacity;
	return TRUE;
}

static bool buffer_append(byte_buffer_t *buffer, const void *data, size_t len)
{
	if (!buffer_reserve(buffer, len))
	{
		return FALSE;
	}
	memcpy(buffer->ptr + buffer->offset + buffer->len, data, len);
	buffer->len += len;
	return TRUE;
}

static void buffer_consume(byte_buffer_t *buffer, size_t len)
{
	if (len >= buffer->len)
	{
		buffer->offset = 0;
		buffer->len = 0;
		return;
	}
	buffer->offset += len;
	buffer->len -= len;
}

static void buffer_destroy(byte_buffer_t *buffer)
{
	free(buffer->ptr);
}

static void destroy_ts_list(linked_list_t *list)
{
	list->destroy_offset(list, offsetof(traffic_selector_t, destroy));
}

static void destroy_host_list(linked_list_t *list)
{
	list->destroy_offset(list, offsetof(host_t, destroy));
}

static void tunnel_destroy(tunnel_t *tunnel)
{
	free(tunnel->ike_name);
	free(tunnel->child_name);
	destroy_ts_list(tunnel->local_ts);
	destroy_ts_list(tunnel->remote_ts);
	destroy_host_list(tunnel->vips);
	free(tunnel);
}

static void dns_entry_destroy(dns_entry_t *entry)
{
	entry->server->destroy(entry->server);
	free(entry);
}

static void event_destroy(socks_event_t *event)
{
	switch (event->type)
	{
		case EVENT_PACKET:
			event->packet->destroy(event->packet);
			break;
		case EVENT_TUNNEL_UP:
			tunnel_destroy(event->tunnel);
			break;
		case EVENT_DNS_ADD:
		case EVENT_DNS_REMOVE:
			event->dns.server->destroy(event->dns.server);
			break;
		default:
			break;
	}
	free(event);
}

static bool set_fd_flags(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
	{
		return FALSE;
	}
	flags = fcntl(fd, F_GETFD);
	return flags != -1 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != -1;
}

static bool enqueue_event(private_kernel_libipsec_socks_t *this,
						  socks_event_t *event)
{
	char byte = 1;

	this->mutex->lock(this->mutex);
	if (event->type == EVENT_PACKET &&
		this->queued_packets >= SOCKS5_PACKET_QUEUE_LIMIT)
	{
		this->mutex->unlock(this->mutex);
		event_destroy(event);
		return FALSE;
	}
	this->events->insert_last(this->events, event);
	if (event->type == EVENT_PACKET)
	{
		this->queued_packets++;
	}
	ignore_result(write(this->notify[1], &byte, sizeof(byte)));
	this->mutex->unlock(this->mutex);
	return TRUE;
}

static bool parse_listener(char *uri, struct sockaddr_storage *storage,
						   socklen_t *len)
{
	char *copy, *address, *portstr, *end;
	long port;
	bool valid = FALSE;

	if (!strpfx(uri, "tcp://"))
	{
		return FALSE;
	}
	copy = strdup(uri + strlen("tcp://"));
	address = copy;
	if (*address == '[')
	{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)storage;

		end = strchr(++address, ']');
		if (!end || end[1] != ':' || !end[2])
		{
			goto done;
		}
		*end = '\0';
		portstr = end + 2;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, address, &sin6->sin6_addr) != 1 ||
			!IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr))
		{
			goto done;
		}
		*len = sizeof(*sin6);
	}
	else
	{
		struct sockaddr_in *sin = (struct sockaddr_in*)storage;
		uint8_t *bytes;

		portstr = strrchr(address, ':');
		if (!portstr || !portstr[1] || strchr(address, ':') != portstr)
		{
			goto done;
		}
		*portstr++ = '\0';
		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		if (inet_pton(AF_INET, address, &sin->sin_addr) != 1)
		{
			goto done;
		}
		bytes = (uint8_t*)&sin->sin_addr;
		if (bytes[0] != 127)
		{
			goto done;
		}
		*len = sizeof(*sin);
	}
	errno = 0;
	port = strtol(portstr, &end, 10);
	if (errno || *end || port < 1 || port > 65535)
	{
		goto done;
	}
	if (storage->ss_family == AF_INET)
	{
		((struct sockaddr_in*)storage)->sin_port = htons(port);
	}
	else
	{
		((struct sockaddr_in6*)storage)->sin6_port = htons(port);
	}
	valid = TRUE;

done:
	free(copy);
	return valid;
}

static bool parse_host_settings(char *value, host_t **v4, host_t **v6,
								linked_list_t *list, char *name)
{
	enumerator_t *enumerator;
	char *token;
	bool valid = TRUE;

	if (!value || !*value)
	{
		return TRUE;
	}
	enumerator = enumerator_create_token(value, ",", " ");
	while (enumerator->enumerate(enumerator, &token))
	{
		host_t *host = host_create_from_string(token, 0);

		if (!host || host->is_anyaddr(host))
		{
			DBG1(DBG_CFG, "invalid %s address '%s'", name, token);
			DESTROY_IF(host);
			valid = FALSE;
			break;
		}
		if (list)
		{
			if (list->get_count(list) >= DNS_MAX_SERVERS)
			{
				DBG1(DBG_CFG, "too many %s addresses (maximum %u)", name,
					  DNS_MAX_SERVERS);
				host->destroy(host);
				valid = FALSE;
				break;
			}
			list->insert_last(list, host);
		}
		else if (host->get_family(host) == AF_INET)
		{
			if (*v4)
			{
				DBG1(DBG_CFG, "multiple IPv4 %s addresses configured", name);
				host->destroy(host);
				valid = FALSE;
				break;
			}
			*v4 = host;
		}
		else
		{
			if (*v6)
			{
				DBG1(DBG_CFG, "multiple IPv6 %s addresses configured", name);
				host->destroy(host);
				valid = FALSE;
				break;
			}
			*v6 = host;
		}
	}
	enumerator->destroy(enumerator);
	return valid;
}

static void client_tunnel_lost(socks_client_t *client);
static void revalidate_clients(private_kernel_libipsec_socks_t *this);

static tunnel_t *tunnel_create(ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	enumerator_t *enumerator;
	traffic_selector_t *ts;
	host_t *vip;
	tunnel_t *tunnel;

	if (child_sa->get_mode(child_sa) != MODE_TUNNEL)
	{
		return NULL;
	}
	INIT(tunnel,
		.ike_id = ike_sa->get_unique_id(ike_sa),
		.child_id = child_sa->get_unique_id(child_sa),
		.reqid = child_sa->get_reqid(child_sa),
		.ike_name = strdup(ike_sa->get_name(ike_sa)),
		.child_name = strdup(child_sa->get_name(child_sa)),
		.local_ts = linked_list_create(),
		.remote_ts = linked_list_create(),
		.vips = linked_list_create(),
	);
	enumerator = child_sa->create_ts_enumerator(child_sa, TRUE);
	while (enumerator->enumerate(enumerator, &ts))
	{
		tunnel->local_ts->insert_last(tunnel->local_ts, ts->clone(ts));
	}
	enumerator->destroy(enumerator);
	enumerator = child_sa->create_ts_enumerator(child_sa, FALSE);
	while (enumerator->enumerate(enumerator, &ts))
	{
		tunnel->remote_ts->insert_last(tunnel->remote_ts, ts->clone(ts));
	}
	enumerator->destroy(enumerator);
	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, TRUE);
	while (enumerator->enumerate(enumerator, &vip))
	{
		tunnel->vips->insert_last(tunnel->vips, vip->clone(vip));
	}
	enumerator->destroy(enumerator);
	return tunnel;
}

static void queue_tunnel_up(private_kernel_libipsec_socks_t *this,
							ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	socks_event_t *event;
	tunnel_t *tunnel = tunnel_create(ike_sa, child_sa);

	if (!tunnel)
	{
		return;
	}
	INIT(event,
		.type = EVENT_TUNNEL_UP,
		.tunnel = tunnel,
	);
	enqueue_event(this, event);
}

static void queue_tunnel_down(private_kernel_libipsec_socks_t *this,
							  ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	socks_event_t *event;

	INIT(event,
		.type = EVENT_TUNNEL_DOWN,
		.down = {
			.ike_id = ike_sa->get_unique_id(ike_sa),
			.child_id = child_sa->get_unique_id(child_sa),
		},
	);
	enqueue_event(this, event);
}

static bool host_address_covered(linked_list_t *selectors, host_t *host)
{
	enumerator_t *enumerator;
	traffic_selector_t *ts;
	bool allowed = FALSE;

	enumerator = selectors->create_enumerator(selectors);
	while (enumerator->enumerate(enumerator, &ts))
	{
		if (ts->includes(ts, host))
		{
			allowed = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return allowed;
}

static bool selector_allows(linked_list_t *selectors, host_t *host,
							uint8_t protocol, uint16_t port)
{
	enumerator_t *enumerator;
	traffic_selector_t *ts;
	bool allowed = FALSE;

	enumerator = selectors->create_enumerator(selectors);
	while (enumerator->enumerate(enumerator, &ts))
	{
		uint8_t ts_protocol = ts->get_protocol(ts);

		if (ts->includes(ts, host) &&
			(!ts_protocol || ts_protocol == protocol) &&
			port >= ts->get_from_port(ts) && port <= ts->get_to_port(ts))
		{
			allowed = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return allowed;
}

static host_t *singleton_source(linked_list_t *selectors, int family)
{
	enumerator_t *enumerator;
	traffic_selector_t *ts;
	host_t *host = NULL;
	ts_type_t type = family == AF_INET ? TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE;

	enumerator = selectors->create_enumerator(selectors);
	while (enumerator->enumerate(enumerator, &ts))
	{
		chunk_t from, to;

		if (ts->get_type(ts) != type)
		{
			continue;
		}
		from = ts->get_from_address(ts);
		to = ts->get_to_address(ts);
		if (chunk_equals(from, to))
		{
			host_t *candidate = host_create_from_chunk(family, from, 0);

			if (!candidate)
			{
				DESTROY_IF(host);
				host = NULL;
				break;
			}
			if (!host)
			{
				host = candidate;
			}
			else if (!host->ip_equals(host, candidate))
			{
				candidate->destroy(candidate);
				host->destroy(host);
				host = NULL;
				break;
			}
			else
			{
				candidate->destroy(candidate);
			}
		}
	}
	enumerator->destroy(enumerator);
	return host;
}

static host_t *derived_source(tunnel_t *tunnel, int family)
{
	enumerator_t *enumerator;
	host_t *vip, *source = NULL;

	enumerator = tunnel->vips->create_enumerator(tunnel->vips);
	while (enumerator->enumerate(enumerator, &vip))
	{
		if (vip->get_family(vip) == family &&
			host_address_covered(tunnel->local_ts, vip))
		{
			source = vip->clone(vip);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return source ?: singleton_source(tunnel->local_ts, family);
}

static bool select_sources(private_kernel_libipsec_socks_t *this,
						   tunnel_t *tunnel, host_t **source4, host_t **source6)
{
	if (this->source4)
	{
		if (!host_address_covered(tunnel->local_ts, this->source4))
		{
			DBG1(DBG_KNL, "configured SOCKS5 source %H is not covered by "
				 "the selected CHILD_SA's local traffic selectors",
				 this->source4);
			return FALSE;
		}
		*source4 = this->source4->clone(this->source4);
	}
	else
	{
		*source4 = derived_source(tunnel, AF_INET);
	}
	if (this->source6)
	{
		if (!host_address_covered(tunnel->local_ts, this->source6))
		{
			DBG1(DBG_KNL, "configured SOCKS5 source %H is not covered by "
				 "the selected CHILD_SA's local traffic selectors",
				 this->source6);
			DESTROY_IF(*source4);
			*source4 = NULL;
			return FALSE;
		}
		*source6 = this->source6->clone(this->source6);
	}
	else
	{
		*source6 = derived_source(tunnel, AF_INET6);
	}
	return *source4 || *source6;
}

static bool hosts_equal(host_t *a, host_t *b)
{
	return (!a && !b) || (a && b && a->ip_equals(a, b));
}

static void host_to_lwip(host_t *host, ip_addr_t *address)
{
	chunk_t chunk = host->get_address(host);

	memset(address, 0, sizeof(*address));
	if (host->get_family(host) == AF_INET)
	{
		IP_SET_TYPE_VAL(*address, IPADDR_TYPE_V4);
		memcpy(&ip_2_ip4(address)->addr, chunk.ptr, 4);
	}
	else
	{
		IP_SET_TYPE_VAL(*address, IPADDR_TYPE_V6);
		memcpy(ip_2_ip6(address)->addr, chunk.ptr, 16);
	}
}

static host_t *lwip_to_host(const ip_addr_t *address, uint16_t port)
{
	if (IP_IS_V6(address))
	{
		return host_create_from_chunk(AF_INET6,
				chunk_create((uint8_t*)ip_2_ip6(address)->addr, 16), port);
	}
	return host_create_from_chunk(AF_INET,
				chunk_create((uint8_t*)&ip_2_ip4(address)->addr, 4), port);
}

static void configure_netif_sources(private_kernel_libipsec_socks_t *this)
{
	ip4_addr_t address4, netmask4, gateway4;
	ip6_addr_t address6;

	ip4_addr_set_zero(&address4);
	ip4_addr_set_zero(&netmask4);
	ip4_addr_set_zero(&gateway4);
	if (this->selected_source4)
	{
		chunk_t address = this->selected_source4->get_address(
											this->selected_source4);
		memcpy(&address4.addr, address.ptr, 4);
		netmask4.addr = 0xffffffffU;
	}
	netif_set_addr(&this->netif, &address4, &netmask4, &gateway4);
	ip6_addr_set_zero(&address6);
	if (this->selected_source6)
	{
		chunk_t address = this->selected_source6->get_address(
											this->selected_source6);
		memcpy(address6.addr, address.ptr, 16);
		netif_ip6_addr_set(&this->netif, 0, &address6);
		netif_ip6_addr_set_state(&this->netif, 0, IP6_ADDR_PREFERRED);
	}
	else
	{
		netif_ip6_addr_set(&this->netif, 0, &address6);
		netif_ip6_addr_set_state(&this->netif, 0, IP6_ADDR_INVALID);
	}
}

static bool dns_server_usable(private_kernel_libipsec_socks_t *this,
							  host_t *server)
{
	host_t *source = server->get_family(server) == AF_INET ?
					 this->selected_source4 : this->selected_source6;

	return source && selector_allows(this->selected->remote_ts, server,
									 IPPROTO_UDP, 53);
}

static bool dns_server_duplicate(ip_addr_t *servers, u_int count,
								 const ip_addr_t *server)
{
	u_int i;

	for (i = 0; i < count; i++)
	{
		if (ip_addr_cmp(&servers[i], server))
		{
			return TRUE;
		}
	}
	return FALSE;
}

static void configure_dns(private_kernel_libipsec_socks_t *this)
{
	ip_addr_t servers[DNS_MAX_SERVERS];
	enumerator_t *enumerator;
	host_t *server;
	dns_entry_t *entry;
	u_int count = 0, i;

	if (!this->selected_ready)
	{
		for (i = 0; i < DNS_MAX_SERVERS; i++)
		{
			dns_setserver(i, NULL);
		}
		this->dns_server_count = 0;
		return;
	}
	if (this->configured_dns->get_count(this->configured_dns))
	{
		enumerator = this->configured_dns->create_enumerator(
											this->configured_dns);
		while (enumerator->enumerate(enumerator, &server))
		{
			ip_addr_t address;

			if (!dns_server_usable(this, server))
			{
				DBG1(DBG_KNL, "SOCKS5 DNS server %H is not reachable through "
					 "the selected CHILD_SA", server);
				continue;
			}
			host_to_lwip(server, &address);
			if (!dns_server_duplicate(servers, count, &address))
			{
				servers[count++] = address;
			}
		}
		enumerator->destroy(enumerator);
	}
	else
	{
		enumerator = this->dns->create_enumerator(this->dns);
		while (count < DNS_MAX_SERVERS &&
			   enumerator->enumerate(enumerator, &entry))
		{
			ip_addr_t address;

			if (entry->ike_id != this->selected_ike_id ||
				!dns_server_usable(this, entry->server))
			{
				continue;
			}
			host_to_lwip(entry->server, &address);
			if (!dns_server_duplicate(servers, count, &address))
			{
				servers[count++] = address;
			}
		}
		enumerator->destroy(enumerator);
	}
	for (i = 0; i < DNS_MAX_SERVERS; i++)
	{
		dns_setserver(i, i < count ? &servers[i] : NULL);
	}
	this->dns_server_count = count;
}

static bool tunnel_matches(private_kernel_libipsec_socks_t *this,
						   tunnel_t *tunnel)
{
	return (!this->ike_name || streq(this->ike_name, tunnel->ike_name)) &&
		   (!this->child_name || streq(this->child_name, tunnel->child_name));
}

static void recompute_selection(private_kernel_libipsec_socks_t *this)
{
	enumerator_t *enumerator;
	tunnel_t *candidate = NULL, *tunnel;
	socks_client_t *client;
	host_t *source4 = NULL, *source6 = NULL;
	bool ambiguous = FALSE, ready = FALSE, preserve;
	uint32_t old_reqid = this->selected_reqid;
	uint32_t old_ike_id = this->selected_ike_id;

	enumerator = this->tunnels->create_enumerator(this->tunnels);
	while (enumerator->enumerate(enumerator, &tunnel))
	{
		if (!tunnel_matches(this, tunnel))
		{
			continue;
		}
		if (!candidate)
		{
			candidate = tunnel;
			continue;
		}
		if (candidate->reqid != tunnel->reqid ||
			candidate->ike_id != tunnel->ike_id)
		{
			ambiguous = TRUE;
			break;
		}
		/* Prefer the newly created SA while both sides of a rekey exist. */
		if (tunnel->child_id > candidate->child_id)
		{
			candidate = tunnel;
		}
	}
	enumerator->destroy(enumerator);
	if (candidate && !ambiguous)
	{
		ready = select_sources(this, candidate, &source4, &source6);
	}
	preserve = this->selected_ready && ready &&
			   old_reqid == candidate->reqid && old_ike_id == candidate->ike_id &&
			   hosts_equal(this->selected_source4, source4) &&
			   hosts_equal(this->selected_source6, source6);
	if (this->selected_ready && !preserve)
	{
		enumerator = this->clients->create_enumerator(this->clients);
		while (enumerator->enumerate(enumerator, &client))
		{
			client_tunnel_lost(client);
		}
		enumerator->destroy(enumerator);
	}
	DESTROY_IF(this->selected_source4);
	DESTROY_IF(this->selected_source6);
	this->selected = ready ? candidate : NULL;
	this->selected_reqid = ready ? candidate->reqid : 0;
	this->selected_ike_id = ready ? candidate->ike_id : 0;
	this->selected_source4 = source4;
	this->selected_source6 = source6;
	this->selected_ready = ready;
	configure_netif_sources(this);
	configure_dns(this);
	if (ambiguous)
	{
		DBG1(DBG_KNL, "multiple eligible kernel-libipsec tunnels; SOCKS5 "
			 "proxy disabled until selection is unambiguous");
	}
	else if (!ready)
	{
		DBG2(DBG_KNL, "no eligible kernel-libipsec tunnel with a usable "
			 "SOCKS5 source address");
	}
	else if (preserve)
	{
		revalidate_clients(this);
	}
}

static void add_tunnel(private_kernel_libipsec_socks_t *this,
					   tunnel_t *tunnel)
{
	enumerator_t *enumerator;
	tunnel_t *current;

	enumerator = this->tunnels->create_enumerator(this->tunnels);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (current->ike_id == tunnel->ike_id &&
			current->child_id == tunnel->child_id)
		{
			if (this->selected == current)
			{
				this->selected = NULL;
			}
			this->tunnels->remove_at(this->tunnels, enumerator);
			tunnel_destroy(current);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->tunnels->insert_last(this->tunnels, tunnel);
	recompute_selection(this);
}

static void remove_tunnel(private_kernel_libipsec_socks_t *this,
						  uint32_t ike_id, uint32_t child_id)
{
	enumerator_t *enumerator;
	tunnel_t *tunnel;

	enumerator = this->tunnels->create_enumerator(this->tunnels);
	while (enumerator->enumerate(enumerator, &tunnel))
	{
		if (tunnel->ike_id == ike_id && tunnel->child_id == child_id)
		{
			if (this->selected == tunnel)
			{
				this->selected = NULL;
			}
			this->tunnels->remove_at(this->tunnels, enumerator);
			tunnel_destroy(tunnel);
			break;
		}
	}
	enumerator->destroy(enumerator);
	recompute_selection(this);
}

static void remove_ike(private_kernel_libipsec_socks_t *this, uint32_t ike_id)
{
	enumerator_t *enumerator;
	tunnel_t *tunnel;
	dns_entry_t *dns;

	enumerator = this->tunnels->create_enumerator(this->tunnels);
	while (enumerator->enumerate(enumerator, &tunnel))
	{
		if (tunnel->ike_id == ike_id)
		{
			if (this->selected == tunnel)
			{
				this->selected = NULL;
			}
			this->tunnels->remove_at(this->tunnels, enumerator);
			tunnel_destroy(tunnel);
		}
	}
	enumerator->destroy(enumerator);
	enumerator = this->dns->create_enumerator(this->dns);
	while (enumerator->enumerate(enumerator, &dns))
	{
		if (dns->ike_id == ike_id)
		{
			this->dns->remove_at(this->dns, enumerator);
			dns_entry_destroy(dns);
		}
	}
	enumerator->destroy(enumerator);
	recompute_selection(this);
}

/**
 * Migrate state that follows CHILD_SAs and attributes across an IKE rekey.
 */
static void migrate_ike(private_kernel_libipsec_socks_t *this,
						uint32_t old_ike_id, uint32_t new_ike_id)
{
	enumerator_t *enumerator;
	tunnel_t *tunnel;
	dns_entry_t *dns;
	bool changed = FALSE;

	if (old_ike_id == new_ike_id)
	{
		return;
	}
	enumerator = this->tunnels->create_enumerator(this->tunnels);
	while (enumerator->enumerate(enumerator, &tunnel))
	{
		if (tunnel->ike_id == old_ike_id)
		{
			tunnel->ike_id = new_ike_id;
			changed = TRUE;
		}
	}
	enumerator->destroy(enumerator);
	enumerator = this->dns->create_enumerator(this->dns);
	while (enumerator->enumerate(enumerator, &dns))
	{
		if (dns->ike_id == old_ike_id)
		{
			dns->ike_id = new_ike_id;
			changed = TRUE;
		}
	}
	enumerator->destroy(enumerator);
	if (this->selected_ike_id == old_ike_id)
	{
		/* Update this before recomputing so existing clients are preserved. */
		this->selected_ike_id = new_ike_id;
		changed = TRUE;
	}
	if (changed)
	{
		recompute_selection(this);
	}
}

static void add_dns(private_kernel_libipsec_socks_t *this, uint32_t ike_id,
					host_t *server)
{
	enumerator_t *enumerator;
	dns_entry_t *entry;

	enumerator = this->dns->create_enumerator(this->dns);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->ike_id == ike_id && entry->server->ip_equals(entry->server,
															 server))
		{
			entry->refs++;
			server->destroy(server);
			enumerator->destroy(enumerator);
			configure_dns(this);
			return;
		}
	}
	enumerator->destroy(enumerator);
	INIT(entry,
		.ike_id = ike_id,
		.server = server,
		.refs = 1,
	);
	this->dns->insert_last(this->dns, entry);
	configure_dns(this);
}

static void remove_dns(private_kernel_libipsec_socks_t *this, uint32_t ike_id,
					   host_t *server)
{
	enumerator_t *enumerator;
	dns_entry_t *entry;

	enumerator = this->dns->create_enumerator(this->dns);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->ike_id == ike_id && entry->server->ip_equals(entry->server,
															 server))
		{
			if (!--entry->refs)
			{
				this->dns->remove_at(this->dns, enumerator);
				dns_entry_destroy(entry);
			}
			break;
		}
	}
	enumerator->destroy(enumerator);
	server->destroy(server);
	configure_dns(this);
}

static void queue_dns(private_kernel_libipsec_socks_t *this, event_type_t type,
					  ike_sa_t *ike_sa, host_t *server)
{
	socks_event_t *event;

	INIT(event,
		.type = type,
		.dns = {
			.ike_id = ike_sa->get_unique_id(ike_sa),
			.server = server,
		},
	);
	enqueue_event(this, event);
}

static void refresh_ike(private_kernel_libipsec_socks_t *this,
						ike_sa_t *ike_sa)
{
	enumerator_t *enumerator;
	child_sa_t *child_sa;

	enumerator = ike_sa->create_child_sa_enumerator(ike_sa);
	while (enumerator->enumerate(enumerator, &child_sa))
	{
		switch (child_sa->get_state(child_sa))
		{
			case CHILD_INSTALLED:
			case CHILD_REKEYING:
			case CHILD_REKEYED:
				queue_tunnel_up(this, ike_sa, child_sa);
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);
}

METHOD(listener_t, child_updown, bool,
	socks_bus_listener_t *listener, ike_sa_t *ike_sa, child_sa_t *child_sa,
	bool up)
{
	if (up)
	{
		queue_tunnel_up(listener->owner, ike_sa, child_sa);
	}
	else
	{
		queue_tunnel_down(listener->owner, ike_sa, child_sa);
	}
	return TRUE;
}

METHOD(listener_t, child_rekey, bool,
	socks_bus_listener_t *listener, ike_sa_t *ike_sa, child_sa_t *old,
	child_sa_t *new)
{
	/* Add before removing so a normal rekey never creates a no-tunnel gap. */
	queue_tunnel_up(listener->owner, ike_sa, new);
	queue_tunnel_down(listener->owner, ike_sa, old);
	return TRUE;
}

METHOD(listener_t, ike_rekey, bool,
	socks_bus_listener_t *listener, ike_sa_t *old, ike_sa_t *new)
{
	socks_event_t *event;
	uint32_t old_ike_id = old->get_unique_id(old);
	uint32_t new_ike_id = new->get_unique_id(new);

	if (old_ike_id == new_ike_id)
	{
		return TRUE;
	}
	INIT(event,
		.type = EVENT_IKE_REKEY,
		.rekey = {
			.old_ike_id = old_ike_id,
			.new_ike_id = new_ike_id,
		},
	);
	enqueue_event(listener->owner, event);
	return TRUE;
}

METHOD(listener_t, ike_updown, bool,
	socks_bus_listener_t *listener, ike_sa_t *ike_sa, bool up)
{
	if (!up)
	{
		socks_event_t *event;

		INIT(event,
			.type = EVENT_IKE_DOWN,
			.ike_id = ike_sa->get_unique_id(ike_sa),
		);
		enqueue_event(listener->owner, event);
	}
	return TRUE;
}

METHOD(listener_t, assign_vips, bool,
	socks_bus_listener_t *listener, ike_sa_t *ike_sa, bool assign)
{
	if (assign)
	{
		refresh_ike(listener->owner, ike_sa);
	}
	return TRUE;
}

METHOD(listener_t, handle_vips, bool,
	socks_bus_listener_t *listener, ike_sa_t *ike_sa, bool handle)
{
	if (handle)
	{
		refresh_ike(listener->owner, ike_sa);
	}
	return TRUE;
}

METHOD(attribute_handler_t, handle_attribute, bool,
	socks_attribute_handler_t *handler, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	host_t *server;
	int family;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			family = AF_INET;
			break;
		case INTERNAL_IP6_DNS:
			family = AF_INET6;
			break;
		default:
			return FALSE;
	}
	server = host_create_from_chunk(family, data, 0);
	if (!server || server->is_anyaddr(server))
	{
		DESTROY_IF(server);
		return FALSE;
	}
	queue_dns(handler->owner, EVENT_DNS_ADD, ike_sa, server);
	return TRUE;
}

METHOD(attribute_handler_t, release_attribute, void,
	socks_attribute_handler_t *handler, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	host_t *server;
	int family;

	if (type == INTERNAL_IP4_DNS)
	{
		family = AF_INET;
	}
	else if (type == INTERNAL_IP6_DNS)
	{
		family = AF_INET6;
	}
	else
	{
		return;
	}
	server = host_create_from_chunk(family, data, 0);
	if (server)
	{
		queue_dns(handler->owner, EVENT_DNS_REMOVE, ike_sa, server);
	}
}

typedef struct {
	enumerator_t public;
	u_int next;
} dns_attribute_enumerator_t;

METHOD(enumerator_t, enumerate_dns_attribute, bool,
	dns_attribute_enumerator_t *this, va_list args)
{
	configuration_attribute_type_t *type;
	chunk_t *data;

	VA_ARGS_VGET(args, type, data);
	if (this->next == 0)
	{
		*type = INTERNAL_IP4_DNS;
	}
	else if (this->next == 1)
	{
		*type = INTERNAL_IP6_DNS;
	}
	else
	{
		return FALSE;
	}
	this->next++;
	*data = chunk_empty;
	return TRUE;
}

METHOD(attribute_handler_t, create_attribute_enumerator, enumerator_t*,
	socks_attribute_handler_t *handler, ike_sa_t *ike_sa,
	linked_list_t *vips)
{
	dns_attribute_enumerator_t *enumerator;

	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _enumerate_dns_attribute,
			.destroy = (void*)free,
		},
	);
	return &enumerator->public;
}

static void scan_existing_sas(private_kernel_libipsec_socks_t *this)
{
	enumerator_t *ikes, *attributes;
	ike_sa_t *ike_sa;
	configuration_attribute_type_t type;
	chunk_t data;
	bool handled;

	ikes = charon->controller->create_ike_sa_enumerator(charon->controller,
													  FALSE);
	while (ikes->enumerate(ikes, &ike_sa))
	{
		refresh_ike(this, ike_sa);
		attributes = ike_sa->create_attribute_enumerator(ike_sa);
		while (attributes->enumerate(attributes, &type, &data, &handled))
		{
			host_t *server = NULL;

			if (type == INTERNAL_IP4_DNS)
			{
				server = host_create_from_chunk(AF_INET, data, 0);
			}
			else if (type == INTERNAL_IP6_DNS)
			{
				server = host_create_from_chunk(AF_INET6, data, 0);
			}
			if (server && !server->is_anyaddr(server))
			{
				queue_dns(this, EVENT_DNS_ADD, ike_sa, server);
			}
			else
			{
				DESTROY_IF(server);
			}
		}
		attributes->destroy(attributes);
	}
	ikes->destroy(ikes);
}

static void pump_upstream(socks_client_t *client);

static void close_client_fd(socks_client_t *client)
{
	if (client->fd >= 0)
	{
		close(client->fd);
		client->fd = -1;
	}
}

static void detach_pcb(socks_client_t *client, bool abort_connection)
{
	struct tcp_pcb *pcb = client->pcb;

	if (!pcb)
	{
		return;
	}
	client->pcb = NULL;
	tcp_arg(pcb, NULL);
	tcp_recv(pcb, NULL);
	tcp_sent(pcb, NULL);
	tcp_err(pcb, NULL);
	tcp_poll(pcb, NULL, 0);
	tcp_ext_arg_set(pcb, client->backend->tcp_ext_id, NULL);
	if (abort_connection)
	{
		tcp_abort(pcb);
	}
}

static void client_destroy(socks_client_t *client)
{
	detach_pcb(client, TRUE);
	close_client_fd(client);
	DESTROY_IF(client->destination);
	buffer_destroy(&client->upstream);
	buffer_destroy(&client->control);
	buffer_destroy(&client->downstream);
	free(client);
}

static void client_dead(socks_client_t *client)
{
	detach_pcb(client, TRUE);
	close_client_fd(client);
	client->state = CLIENT_DEAD;
}

static bool append_method_reply(socks_client_t *client, uint8_t method)
{
	uint8_t reply[] = { SOCKS5_VERSION, method };

	return buffer_append(&client->control, reply, sizeof(reply));
}

static bool append_socks_reply(socks_client_t *client, uint8_t code,
							   const ip_addr_t *bound, uint16_t port)
{
	uint8_t reply[22] = { SOCKS5_VERSION, code, 0, SOCKS5_ATYP_IPV4 };
	size_t len = 10;

	if (bound && IP_IS_V6(bound))
	{
		reply[3] = SOCKS5_ATYP_IPV6;
		memcpy(reply + 4, ip_2_ip6(bound)->addr, 16);
		len = 22;
	}
	else if (bound)
	{
		memcpy(reply + 4, &ip_2_ip4(bound)->addr, 4);
	}
	reply[len - 2] = port >> 8;
	reply[len - 1] = port;
	return buffer_append(&client->control, reply, len);
}

static uint8_t error_reply(err_t error)
{
	switch (error)
	{
		case ERR_RTE:
			return SOCKS5_REP_NETWORK_UNREACHABLE;
		case ERR_TIMEOUT:
			return SOCKS5_REP_HOST_UNREACHABLE;
		case ERR_RST:
			return SOCKS5_REP_CONNECTION_REFUSED;
		case ERR_CONN:
			return SOCKS5_REP_CONNECTION_REFUSED;
		default:
			return SOCKS5_REP_GENERAL_FAILURE;
	}
}

static void client_fail(socks_client_t *client, uint8_t reply)
{
	if (client->state == CLIENT_RELAY || client->state == CLIENT_CLOSING)
	{
		client_dead(client);
		return;
	}
	if (client->state == CLIENT_FAILED || client->state == CLIENT_DEAD)
	{
		return;
	}
	detach_pcb(client, TRUE);
	if (client->fd < 0 || !append_socks_reply(client, reply, NULL, 0))
	{
		client_dead(client);
		return;
	}
	client->state = CLIENT_FAILED;
	client->close_after_write = TRUE;
}

static void pcb_destroyed(u8_t id, void *data)
{
	socks_client_t *client = data;

	if (client)
	{
		client->pcb = NULL;
		if (client->state == CLIENT_CLOSING)
		{
			client->state = CLIENT_DEAD;
		}
	}
}

static const struct tcp_ext_arg_callbacks pcb_ext_callbacks = {
	.destroy = pcb_destroyed,
};

static err_t tcp_receive(void *arg, struct tcp_pcb *pcb, struct pbuf *p,
					 err_t error)
{
	socks_client_t *client = arg;

	if (!p)
	{
		client->remote_eof = TRUE;
		if (!client->downstream.len && client->fd >= 0 &&
			!client->socket_write_shutdown)
		{
			shutdown(client->fd, SHUT_WR);
			client->socket_write_shutdown = TRUE;
		}
		return ERR_OK;
	}
	if (error != ERR_OK || client->state != CLIENT_RELAY)
	{
		return ERR_VAL;
	}
	if (!buffer_reserve(&client->downstream, p->tot_len))
	{
		/* Returning ERR_MEM leaves the pbuf with lwIP for a later retry. */
		return ERR_MEM;
	}
	pbuf_copy_partial(p,
		client->downstream.ptr + client->downstream.offset +
		client->downstream.len, p->tot_len, 0);
	client->downstream.len += p->tot_len;
	pbuf_free(p);
	return ERR_OK;
}

static err_t tcp_data_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
	socks_client_t *client = arg;

	pump_upstream(client);
	return ERR_OK;
}

static err_t tcp_poll_client(void *arg, struct tcp_pcb *pcb)
{
	socks_client_t *client = arg;

	pump_upstream(client);
	return ERR_OK;
}

static void tcp_error(void *arg, err_t error)
{
	socks_client_t *client = arg;

	client->pcb = NULL;
	if (client->state == CLIENT_CONNECTING)
	{
		client_fail(client, error_reply(error));
	}
	else
	{
		client_dead(client);
	}
}

static err_t tcp_connected(void *arg, struct tcp_pcb *pcb, err_t error)
{
	socks_client_t *client = arg;

	if (error != ERR_OK)
	{
		client_fail(client, error_reply(error));
		return ERR_OK;
	}
	if (client->state != CLIENT_CONNECTING)
	{
		return ERR_ABRT;
	}
	client->state = CLIENT_RELAY;
	client->deadline = 0;
	if (!append_socks_reply(client, SOCKS5_REP_SUCCESS, &pcb->local_ip,
							  pcb->local_port))
	{
		client_dead(client);
		return ERR_ABRT;
	}
	pump_upstream(client);
	return ERR_OK;
}

static void pump_upstream(socks_client_t *client)
{
	struct tcp_pcb *pcb = client->pcb;
	bool wrote = FALSE;

	if (!pcb || client->state != CLIENT_RELAY)
	{
		return;
	}
	while (client->upstream.len && tcp_sndbuf(pcb))
	{
		u16_t len = min(client->upstream.len, tcp_sndbuf(pcb));
		err_t error;

		error = tcp_write(pcb, client->upstream.ptr + client->upstream.offset,
						  len, TCP_WRITE_FLAG_COPY);
		if (error == ERR_MEM)
		{
			break;
		}
		if (error != ERR_OK)
		{
			client_dead(client);
			return;
		}
		buffer_consume(&client->upstream, len);
		wrote = TRUE;
	}
	if (wrote)
	{
		tcp_output(pcb);
	}
	if (client->local_eof && !client->upstream.len &&
		!client->tcp_write_shutdown)
	{
		err_t error = tcp_shutdown(pcb, 0, 1);

		if (error == ERR_OK || error == ERR_CONN)
		{
			client->tcp_write_shutdown = TRUE;
		}
		else if (error != ERR_MEM)
		{
			client_dead(client);
		}
	}
}

static void write_client(socks_client_t *client)
{
	ssize_t written;

	while (client->fd >= 0 && client->control.len)
	{
		written = send(client->fd,
					   client->control.ptr + client->control.offset,
					   client->control.len, MSG_NOSIGNAL);
		if (written > 0)
		{
			buffer_consume(&client->control, written);
			continue;
		}
		if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		{
			return;
		}
		client_dead(client);
		return;
	}
	if (client->close_after_write && !client->control.len)
	{
		client_dead(client);
		return;
	}
	while (client->fd >= 0 && client->downstream.len)
	{
		written = send(client->fd,
					   client->downstream.ptr + client->downstream.offset,
					   client->downstream.len, MSG_NOSIGNAL);
		if (written > 0)
		{
			buffer_consume(&client->downstream, written);
			if (client->pcb)
			{
				tcp_recved(client->pcb, written);
				tcp_output(client->pcb);
			}
			continue;
		}
		if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		{
			return;
		}
		client_dead(client);
		return;
	}
	if (client->remote_eof && !client->downstream.len && client->fd >= 0 &&
		!client->socket_write_shutdown)
	{
		shutdown(client->fd, SHUT_WR);
		client->socket_write_shutdown = TRUE;
	}
	if (client->remote_eof && client->local_eof &&
		!client->downstream.len && !client->upstream.len)
	{
		close_client_fd(client);
		client->state = client->pcb ? CLIENT_CLOSING : CLIENT_DEAD;
		client->deadline = now_ms() +
						   (uint64_t)client->backend->connect_timeout * 1000;
	}
}

static void start_address(socks_client_t *client, const ip_addr_t *destination)
{
	private_kernel_libipsec_socks_t *this = client->backend;
	host_t *remote, *source;
	struct tcp_pcb *pcb;
	err_t error;

	if (!this->selected_ready ||
		(client->reqid && client->reqid != this->selected_reqid))
	{
		client_fail(client, SOCKS5_REP_NETWORK_UNREACHABLE);
		return;
	}
	remote = lwip_to_host(destination, client->request.port);
	source = remote->get_family(remote) == AF_INET ?
			 this->selected_source4 : this->selected_source6;
	if (!source)
	{
		remote->destroy(remote);
		client_fail(client, SOCKS5_REP_NETWORK_UNREACHABLE);
		return;
	}
	if (!selector_allows(this->selected->remote_ts, remote, IPPROTO_TCP,
						 client->request.port))
	{
		remote->destroy(remote);
		client_fail(client, SOCKS5_REP_POLICY_DENIED);
		return;
	}
	pcb = tcp_new_ip_type(IP_IS_V6(destination) ? IPADDR_TYPE_V6 :
														 IPADDR_TYPE_V4);
	if (!pcb)
	{
		remote->destroy(remote);
		client_fail(client, SOCKS5_REP_GENERAL_FAILURE);
		return;
	}
	client->pcb = pcb;
	client->reqid = this->selected_reqid;
	DESTROY_IF(client->destination);
	client->destination = remote;
	{
		ip_addr_t local;

		host_to_lwip(source, &local);
		error = tcp_bind(pcb, &local, 0);
	}
	if (error != ERR_OK ||
		!selector_allows(this->selected->local_ts, source, IPPROTO_TCP,
						 pcb->local_port))
	{
		detach_pcb(client, TRUE);
		client_fail(client, error == ERR_OK ? SOCKS5_REP_POLICY_DENIED :
											 error_reply(error));
		return;
	}
	tcp_bind_netif(pcb, &this->netif);
	tcp_arg(pcb, client);
	tcp_recv(pcb, tcp_receive);
	tcp_sent(pcb, tcp_data_sent);
	tcp_err(pcb, tcp_error);
	tcp_poll(pcb, tcp_poll_client, 2);
	tcp_ext_arg_set_callbacks(pcb, this->tcp_ext_id, &pcb_ext_callbacks);
	tcp_ext_arg_set(pcb, this->tcp_ext_id, client);
	tcp_nagle_disable(pcb);
	client->state = CLIENT_CONNECTING;
	client->deadline = now_ms() + (uint64_t)this->connect_timeout * 1000;
	error = tcp_connect(pcb, destination, client->request.port, tcp_connected);
	if (error != ERR_OK)
	{
		detach_pcb(client, TRUE);
		client_fail(client, error_reply(error));
	}
}

static void dns_result(const char *name, const ip_addr_t *address, void *arg)
{
	socks_client_t *client = arg;

	client->dns_pending = FALSE;
	if (client->state != CLIENT_RESOLVING)
	{
		return;
	}
	if (!address)
	{
		client_fail(client, SOCKS5_REP_HOST_UNREACHABLE);
		return;
	}
	start_address(client, address);
}

static void start_domain(socks_client_t *client)
{
	private_kernel_libipsec_socks_t *this = client->backend;
	enumerator_t *enumerator;
	traffic_selector_t *ts;
	ip_addr_t address;
	u8_t type;
	err_t error;
	bool ipv4 = FALSE, ipv6 = FALSE;

	if (!this->selected_ready)
	{
		client_fail(client, SOCKS5_REP_NETWORK_UNREACHABLE);
		return;
	}
	if (!this->dns_server_count)
	{
		client_fail(client, SOCKS5_REP_HOST_UNREACHABLE);
		return;
	}
	/* Prefer IPv6 only if the selected policy actually offers that path. */
	enumerator = this->selected->remote_ts->create_enumerator(
										this->selected->remote_ts);
	while (enumerator->enumerate(enumerator, &ts))
	{
		uint8_t protocol = ts->get_protocol(ts);

		if ((protocol && protocol != IPPROTO_TCP) ||
			client->request.port < ts->get_from_port(ts) ||
			client->request.port > ts->get_to_port(ts))
		{
			continue;
		}
		ipv4 |= ts->get_type(ts) == TS_IPV4_ADDR_RANGE &&
				this->selected_source4;
		ipv6 |= ts->get_type(ts) == TS_IPV6_ADDR_RANGE &&
				this->selected_source6;
	}
	enumerator->destroy(enumerator);
	if (!ipv4 && !ipv6)
	{
		client_fail(client, SOCKS5_REP_POLICY_DENIED);
		return;
	}
	if (ipv6 && ipv4)
	{
		type = LWIP_DNS_ADDRTYPE_IPV6_IPV4;
	}
	else if (ipv6)
	{
		type = LWIP_DNS_ADDRTYPE_IPV6;
	}
	else
	{
		type = LWIP_DNS_ADDRTYPE_IPV4;
	}
	client->reqid = this->selected_reqid;
	client->state = CLIENT_RESOLVING;
	client->deadline = now_ms() + (uint64_t)this->connect_timeout * 1000;
	error = dns_gethostbyname_addrtype(client->request.domain, &address,
									   dns_result, client, type);
	if (error == ERR_OK)
	{
		dns_result(client->request.domain, &address, client);
	}
	else if (error == ERR_INPROGRESS)
	{
		client->dns_pending = TRUE;
	}
	else
	{
		client_fail(client, SOCKS5_REP_HOST_UNREACHABLE);
	}
}

static void process_connect_request(socks_client_t *client)
{
	ip_addr_t destination;
	host_t *host;
	int family;
	size_t len;

	if (client->request.command != SOCKS5_CMD_CONNECT)
	{
		client_fail(client, SOCKS5_REP_COMMAND_UNSUPPORTED);
		return;
	}
	if (client->request.atyp == SOCKS5_ATYP_DOMAIN)
	{
		start_domain(client);
		return;
	}
	family = client->request.atyp == SOCKS5_ATYP_IPV4 ? AF_INET : AF_INET6;
	len = family == AF_INET ? 4 : 16;
	host = host_create_from_chunk(family,
				chunk_create(client->request.address, len), client->request.port);
	if (!host)
	{
		client_fail(client, SOCKS5_REP_ADDRESS_UNSUPPORTED);
		return;
	}
	host_to_lwip(host, &destination);
	host->destroy(host);
	start_address(client, &destination);
}

static void client_tunnel_lost(socks_client_t *client)
{
	switch (client->state)
	{
		case CLIENT_RESOLVING:
		case CLIENT_CONNECTING:
			client_fail(client, SOCKS5_REP_NETWORK_UNREACHABLE);
			break;
		case CLIENT_RELAY:
		case CLIENT_CLOSING:
			client_dead(client);
			break;
		default:
			break;
	}
}

static void revalidate_clients(private_kernel_libipsec_socks_t *this)
{
	enumerator_t *enumerator;
	socks_client_t *client;

	enumerator = this->clients->create_enumerator(this->clients);
	while (enumerator->enumerate(enumerator, &client))
	{
		if (client->reqid && client->reqid != this->selected_reqid)
		{
			client_tunnel_lost(client);
		}
		else if (client->destination &&
				 !selector_allows(this->selected->remote_ts,
							  client->destination, IPPROTO_TCP,
							  client->request.port))
		{
			client_tunnel_lost(client);
		}
		else if (client->pcb)
		{
			host_t *source = IP_IS_V6_VAL(client->pcb->local_ip) ?
							 this->selected_source6 : this->selected_source4;

			if (!source ||
				!selector_allows(this->selected->local_ts, source,
							 IPPROTO_TCP, client->pcb->local_port))
			{
				client_tunnel_lost(client);
			}
		}
	}
	enumerator->destroy(enumerator);
}

static void process_client_protocol(socks_client_t *client)
{
	while (client->state == CLIENT_GREETING ||
		   client->state == CLIENT_REQUEST)
	{
		socks5_parse_status_t status;
		size_t consumed;

		if (client->state == CLIENT_GREETING)
		{
			uint8_t method;

			status = kernel_libipsec_socks_parse_greeting(
					client->upstream.ptr + client->upstream.offset,
					client->upstream.len, &consumed, &method);
			if (status == SOCKS5_PARSE_MORE)
			{
				return;
			}
			if (status != SOCKS5_PARSE_OK)
			{
				client_dead(client);
				return;
			}
			buffer_consume(&client->upstream, consumed);
			if (!append_method_reply(client, method))
			{
				client_dead(client);
				return;
			}
			if (method != SOCKS5_METHOD_NO_AUTH)
			{
				client->state = CLIENT_FAILED;
				client->close_after_write = TRUE;
				return;
			}
			client->state = CLIENT_REQUEST;
			continue;
		}
		status = kernel_libipsec_socks_parse_request(
					client->upstream.ptr + client->upstream.offset,
					client->upstream.len, &consumed, &client->request);
		if (status == SOCKS5_PARSE_MORE)
		{
			return;
		}
		if (status == SOCKS5_PARSE_UNSUPPORTED_ADDRESS)
		{
			buffer_consume(&client->upstream, consumed);
			client_fail(client, SOCKS5_REP_ADDRESS_UNSUPPORTED);
			return;
		}
		if (status != SOCKS5_PARSE_OK)
		{
			client_dead(client);
			return;
		}
		buffer_consume(&client->upstream, consumed);
		process_connect_request(client);
	}
}

static void read_client(socks_client_t *client)
{
	ssize_t len;

	while (client->fd >= 0 && !client->local_eof &&
		   client->state != CLIENT_FAILED && client->state != CLIENT_CLOSING &&
		   client->state != CLIENT_DEAD)
	{
		size_t available = client->upstream.limit - client->upstream.len;
		size_t request = min(available, (size_t)SOCKS5_IO_CHUNK);

		if (!request || !buffer_reserve(&client->upstream, request))
		{
			return;
		}
		len = recv(client->fd,
				   client->upstream.ptr + client->upstream.offset +
				   client->upstream.len, request, 0);
		if (len > 0)
		{
			client->upstream.len += len;
			process_client_protocol(client);
			pump_upstream(client);
			continue;
		}
		if (!len)
		{
			if (client->state == CLIENT_RELAY)
			{
				client->local_eof = TRUE;
				pump_upstream(client);
				write_client(client);
			}
			else
			{
				client_dead(client);
			}
			return;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return;
		}
		if (errno == EINTR)
		{
			continue;
		}
		client_dead(client);
		return;
	}
}

static socks_client_t *client_create(
						private_kernel_libipsec_socks_t *this, int fd)
{
	socks_client_t *client;

	INIT(client,
		.backend = this,
		.id = ++this->next_client_id,
		.fd = fd,
		.state = CLIENT_GREETING,
		.deadline = now_ms() + (uint64_t)this->handshake_timeout * 1000,
		.upstream = { .limit = SOCKS5_BUFFER_LIMIT },
		.control = { .limit = 64 },
		.downstream = { .limit = SOCKS5_BUFFER_LIMIT },
	);
	return client;
}

static void accept_clients(private_kernel_libipsec_socks_t *this)
{
	int fd;

	while (TRUE)
	{
		fd = accept(this->listener, NULL, NULL);
		if (fd < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			if (errno != EAGAIN && errno != EWOULDBLOCK)
			{
				DBG1(DBG_NET, "accepting kernel-libipsec SOCKS5 client "
					 "failed: %s", strerror(errno));
			}
			return;
		}
		if (this->clients->get_count(this->clients) >= this->max_connections ||
			!set_fd_flags(fd))
		{
			close(fd);
			continue;
		}
#ifdef SO_NOSIGPIPE
		{
			int on = 1;
			setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
		}
#endif
		this->clients->insert_last(this->clients, client_create(this, fd));
	}
}

static err_t output_packet(private_kernel_libipsec_socks_t *this,
						   struct pbuf *p)
{
	ip_packet_t *packet;
	chunk_t raw;
	host_t *source, *destination;
	uint8_t protocol;

	if (!this->selected_ready || !p->tot_len)
	{
		return ERR_RTE;
	}
	raw = chunk_alloc(p->tot_len);
	if (pbuf_copy_partial(p, raw.ptr, p->tot_len, 0) != p->tot_len)
	{
		chunk_free(&raw);
		return ERR_VAL;
	}
	packet = ip_packet_create(raw);
	if (!packet)
	{
		return ERR_VAL;
	}
	source = packet->get_source(packet);
	destination = packet->get_destination(packet);
	protocol = packet->get_next_header(packet);
	if (!selector_allows(this->selected->local_ts, source, protocol,
						 source->get_port(source)) ||
		!selector_allows(this->selected->remote_ts, destination, protocol,
						 destination->get_port(destination)))
	{
		DBG1(DBG_KNL, "dropping lwIP packet outside selected CHILD_SA "
			 "traffic selectors: %H to %H", source, destination);
		packet->destroy(packet);
		return ERR_RTE;
	}
	ipsec->processor->queue_outbound(ipsec->processor, packet);
	return ERR_OK;
}

static err_t netif_output4(struct netif *netif, struct pbuf *p,
						   const ip4_addr_t *destination)
{
	return output_packet(netif->state, p);
}

static err_t netif_output6(struct netif *netif, struct pbuf *p,
						   const ip6_addr_t *destination)
{
	return output_packet(netif->state, p);
}

static err_t init_netif(struct netif *netif)
{
	private_kernel_libipsec_socks_t *this = netif->state;

	netif->name[0] = 's';
	netif->name[1] = 'w';
	netif->output = netif_output4;
	netif->output_ip6 = netif_output6;
	netif->mtu = this->mtu;
	netif->flags = NETIF_FLAG_LINK_UP;
	return ERR_OK;
}

static void input_packet(private_kernel_libipsec_socks_t *this,
						 ip_packet_t *packet)
{
	chunk_t raw = packet->get_encoding(packet);
	host_t *source = packet->get_source(packet);
	host_t *destination = packet->get_destination(packet);
	uint8_t protocol = packet->get_next_header(packet);
	struct pbuf *p;

	if (!this->selected_ready || !raw.len || raw.len > UINT16_MAX ||
		!selector_allows(this->selected->remote_ts, source, protocol,
						 source->get_port(source)) ||
		!selector_allows(this->selected->local_ts, destination, protocol,
						 destination->get_port(destination)))
	{
		packet->destroy(packet);
		return;
	}
	p = pbuf_alloc(PBUF_RAW, raw.len, PBUF_POOL);
	if (!p || pbuf_take(p, raw.ptr, raw.len) != ERR_OK)
	{
		if (p)
		{
			pbuf_free(p);
		}
		packet->destroy(packet);
		return;
	}
	packet->destroy(packet);
	/* ip_input() owns the pbuf regardless of its return value. */
	this->netif.input(p, &this->netif);
}

static bool process_events(private_kernel_libipsec_socks_t *this)
{
	socks_event_t *event;
	bool stop = FALSE;

	while (TRUE)
	{
		this->mutex->lock(this->mutex);
		if (this->events->remove_first(this->events, (void**)&event) != SUCCESS)
		{
			this->mutex->unlock(this->mutex);
			break;
		}
		if (event->type == EVENT_PACKET)
		{
			this->queued_packets--;
		}
		this->mutex->unlock(this->mutex);
		switch (event->type)
		{
			case EVENT_PACKET:
				input_packet(this, event->packet);
				event->packet = NULL;
				break;
			case EVENT_TUNNEL_UP:
				add_tunnel(this, event->tunnel);
				event->tunnel = NULL;
				break;
			case EVENT_TUNNEL_DOWN:
				remove_tunnel(this, event->down.ike_id, event->down.child_id);
				break;
			case EVENT_IKE_REKEY:
				migrate_ike(this, event->rekey.old_ike_id,
							event->rekey.new_ike_id);
				break;
			case EVENT_IKE_DOWN:
				remove_ike(this, event->ike_id);
				break;
			case EVENT_DNS_ADD:
				add_dns(this, event->dns.ike_id, event->dns.server);
				event->dns.server = NULL;
				break;
			case EVENT_DNS_REMOVE:
				remove_dns(this, event->dns.ike_id, event->dns.server);
				event->dns.server = NULL;
				break;
			case EVENT_STOP:
				stop = TRUE;
				break;
		}
		free(event);
		if (stop)
		{
			break;
		}
	}
	return stop;
}

static void maintain_clients(private_kernel_libipsec_socks_t *this)
{
	enumerator_t *enumerator;
	socks_client_t *client;
	uint64_t now = now_ms();

	enumerator = this->clients->create_enumerator(this->clients);
	while (enumerator->enumerate(enumerator, &client))
	{
		pump_upstream(client);
		write_client(client);
		if (client->deadline && now >= client->deadline)
		{
			switch (client->state)
			{
				case CLIENT_GREETING:
				case CLIENT_REQUEST:
					client_dead(client);
					break;
				case CLIENT_RESOLVING:
				case CLIENT_CONNECTING:
					client_fail(client, SOCKS5_REP_HOST_UNREACHABLE);
					break;
				case CLIENT_CLOSING:
					client_dead(client);
					break;
				default:
					break;
			}
			client->deadline = 0;
		}
		if (client->state == CLIENT_DEAD && !client->dns_pending)
		{
			this->clients->remove_at(this->clients, enumerator);
			client_destroy(client);
		}
	}
	enumerator->destroy(enumerator);
}

static int create_listener(private_kernel_libipsec_socks_t *this)
{
	int fd, on = 1;

	fd = socket(this->listen_addr.ss_family, SOCK_STREAM, 0);
	if (fd < 0 || !set_fd_flags(fd))
	{
		if (fd >= 0)
		{
			close(fd);
		}
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (this->listen_addr.ss_family == AF_INET6)
	{
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
	}
#ifdef SO_NOSIGPIPE
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
	if (bind(fd, (struct sockaddr*)&this->listen_addr, this->listen_len) < 0 ||
		listen(fd, min(this->max_connections, (u_int)SOMAXCONN)) < 0)
	{
		DBG1(DBG_NET, "binding kernel-libipsec SOCKS5 listener failed: %s",
			 strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static void signal_started(private_kernel_libipsec_socks_t *this, bool success)
{
	this->mutex->lock(this->mutex);
	this->start_success = success;
	this->started = TRUE;
	this->condvar->broadcast(this->condvar);
	this->mutex->unlock(this->mutex);
}

static void cleanup_thread_state(private_kernel_libipsec_socks_t *this,
								 bool netif_added)
{
	socks_client_t *client;
	tunnel_t *tunnel;
	dns_entry_t *dns;

	if (this->listener >= 0)
	{
		close(this->listener);
		this->listener = -1;
	}
	while (this->clients->remove_first(this->clients,
									 (void**)&client) == SUCCESS)
	{
		client->dns_pending = FALSE;
		client_destroy(client);
	}
	while (this->tunnels->remove_first(this->tunnels,
									  (void**)&tunnel) == SUCCESS)
	{
		tunnel_destroy(tunnel);
	}
	while (this->dns->remove_first(this->dns, (void**)&dns) == SUCCESS)
	{
		dns_entry_destroy(dns);
	}
	DESTROY_IF(this->selected_source4);
	DESTROY_IF(this->selected_source6);
	this->selected_source4 = NULL;
	this->selected_source6 = NULL;
	if (netif_added)
	{
		netif_remove(&this->netif);
	}
	kernel_libipsec_lwip_set_rng(NULL);
	DESTROY_IF(this->rng);
	this->rng = NULL;
}

static void *event_loop(private_kernel_libipsec_socks_t *this)
{
	bool netif_added = FALSE, stopping = FALSE;

	this->rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!this->rng)
	{
		DBG1(DBG_KNL, "creating strong RNG for kernel-libipsec SOCKS5 "
			 "backend failed");
		signal_started(this, FALSE);
		return NULL;
	}
	kernel_libipsec_lwip_set_rng(this->rng);
	lwip_init();
	this->tcp_ext_id = tcp_ext_arg_alloc_id();
	if (this->tcp_ext_id == LWIP_TCP_PCB_NUM_EXT_ARG_ID_INVALID ||
		!netif_add_noaddr(&this->netif, this, init_netif, ip_input))
	{
		DBG1(DBG_KNL, "initializing embedded lwIP interface failed");
		signal_started(this, FALSE);
		cleanup_thread_state(this, FALSE);
		return NULL;
	}
	netif_added = TRUE;
	netif_set_default(&this->netif);
	netif_set_up(&this->netif);
	netif_set_link_up(&this->netif);
	this->listener = create_listener(this);
	if (this->listener < 0)
	{
		signal_started(this, FALSE);
		cleanup_thread_state(this, netif_added);
		return NULL;
	}
	signal_started(this, TRUE);

	while (!stopping)
	{
		enumerator_t *enumerator;
		socks_client_t *client;
		struct pollfd *fds;
		socks_client_t **map;
		u_int count = 2, index;
		u32_t sleep;
		int result, timeout;

		enumerator = this->clients->create_enumerator(this->clients);
		while (enumerator->enumerate(enumerator, &client))
		{
			if (client->fd >= 0)
			{
				count++;
			}
		}
		enumerator->destroy(enumerator);
		fds = calloc(count, sizeof(*fds));
		map = calloc(count, sizeof(*map));
		if (!fds || !map)
		{
			DBG1(DBG_KNL, "allocating kernel-libipsec SOCKS5 poll set failed");
			free(fds);
			free(map);
			break;
		}
		fds[0] = (struct pollfd){ .fd = this->notify[0], .events = POLLIN };
		fds[1] = (struct pollfd){ .fd = this->listener, .events = POLLIN };
		index = 2;
		enumerator = this->clients->create_enumerator(this->clients);
		while (enumerator->enumerate(enumerator, &client))
		{
			if (client->fd < 0)
			{
				continue;
			}
			fds[index].fd = client->fd;
			if (!client->local_eof && client->state != CLIENT_FAILED &&
				client->state != CLIENT_CLOSING &&
				client->upstream.len < client->upstream.limit)
			{
				fds[index].events |= POLLIN;
			}
			if (client->control.len || client->downstream.len)
			{
				fds[index].events |= POLLOUT;
			}
			map[index++] = client;
		}
		enumerator->destroy(enumerator);
		sleep = sys_timeouts_sleeptime();
		timeout = sleep == SYS_TIMEOUTS_SLEEPTIME_INFINITE ? 100 :
				  min(sleep, 100U);
		result = poll(fds, count, timeout);
		if (result < 0 && errno != EINTR)
		{
			DBG1(DBG_NET, "polling kernel-libipsec SOCKS5 backend failed: %s",
				 strerror(errno));
		}
		if (fds[0].revents & POLLIN)
		{
			char buffer[64];

			while (read(this->notify[0], buffer, sizeof(buffer)) > 0)
			{
				/* drain */
			}
		}
		/* Also check the queue if a nonblocking pipe write was interrupted. */
		stopping = process_events(this);
		if (!stopping && fds[1].revents & POLLIN)
		{
			accept_clients(this);
		}
		if (!stopping)
		{
			for (index = 2; index < count; index++)
			{
				client = map[index];
				if (!client || client->fd != fds[index].fd)
				{
					continue;
				}
				if (fds[index].revents & (POLLERR | POLLNVAL))
				{
					client_dead(client);
					continue;
				}
				if (fds[index].revents & (POLLIN | POLLHUP))
				{
					read_client(client);
				}
				if (client->fd >= 0 && fds[index].revents & POLLOUT)
				{
					write_client(client);
				}
			}
			sys_check_timeouts();
			maintain_clients(this);
		}
		free(map);
		free(fds);
	}
	cleanup_thread_state(this, netif_added);
	return NULL;
}

METHOD(kernel_libipsec_plain_t, deliver, void,
	private_kernel_libipsec_socks_t *this, ip_packet_t *packet)
{
	socks_event_t *event;

	INIT(event,
		.type = EVENT_PACKET,
		.packet = packet,
	);
	enqueue_event(this, event);
}

METHOD(kernel_libipsec_plain_t, get_tun_name, char*,
	private_kernel_libipsec_socks_t *this, host_t *vip)
{
	return NULL;
}

static void destroy_unstarted(private_kernel_libipsec_socks_t *this)
{
	socks_event_t *event;

	if (this->thread)
	{
		this->thread->join(this->thread);
	}
	while (this->events->remove_first(this->events, (void**)&event) == SUCCESS)
	{
		event_destroy(event);
	}
	if (this->notify[0] >= 0)
	{
		close(this->notify[0]);
	}
	if (this->notify[1] >= 0)
	{
		close(this->notify[1]);
	}
	DESTROY_IF(this->source4);
	DESTROY_IF(this->source6);
	free(this->ike_name);
	free(this->child_name);
	if (this->configured_dns)
	{
		destroy_host_list(this->configured_dns);
	}
	DESTROY_IF(this->clients);
	DESTROY_IF(this->tunnels);
	DESTROY_IF(this->dns);
	DESTROY_IF(this->events);
	DESTROY_IF(this->condvar);
	DESTROY_IF(this->mutex);
	free(this);
}

METHOD(kernel_libipsec_plain_t, destroy, void,
	private_kernel_libipsec_socks_t *this)
{
	socks_event_t *event;

	charon->bus->remove_listener(charon->bus, &this->bus.public);
	charon->attributes->remove_handler(charon->attributes,
									   &this->attribute.public);
	INIT(event, .type = EVENT_STOP);
	enqueue_event(this, event);
	this->thread->join(this->thread);
	this->thread = NULL;
	destroy_unstarted(this);
}

kernel_libipsec_plain_t *kernel_libipsec_socks_create(void)
{
	private_kernel_libipsec_socks_t *this;
	char *listen, *ike, *child, *sources, *dns;
	int mtu, max_connections;
	bool valid = TRUE;

	INIT(this,
		.public = {
			.deliver = _deliver,
			.get_tun_name = _get_tun_name,
			.destroy = _destroy,
		},
		.bus = {
			.public = {
				.ike_updown = _ike_updown,
				.ike_rekey = _ike_rekey,
				.child_updown = _child_updown,
				.child_rekey = _child_rekey,
				.assign_vips = _assign_vips,
				.handle_vips = _handle_vips,
			},
			.owner = this,
		},
		.attribute = {
			.public = {
				.handle = _handle_attribute,
				.release = _release_attribute,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.owner = this,
		},
		.listener = -1,
		.notify = { -1, -1 },
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.condvar = condvar_create(CONDVAR_TYPE_DEFAULT),
		.events = linked_list_create(),
		.configured_dns = linked_list_create(),
		.clients = linked_list_create(),
		.tunnels = linked_list_create(),
		.dns = linked_list_create(),
	);
	listen = lib->settings->get_str(lib->settings,
				"%s.plugins.kernel-libipsec.socks5.listen",
				SOCKS5_DEFAULT_LISTEN, lib->ns);
	ike = lib->settings->get_str(lib->settings,
				"%s.plugins.kernel-libipsec.socks5.ike", NULL, lib->ns);
	child = lib->settings->get_str(lib->settings,
				"%s.plugins.kernel-libipsec.socks5.child", NULL, lib->ns);
	sources = lib->settings->get_str(lib->settings,
				"%s.plugins.kernel-libipsec.socks5.source_addresses", NULL,
				lib->ns);
	dns = lib->settings->get_str(lib->settings,
				"%s.plugins.kernel-libipsec.socks5.dns_servers", NULL,
				lib->ns);
	mtu = lib->settings->get_int(lib->settings,
				"%s.plugins.kernel-libipsec.socks5.mtu", SOCKS5_DEFAULT_MTU,
				lib->ns);
	max_connections = lib->settings->get_int(lib->settings,
				"%s.plugins.kernel-libipsec.socks5.max_connections",
				SOCKS5_DEFAULT_MAX_CONNECTIONS, lib->ns);
	this->handshake_timeout = lib->settings->get_time(lib->settings,
				"%s.plugins.kernel-libipsec.socks5.handshake_timeout",
				SOCKS5_DEFAULT_HANDSHAKE_TIMEOUT, lib->ns);
	this->connect_timeout = lib->settings->get_time(lib->settings,
				"%s.plugins.kernel-libipsec.socks5.connect_timeout",
				SOCKS5_DEFAULT_CONNECT_TIMEOUT, lib->ns);
	if (!parse_listener(listen, &this->listen_addr, &this->listen_len))
	{
		DBG1(DBG_CFG, "invalid kernel-libipsec SOCKS5 listener '%s' (a "
			 "literal loopback address is required)", listen);
		valid = FALSE;
	}
	if (mtu < 1280 || mtu > UINT16_MAX)
	{
		DBG1(DBG_CFG, "invalid kernel-libipsec SOCKS5 MTU %d", mtu);
		valid = FALSE;
	}
	if (max_connections < 1 || max_connections > 4096)
	{
		DBG1(DBG_CFG, "invalid kernel-libipsec SOCKS5 connection limit %d",
			 max_connections);
		valid = FALSE;
	}
	if (!this->handshake_timeout || !this->connect_timeout)
	{
		DBG1(DBG_CFG, "kernel-libipsec SOCKS5 timeouts must be non-zero");
		valid = FALSE;
	}
	this->mtu = mtu;
	this->max_connections = max_connections;
	this->ike_name = ike && *ike ? strdup(ike) : NULL;
	this->child_name = child && *child ? strdup(child) : NULL;
	valid = parse_host_settings(sources, &this->source4, &this->source6,
								NULL, "SOCKS5 source") && valid;
	valid = parse_host_settings(dns, NULL, NULL, this->configured_dns,
								"SOCKS5 DNS server") && valid;
	if (!valid || pipe(this->notify) != 0 || !set_fd_flags(this->notify[0]) ||
		!set_fd_flags(this->notify[1]))
	{
		if (valid)
		{
			DBG1(DBG_KNL, "creating notification pipe for kernel-libipsec "
				 "SOCKS5 backend failed: %s", strerror(errno));
		}
		destroy_unstarted(this);
		return NULL;
	}
	this->thread = thread_create((thread_main_t)event_loop, this);
	if (!this->thread)
	{
		destroy_unstarted(this);
		return NULL;
	}
	this->mutex->lock(this->mutex);
	while (!this->started)
	{
		this->condvar->wait(this->condvar, this->mutex);
	}
	valid = this->start_success;
	this->mutex->unlock(this->mutex);
	if (!valid)
	{
		destroy_unstarted(this);
		return NULL;
	}
	charon->bus->add_listener(charon->bus, &this->bus.public);
	charon->attributes->add_handler(charon->attributes,
									&this->attribute.public);
	if (charon->controller)
	{
		scan_existing_sas(this);
	}
	DBG1(DBG_KNL, "kernel-libipsec SOCKS5 data plane listening on %s", listen);
	return &this->public;
}
