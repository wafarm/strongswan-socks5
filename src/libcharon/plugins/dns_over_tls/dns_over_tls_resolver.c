/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "dns_over_tls_resolver.h"
#include "dns_over_tls_dns.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <unistd.h>

#include <daemon.h>
#include <tls_socket.h>
#include <tls_cache.h>
#include <threading/mutex.h>
#include <threading/thread.h>
#include <utils/debug.h>

#define DOT_DEFAULT_PORT       853
#define DOT_DEFAULT_TIMEOUT    5
#define DOT_SESSION_COUNT      4
#define DOT_SESSION_MAX_AGE    300
#define DNS_HEADER_LEN         12

typedef struct private_dns_over_tls_resolver_t private_dns_over_tls_resolver_t;

struct private_dns_over_tls_resolver_t {
	dns_over_tls_resolver_t public;
	mutex_t *mutex;
	tls_cache_t *cache;
	char *uri;
	dns_over_tls_endpoint_t endpoint;
	bool endpoint_valid;
	tls_socket_t *tls;
	int fd;
	uint16_t next_id;
};

typedef enum {
	QUERY_SUCCESS,
	QUERY_NXDOMAIN,
	QUERY_SERVER_ERROR,
	QUERY_BROKEN,
	QUERY_INVALID,
} query_status_t;

static uint64_t now_ms(void)
{
	timeval_t now;

	time_monotonic(&now);
	return (uint64_t)now.tv_sec * 1000 + now.tv_usec / 1000;
}

static int remaining_ms(uint64_t deadline)
{
	uint64_t now = now_ms(), remaining;

	if (now >= deadline)
	{
		return 0;
	}
	remaining = deadline - now;
	return min(remaining, (uint64_t)INT_MAX);
}

static bool valid_domain(char *domain)
{
	size_t len, label = 0;
	u_int i;
	bool alpha = FALSE;

	len = domain ? strlen(domain) : 0;
	if (!len || len > 253 || domain[0] == '-' || domain[len - 1] == '-' ||
		domain[len - 1] == '.')
	{
		return FALSE;
	}
	for (i = 0; i < len; i++)
	{
		char c = domain[i];

		if (c == '.')
		{
			if (!label || label > 63 || domain[i - 1] == '-' ||
				i + 1 == len || domain[i + 1] == '-')
			{
				return FALSE;
			}
			label = 0;
		}
		else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				 (c >= '0' && c <= '9') || c == '-')
		{
			alpha |= (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
			label++;
		}
		else
		{
			return FALSE;
		}
	}
	return alpha && label && label <= 63;
}

static bool parse_port(char *str, uint16_t *port)
{
	char *end;
	unsigned long value;

	if (!str || !*str)
	{
		return FALSE;
	}
	for (end = str; *end; end++)
	{
		if (*end < '0' || *end > '9')
		{
			return FALSE;
		}
	}
	errno = 0;
	value = strtoul(str, &end, 10);
	if (errno || *end || !value || value > UINT16_MAX || value == 53)
	{
		return FALSE;
	}
	*port = value;
	return TRUE;
}

bool dns_over_tls_endpoint_parse(char *uri, dns_over_tls_endpoint_t *endpoint)
{
	char *copy, *at, *server, *portstr = NULL, *end;
	uint16_t port = DOT_DEFAULT_PORT;
	int family;

	*endpoint = (dns_over_tls_endpoint_t){};
	if (!uri || !strpfx(uri, "tls://"))
	{
		return FALSE;
	}
	copy = strdup(uri + strlen("tls://"));
	at = strchr(copy, '@');
	if (!at || at == copy || !at[1] || strchr(at + 1, '@'))
	{
		free(copy);
		return FALSE;
	}
	*at = '\0';
	server = at + 1;
	if (!valid_domain(copy))
	{
		free(copy);
		return FALSE;
	}
	if (*server == '[')
	{
		end = strchr(server + 1, ']');
		if (!end || end == server + 1 ||
			(end[1] && end[1] != ':'))
		{
			free(copy);
			return FALSE;
		}
		if (end[1] == ':')
		{
			portstr = end + 2;
		}
		*end = '\0';
		server++;
		family = AF_INET6;
	}
	else
	{
		end = strchr(server, ':');
		if (end)
		{
			if (strchr(end + 1, ':'))
			{
				free(copy);
				return FALSE;
			}
			*end = '\0';
			portstr = end + 1;
		}
		family = AF_INET;
	}
	if ((portstr && !parse_port(portstr, &port)) || !*server)
	{
		free(copy);
		return FALSE;
	}
	endpoint->address = host_create_from_string_and_family(server, family, port);
	if (!endpoint->address)
	{
		free(copy);
		return FALSE;
	}
	endpoint->identity = identification_create_from_encoding(ID_FQDN,
										chunk_create(copy, strlen(copy)));
	free(copy);
	if (!endpoint->identity)
	{
		dns_over_tls_endpoint_clear(endpoint);
		return FALSE;
	}
	return TRUE;
}

void dns_over_tls_endpoint_clear(dns_over_tls_endpoint_t *endpoint)
{
	DESTROY_IF(endpoint->identity);
	DESTROY_IF(endpoint->address);
	*endpoint = (dns_over_tls_endpoint_t){};
}

/**
 * Close the reusable TLS connection. Caller holds the resolver mutex.
 */
static void close_connection(private_dns_over_tls_resolver_t *this,
							 bool broken)
{
	if (broken && this->fd >= 0)
	{
		shutdown(this->fd, SHUT_RDWR);
	}
	DESTROY_IF(this->tls);
	this->tls = NULL;
	if (this->fd >= 0)
	{
		close(this->fd);
		this->fd = -1;
	}
}

/**
 * Replace the cached endpoint if the URI changed. Caller holds the mutex.
 */
static bool load_endpoint(private_dns_over_tls_resolver_t *this, char *uri)
{
	if (this->uri && streq(this->uri, uri))
	{
		return this->endpoint_valid;
	}
	close_connection(this, FALSE);
	dns_over_tls_endpoint_clear(&this->endpoint);
	free(this->uri);
	this->uri = strdup(uri);
	this->endpoint_valid = dns_over_tls_endpoint_parse(uri, &this->endpoint);
	if (!this->endpoint_valid)
	{
		DBG1(DBG_CFG, "invalid DNS-over-TLS resolver URI '%s'", uri);
	}
	return this->endpoint_valid;
}

/**
 * Apply the remaining absolute deadline to blocking socket operations.
 */
static bool set_socket_timeout(int fd, uint64_t deadline)
{
	int remaining = remaining_ms(deadline);
	struct timeval timeout;

	if (!remaining)
	{
		return FALSE;
	}
	timeout.tv_sec = remaining / 1000;
	timeout.tv_usec = (remaining % 1000) * 1000;
	return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
		   setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0;
}

/**
 * Establish a TCP connection without exceeding the absolute deadline.
 */
static int connect_tcp(host_t *address, uint64_t deadline)
{
	struct pollfd pfd;
	socklen_t len;
	int fd, flags, error, result, remaining;

	fd = socket(address->get_family(address), SOCK_STREAM, 0);
	if (fd < 0)
	{
		return -1;
	}
	flags = fcntl(fd, F_GETFL);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
		fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
	{
		close(fd);
		return -1;
	}
	result = connect(fd, address->get_sockaddr(address),
					 *address->get_sockaddr_len(address));
	if (result < 0 && errno != EINPROGRESS)
	{
		close(fd);
		return -1;
	}
	if (result < 0)
	{
		pfd = (struct pollfd){ .fd = fd, .events = POLLOUT };
		do
		{
			remaining = remaining_ms(deadline);
			if (!remaining)
			{
				close(fd);
				errno = ETIMEDOUT;
				return -1;
			}
			result = poll(&pfd, 1, remaining);
		}
		while (result < 0 && errno == EINTR);
		if (result <= 0)
		{
			close(fd);
			if (!result)
			{
				errno = ETIMEDOUT;
			}
			return -1;
		}
		len = sizeof(error);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error)
		{
			close(fd);
			errno = error ?: errno;
			return -1;
		}
	}
	if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0 ||
		!set_socket_timeout(fd, deadline))
	{
		close(fd);
		return -1;
	}
	return fd;
}

/**
 * Open the TLS wrapper. The handshake is driven by the first I/O operation.
 */
static bool open_connection(private_dns_over_tls_resolver_t *this,
								uint64_t deadline)
{
	if (this->tls)
	{
		return TRUE;
	}
	this->fd = connect_tcp(this->endpoint.address, deadline);
	if (this->fd < 0)
	{
		DBG1(DBG_NET, "connecting to DNS-over-TLS server %H failed: %s",
			 this->endpoint.address, strerror(errno));
		return FALSE;
	}
	this->tls = tls_socket_create(FALSE, this->endpoint.identity, NULL,
								  this->fd, this->cache, TLS_1_2, TLS_1_3, 0);
	if (!this->tls)
	{
		DBG1(DBG_TLS, "creating TLS socket for DNS server %H failed",
			 this->endpoint.address);
		close_connection(this, TRUE);
		return FALSE;
	}
	return TRUE;
}

static bool tls_write_all(private_dns_over_tls_resolver_t *this, chunk_t data,
						  uint64_t deadline)
{
	ssize_t written;

	while (data.len)
	{
		if (!set_socket_timeout(this->fd, deadline))
		{
			errno = ETIMEDOUT;
			return FALSE;
		}
		written = this->tls->write(this->tls, data.ptr, data.len);
		if (written <= 0)
		{
			if (!remaining_ms(deadline))
			{
				errno = ETIMEDOUT;
			}
			return FALSE;
		}
		data = chunk_skip(data, written);
	}
	return TRUE;
}

static bool tls_read_all(private_dns_over_tls_resolver_t *this, chunk_t data,
						 uint64_t deadline)
{
	ssize_t received;

	while (data.len)
	{
		if (!set_socket_timeout(this->fd, deadline))
		{
			errno = ETIMEDOUT;
			return FALSE;
		}
		received = this->tls->read(this->tls, data.ptr, data.len, TRUE);
		if (received <= 0)
		{
			if (!remaining_ms(deadline))
			{
				errno = ETIMEDOUT;
			}
			return FALSE;
		}
		data = chunk_skip(data, received);
	}
	return TRUE;
}

/**
 * Send one framed DNS query and parse its framed response.
 */
static query_status_t query_once(private_dns_over_tls_resolver_t *this,
								 char *name, uint16_t type,
								 uint64_t deadline, linked_list_t **hosts)
{
	chunk_t query, frame, response = chunk_empty;
	dot_dns_status_t status;
	uint16_t id, length;
	uint8_t rcode;
	uint8_t prefix[2];

	*hosts = NULL;
	id = ++this->next_id;
	if (!dns_over_tls_build_query(name, type, id, &query))
	{
		DBG1(DBG_CFG, "invalid DNS gateway name '%s'", name);
		return QUERY_INVALID;
	}
	if (!open_connection(this, deadline))
	{
		chunk_free(&query);
		return QUERY_BROKEN;
	}
	frame = chunk_alloc(query.len + 2);
	frame.ptr[0] = query.len >> 8;
	frame.ptr[1] = query.len;
	memcpy(frame.ptr + 2, query.ptr, query.len);
	chunk_free(&query);
	if (!tls_write_all(this, frame, deadline) ||
		!tls_read_all(this, chunk_create(prefix, sizeof(prefix)), deadline))
	{
		DBG1(DBG_NET, "DNS-over-TLS query for '%s' failed: %s", name,
			 errno == ETIMEDOUT ? "timeout" : strerror(errno));
		chunk_free(&frame);
		close_connection(this, TRUE);
		return QUERY_BROKEN;
	}
	chunk_free(&frame);
	length = ((uint16_t)prefix[0] << 8) | prefix[1];
	if (length < DNS_HEADER_LEN)
	{
		DBG1(DBG_NET, "DNS-over-TLS server returned invalid message length %u",
			 length);
		close_connection(this, TRUE);
		return QUERY_INVALID;
	}
	response = chunk_alloc(length);
	if (!tls_read_all(this, response, deadline))
	{
		DBG1(DBG_NET, "reading DNS-over-TLS response for '%s' failed: %s",
			 name, errno == ETIMEDOUT ? "timeout" : strerror(errno));
		chunk_free(&response);
		close_connection(this, TRUE);
		return QUERY_BROKEN;
	}
	status = dns_over_tls_parse_response(response, name, type, id, hosts,
										 &rcode);
	chunk_free(&response);
	switch (status)
	{
		case DOT_DNS_SUCCESS:
			return QUERY_SUCCESS;
		case DOT_DNS_NXDOMAIN:
			DBG1(DBG_NET, "DNS-over-TLS name '%s' does not exist", name);
			return QUERY_NXDOMAIN;
		case DOT_DNS_SERVER_ERROR:
			DBG1(DBG_NET, "DNS-over-TLS server returned %s (RCODE %u) for "
				 "'%s'", rcode == 1 ? "FORMERR" :
						 rcode == 2 ? "SERVFAIL" :
						 rcode == 4 ? "NOTIMP" :
						 rcode == 5 ? "REFUSED" : "DNS error",
				 rcode, name);
			return QUERY_SERVER_ERROR;
		default:
			DBG1(DBG_NET, "DNS-over-TLS server returned malformed response for "
				 "'%s'", name);
			close_connection(this, TRUE);
			return QUERY_INVALID;
	}
}

static query_status_t query_retry(private_dns_over_tls_resolver_t *this,
								  char *name, uint16_t type,
								  uint64_t deadline, bool *retried,
								  linked_list_t **hosts)
{
	query_status_t status;

	status = query_once(this, name, type, deadline, hosts);
	if (status == QUERY_BROKEN && !*retried && remaining_ms(deadline))
	{
		*retried = TRUE;
		DBG2(DBG_NET, "reconnecting to DNS-over-TLS server");
		status = query_once(this, name, type, deadline, hosts);
	}
	return status;
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

static host_t *first_host(linked_list_t *hosts)
{
	host_t *host;

	if (hosts && hosts->get_first(hosts, (void**)&host) == SUCCESS)
	{
		return host->clone(host);
	}
	return NULL;
}

/**
 * Prefer the first candidate that has a usable source route. Family and
 * answer order are otherwise AAAA-before-A and stable within each family.
 */
static host_t *select_unspec(linked_list_t *v6, linked_list_t *v4)
{
	linked_list_t *lists[] = { v6, v4 };
	enumerator_t *enumerator;
	host_t *candidate, *source, *selected = NULL;
	u_int i;

	if (charon && charon->kernel)
	{
		for (i = 0; i < countof(lists) && !selected; i++)
		{
			if (!lists[i])
			{
				continue;
			}
			enumerator = lists[i]->create_enumerator(lists[i]);
			while (enumerator->enumerate(enumerator, &candidate))
			{
				source = charon->kernel->get_source_addr(charon->kernel,
												 candidate, NULL);
				if (source)
				{
					source->destroy(source);
					selected = candidate->clone(candidate);
					break;
				}
			}
			enumerator->destroy(enumerator);
		}
	}
	if (!selected)
	{
		selected = first_host(v6);
		if (!selected)
		{
			selected = first_host(v4);
		}
	}
	return selected;
}

METHOD(host_resolver_provider_t, resolve, host_t*,
	private_dns_over_tls_resolver_t *this, char *uri, char *name, int family)
{
	linked_list_t *v6 = NULL, *v4 = NULL;
	query_status_t status;
	host_t *result = NULL;
	uint64_t deadline;
	uint32_t timeout;
	bool retried = FALSE, old;

	old = thread_cancelability(FALSE);
	this->mutex->lock(this->mutex);
	if (!load_endpoint(this, uri))
	{
		goto done;
	}
	timeout = lib->settings->get_time(lib->settings,
								  "%s.host_resolver.dot_timeout",
								  DOT_DEFAULT_TIMEOUT, lib->ns);
	deadline = now_ms() + (uint64_t)timeout * 1000;
	switch (family)
	{
		case AF_INET:
			status = query_retry(this, name, DNS_TYPE_A, deadline, &retried,
								 &v4);
			if (status == QUERY_SUCCESS)
			{
				result = first_host(v4);
			}
			break;
		case AF_INET6:
			status = query_retry(this, name, DNS_TYPE_AAAA, deadline, &retried,
								 &v6);
			if (status == QUERY_SUCCESS)
			{
				result = first_host(v6);
			}
			break;
		case AF_UNSPEC:
			status = query_retry(this, name, DNS_TYPE_AAAA, deadline, &retried,
								 &v6);
			if (status != QUERY_SUCCESS)
			{
				break;
			}
			status = query_retry(this, name, DNS_TYPE_A, deadline, &retried,
								 &v4);
			if (status == QUERY_SUCCESS)
			{
				result = select_unspec(v6, v4);
			}
			break;
		default:
			DBG1(DBG_CFG, "unsupported address family %d for DNS-over-TLS",
				 family);
			break;
	}

done:
	destroy_hosts(v6);
	destroy_hosts(v4);
	this->mutex->unlock(this->mutex);
	thread_cancelability(old);
	return result;
}

METHOD(dns_over_tls_resolver_t, reload, bool,
	private_dns_over_tls_resolver_t *this)
{
	char *uri, *copy = NULL;

	uri = lib->settings->get_str(lib->settings,
								"%s.host_resolver.dot_server", NULL, lib->ns);
	if (uri && *uri)
	{
		copy = strdup(uri);
	}
	this->mutex->lock(this->mutex);
	close_connection(this, FALSE);
	dns_over_tls_endpoint_clear(&this->endpoint);
	free(this->uri);
	this->uri = NULL;
	this->endpoint_valid = FALSE;
	if (copy)
	{
		load_endpoint(this, copy);
	}
	this->mutex->unlock(this->mutex);
	free(copy);
	return TRUE;
}

METHOD(dns_over_tls_resolver_t, destroy, void,
	private_dns_over_tls_resolver_t *this)
{
	close_connection(this, FALSE);
	dns_over_tls_endpoint_clear(&this->endpoint);
	free(this->uri);
	this->cache->destroy(this->cache);
	this->mutex->destroy(this->mutex);
	free(this);
}

dns_over_tls_resolver_t *dns_over_tls_resolver_create()
{
	private_dns_over_tls_resolver_t *this;

	INIT(this,
		.public = {
			.provider = {
				.scheme = "tls",
				.resolve = _resolve,
			},
			.reload = _reload,
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.cache = tls_cache_create(DOT_SESSION_COUNT, DOT_SESSION_MAX_AGE),
		.fd = -1,
		.next_id = now_ms(),
	);
	return &this->public;
}
