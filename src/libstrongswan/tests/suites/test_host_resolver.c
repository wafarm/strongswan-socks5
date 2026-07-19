/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "test_suite.h"

#include <unistd.h>

#include <library.h>
#include <networking/host.h>
#include <networking/host_resolver.h>
#include <threading/mutex.h>
#include <threading/semaphore.h>
#include <threading/thread.h>

typedef struct {
	host_resolver_provider_t provider;
	mutex_t *mutex;
	semaphore_t *entered;
	semaphore_t *release;
	char *address;
	char *last_uri;
	char *last_name;
	int last_family;
	u_int calls;
	bool fail;
} fake_provider_t;

static host_t *fake_resolve(host_resolver_provider_t *provider, char *uri,
							char *name, int family)
{
	fake_provider_t *this = (fake_provider_t*)provider;
	bool fail;
	char *address;

	this->mutex->lock(this->mutex);
	this->calls++;
	free(this->last_uri);
	free(this->last_name);
	this->last_uri = strdup(uri);
	this->last_name = strdup(name);
	this->last_family = family;
	fail = this->fail;
	address = this->address;
	this->mutex->unlock(this->mutex);
	if (this->entered)
	{
		this->entered->post(this->entered);
	}
	if (this->release)
	{
		this->release->wait(this->release);
	}
	return fail ? NULL : host_create_from_string(address, 0);
}

static void fake_init(fake_provider_t *this, char *scheme, char *address)
{
	*this = (fake_provider_t){
		.provider = {
			.scheme = scheme,
			.resolve = fake_resolve,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.address = address,
	};
}

static void fake_destroy(fake_provider_t *this)
{
	DESTROY_IF(this->entered);
	DESTROY_IF(this->release);
	free(this->last_uri);
	free(this->last_name);
	this->mutex->destroy(this->mutex);
}

static u_int fake_calls(fake_provider_t *this)
{
	u_int calls;

	this->mutex->lock(this->mutex);
	calls = this->calls;
	this->mutex->unlock(this->mutex);
	return calls;
}

START_TEST(test_provider_resolution)
{
	fake_provider_t fake;
	host_t *host, *expected;

	fake_init(&fake, "unit-resolver", "192.0.2.10");
	ck_assert(lib->hosts->add_provider(lib->hosts, &fake.provider));
	ck_assert(!lib->hosts->add_provider(lib->hosts, &fake.provider));

	host = lib->hosts->resolve_with_uri(lib->hosts,
										"unit-resolver://first", "gateway.test",
										AF_INET);
	ck_assert(host);
	expected = host_create_from_string("192.0.2.10", 0);
	ck_assert(host->ip_equals(host, expected));
	expected->destroy(expected);
	host->destroy(host);
	ck_assert_int_eq(fake_calls(&fake), 1);
	ck_assert_str_eq(fake.last_uri, "unit-resolver://first");
	ck_assert_str_eq(fake.last_name, "gateway.test");
	ck_assert_int_eq(fake.last_family, AF_INET);

	/* A provider failure must not fall back even if the OS resolves the name. */
	fake.fail = TRUE;
	host = lib->hosts->resolve_with_uri(lib->hosts,
										"unit-resolver://first", "localhost", AF_INET);
	ck_assert(!host);
	ck_assert_int_eq(fake_calls(&fake), 2);
	ck_assert(!lib->hosts->resolve_with_uri(lib->hosts,
										 "missing://resolver", "localhost", AF_INET));
	ck_assert_int_eq(fake_calls(&fake), 2);

	lib->hosts->remove_provider(lib->hosts, &fake.provider);
	ck_assert(!lib->hosts->resolve_with_uri(lib->hosts,
										 "unit-resolver://first", "localhost", AF_INET));
	fake_destroy(&fake);
}
END_TEST

START_TEST(test_numeric_bypass)
{
	fake_provider_t fake;
	host_t *host;

	fake_init(&fake, "unit-numeric", "192.0.2.11");
	ck_assert(lib->hosts->add_provider(lib->hosts, &fake.provider));

	host = host_create_from_dns_with_uri("198.51.100.8", AF_INET, 4500,
										 "unit-numeric://unused");
	ck_assert(host);
	ck_assert_int_eq(host->get_port(host), 4500);
	ck_assert_int_eq(fake_calls(&fake), 0);
	host->destroy(host);

	host = host_create_from_dns_with_uri("gateway.test", AF_INET, 500,
										 "unit-numeric://used");
	ck_assert(host);
	ck_assert_int_eq(host->get_port(host), 500);
	ck_assert_int_eq(fake_calls(&fake), 1);
	host->destroy(host);

	lib->hosts->remove_provider(lib->hosts, &fake.provider);
	fake_destroy(&fake);
}
END_TEST

typedef struct {
	char *uri;
	host_t *result;
	semaphore_t *started;
} resolve_call_t;

static void *run_resolve(resolve_call_t *call)
{
	if (call->started)
	{
		call->started->post(call->started);
	}
	call->result = lib->hosts->resolve_with_uri(lib->hosts, call->uri,
											 "gateway.test", AF_INET);
	return NULL;
}

START_TEST(test_uri_deduplication)
{
	fake_provider_t fake;
	resolve_call_t calls[2] = {
		{ .uri = "unit-dedup://one" },
		{ .uri = "unit-dedup://one" },
	};
	thread_t *threads[2];
	u_int i;

	fake_init(&fake, "unit-dedup", "192.0.2.12");
	fake.entered = semaphore_create(0);
	fake.release = semaphore_create(0);
	ck_assert(lib->hosts->add_provider(lib->hosts, &fake.provider));

	threads[0] = thread_create((thread_main_t)run_resolve, &calls[0]);
	fake.entered->wait(fake.entered);
	calls[1].started = semaphore_create(0);
	threads[1] = thread_create((thread_main_t)run_resolve, &calls[1]);
	calls[1].started->wait(calls[1].started);
	usleep(50000);
	/* Both callers share the single provider callback. */
	fake.release->post(fake.release);
	/* Avoid hanging if a regression incorrectly starts a late second callback. */
	fake.release->post(fake.release);
	for (i = 0; i < countof(threads); i++)
	{
		threads[i]->join(threads[i]);
		ck_assert(calls[i].result);
		calls[i].result->destroy(calls[i].result);
	}
	ck_assert_int_eq(fake_calls(&fake), 1);
	calls[1].started->destroy(calls[1].started);

	lib->hosts->remove_provider(lib->hosts, &fake.provider);
	fake_destroy(&fake);
}
END_TEST

START_TEST(test_uri_separates_queries)
{
	fake_provider_t fake;
	resolve_call_t calls[2] = {
		{ .uri = "unit-uri-key://one" },
		{ .uri = "unit-uri-key://two" },
	};
	thread_t *threads[2];
	u_int i;

	fake_init(&fake, "unit-uri-key", "192.0.2.13");
	fake.entered = semaphore_create(0);
	fake.release = semaphore_create(0);
	ck_assert(lib->hosts->add_provider(lib->hosts, &fake.provider));

	threads[0] = thread_create((thread_main_t)run_resolve, &calls[0]);
	fake.entered->wait(fake.entered);
	threads[1] = thread_create((thread_main_t)run_resolve, &calls[1]);
	/* A different URI is a different in-flight query. */
	fake.entered->wait(fake.entered);
	fake.release->post(fake.release);
	fake.release->post(fake.release);
	for (i = 0; i < countof(threads); i++)
	{
		threads[i]->join(threads[i]);
		ck_assert(calls[i].result);
		calls[i].result->destroy(calls[i].result);
	}
	ck_assert_int_eq(fake_calls(&fake), 2);

	lib->hosts->remove_provider(lib->hosts, &fake.provider);
	fake_destroy(&fake);
}
END_TEST

typedef struct {
	host_resolver_provider_t *provider;
	semaphore_t *started;
	semaphore_t *removed;
} remove_call_t;

static void *run_remove(remove_call_t *call)
{
	call->started->post(call->started);
	lib->hosts->remove_provider(lib->hosts, call->provider);
	call->removed->post(call->removed);
	return NULL;
}

START_TEST(test_remove_waits_for_callback)
{
	fake_provider_t fake;
	resolve_call_t resolve = { .uri = "unit-remove://resolver" };
	remove_call_t remove;
	semaphore_t *started, *removed;
	thread_t *resolver, *remover;

	fake_init(&fake, "unit-remove", "192.0.2.14");
	fake.entered = semaphore_create(0);
	fake.release = semaphore_create(0);
	ck_assert(lib->hosts->add_provider(lib->hosts, &fake.provider));

	resolver = thread_create((thread_main_t)run_resolve, &resolve);
	fake.entered->wait(fake.entered);
	started = semaphore_create(0);
	removed = semaphore_create(0);
	remove = (remove_call_t){
		.provider = &fake.provider,
		.started = started,
		.removed = removed,
	};
	remover = thread_create((thread_main_t)run_remove, &remove);
	started->wait(started);
	ck_assert(removed->timed_wait(removed, 50));

	fake.release->post(fake.release);
	ck_assert(!removed->timed_wait(removed, 1000));
	resolver->join(resolver);
	remover->join(remover);
	ck_assert(resolve.result);
	resolve.result->destroy(resolve.result);
	started->destroy(started);
	removed->destroy(removed);
	fake_destroy(&fake);
}
END_TEST

Suite *host_resolver_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("host resolver");
	tc = tcase_create("providers");
	tcase_add_test(tc, test_provider_resolution);
	tcase_add_test(tc, test_numeric_bypass);
	tcase_add_test(tc, test_uri_deduplication);
	tcase_add_test(tc, test_uri_separates_queries);
	tcase_add_test(tc, test_remove_waits_for_callback);
	suite_add_tcase(s, tc);
	return s;
}
