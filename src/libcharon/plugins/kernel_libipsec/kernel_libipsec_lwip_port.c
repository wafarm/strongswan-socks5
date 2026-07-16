/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "kernel_libipsec_lwip_port.h"

#include <stdarg.h>
#include <stdlib.h>

#include <library.h>
#include <utils/debug.h>
#include <utils/utils/time.h>

/* Accessed exclusively by the dedicated lwIP event thread. */
static rng_t *lwip_rng;

void kernel_libipsec_lwip_set_rng(rng_t *rng)
{
	lwip_rng = rng;
}

unsigned int kernel_libipsec_lwip_rand(void)
{
	uint32_t value;

	if (!lwip_rng || !lwip_rng->get_bytes(lwip_rng, sizeof(value),
										(uint8_t*)&value))
	{
		DBG1(DBG_KNL, "strong RNG failed for kernel-libipsec SOCKS backend");
		abort();
	}
	return value;
}

void kernel_libipsec_lwip_diag(const char *format, ...)
{
	char message[512];
	va_list args;

	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);
	DBG2(DBG_KNL, "lwIP: %s", message);
}

void kernel_libipsec_lwip_assert(const char *message, const char *file,
								 int line)
{
	DBG1(DBG_KNL, "lwIP assertion '%s' failed at %s:%d", message, file, line);
	abort();
}

uint32_t sys_now(void)
{
	timeval_t now;

	time_monotonic(&now);
	return (uint32_t)((uint64_t)now.tv_sec * 1000 + now.tv_usec / 1000);
}
