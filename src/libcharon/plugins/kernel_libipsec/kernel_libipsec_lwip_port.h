/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#ifndef KERNEL_LIBIPSEC_LWIP_PORT_H_
#define KERNEL_LIBIPSEC_LWIP_PORT_H_

#include <crypto/rngs/rng.h>

/** Install the RNG used by the single lwIP event thread. */
void kernel_libipsec_lwip_set_rng(rng_t *rng);

/** lwIP sys_now() implementation based on strongSwan's monotonic clock. */
uint32_t sys_now(void);

#endif /* KERNEL_LIBIPSEC_LWIP_PORT_H_ */
