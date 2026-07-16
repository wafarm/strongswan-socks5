/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#ifndef KERNEL_LIBIPSEC_SOCKS_H_
#define KERNEL_LIBIPSEC_SOCKS_H_

#include "kernel_libipsec_plain.h"

/** Create the embedded lwIP SOCKS5 plaintext backend. */
kernel_libipsec_plain_t *kernel_libipsec_socks_create(void);

#endif /* KERNEL_LIBIPSEC_SOCKS_H_ */
