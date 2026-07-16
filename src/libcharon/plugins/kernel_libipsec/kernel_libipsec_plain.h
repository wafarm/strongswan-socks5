/*
 * Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#ifndef KERNEL_LIBIPSEC_PLAIN_H_
#define KERNEL_LIBIPSEC_PLAIN_H_

#include <ip_packet.h>

typedef struct kernel_libipsec_plain_t kernel_libipsec_plain_t;

/**
 * Plaintext side of the kernel-libipsec router.
 *
 * Implementations own packets passed to deliver().
 */
struct kernel_libipsec_plain_t {
	void (*deliver)(kernel_libipsec_plain_t *this, ip_packet_t *packet);

	/**
	 * Return the TUN interface for a virtual IP, or NULL for non-TUN planes.
	 */
	char *(*get_tun_name)(kernel_libipsec_plain_t *this, host_t *vip);

	void (*destroy)(kernel_libipsec_plain_t *this);
};

#endif /* KERNEL_LIBIPSEC_PLAIN_H_ */
