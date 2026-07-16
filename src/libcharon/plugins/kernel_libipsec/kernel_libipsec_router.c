/*
 * Copyright (C) 2013 Tobias Brunner
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "kernel_libipsec_router.h"
#include "kernel_libipsec_esp_handler.h"

#include <daemon.h>
#include <ipsec.h>

typedef struct private_kernel_libipsec_router_t private_kernel_libipsec_router_t;

kernel_libipsec_router_t *router;

struct private_kernel_libipsec_router_t {
	kernel_libipsec_router_t public;
	kernel_libipsec_plain_t *plain;
	kernel_libipsec_esp_handler_t *esp_handler;
};

CALLBACK(send_esp, void,
	private_kernel_libipsec_router_t *this, esp_packet_t *packet, bool encap)
{
	if (encap)
	{
		charon->sender->send_no_marker(charon->sender, (packet_t*)packet);
	}
	else if (this->esp_handler)
	{
		this->esp_handler->send(this->esp_handler, packet);
	}
	else
	{
		packet->destroy(packet);
	}
}

CALLBACK(receiver_esp_cb, void, void *data, packet_t *packet)
{
	ipsec->processor->queue_inbound(ipsec->processor,
									esp_packet_create_from_packet(packet));
}

CALLBACK(deliver_plain, void,
	private_kernel_libipsec_router_t *this, ip_packet_t *packet)
{
	this->plain->deliver(this->plain, packet);
}

METHOD(kernel_libipsec_router_t, get_tun_name, char*,
	private_kernel_libipsec_router_t *this, host_t *vip)
{
	return this->plain->get_tun_name(this->plain, vip);
}

METHOD(kernel_libipsec_router_t, destroy, void,
	private_kernel_libipsec_router_t *this)
{
	charon->receiver->del_esp_cb(charon->receiver, receiver_esp_cb);
	ipsec->processor->unregister_outbound(ipsec->processor, send_esp);
	ipsec->processor->unregister_inbound(ipsec->processor, deliver_plain);
	this->plain->destroy(this->plain);
	router = NULL;
	free(this);
}

kernel_libipsec_router_t *kernel_libipsec_router_create(
										kernel_libipsec_plain_t *plain)
{
	private_kernel_libipsec_router_t *this;

	if (!plain)
	{
		return NULL;
	}
	INIT(this,
		.public = {
			.get_tun_name = _get_tun_name,
			.destroy = _destroy,
		},
		.plain = plain,
		.esp_handler = lib->get(lib, "kernel-libipsec-esp-handler"),
	);
	ipsec->processor->register_outbound(ipsec->processor, send_esp, this);
	ipsec->processor->register_inbound(ipsec->processor, deliver_plain, this);
	charon->receiver->add_esp_cb(charon->receiver, receiver_esp_cb, NULL);
	router = &this->public;
	return &this->public;
}
