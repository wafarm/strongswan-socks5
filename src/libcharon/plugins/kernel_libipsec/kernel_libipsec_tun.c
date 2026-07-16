/*
 * Copyright (C) 2013 Tobias Brunner
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 */

#include "kernel_libipsec_tun.h"

#include <fcntl.h>
#include <unistd.h>

#include <daemon.h>
#include <ipsec.h>
#include <collections/hashtable.h>
#include <networking/tun_device.h>
#include <processing/jobs/callback_job.h>
#include <threading/rwlock.h>
#include <threading/thread.h>

typedef struct private_kernel_libipsec_tun_t private_kernel_libipsec_tun_t;

typedef struct {
	host_t *addr;
	int fd;
	tun_device_t *tun;
} tun_entry_t;

struct private_kernel_libipsec_tun_t {
	kernel_libipsec_plain_t public;
	kernel_listener_t listener;
	tun_entry_t tun;
	hashtable_t *tuns;
	rwlock_t *lock;
	int notify[2];
};

static u_int tun_entry_hash(tun_entry_t *entry)
{
	return chunk_hash(entry->addr->get_address(entry->addr));
}

static bool tun_entry_equals(tun_entry_t *a, tun_entry_t *b)
{
	return a->addr->ip_equals(a->addr, b->addr);
}

static void process_plain(tun_device_t *tun)
{
	chunk_t raw;

	if (tun->read_packet(tun, &raw))
	{
		ip_packet_t *packet = ip_packet_create(raw);

		if (packet)
		{
			ipsec->processor->queue_outbound(ipsec->processor, packet);
		}
		else
		{
			DBG1(DBG_KNL, "invalid IP packet read from TUN device");
		}
	}
}

static int find_revents(struct pollfd *pfd, int count, int fd)
{
	int i;

	for (i = 0; i < count; i++)
	{
		if (pfd[i].fd == fd)
		{
			return pfd[i].revents;
		}
	}
	return 0;
}

static job_requeue_t handle_plain(private_kernel_libipsec_tun_t *this)
{
	enumerator_t *enumerator;
	tun_entry_t *entry;
	bool oldstate;
	int count = 0;
	char buf[1];
	struct pollfd *pfd;

	this->lock->read_lock(this->lock);
	pfd = alloca(sizeof(*pfd) * (this->tuns->get_count(this->tuns) + 2));
	pfd[count++] = (struct pollfd){ .fd = this->notify[0], .events = POLLIN };
	pfd[count++] = (struct pollfd){ .fd = this->tun.fd, .events = POLLIN };

	enumerator = this->tuns->create_enumerator(this->tuns);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		pfd[count++] = (struct pollfd){ .fd = entry->fd, .events = POLLIN };
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	oldstate = thread_cancelability(TRUE);
	if (poll(pfd, count, -1) <= 0)
	{
		thread_cancelability(oldstate);
		return JOB_REQUEUE_FAIR;
	}
	thread_cancelability(oldstate);

	if (pfd[0].revents & POLLIN)
	{
		while (read(this->notify[0], buf, sizeof(buf)) == sizeof(buf))
		{
			/* drain */
		}
		return JOB_REQUEUE_DIRECT;
	}
	if (pfd[1].revents & POLLIN)
	{
		process_plain(this->tun.tun);
	}

	this->lock->read_lock(this->lock);
	enumerator = this->tuns->create_enumerator(this->tuns);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		if (find_revents(pfd, count, entry->fd) & POLLIN)
		{
			process_plain(entry->tun);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	return JOB_REQUEUE_DIRECT;
}

METHOD(kernel_listener_t, tun, bool,
	private_kernel_libipsec_tun_t *this, tun_device_t *tun, bool created)
{
	tun_entry_t *entry, lookup;
	char byte = 1;

	this->lock->write_lock(this->lock);
	if (created)
	{
		INIT(entry,
			.addr = tun->get_address(tun, NULL),
			.fd = tun->get_fd(tun),
			.tun = tun,
		);
		this->tuns->put(this->tuns, entry, entry);
	}
	else
	{
		lookup.addr = tun->get_address(tun, NULL);
		entry = this->tuns->remove(this->tuns, &lookup);
		free(entry);
	}
	ignore_result(write(this->notify[1], &byte, sizeof(byte)));
	this->lock->unlock(this->lock);
	return TRUE;
}

METHOD(kernel_libipsec_plain_t, deliver, void,
	private_kernel_libipsec_tun_t *this, ip_packet_t *packet)
{
	tun_device_t *tun;
	tun_entry_t *entry, lookup = {
		.addr = packet->get_destination(packet),
	};

	this->lock->read_lock(this->lock);
	entry = this->tuns->get(this->tuns, &lookup);
	tun = entry ? entry->tun : this->tun.tun;
	tun->write_packet(tun, packet->get_encoding(packet));
	this->lock->unlock(this->lock);
	packet->destroy(packet);
}

METHOD(kernel_libipsec_plain_t, get_tun_name, char*,
	private_kernel_libipsec_tun_t *this, host_t *vip)
{
	tun_entry_t *entry, lookup = { .addr = vip };
	tun_device_t *tun;
	char *name;

	if (!vip)
	{
		return strdup(this->tun.tun->get_name(this->tun.tun));
	}
	this->lock->read_lock(this->lock);
	entry = this->tuns->get(this->tuns, &lookup);
	tun = entry ? entry->tun : this->tun.tun;
	name = strdup(tun->get_name(tun));
	this->lock->unlock(this->lock);
	return name;
}

METHOD(kernel_libipsec_plain_t, destroy, void,
	private_kernel_libipsec_tun_t *this)
{
	charon->kernel->remove_listener(charon->kernel, &this->listener);
	close(this->notify[0]);
	close(this->notify[1]);
	this->lock->destroy(this->lock);
	this->tuns->destroy(this->tuns);
	free(this);
}

static bool set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	return flags != -1 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

kernel_libipsec_plain_t *kernel_libipsec_tun_create(void)
{
	private_kernel_libipsec_tun_t *this;

	INIT(this,
		.public = {
			.deliver = _deliver,
			.get_tun_name = _get_tun_name,
			.destroy = _destroy,
		},
		.listener = {
			.tun = _tun,
		},
		.tun = {
			.tun = lib->get(lib, "kernel-libipsec-tun"),
		},
	);
	if (!this->tun.tun || pipe(this->notify) != 0 ||
		!set_nonblock(this->notify[0]) || !set_nonblock(this->notify[1]))
	{
		DBG1(DBG_KNL, "creating kernel-libipsec TUN backend failed");
		if (this->notify[0] > 0)
		{
			close(this->notify[0]);
		}
		if (this->notify[1] > 0)
		{
			close(this->notify[1]);
		}
		free(this);
		return NULL;
	}
	this->tun.fd = this->tun.tun->get_fd(this->tun.tun);
	this->tuns = hashtable_create((hashtable_hash_t)tun_entry_hash,
								  (hashtable_equals_t)tun_entry_equals, 4);
	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);
	charon->kernel->add_listener(charon->kernel, &this->listener);
	lib->processor->queue_job(lib->processor,
		(job_t*)callback_job_create((callback_job_cb_t)handle_plain, this,
									NULL, callback_job_cancel_thread));
	return &this->public;
}
