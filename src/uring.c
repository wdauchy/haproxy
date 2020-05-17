/*
 * liburing interface
 *
 * Copyright 2020 William Dauchy <wdauchy@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <liburing.h>

#include <haproxy/log.h>

int setup_context(unsigned entries, struct io_uring *ring)
{
	int ret;

	ret = io_uring_queue_init(entries, ring, 0);
	if (ret < 0) {
		ha_alert("queue_init: %s\n", strerror(-ret));
		return ERR_ALERT;
	}
	return 0;
}
