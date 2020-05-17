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

#ifndef _HAPROXY_URING_H
#define _HAPROXY_URING_H

#ifdef USE_IO_URING

#include <liburing.h>

#define QD	4096

int setup_context(unsigned entries, struct io_uring *ring);

#endif /* USE_IO_URING */
#endif /* _HAPROXY_URING_H */
