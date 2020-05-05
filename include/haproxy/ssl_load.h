/*
 * load certificates in batch with liburing
 *
 * Copyright 2020 William Dauchy <wdauchy@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _PROTO_SSL_LOAD_H
#define _PROTO_SSL_LOAD_H

#ifdef USE_IO_URING

#include <liburing.h>

#include <import/ebpttree.h>

#define QD	4096

struct cert_iobuf {
	int fd;
	char *buf;
	off_t filesize;
	struct statx stx;
	struct ebmb_node node;
	char filepath[0];
};

struct io_op {
	char name[6];                                               /* operation name for logging */
	int (*queue)(struct io_uring *, struct cert_iobuf *, int);
	void (*handle)(struct cert_iobuf *, struct io_uring_cqe *);
};

extern struct eb_root cert_iobuf_tree;

int ssl_load_certiodir(const char *filedir, struct eb_root *file_tree);
void ssl_free_certiodir(const char *filedir, struct eb_root *file_tree);

#endif /* USE_IO_URING */
#endif /* _PROTO_SSL_LOAD_H */
