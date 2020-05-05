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

#define _GNU_SOURCE

#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#include <liburing.h>

#include <import/ebpttree.h>
#include <import/ebsttree.h>

#include <haproxy/dynbuf.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/ssl_load.h>
#include <haproxy/log.h>


struct eb_root cert_iobuf_tree = EB_ROOT_UNIQUE; /* IO_URING certificates buffer */

static int setup_context(unsigned entries, struct io_uring *ring)
{
	int ret;

	ret = io_uring_queue_init(entries, ring, 0);
	if (ret < 0) {
		ha_alert("queue_init: %s\n", strerror(-ret));
		return ERR_ALERT;
	}
	return 0;
}

static int do_io_op(struct io_uring *ring, struct eb_root *cert_iobuf_tree,
		    struct io_op *op, int dirfd)
{
	struct cert_iobuf *cert_io;
	struct eb_node *node, *next;
	struct io_uring_cqe *cqe;
	unsigned int i;
	int inqueue;
	int pending;
	int ret;

	inqueue = 0;
	node = eb_first(cert_iobuf_tree);
	while (node) {
		for (; node && inqueue < QD; inqueue++) {
			next = eb_next(node);
			cert_io = ebmb_entry(node, struct cert_iobuf, node);
			ret = op->queue(ring, cert_io, dirfd);
			if (ret)
				ha_warning("ssl_load: queue error\n");
			node = next;
		}
		ret = io_uring_submit(ring);
		if (ret < 0) {
			ha_warning("ssl_load, %s: io_uring_submit: %s\n",
				   op->name, strerror(-ret));
			return ERR_ALERT;
		}
		pending = ret;
		for (i = 0; i < pending; i++) {
			ret = io_uring_wait_cqe(ring, &cqe);
			if (ret < 0) {
				ha_warning("ssl_load, %s: io_uring_wait_cqe: %s\n",
					   op->name, strerror(-ret));
				continue;
			}
			if (!cqe)
				continue;
			cert_io = io_uring_cqe_get_data(cqe);
			if (cqe->res < 0)
				ha_warning("ssl_load, %s: cqe failed: %s (%s)\n",
					   op->name, strerror(-cqe->res), cert_io->filepath);
			else
				op->handle(cert_io, cqe);
			io_uring_cqe_seen(ring, cqe);
			inqueue--;
		}
	}
	if (inqueue > 0) {
		ha_warning("ssl_load, %s: inqueue error\n", op->name);
		return ERR_ALERT;
	}
	return 0;
}

static int queue_statx(struct io_uring *ring, struct cert_iobuf *cert_io, int dirfd)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return ERR_ALERT;

	io_uring_prep_statx(sqe, dirfd, cert_io->filepath, 0, STATX_SIZE, &(cert_io->stx));
	io_uring_sqe_set_data(sqe, cert_io);
	return 0;
}

static void handle_statx(struct cert_iobuf *cert_io, struct io_uring_cqe *cqe)
{
	cert_io->filesize = cert_io->stx.stx_size;
}

static int queue_open(struct io_uring *ring, struct cert_iobuf *cert_io, int dirfd)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return ERR_ALERT;

	io_uring_prep_openat(sqe, dirfd, cert_io->filepath, O_RDONLY, 0);
	io_uring_sqe_set_data(sqe, cert_io);
	return 0;
}

static void handle_open(struct cert_iobuf *cert_io, struct io_uring_cqe *cqe)
{
	cert_io->fd = cqe->res;
}

static int queue_read(struct io_uring *ring, struct cert_iobuf *cert_io, int dirfd)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return ERR_ALERT;

	cert_io->buf = malloc(sizeof(*(cert_io->buf)) * cert_io->filesize + 1);
	if (!cert_io->buf) {
		ha_alert("ssl_load: out of memory in buffer allocation\n");
		return ERR_ALERT;
	}

	io_uring_prep_read(sqe, cert_io->fd, cert_io->buf, cert_io->filesize, 0);
	io_uring_sqe_set_data(sqe, cert_io);
	return 0;
}

static void handle_read(struct cert_iobuf *cert_io, struct io_uring_cqe *cqe)
{
	cert_io->buf[cert_io->filesize] = 0;
}

static int queue_close(struct io_uring *ring, struct cert_iobuf *cert_io, int dirfd)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return ERR_ALERT;

	io_uring_prep_close(sqe, cert_io->fd);
	return 0;
}

static void handle_close(struct cert_iobuf *cert_io, struct io_uring_cqe *cqe)
{
}

static int ssl_load_preparetree(const char *filedir, struct eb_root *cert_iobuf_tree)
{
	struct cert_iobuf *cert_io;
	struct dirent **de_list;
	struct dirent *de;
	int path_len;
	int nb_file;
	int i, j;
	char *end;

	nb_file = scandir(filedir, &de_list, 0, alphasort);
	if (nb_file < 0) {
		ha_warning("ssl_load: unable to scan directory\n");
		return ERR_ALERT;
	}
	for (i = 0; i < nb_file; i++) {
		de = de_list[i];
		end = strrchr(de->d_name, '.');
		for (j = 0; j < SSL_SOCK_NUM_KEYTYPES; j++)
			if (!strcmp(end + 1, SSL_SOCK_KEYTYPE_NAMES[j]))
				goto load_entry;
		goto skip_entry;
load_entry:
		/* filedir + slash + name + \0 */
		path_len = strlen(filedir) + strlen(de->d_name) + 2;
		cert_io = malloc(sizeof(*cert_io) + path_len);
		if (cert_io == NULL) {
			ha_alert("ssl_load: out of memory in tree allocation\n");
			return ERR_ALERT;
		}
		snprintf((char *) cert_io->node.key, path_len, "%s/%s",
		         filedir, de->d_name);
		cert_io->filesize = 0;
		cert_io->buf = NULL;
		ebst_insert(cert_iobuf_tree, &cert_io->node);
skip_entry:
		free(de);
	}
	free(de_list);
	return 0;
}

int ssl_load_certiodir(const char *filedir, struct eb_root *cert_iobuf_tree)
{
	struct io_uring ring;
	struct io_op op;
	int dirfd;
	int ret = 0;

	ret = ssl_load_preparetree(filedir, cert_iobuf_tree);
	if (ret)
		return ret;

	dirfd = open(filedir, 0);
	if (dirfd < 0)
		return ERR_ALERT;
	if (setup_context(QD, &ring))
		return ERR_ALERT;
	memcpy(op.name, "statx", strlen("statx") + 1);
	op.queue = queue_statx;
	op.handle = handle_statx;
	ret = do_io_op(&ring, cert_iobuf_tree, &op, dirfd);
	if (ret)
		goto exit;
	memcpy(op.name, "open", strlen("open") + 1);
	op.queue = queue_open;
	op.handle = handle_open;
	ret = do_io_op(&ring, cert_iobuf_tree, &op, dirfd);
	if (ret)
		goto exit;
	memcpy(op.name, "read", strlen("open") + 1);
	op.queue = queue_read;
	op.handle = handle_read;
	ret = do_io_op(&ring, cert_iobuf_tree, &op, dirfd);
	if (ret)
		goto exit;
	memcpy(op.name, "close", strlen("open") + 1);
	op.queue = queue_close;
	op.handle = handle_close;
	ret = do_io_op(&ring, cert_iobuf_tree, &op, dirfd);
	if (ret)
		goto exit;
exit:
	io_uring_queue_exit(&ring);
	return ret;
}

void ssl_free_certiodir(const char *filedir, struct eb_root *cert_iobuf_tree)
{
	struct eb_node *node, *next;
	struct cert_iobuf *cert_io;

	node = eb_first(cert_iobuf_tree);
	while (node) {
		next = eb_next(node);
		eb_delete(node);
		cert_io = ebmb_entry(node, struct cert_iobuf, node);
		free(cert_io->buf);
		free(cert_io);
		node = next;
	}
}
