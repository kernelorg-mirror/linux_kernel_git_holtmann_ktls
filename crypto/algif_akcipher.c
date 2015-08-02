/*
 * algif_aead: User-space interface for asymmetric key algorithms
 *
 * Copyright (C) 2015, Stephan Mueller <smueller@chronox.de>
 *
 * This file provides the user-space API for akciphers.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#include <crypto/akcipher.h>
#include <crypto/if_alg.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>

struct akcipher_ctx {
	u8 *req_data_ptr;	/* pointer to buffer to be processed */
	struct page *page_ptr;
	u8 *req_data;		/* buffer used for sendmsg requests */
	size_t req_size;	/* minimum buffer size */

	struct af_alg_completion completion;

	size_t used;

	unsigned int len;
	bool more;
	int op;

	struct akcipher_request req;
};

static inline bool akcipher_sufficient_data(struct akcipher_ctx *ctx)
{
	return ctx->used >= ctx->req_size;
}

static void akcipher_put_sgl(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct akcipher_ctx *ctx = ask->private;

	ctx->used = 0;
	ctx->more = 0;

	ctx->req_data_ptr = NULL;

	if (ctx->page_ptr)
		put_page(ctx->page_ptr);
	ctx->page_ptr = NULL;
}

static void akcipher_wmem_wakeup(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct akcipher_ctx *ctx = ask->private;
	struct socket_wq *wq;

	if (akcipher_sufficient_data(ctx))
		return;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, POLLIN |
							   POLLRDNORM |
							   POLLRDBAND);
	sk_wake_async(sk, SOCK_WAKE_WAITD, POLL_IN);
	rcu_read_unlock();
}

static int akcipher_wait_for_data(struct sock *sk, unsigned flags)
{
	struct alg_sock *ask = alg_sk(sk);
	struct akcipher_ctx *ctx = ask->private;
	long timeout;
	DEFINE_WAIT(wait);
	int err = -ERESTARTSYS;

	if (flags & MSG_DONTWAIT)
		return -EAGAIN;

	set_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);

	for (;;) {
		if (signal_pending(current))
			break;
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		timeout = MAX_SCHEDULE_TIMEOUT;
		if (sk_wait_event(sk, &timeout, !ctx->more)) {
			err = 0;
			break;
		}
	}
	finish_wait(sk_sleep(sk), &wait);

	clear_bit(SOCK_ASYNC_WAITDATA, &sk->sk_socket->flags);

	return err;
}

static void akcipher_data_wakeup(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct akcipher_ctx *ctx = ask->private;
	struct socket_wq *wq;

	if (ctx->more)
		return;
	if (!ctx->used)
		return;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, POLLOUT |
							   POLLRDNORM |
							   POLLRDBAND);
	sk_wake_async(sk, SOCK_WAKE_SPACE, POLL_OUT);
	rcu_read_unlock();
}

static int akcipher_get_reqsize(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct akcipher_ctx *ctx = ask->private;

	akcipher_request_set_crypt(&ctx->req, NULL, NULL, 0, 0);
	/* expect this to fail, and update the required buf len */
	crypto_akcipher_encrypt(&ctx->req);

	if (!ctx->req.dst_len)

	BUG_ON(ctx->req.dst_len > PAGE_SIZE);

	/* Existing memory size matches required size. */
	if (ctx->req_size == ctx->req.dst_len)
		return 0;

	if (ctx->req_data) {
		sock_kzfree_s(sk, ctx->req_data, ctx->req_size);
		ctx->req_data = NULL;
	}

	ctx->req_size = ctx->req.dst_len;
	ctx->req_data = sock_kmalloc(sk, ctx->req_size, GFP_KERNEL);
	if (!ctx->req_data) {
		ctx->req_size = 0;
		return -ENOMEM;
	}

	return 0;
}

static int akcipher_sendmsg(struct socket *sock, struct msghdr *msg,
			    size_t size)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct akcipher_ctx *ctx = ask->private;
	struct af_alg_control con = {};
	long copied = 0;
	int op = 0;
	bool init = 0;
	int err = -EINVAL;

	if (msg->msg_controllen) {
		err = af_alg_cmsg_send(msg, &con);
		if (err)
			return err;

		init = 1;
		switch (con.op) {
		case ALG_OP_VERIFY:
			break;
		case ALG_OP_SIGN:
			break;
		case ALG_OP_ENCRYPT:
			break;
		case ALG_OP_DECRYPT:
			break;
		default:
			return -EINVAL;
		}
		op = con.op;
	}

	lock_sock(sk);
	if (!ctx->more && ctx->used)
		goto unlock;

	if (init) {
		ctx->op = op;

		err = akcipher_get_reqsize(sk);
		if (err)
			goto unlock;
	}

	if (!size)
		goto done;


	/*
	 * We do not allow mixing of sendmsg and sendpage calls as this would
	 * require a hairy memory management.
	 */
	if (ctx->page_ptr)
		goto unlock;

	ctx->req_data_ptr = ctx->req_data;

	if (ctx->req_size > ctx->used) {
		size_t len = min_t(size_t, size, ctx->req_size - ctx->used);

		err = memcpy_from_msg(ctx->req_data + ctx->used, msg, len);
		if (err)
			goto unlock;

		ctx->used += len;
		copied += len;
		size -= len;
	}

	err = 0;

done:
	ctx->more = msg->msg_flags & MSG_MORE;

unlock:
	akcipher_data_wakeup(sk);
	release_sock(sk);

	return err ?: copied;
}

static ssize_t akcipher_sendpage(struct socket *sock, struct page *page,
				 int offset, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct akcipher_ctx *ctx = ask->private;
	int err = -EINVAL;

	if (flags & MSG_SENDPAGE_NOTLAST)
		flags |= MSG_MORE;

	lock_sock(sk);

	/*
	 * We do not allow mixing of sendmsg and sendpage calls as this would
	 * require a hairy memory management.
	 *
	 * This check also guards against double call of sendpage.
	 * We require that the output buffer size must be provided with one
	 * sendpage request as otherwise we cannot have a linear buffer required
	 * by the akcipher API.
	 */
	if (ctx->req_data_ptr)
		goto unlock;

	if (akcipher_sufficient_data(ctx)) {
		err = -EAGAIN;
		goto done;
	}

	if (!size)
		goto done;

	get_page(page);
	ctx->req_data_ptr = page_address(page) + offset;
	ctx->page_ptr = page;
	ctx->used = size;
	if (ctx->used > ctx->req_size)
		ctx->used = ctx->req_size;

	err = 0;

done:
	ctx->more = flags & MSG_MORE;

unlock:
	akcipher_data_wakeup(sk);
	release_sock(sk);

	return err ?: size;
}

static int akcipher_recvmsg(struct socket *sock, struct msghdr *msg,
			    size_t ignored, int flags)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct akcipher_ctx *ctx = ask->private;
	int err = -EINVAL;
	size_t outlen = 0;

	lock_sock(sk);

	if (ctx->more && !akcipher_sufficient_data(ctx)) {
		err = akcipher_wait_for_data(sk, flags);
		if (err)
			goto unlock;
	}

	BUG_ON(!ctx->req_data_ptr);
	akcipher_request_set_crypt(&ctx->req, ctx->req_data_ptr,
				   ctx->req_data, ctx->used, ctx->req_size);
	switch(ctx->op) {
	case ALG_OP_VERIFY:
		err = crypto_akcipher_verify(&ctx->req);
		break;
	case ALG_OP_SIGN:
		err = crypto_akcipher_sign(&ctx->req);
		break;
	case ALG_OP_ENCRYPT:
		err = crypto_akcipher_encrypt(&ctx->req);
		break;
	case ALG_OP_DECRYPT:
		err = crypto_akcipher_decrypt(&ctx->req);
		break;
	default:
		BUG();
	}

	err = af_alg_wait_for_completion(err, &ctx->completion);

	/* EBADMSG implies a valid cipher operation took place */
	if (err) {
		if (err == -EBADMSG)
			akcipher_put_sgl(sk);
		goto unlock;
	}

	/* Only copy the size of the calculated value to user space. */
	outlen = ctx->req.dst_len;
	err = memcpy_to_msg(msg, ctx->req_data, outlen);
	if (err)
		goto unlock;

	akcipher_put_sgl(sk);

unlock:
	akcipher_wmem_wakeup(sk);
	release_sock(sk);

	return err ? err : outlen;
}

static unsigned int akcipher_poll(struct file *file, struct socket *sock,
			      poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct akcipher_ctx *ctx = ask->private;
	unsigned int mask;

	sock_poll_wait(file, sk_sleep(sk), wait);
	mask = 0;

	if (!ctx->more)
		mask |= POLLIN | POLLRDNORM;

	if (!akcipher_sufficient_data(ctx))
		mask |= POLLOUT | POLLWRNORM | POLLWRBAND;

	return mask;
}

static struct proto_ops algif_akcipher_ops = {
	.family		=	PF_ALG,

	.connect	=	sock_no_connect,
	.socketpair	=	sock_no_socketpair,
	.getname	=	sock_no_getname,
	.ioctl		=	sock_no_ioctl,
	.listen		=	sock_no_listen,
	.shutdown	=	sock_no_shutdown,
	.getsockopt	=	sock_no_getsockopt,
	.mmap		=	sock_no_mmap,
	.bind		=	sock_no_bind,
	.accept		=	sock_no_accept,
	.setsockopt	=	sock_no_setsockopt,

	.release	=	af_alg_release,
	.sendmsg	=	akcipher_sendmsg,
	.sendpage	=	akcipher_sendpage,
	.recvmsg	=	akcipher_recvmsg,
	.poll		=	akcipher_poll,
};

static void *akcipher_bind(const char *name, u32 type, u32 mask)
{
	return crypto_alloc_akcipher(name, type, mask);
}

static void akcipher_release(void *private)
{
	crypto_free_akcipher(private);
}

static int akcipher_setkey(void *private, const u8 *key, unsigned int keylen)
{
	return crypto_akcipher_setkey(private, (u8 *)key, keylen);
}

static void akcipher_sock_destruct(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct akcipher_ctx *ctx = ask->private;

	akcipher_put_sgl(sk);
	if (ctx->req_data)
		sock_kzfree_s(sk, ctx->req_data, ctx->req_size);
	sock_kfree_s(sk, ctx, ctx->len);
	af_alg_release_parent(sk);
}

static int akcipher_accept_parent(void *private, struct sock *sk)
{
	struct akcipher_ctx *ctx;
	struct alg_sock *ask = alg_sk(sk);
	unsigned int len = sizeof(*ctx) + crypto_akcipher_reqsize(private);

	ctx = sock_kmalloc(sk, len, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	memset(ctx, 0, len);

	ctx->len = len;
	ctx->used = 0;
	ctx->more = 0;
	ctx->op = 0;
	ctx->req_size = 0;
	af_alg_init_completion(&ctx->completion);

	ask->private = ctx;

	akcipher_request_set_tfm(&ctx->req, private);
	akcipher_request_set_callback(&ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      af_alg_complete, &ctx->completion);

	sk->sk_destruct = akcipher_sock_destruct;

	return 0;
}

static const struct af_alg_type algif_type_aead = {
	.bind		=	akcipher_bind,
	.release	=	akcipher_release,
	.setkey		=	akcipher_setkey,
	.accept		=	akcipher_accept_parent,
	.ops		=	&algif_akcipher_ops,
	.name		=	"akcipher",
	.owner		=	THIS_MODULE
};

static int __init algif_akcipher_init(void)
{
	return af_alg_register_type(&algif_type_aead);
}

static void __exit algif_akcipher_exit(void)
{
	int err = af_alg_unregister_type(&algif_type_aead);
	BUG_ON(err);
}

module_init(algif_akcipher_init);
module_exit(algif_akcipher_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Asymmetric key kernel crypto API user space interface");
