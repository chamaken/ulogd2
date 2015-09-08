/* ulogd_input_NFQ.c
 *
 * ulogd input plugin for mmaped nfqueue
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */
#define _GNU_SOURCE /* _sys_errlist[] */

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <ulogd/ulogd.h>
#include <ulogd/ring.h>

struct nfq_priv {
	struct mnl_socket	*nl;
	uint32_t		portid;
	struct ulogd_fd		ufd;
	struct mnl_ring		*nlr;
	bool			skipped;
};

/*
 * Each ring contains a number of continuous memory blocks, containing frames of
 * fixed size dependent on the parameters used for ring setup.
 *
 * Ring:[ block 0 ]
 * 		[ frame 0 ]
 * 		[ frame 1 ]
 * 	[ block 1 ]
 * 		[ frame 2 ]
 * 		[ frame 3 ]
 * 	...
 * 	[ block n ]
 * 		[ frame 2 * n ]
 * 		[ frame 2 * n + 1 ]
 *
 * The blocks are only visible to the kernel, from the point of view of user-space
 * the ring just contains the frames in a continuous memory zone.
 */
enum nfq_conf {
	NFQ_CONF_BLOCK_SIZE = 0,	/* 8192 */
	NFQ_CONF_BLOCK_NR,		/* 32 */
	NFQ_CONF_FRAME_SIZE,		/* 8192 */
	NFQ_CONF_ONESHOT,
	NFQ_CONF_QUEUE_NUM,
	NFQ_CONF_COPY_MODE,		/* NFQNL_COPY_META / NFQNL_COPY_PACKET */
	NFQ_CONF_FAIL_OPEN,		/* NFQA_CFG_F_FAIL_OPEN */
	NFQ_CONF_CONNTRACK,		/* NFQA_CFG_F_CONNTRACK */
	NFQ_CONF_GSO,			/* NFQA_CFG_F_GSO */
	NFQ_CONF_UID_GID,		/* NFQA_CFG_F_UID_GID */
	NFQ_CONF_SECCTX,		/* NFQA_CFG_F_SECCTX */
	NFQ_CONF_MAX,
};

static struct config_keyset nfq_kset = {
	.ces = {
		[NFQ_CONF_BLOCK_SIZE] = {
			.key	 = "block_size",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 8192,
		},
		[NFQ_CONF_BLOCK_NR] = {
			.key	 = "block_nr",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 32,
		},
		[NFQ_CONF_FRAME_SIZE] = {
			.key	 = "frame_size",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 8192,
		},
		[NFQ_CONF_ONESHOT] = {
			.key	 = "oneshot",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFQ_CONF_QUEUE_NUM] = {
			.key	 = "queue_num",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFQ_CONF_COPY_MODE] = {
			.key	 = "copy_mode",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u.string = "packet",
		},
		[NFQ_CONF_FAIL_OPEN] = {
			.key	 = "fail_open",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFQ_CONF_CONNTRACK] = {
			.key	 = "conntrack",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFQ_CONF_GSO] = {
			.key	 = "gso",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFQ_CONF_UID_GID] = {
			.key	 = "uid_gid",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFQ_CONF_SECCTX] = {
			.key	 = "secctx",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
	},
	.num_ces = NFQ_CONF_MAX,
};

#define block_size_ce(x)	(((x)->config_kset->ces[NFQ_CONF_BLOCK_SIZE]).u.value)
#define block_nr_ce(x)		(((x)->config_kset->ces[NFQ_CONF_BLOCK_NR]).u.value)
#define frame_size_ce(x)	(((x)->config_kset->ces[NFQ_CONF_FRAME_SIZE]).u.value)
#define oneshot_ce(x)		(((x)->config_kset->ces[NFQ_CONF_ONESHOT]).u.value)
#define queue_num_ce(x)		(((x)->config_kset->ces[NFQ_CONF_QUEUE_NUM]).u.value)
#define copy_mode_ce(x)		(((x)->config_kset->ces[NFQ_CONF_COPY_MODE]).u.string)
#define fail_open_ce(x)		(((x)->config_kset->ces[NFQ_CONF_FAIL_OPEN]).u.value)
#define conntrack_ce(x)		(((x)->config_kset->ces[NFQ_CONF_CONNTRACK]).u.value)
#define gso_ce(x)		(((x)->config_kset->ces[NFQ_CONF_GSO]).u.value)
#define uid_gid_ce(x)		(((x)->config_kset->ces[NFQ_CONF_UID_GID]).u.value)
#define secctx_ce(x)		(((x)->config_kset->ces[NFQ_CONF_SECCTX]).u.value)


enum ulogd_nfq_keys {
	ULOGD_NFQ_OKEY_NLATTRS,
	ULOGD_NFQ_OKEY_FAMILY,
	ULOGD_NFQ_OKEY_RES_ID,
	ULOGD_NFQ_OKEY_FRAME,
	ULOGD_NFQ_OKEY_MAX
};

static void frame_destructor(void *data);

static struct ulogd_key nfq_okeys[] = {
	[ULOGD_NFQ_OKEY_NLATTRS] = {
		/* struct nlattr *attr[NFQA_MAX+1] = {}; */
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_RETF_EMBED,
		.name	= "nfq.attrs",
		.len	= sizeof(struct nlattr *) * (NFQA_MAX + 1),
	},
	[ULOGD_NFQ_OKEY_FAMILY] = {
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "oob.family",
	},
	[ULOGD_NFQ_OKEY_RES_ID] = {
		.type	= ULOGD_RET_UINT16,
		.flags	= ULOGD_RETF_NONE,
		.name	= "nfq.res_id",
	},
	[ULOGD_NFQ_OKEY_FRAME] = {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_RETF_NONE | ULOGD_RETF_DESTRUCT,
		.name	= "nfq.frame",
		.destruct = frame_destructor,
	},
};

static void frame_destructor(void *data)
{
	struct nl_mmap_hdr *frame = data;
	frame->nm_status = NL_MMAP_STATUS_UNUSED;
}

static int nfq_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	struct ulogd_source_pluginstance *upi = data;
	struct ulogd_keyset *output = ulogd_get_output_keyset(upi);
	struct ulogd_key *ret = output->keys;
	struct nlattr **attrs;
	struct nl_mmap_hdr *frame = (void *)nlh - NL_MMAP_HDRLEN;

	okey_set_u8(&ret[ULOGD_NFQ_OKEY_FAMILY], nfg->nfgen_family);
	okey_set_u16(&ret[ULOGD_NFQ_OKEY_RES_ID], ntohs(nfg->res_id));
	okey_set_ptr(&ret[ULOGD_NFQ_OKEY_FRAME], frame);

	attrs = (struct nlattr **)okey_get_ptr(&ret[ULOGD_NFQ_OKEY_NLATTRS]);
	if (nfq_nlmsg_parse(nlh, attrs) < 0) {
		ulogd_log(ULOGD_ERROR, "could not parse nfq message\n");
		ulogd_put_output_keyset(output);
		return MNL_CB_ERROR;
	}
	okey_set_valid(&ret[ULOGD_NFQ_OKEY_NLATTRS]);

	ulogd_propagate_results(output);

	return MNL_CB_OK;
}

static int handle_valid_frame(struct ulogd_source_pluginstance *upi,
			      struct nl_mmap_hdr *frame)
{
	struct nfq_priv *priv =	(struct nfq_priv *)upi->private;
	int ret;

	if (frame->nm_len == 0) {
		/* an error may occured in kernel */
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		return ULOGD_IRET_OK;
	}

	frame->nm_status = NL_MMAP_STATUS_SKIP;
	ret = mnl_cb_run(MNL_FRAME_PAYLOAD(frame), frame->nm_len,
			 0, priv->portid, nfq_cb, upi);
	if (ret == MNL_CB_ERROR) {
		ulogd_log(ULOGD_ERROR, "mnl_cb_run: %d %s\n",
			  errno, _sys_errlist[errno]);
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		return ULOGD_IRET_ERR;
	}

	return ULOGD_IRET_OK;
}

static int nfq_read_cb(int fd, unsigned int what, void *param)
{
	struct ulogd_source_pluginstance *upi = param;
	struct nfq_priv *priv =	(struct nfq_priv *)upi->private;
	struct nl_mmap_hdr *frame;
	char buf[65535 + 4096]; /* max IP total len + some nla */
	int ret = ULOGD_IRET_ERR, nproc = 0;

	if (!(what & ULOGD_FD_READ))
		return 0;

	do {
		frame = mnl_ring_get_frame(priv->nlr);
		switch (frame->nm_status) {
		case NL_MMAP_STATUS_VALID:
			ret = handle_valid_frame(upi, frame);
			mnl_ring_advance(priv->nlr);
			if (ret != ULOGD_IRET_OK)
				return ret;
			break;
		case NL_MMAP_STATUS_RESERVED:
			/* currently used by the kernel */
			if (nproc > 0)
				return ULOGD_IRET_OK;
			return ULOGD_IRET_ERR;
		case NL_MMAP_STATUS_COPY:
			/* only consuming message */
			/* assert(frame->nm_len < sizeof(buf)); */
			recv(fd, buf, frame->nm_len, MSG_DONTWAIT);
			ulogd_log(ULOGD_ERROR, "recv frame exceeded size: %d\n",
				  frame->nm_len);
			frame->nm_status = NL_MMAP_STATUS_UNUSED;
			mnl_ring_advance(priv->nlr);
			break;
		case NL_MMAP_STATUS_UNUSED:
			if (nproc > 0)
				return ULOGD_IRET_OK;
			if (!mnl_ring_lookup_frame(priv->nlr,
						   NL_MMAP_STATUS_VALID)) {
				ulogd_log(ULOGD_ERROR,
					  "could not found valid frame\n");
				return ULOGD_IRET_ERR;
			}
			continue;
		case NL_MMAP_STATUS_SKIP:
			if (!priv->skipped) {
				priv->skipped = true;
				ulogd_log(ULOGD_ERROR, "found SKIP status"
					  " frame, ENOBUFS maybe\n");
			}
			return ULOGD_IRET_ERR;
		default:
			ulogd_log(ULOGD_ERROR, "unknown frame_status: %d\n",
				  frame->nm_status);
			return ULOGD_IRET_ERR;
		}
		nproc++;
	} while (oneshot_ce(upi));

	return ret;
}

/* copy from library examples */
static struct nlmsghdr *
nfq_hdr_put(char *buf, int type, uint32_t queue_num)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= (NFNL_SUBSYS_QUEUE << 8) | type;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(queue_num);

	return nlh;
}

static int nfq_put_config(struct nlmsghdr *nlh,
			  struct ulogd_source_pluginstance *upi)
{
	char *copy_mode = copy_mode_ce(upi);
	uint32_t flags = 0;

	if (strcasecmp(copy_mode, "packet") == 0) {
		/* copy_range is determined by frame size in mmaped socket.
		 * set max size to show the size at NL_MMAP_STATUS_COPY */
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);
	} else if (strcasecmp(copy_mode, "meta") == 0) {
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_META, 0);
	} else if (strcasecmp(copy_mode, "none") == 0) {
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_NONE, 0);
	} else {
		ulogd_log(ULOGD_ERROR, "unknow copy_mode: %s\n", copy_mode);
		return -1;
	}

	if (fail_open_ce(upi))
		flags |= NFQA_CFG_F_FAIL_OPEN;
	if (conntrack_ce(upi))
		flags |= NFQA_CFG_F_CONNTRACK;
	if (gso_ce(upi))
		flags |= NFQA_CFG_F_GSO;
	if (uid_gid_ce(upi))
		flags |= NFQA_CFG_F_UID_GID;
#if defined(NFQA_CFG_F_SECCTX)
	if (secctx_ce(upi))
		flags |= NFQA_CFG_F_SECCTX;
#endif
	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(flags));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_MAX - 1));

	return 0;
}

static int nfq_config_response(struct nfq_priv *priv)
{
	struct mnl_ring *nlr = priv->nlr;
	struct nl_mmap_hdr *frame = mnl_ring_get_frame(nlr);
	void *buf = MNL_FRAME_PAYLOAD(frame);
	int ret;

	if (frame->nm_status != NL_MMAP_STATUS_VALID) {
		ulogd_log(ULOGD_ERROR, "no valid response\n");
		return ULOGD_IRET_ERR;
	}
	frame->nm_status = NL_MMAP_STATUS_SKIP;
	ret = mnl_cb_run(buf, frame->nm_len, 0, priv->portid, NULL, NULL);
	frame->nm_status = NL_MMAP_STATUS_UNUSED;
	mnl_ring_advance(nlr);

	if (ret == MNL_CB_ERROR)
		return ULOGD_IRET_ERR;
	return ULOGD_IRET_OK;
}

static int nfq_send_request(struct ulogd_source_pluginstance *upi)
{
	struct nfq_priv *priv =	(struct nfq_priv *)upi->private;
	struct nlmsghdr *nlh;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int queue_num = queue_num_ce(upi);

	/* kernels 3.8 and later is required to omit PF_(UN)BIND */
	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, 0);
	nlh->nlmsg_flags |= NLM_F_ACK;
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_PF_BIND);
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_send: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}
	if (nfq_config_response(priv) != 0) {
		ulogd_log(ULOGD_ERROR, "config PF_BIND: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nlh->nlmsg_flags |= NLM_F_ACK;	
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_send: %s\n",
			_sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}
	if (nfq_config_response(priv) != 0) {
		ulogd_log(ULOGD_ERROR, "config BIND: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nlh->nlmsg_flags |= NLM_F_ACK;	
	if (nfq_put_config(nlh, upi) == -1)
		return ULOGD_IRET_ERR;
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_send: %s\n",
			_sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}
	if (nfq_config_response(priv) != 0) {
		ulogd_log(ULOGD_ERROR, "config params: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}

	return ULOGD_IRET_OK;
}

static int configure_nfq(struct ulogd_source_pluginstance *upi)
{
	return config_parse_file(upi->id, upi->config_kset);
}

static int constructor_nfq(struct ulogd_source_pluginstance *upi)
{
	struct nfq_priv *priv =	(struct nfq_priv *)upi->private;
	struct nl_mmap_req req = {
		.nm_block_size	= block_size_ce(upi),
		.nm_block_nr	= block_nr_ce(upi),
		.nm_frame_size	= frame_size_ce(upi),
		.nm_frame_nr	= block_size_ce(upi)
				/ frame_size_ce(upi)
				* block_nr_ce(upi),
	};
	int optval = 1;

	priv->nl = mnl_socket_open(NETLINK_NETFILTER);
	if (priv->nl == NULL) {
		ulogd_log(ULOGD_FATAL, "mnl_socket_open: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}
	ulogd_log(ULOGD_INFO, "mmap - block size: %d, block_nr: %d,"
		  " frame_size: %d, frame_nr: %d\n",
		  req.nm_block_size, req.nm_block_nr,
		  req.nm_frame_size, req.nm_frame_nr);
	priv->nlr = mnl_socket_rx_mmap(priv->nl, &req, MAP_SHARED);
	if (priv->nlr == NULL) {
		ulogd_log(ULOGD_FATAL, "mnl_socket_mmap: %s\n",
			  _sys_errlist[errno]);
		goto error_close_sock;
	}
	if (mnl_socket_bind(priv->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		ulogd_log(ULOGD_FATAL, "mnl_socket_bind: %s\n",
			  _sys_errlist[errno]);
		goto error_unmap;
	}
	priv->portid = mnl_socket_get_portid(priv->nl);

	/* ENOBUFS is signalled to userspace when packets were lost
	 * on kernel side.  In most cases, userspace isn't interested
	 * in this information, so turn it off. */
	mnl_socket_setsockopt(priv->nl, NETLINK_NO_ENOBUFS,
			      &optval, sizeof(int));

	if (nfq_send_request(upi) < 0) {
		ulogd_log(ULOGD_FATAL, "failed to nfq_send_request\n");
		goto error_unmap;
	}

	priv->ufd.fd = mnl_socket_get_fd(priv->nl);
	priv->ufd.cb = &nfq_read_cb;
	priv->ufd.data = upi;
	priv->ufd.when = ULOGD_FD_READ;
	if (ulogd_register_fd(&priv->ufd) < 0) {
		ulogd_log(ULOGD_FATAL, "ulogd_register_fd: %s\n",
			  _sys_errlist[errno]);
		goto error_unmap;
	}

	return ULOGD_IRET_OK;

error_unmap:
	mnl_socket_unmap(priv->nlr);
error_close_sock:
	mnl_socket_close(priv->nl);
	return ULOGD_IRET_ERR;
}

static int destructor_nfq(struct ulogd_source_pluginstance *upi)
{
	struct nfq_priv *priv = (void *)upi->private;

	ulogd_unregister_fd(&priv->ufd);
	mnl_socket_unmap(priv->nlr);
	mnl_socket_close(priv->nl);

	return 0;
}

static void signal_nfq(struct ulogd_source_pluginstance *upi, int signal)
{
	struct nfq_priv *priv =	(struct nfq_priv *)upi->private;
	struct nl_mmap_hdr *frame, *sentinel;;

	switch (signal) {
	case SIGUSR1:
		sentinel = frame = mnl_ring_get_frame(priv->nlr);
		do {
			ulogd_log(ULOGD_DEBUG, "---- frame status %p: %d\n",
				  frame, frame->nm_status);
			mnl_ring_advance(priv->nlr);
			frame = mnl_ring_get_frame(priv->nlr);
		} while (frame != sentinel);
		break;
	default:
		ulogd_log(ULOGD_DEBUG, "receive signal: %d\n", signal);
	}
}

static struct ulogd_source_plugin nfq_plugin = {
	.name = "NFQ",
	.output = {
		.keys = nfq_okeys,
		.num_keys = ARRAY_SIZE(nfq_okeys),
		.type = ULOGD_DTYPE_RAW,
	},
	.config_kset	= &nfq_kset,
	.configure	= &configure_nfq,
	.start		= &constructor_nfq,
	.stop		= &destructor_nfq,
	.signal		= &signal_nfq,
	.priv_size	= sizeof(struct nfq_priv),
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_source_plugin(&nfq_plugin);
}
