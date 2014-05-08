/* ulogd_input_NFCTST.c
 *
 * ulogd input plugin for ctnetlink stats
 *
 * (C) 2014 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>

#include <ulogd/ulogd.h>
#include <ulogd/timer.h>

#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libmnl/libmnl.h>

enum nfctst_keys {
	OKEY_STATS_SEARCHED		= CTA_STATS_SEARCHED	   - 1,
	OKEY_STATS_FOUND		= CTA_STATS_FOUND	   - 1,
	OKEY_STATS_NEW			= CTA_STATS_NEW		   - 1,
	OKEY_STATS_INVALID		= CTA_STATS_INVALID	   - 1,
	OKEY_STATS_IGNORE		= CTA_STATS_IGNORE	   - 1,
	OKEY_STATS_DELETE		= CTA_STATS_DELETE	   - 1,
	OKEY_STATS_DELETE_LIST		= CTA_STATS_DELETE_LIST	   - 1,
	OKEY_STATS_INSERT		= CTA_STATS_INSERT	   - 1,
	OKEY_STATS_INSERT_FAILED	= CTA_STATS_INSERT_FAILED  - 1,
	OKEY_STATS_DROP			= CTA_STATS_DROP	   - 1,
	OKEY_STATS_EARLY_DROP		= CTA_STATS_EARLY_DROP	   - 1,
	OKEY_STATS_ERROR		= CTA_STATS_ERROR	   - 1,
	OKEY_STATS_SEARCH_RESTART 	= CTA_STATS_SEARCH_RESTART - 1,
	OKEY_MAX			= OKEY_STATS_SEARCH_RESTART,
};

#define CTA2OKEY(cta) ((cta) - 1)

struct nfctst_pluginstance {
	struct mnl_socket *sock;
	int seq, portid;
	struct ulogd_fd fd;
	struct ulogd_timer timer;
	uint32_t stat[OKEY_MAX + 1];
	char nlbuf[sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg)];
};

static struct config_keyset nfctst_kset = {
	.num_ces = 1,
	.ces = {
		{
			.key	 = "pollinterval",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 60,
		},
	},
};

#define pollint_ce(x)	(x->ces[0])

static struct ulogd_key nfctst_okeys[] = {
	[OKEY_STATS_SEARCHED] = {
		.type 	= ULOGD_RET_UINT32,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.searched",
	},
	[OKEY_STATS_FOUND] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.found",
	},
	[OKEY_STATS_NEW] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.new",
	},
	[OKEY_STATS_INVALID] = {
		.type	= ULOGD_RET_UINT32,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.invalid",
	},
	[OKEY_STATS_IGNORE] = {
		.type	= ULOGD_RET_UINT32,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.ignore",
	},
	[OKEY_STATS_DELETE] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.delete",
	},
	[OKEY_STATS_DELETE_LIST] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.delete_list",
	},
	[OKEY_STATS_INSERT] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.insert",
	},
	[OKEY_STATS_INSERT_FAILED] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.insert_failed",
	},
	[OKEY_STATS_DROP] = {
		.type 	= ULOGD_RET_UINT32,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.drop",
	},
	[OKEY_STATS_EARLY_DROP] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.early_drop",
	},
	[OKEY_STATS_ERROR] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.error",
	},
	[OKEY_STATS_SEARCH_RESTART] = {
		.type	= ULOGD_RET_UINT32,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "nfct.stats.search_restart",
	},
};

static int data_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTA_STATS_MAX) < 0)
		return MNL_CB_OK;

	if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
		ulogd_log(ULOGD_ERROR, "invalid attribute: %s\n",
			  strerror(errno));
		return MNL_CB_ERROR;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct ulogd_pluginstance *upi = (struct ulogd_pluginstance *)data;
	struct nfctst_pluginstance *cpi =
			(struct nfctst_pluginstance *)upi->private;
	struct nlattr *tb[CTA_STATS_MAX + 1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	int i, ret;

	ret = mnl_attr_parse(nlh, sizeof(*nfg), data_attr_cb, tb);
	if (ret != MNL_CB_OK)
		return ret;

	for (i = CTA_STATS_SEARCHED; i < CTA_STATS_MAX + 1; i++)
		if (tb[i])
			cpi->stat[CTA2OKEY(i)]
				+= ntohl(mnl_attr_get_u32(tb[i]));

	return MNL_CB_OK;
}

static int read_cb_nfctst(int fd, unsigned int what, void *param)
{
	struct ulogd_pluginstance *upi = (struct ulogd_pluginstance *)param;
	struct nfctst_pluginstance *cpi =
			(struct nfctst_pluginstance *)upi->private;
	struct ulogd_key *okey = upi->output.keys;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int nrecv, ret, i;

	if (!(what & ULOGD_FD_READ))
		return 0;

	memset(&cpi->stat, 0, sizeof(cpi->stat));

	nrecv = mnl_socket_recvfrom(cpi->sock, buf, sizeof(buf));
	while (nrecv > 0) {
		ret = mnl_cb_run(buf, nrecv, cpi->seq, cpi->portid,
				 data_cb, upi);
		if (ret <= MNL_CB_STOP) {
			if (ret == MNL_CB_ERROR) {
				ulogd_log(ULOGD_ERROR, "callback error: %s\n",
					  strerror(errno));
				return -1;
			}
			break;
		}
		nrecv = mnl_socket_recvfrom(cpi->sock, buf, sizeof(buf));
	}
	ulogd_log(ULOGD_INFO, "finished receiving\n");
	if (nrecv < 0) {
		ulogd_log(ULOGD_ERROR, "receiving nlmsg error: %s\n",
			  strerror(errno));
		return -1;
	}

	for (i = OKEY_STATS_SEARCHED; i <= OKEY_MAX; i++)
		okey_set_u32(&okey[i], cpi->stat[i]);

	ulogd_propagate_results(upi);

	return 0;
}

static void polling_timer_cb(struct ulogd_timer *t, void *data)
{
	struct ulogd_pluginstance *upi = data;
	struct nfctst_pluginstance *cpi =
			(struct nfctst_pluginstance *)upi->private;
	struct nlmsghdr *nlh = (struct nlmsghdr *)cpi->nlbuf;

	nlh->nlmsg_seq = ++cpi->seq;
	mnl_socket_sendto(cpi->sock, nlh, nlh->nlmsg_len);
	ulogd_add_timer(&cpi->timer, pollint_ce(upi->config_kset).u.value);
}

static int configure_nfctst(struct ulogd_pluginstance *upi,
			    struct ulogd_pluginstance_stack *stack)
{
	int ret;

	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0)
		return ret;

	return 0;
}

static int start_nfctst(struct ulogd_pluginstance *upi)
{
	struct nfctst_pluginstance *cpi =
			(struct nfctst_pluginstance *) upi->private;
	int pollint = pollint_ce(upi->config_kset).u.value;
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;

	if (pollint <= 0) {
		ulogd_log(ULOGD_FATAL, "invalid pollinterval: %d\n",
			pollint);
		return -1;
	}
	cpi->sock = mnl_socket_open(NETLINK_NETFILTER);
	if (cpi->sock == NULL) {
		ulogd_log(ULOGD_FATAL, "could not open socket: %s\n",
			  strerror(errno));
		goto err_open;
	}
	if (mnl_socket_bind(cpi->sock, 0, MNL_SOCKET_AUTOPID) < 0) {
		ulogd_log(ULOGD_FATAL, "could not bind socket: %s\n",
			  strerror(errno));
		goto err_bind;
	}
	cpi->portid = mnl_socket_get_portid(cpi->sock);
	cpi->seq = time(NULL);

	nlh = mnl_nlmsg_put_header(cpi->nlbuf);
	nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) |
		IPCTNL_MSG_CT_GET_STATS_CPU;
	nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP;

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_INET;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	ulogd_init_timer(&cpi->timer, upi, polling_timer_cb);
	ulogd_add_timer(&cpi->timer,
			pollint_ce(upi->config_kset).u.value);

	cpi->fd.fd = mnl_socket_get_fd(cpi->sock);
	cpi->fd.cb = &read_cb_nfctst;
	cpi->fd.data = upi;
	cpi->fd.when = ULOGD_FD_READ;
	ulogd_register_fd(&cpi->fd);

	return 0;

err_bind:
	mnl_socket_close(cpi->sock);
err_open:
	return -1;
}

static int stop_nfctst(struct ulogd_pluginstance *upi)
{
	struct nfctst_pluginstance *cpi = (void *)upi->private;

	if (mnl_socket_close(cpi->sock) == 0)
		return 0;

	return -1;
}

static struct ulogd_plugin nfctst_plugin = {
	.name = "NFCTST",
	.input = {
		.type = ULOGD_DTYPE_SOURCE,
	},
	.output = {
		.keys = nfctst_okeys,
		.num_keys = ARRAY_SIZE(nfctst_okeys),
		/* XXX: type? intend for IPFIX Options */
		.type = ULOGD_DTYPE_FLOW,
	},
	.config_kset 	= &nfctst_kset,
	.configure	= &configure_nfctst,
	.start		= &start_nfctst,
	.stop		= &stop_nfctst,
	.priv_size	= sizeof(struct nfctst_pluginstance),
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&nfctst_plugin);
}
