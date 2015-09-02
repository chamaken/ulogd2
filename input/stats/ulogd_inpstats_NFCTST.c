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
#define _GNU_SOURCE /* _sys_errlist[] */

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

struct nfctst_priv {
	struct mnl_socket *nls;
	int seq, portid;
	struct ulogd_fd fd;
	struct ulogd_timer timer;
	uint32_t stats[OKEY_MAX + 1];
	char dumpreq[sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg)];
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

#define pollint_ce(x)	(((x)->ces[0]).u.value)

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
	struct ulogd_source_pluginstance *spi = data;
	struct nfctst_priv *priv = (struct nfctst_priv *)spi->private;
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[CTA_STATS_MAX + 1] = {};
	int i, ret;

	ulogd_log(ULOGD_DEBUG, "got stats - CPU# %d\n", ntohs(nfg->res_id));
	ret = mnl_attr_parse(nlh, sizeof(struct nfgenmsg), data_attr_cb, tb);
	if (ret != MNL_CB_OK)
		return ret;

	for (i = CTA_STATS_SEARCHED; i < CTA_STATS_MAX + 1; i++)
		if (tb[i])
			priv->stats[CTA2OKEY(i)]
				+= ntohl(mnl_attr_get_u32(tb[i]));

	return MNL_CB_OK;
}

static int read_cb_nfctst(int fd, unsigned int what, void *param)
{
	struct ulogd_source_pluginstance *spi = param;
	struct nfctst_priv *priv = (struct nfctst_priv *)spi->private;
	struct ulogd_keyset *output = ulogd_get_output_keyset(spi);
	struct ulogd_key *okey = output->keys;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int nrecv, ret, i;

	if (!(what & ULOGD_FD_READ))
		return 0;

	memset(&priv->stats, 0, sizeof(priv->stats));
	do {
		nrecv = mnl_socket_recvfrom(priv->nls, buf, sizeof(buf));
		if (nrecv < 0) {
			ulogd_log(ULOGD_ERROR, "mnl_socket_recvfrom: %s\n",
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
		ret = mnl_cb_run(buf, nrecv, priv->seq,
				 priv->portid, data_cb, spi);
		if (ret == MNL_CB_ERROR) {
			ulogd_log(ULOGD_ERROR, "mnl_cb_run: %s\n",
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
	} while (ret == MNL_CB_OK);

	for (i = OKEY_STATS_SEARCHED; i <= OKEY_MAX; i++)
		okey_set_u32(&okey[i], priv->stats[i]);
	ulogd_propagate_results(output);

	return ULOGD_IRET_OK;
}

static void polling_timer_cb(struct ulogd_timer *t, void *data)
{
	struct ulogd_source_pluginstance *spi = data;
	struct nfctst_priv *priv = (struct nfctst_priv *)spi->private;
	struct nlmsghdr *nlh = (struct nlmsghdr *)priv->dumpreq;

	nlh->nlmsg_seq = ++priv->seq;
	if (mnl_socket_sendto(priv->nls, nlh, nlh->nlmsg_len) < 0)
		ulogd_log(ULOGD_ERROR, "mnl_socket_sendto: %s\n",
			  _sys_errlist[errno]);
}

static int configure_nfctst(struct ulogd_source_pluginstance *spi)
{
	return config_parse_file(spi->id, spi->config_kset);
}

static int start_nfctst(struct ulogd_source_pluginstance *spi)
{
	struct nfctst_priv *priv = (struct nfctst_priv *)spi->private;
	int pollint = pollint_ce(spi->config_kset);
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;

	if (pollint <= 0) {
		ulogd_log(ULOGD_FATAL, "invalid pollinterval: %d\n",
			pollint);
		return -1;
	}
	priv->nls = mnl_socket_open(NETLINK_NETFILTER);
	if (priv->nls == NULL) {
		ulogd_log(ULOGD_FATAL, "mnl_socket_open: %s\n",
			  _sys_errlist[errno]);
		goto err_exit;
	}
	if (mnl_socket_bind(priv->nls, 0, MNL_SOCKET_AUTOPID) < 0) {
		ulogd_log(ULOGD_FATAL, "mnl_socket_bind: %s\n",
			  _sys_errlist[errno]);
		goto err_close;
	}
	priv->portid = mnl_socket_get_portid(priv->nls);
	priv->seq = time(NULL);

	nlh = mnl_nlmsg_put_header(priv->dumpreq);
	nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) |
			   IPCTNL_MSG_CT_GET_STATS_CPU;
	nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP;

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_INET;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	if (ulogd_init_timer(&priv->timer, spi, polling_timer_cb) < 0) {
		ulogd_log(ULOGD_ERROR, "ulogd_init_timer: %s\n",
			  _sys_errlist[errno]);
		goto err_close;
	}
	if (ulogd_add_itimer(&priv->timer, pollint, pollint) < 0) {
		ulogd_log(ULOGD_ERROR, "ulogd_add_timer: %s\n",
			  _sys_errlist[errno]);
		goto err_close;
	}

	priv->fd.fd = mnl_socket_get_fd(priv->nls);
	priv->fd.cb = &read_cb_nfctst;
	priv->fd.data = spi;
	priv->fd.when = ULOGD_FD_READ;
	if (ulogd_register_fd(&priv->fd) < 0) {
		ulogd_log(ULOGD_ERROR, "ulogd_register_fd: %s\n",
			  _sys_errlist[errno]);
		goto err_del_timer;
	}

	return ULOGD_IRET_OK;

err_del_timer:
	ulogd_del_timer(&priv->timer);
err_close:
	mnl_socket_close(priv->nls);
err_exit:
	return ULOGD_IRET_ERR;
}

static int stop_nfctst(struct ulogd_source_pluginstance *spi)
{
	struct nfctst_priv *priv = (struct nfctst_priv *)spi->private;
	int ret = 0;

	ret |= ulogd_del_timer(&priv->timer);
	ret |= ulogd_unregister_fd(&priv->fd);
	ret |= mnl_socket_close(priv->nls);
	
	if (ret == 0)
		return ULOGD_IRET_OK;

	return ULOGD_IRET_ERR;
}

static struct ulogd_source_plugin nfctst_plugin = {
	.name = "NFCTST",
	.output = {
		.keys = nfctst_okeys,
		.num_keys = ARRAY_SIZE(nfctst_okeys),
		/* XXX: introduce ULOGD_DTYPE_STATS? */
		.type = ULOGD_DTYPE_FLOW,
	},
	.config_kset 	= &nfctst_kset,
	.configure	= &configure_nfctst,
	.start		= &start_nfctst,
	.stop		= &stop_nfctst,
	.priv_size	= sizeof(struct nfctst_priv),
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_source_plugin(&nfctst_plugin);
}
