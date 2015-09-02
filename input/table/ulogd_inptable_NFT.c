/* ulogd_input_NFT.c
 *
 * ulogd input plugin for monitoring nftables
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
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <ulogd/ulogd.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/gen.h>
#include <libnftnl/common.h>
#include <libnftnl/expr.h>


/* libnftnl commit 37268a018e99181a1d203f0a8a6fc5c6670d09b2 */
enum nft_output_keys_index {
	OKEY_NFT_EVENT,
	/* src/table.c, include/libnftnl/table.h						*/
	OKEY_TABLE_OBJECT,	/* struct nft_table 						*/
	/* src/rule.c, include/libnftnl/rule.h							*/
	OKEY_RULE_OBJECT,	/* struct nft_rule						*/
	/* src/chain.c, include/libnftnl/chain.h						*/
	OKEY_CHAIN_OBJECT,	/* struct nft_chain						*/
	/* include/set.h, include/libnftnl/set.h						*/
	OKEY_SET_OBJECT,	/* struct nft_set						*/
	/* include/set_elem.h, include/libnftnl/set.h						*/
	OKEY_SET_ELEM_OBJECT,	/* struct nft_set_elem						*/
	/* src/gen.c, include/libnftnl/gen.h							*/
	OKEY_GEN_OBJECT,	/* struct nft_gen						*/


	/* primitive */

	/* struct nft_table::src/table.c, include/libnftnl/table.h				*/
	OKEY_TABLE_NAME,	/* const char	*name		NFT_TABLE_ATTR_NAME		*/
	OKEY_TABLE_FAMILY,	/* uint32_t	family		NFT_TABLE_ATTR_FAMILY		*/
	OKEY_TABLE_TABLE_FLAGS,	/* uint32_t	table_flags	NFT_TABLE_ATTR_FLAGS		*/
	OKEY_TABLE_USE,		/* uint32_t	use		NFT_TABLE_ATTR_USE		*/

	/* struct nft_rule::src/rule.c, include/libnftnl/rule.h					*/
	OKEY_RULE_FAMILY,	/* uint32_t	family		NFT_RULE_ATTR_FAMILY		*/
	OKEY_RULE_TABLE,	/* const char	*table		NFT_RULE_ATTR_TABLE		*/
	OKEY_RULE_CHAIN,	/* const char	*chain		NFT_RULE_ATTR_CHAIN		*/
	OKEY_RULE_HANDLE,	/* uint64_t	handle		NFT_RULE_ATTR_HANDLE		*/
	OKEY_RULE_POSITION,	/* uint64_t	position	NFT_RULE_ATTR_POSITION		*/
	OKEY_RULE_USER_DATA,	/* void		*data		NFT_RULE_ATTR_USERDATA		*/
				/* uint32_t	len						*/
	OKEY_RULE_COMPAT_FLAGS,	/* uint32_t	flags		NFT_RULE_ATTR_COMPAT_FLAGS	*/
	OKEY_RULE_COMPAT_PROTO,	/* uint32_t	proto		NFT_RULE_ATTR_COMPAT_PROTO	*/

	/* struct nft_chain::src/chain.c, include/libnftnl/chain.h				*/
	OKEY_CHAIN_NAME,	/* char		name[NFT_CHAIN_MAXNAMELEN] NFT_CHAIN_ATTR_NAME	*/
	OKEY_CHAIN_TYPE,	/* const char	*type		NFT_CHAIN_ATTR_TYPE		*/
	OKEY_CHAIN_TABLE,	/* const char	*table		NFT_CHAIN_ATTR_TABLE		*/
	OKEY_CHAIN_DEV,		/* const char	*dev		NFT_CHAIN_ATTR_DEV		*/
	OKEY_CHAIN_FAMILY,	/* uint32_t	family		NFT_CHAIN_ATTR_FAMILY		*/
	OKEY_CHAIN_POLICY,	/* uint32_t	policy		NFT_CHAIN_ATTR_POLICY		*/
	OKEY_CHAIN_HOOKNUM,	/* uint32_t	hooknum		NFT_CHAIN_ATTR_HOOKNUM		*/
	OKEY_CHAIN_PRIO,	/* int32_t	prio		NFT_CHAIN_ATTR_PRIO		*/
	OKEY_CHAIN_USE,		/* uint32_t	use		NFT_CHAIN_ATTR_USE		*/
	OKEY_CHAIN_PACKETS,	/* uint64_t	packets		NFT_CHAIN_ATTR_PACKETS		*/
	OKEY_CHAIN_BYTES,	/* uint64_t	bytes		NFT_CHAIN_ATTR_BYTES		*/
	OKEY_CHAIN_HANDLE,	/* uint64_t	handle		NFT_CHAIN_ATTR_HANDLE		*/

	/* struct nft_set::include/set.h, include/libnftnl/set.h				*/
	OKEY_SET_FAMILY,	/* uint32_t	family		NFT_SET_ATTR_FAMILY		*/
	OKEY_SET_SET_FLAGS,	/* uint32_t	set_flags	NFT_SET_ATTR_FLAGS		*/
	OKEY_SET_TABLE,		/* const char	*table		NFT_SET_ATTR_TABLE		*/
	OKEY_SET_NAME,		/* const char	*name		NFT_SET_ATTR_NAME		*/
	OKEY_SET_KEY_TYPE,	/* uint32_t	key_type	NFT_SET_ATTR_KEY_TYPE		*/
	OKEY_SET_KEY_LEN,	/* uint32_t	key_len		NFT_SET_ATTR_KEY_LEN		*/
	OKEY_SET_DATA_TYPE,	/* uint32_t	data_type	NFT_SET_ATTR_DATA_TYPE		*/
	OKEY_SET_DATA_LEN,	/* uint32_t	data_len	NFT_SET_ATTR_DATA_LEN		*/
	OKEY_SET_ID,		/* uint32_t	id		NFT_SET_ATTR_ID			*/
	OKEY_SET_POLICY,	/* enum nft_set_policies policy	NFT_SET_ATTR_POLICY		*/
	OKEY_SET_DESC_SIZE,	/* uint32_t	size		NFT_SET_ATTR_DESC_SIZE		*/
	OKEY_SET_GC_INTERVAL,	/* uint32_t	gc_interval	NFT_SET_ATTR_GC_INTERVAL	*/
	OKEY_SET_TIEOUT,	/* uint64_t	timeout		NFT_SET_ATTR_TIMEOUT		*/

	/* struct nft_set_elem::include/set_elem.h, include/libnftnl/set.h			*/
	OKEY_SET_ELEM_FLAGS,	/* uint32_t	set_elem_flags	NFT_SET_ELEM_ATTR_FLAGS		*/
	OKEY_SET_ELEM_KEY,	/* union nft_data_reg	key	NFT_SET_ELEM_ATTR_KEY		*/
	OKEY_SET_ELEM_DATA,	/* union nft_data_reg	data	NFT_SET_ELEM_ATTR_DATA		*/
	OKEY_SET_ELEM_EXPR,	/* struct nft_rule_expr	*expr	NFT_SET_ELEM_ATTR_EXPR		*/
	OKEY_SET_ELEM_TIMEOUT,	/* uint64_t	timeout		NFT_SET_ELEM_ATTR_TIMEOUT	*/
	OKEY_SET_ELEM_EXPIRATION, /* uint64_t	expiration	NFT_SET_ELEM_ATTR_EXPIRATION	*/
	OKEY_SET_USER_DATA,	/* void		*data		NFT_SET_ELEM_ATTR_USERDATA	*/
				/* uint32_t	len						*/
	OKEY_SET_ELEM_VERDICT,	/* int nft_data_reg.verdict	NFT_SET_ELEM_ATTR_VERDICT	*/
	OKEY_SET_ELEM_CHAIN,	/* char *nft_data_reg.chain 	NFT_SET_ELEM_ATTR_CHAIN		*/

	/* struct nft_gen::src/gen.c, include/libnftnl/gen.h						*/
	OKEY_GEN_ID,		/* uint32_t 	id		NFT_GEN_ID			*/
};

static struct ulogd_key nft_okeys[] = {
	[OKEY_NFT_EVENT]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "nft.event",
	},
	[OKEY_TABLE_OBJECT]	= {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_KEYF_OPTIONAL | ULOGD_RETF_DESTRUCT,
		.name	= "nft.table.object",
		.destruct = (void (*)(void *))nft_table_free,
	},
	[OKEY_RULE_OBJECT]	= {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_KEYF_OPTIONAL | ULOGD_RETF_DESTRUCT,
		.name	= "nft.rule.object",
		.destruct = (void (*)(void *))nft_rule_free,
	},
	[OKEY_CHAIN_OBJECT]	= {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_KEYF_OPTIONAL | ULOGD_RETF_DESTRUCT,
		.name	= "nft.chain.object",
		.destruct = (void (*)(void *))nft_chain_free,
	},
	[OKEY_SET_OBJECT]	= {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_KEYF_OPTIONAL | ULOGD_RETF_DESTRUCT,
		.name	= "nft.set.object",
		.destruct = (void (*)(void *))nft_set_free,
	},
	[OKEY_SET_ELEM_OBJECT]	= {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_KEYF_OPTIONAL | ULOGD_RETF_DESTRUCT,
		.name	= "nft.set_elem.object",
		/* .destruct = (void (*)(void *))nft_set_elem_free, */
		.destruct = (void (*)(void *))nft_set_free,
	},
	[OKEY_GEN_OBJECT]	= {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_KEYF_OPTIONAL | ULOGD_RETF_DESTRUCT,
		.name	= "nft.gen.object",
		.destruct = (void (*)(void *))nft_gen_free,
	},

	/* primitive */
	[OKEY_TABLE_NAME]	= {
		.type	= ULOGD_RET_STRING,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.table.name",
		.len	= NFT_TABLE_MAXNAMELEN + 1,
	},
	[OKEY_TABLE_FAMILY]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.table.family",
	},
	[OKEY_TABLE_TABLE_FLAGS]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.table.flags",
	},
	[OKEY_TABLE_USE]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.table.use",
	},
	[OKEY_RULE_FAMILY]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.rule.family",
	},
	[OKEY_RULE_TABLE]	= {
		.type	= ULOGD_RET_STRING,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.rule.table",
	},
	[OKEY_RULE_CHAIN]	= {
		.type	= ULOGD_RET_STRING,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.rule.chain",
	},
	[OKEY_RULE_HANDLE]	= {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.rule.handle",
	},
	[OKEY_RULE_POSITION]	= {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.rule.position",
	},
	[OKEY_RULE_USER_DATA]	= {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.rule.userdata",
		.len	= NFT_USERDATA_MAXLEN + 1,
	},
	[OKEY_RULE_COMPAT_FLAGS]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.rule.compat_flags",
	},
	[OKEY_RULE_COMPAT_PROTO]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.rule.compat_proto",
	},
	[OKEY_CHAIN_NAME]	= {
		.type	= ULOGD_RET_STRING,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.chain.name",
		.len	= NFT_CHAIN_MAXNAMELEN + 1,
	},
	[OKEY_CHAIN_TYPE]	= {
		.type	= ULOGD_RET_STRING,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.chain.type",
	},
	[OKEY_CHAIN_TABLE]	= {
		.type	= ULOGD_RET_STRING,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.chain.table",
	},
	[OKEY_CHAIN_DEV]	= {
		.type	= ULOGD_RET_STRING,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.chain.dev",
	},
	[OKEY_CHAIN_FAMILY]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.chain.family",
	},
	[OKEY_CHAIN_POLICY]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.chain.policy",
	},
	[OKEY_CHAIN_HOOKNUM]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.chain.hooknum",
	},
	[OKEY_CHAIN_PRIO]	= {
		.type	= ULOGD_RET_INT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.chain.prio",
	},
	[OKEY_CHAIN_USE]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.chain.use",
	},
	[OKEY_CHAIN_PACKETS]	= {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.chain.packets",
	},
	[OKEY_CHAIN_BYTES]	= {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.chain.bytes",
	},
	[OKEY_CHAIN_HANDLE]	= {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.chain.handle",
	},
	[OKEY_SET_FAMILY]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.family",
	},
	[OKEY_SET_SET_FLAGS]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.flags",
	},
	[OKEY_SET_TABLE]	= {
		.type	= ULOGD_RET_STRING,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.table",
	},
	[OKEY_SET_NAME]	= {
		.type	= ULOGD_RET_STRING,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.name",
	},
	[OKEY_SET_KEY_TYPE]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.key_type",
	},
	[OKEY_SET_KEY_LEN]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.key_len",
	},
	[OKEY_SET_DATA_TYPE]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.data_type",
	},
	[OKEY_SET_DATA_LEN]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.data_len",
	},
	[OKEY_SET_ID]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.id",
	},
	[OKEY_SET_POLICY]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.policy",
	},
	[OKEY_SET_DESC_SIZE]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.desc_size",
	},
	[OKEY_SET_GC_INTERVAL]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.gc_interval",
	},
	[OKEY_SET_TIEOUT]	= {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set.timeout",
	},
	[OKEY_SET_ELEM_FLAGS]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set_elem.flags",
	},
	[OKEY_SET_ELEM_KEY]	= {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set_elem.key",
		/* XXX: len */
	},
	[OKEY_SET_ELEM_DATA]	= {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set_elem.data",
		/* XXX: len */
	},
	[OKEY_SET_ELEM_VERDICT]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set_elem.verdict",
	},
	[OKEY_SET_ELEM_EXPR]	= {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_KEYF_OPTIONAL | ULOGD_RETF_DESTRUCT,
		.name	= "nft.set_elem.expr",
		.destruct = (void (*)(void *))nft_rule_expr_free,
	},
	[OKEY_SET_ELEM_TIMEOUT]	= {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set_elem.timeout",
	},
	[OKEY_SET_ELEM_EXPIRATION]	= {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set_elem.expiration",
	},
	[OKEY_SET_USER_DATA]	= {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.set_elem.userdata",
		.len	= NFT_USERDATA_MAXLEN + 1,
	},
	[OKEY_GEN_ID]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_KEYF_OPTIONAL,
		.name	= "nft.gen.id",
	},
};

enum nftable_config_keys_index {
	NFT_CONFIG_BUFSIZE,
	NFT_CONFIG_MAX,
};

static struct config_keyset nft_config_kset = {
	.num_ces = NFT_CONFIG_MAX,
	.ces = {
		[NFT_CONFIG_BUFSIZE]	= {
			.key	 = "socket_buffer_size",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
	},
};

#define bufsize_ce(x)	(((x)->ces[NFT_CONFIG_BUFSIZE]).u.value)

struct nft_priv {
	struct mnl_socket *nls;
	struct ulogd_fd fd;
};

static int set_table_keys(struct ulogd_key *dst, struct nft_table *src)
{
	return MNL_CB_OK;
}

static int set_chain_keys(struct ulogd_key *dst, struct nft_chain *src)
{
	return MNL_CB_OK;
}

static int set_rule_keys(struct ulogd_key *dst, struct nft_rule *src)
{
	return MNL_CB_OK;
}

static int set_set_keys(struct ulogd_key *dst, struct nft_set *src)
{
	return MNL_CB_OK;
}

static int set_gen_keys(struct ulogd_key *dst, struct nft_gen *src)
{
	return MNL_CB_OK;
}

static int set_set_elems_keys(struct ulogd_key *dst, struct nft_set *src)
{
	return MNL_CB_OK;
}

#define NFT_CB(name, objname, keyidx)					\
static int name##_cb(struct ulogd_source_pluginstance *spi,		\
		     const struct nlmsghdr *nlh, int event) {		\
	struct ulogd_keyset *_output = ulogd_get_output_keyset(spi);	\
	struct ulogd_key *_ret = _output->keys;				\
	struct nft_##objname *_t = nft_##objname##_alloc();		\
	if (_t == NULL)							\
		return MNL_CB_ERROR;					\
	if (nft_##name##_nlmsg_parse(nlh, _t) < 0)			\
		goto free;						\
	okey_set_u32(&_ret[OKEY_NFT_EVENT], event);			\
	okey_set_ptr(&_ret[keyidx], _t);				\
	set_##name##_keys(_ret, _t);					\
	if (ulogd_propagate_results(_output) == 0)			\
		return MNL_CB_OK;					\
free:									\
	okey_set_ptr(&_ret[keyidx], NULL);				\
	nft_##objname##_free(_t);					\
	return MNL_CB_ERROR;						\
}

NFT_CB(table,		table,	OKEY_TABLE_OBJECT)
NFT_CB(chain,		chain,	OKEY_CHAIN_OBJECT)
NFT_CB(rule,		rule,	OKEY_RULE_OBJECT)
NFT_CB(set,		set,	OKEY_SET_OBJECT)
NFT_CB(set_elems,	set,	OKEY_SET_ELEM_OBJECT)
NFT_CB(gen,		gen,	OKEY_GEN_OBJECT)

static int events_cb(const struct nlmsghdr *nlh, void *data)
{
	struct ulogd_source_pluginstance *spi = data;
	int event = NFNL_MSG_TYPE(nlh->nlmsg_type);
	int ret;

	switch(event) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_DELTABLE:
		ret = table_cb(spi, nlh, event);
		break;
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_DELCHAIN:
		ret = chain_cb(spi, nlh, event);
		break;
	case NFT_MSG_NEWRULE:
	case NFT_MSG_DELRULE:
		ret = rule_cb(spi, nlh, event);
		break;
	case NFT_MSG_NEWSET:
	case NFT_MSG_DELSET:
		ret = set_cb(spi, nlh, event);
		break;
	case NFT_MSG_NEWSETELEM:
	case NFT_MSG_DELSETELEM:
		ret = set_elems_cb(spi, nlh, event);
		break;
	case NFT_MSG_NEWGEN:
		ret = gen_cb(spi, nlh, event);
		break;
	default:
		ulogd_log(ULOGD_ERROR, "unknown nft event: %d\n", event);
		ret = MNL_CB_ERROR;
	}

	return ret;
}

static int read_cb(int fd, unsigned int what, void *param)
{
	struct ulogd_source_pluginstance *spi = param;
	struct nft_priv *priv = (struct nft_priv *)spi->private;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int nrecv, ret;

	if (!(what & ULOGD_FD_READ))
		return 0;

	nrecv = mnl_socket_recvfrom(priv->nls, buf, sizeof(buf));
	if (nrecv < 0) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_recvfrom: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}

	ret = mnl_cb_run(buf, nrecv, 0, 0, events_cb, spi);
	if (ret == MNL_CB_ERROR) {
		ulogd_log(ULOGD_ERROR, "mnl_cb_run: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}

	return ULOGD_IRET_OK;
}

static int configure_nft(struct ulogd_source_pluginstance *spi)
{
	return config_parse_file(spi->id, spi->config_kset);
}

static int setnlbufsize(struct mnl_socket *nl, int size)
{
	int fd = mnl_socket_get_fd(nl);
	socklen_t socklen = sizeof(int);

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, socklen) == -1) {
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, socklen);
	}
	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, &socklen) == -1)
		return -1;
	return size;
}

static int start_nft(struct ulogd_source_pluginstance *spi)
{
	struct nft_priv *priv = (struct nft_priv *)spi->private;
	int nlbufsize = bufsize_ce(spi->config_kset);

	priv->nls = mnl_socket_open(NETLINK_NETFILTER);
	if (priv->nls == NULL) {
		ulogd_log(ULOGD_FATAL, "mnl_socket_open: %s\n",
			  _sys_errlist[errno]);
		goto err_exit;
	}
	if (nlbufsize > 0) {
		if (setnlbufsize(priv->nls, nlbufsize) < 0) {
			ulogd_log(ULOGD_FATAL, "setnlbufsize: %s\n",
				  _sys_errlist[errno]);
			goto err_close;
		}
	}
	if (mnl_socket_bind(priv->nls, (1 << (NFNLGRP_NFTABLES-1)), MNL_SOCKET_AUTOPID) < 0) {
		ulogd_log(ULOGD_FATAL, "mnl_socket_bind: %s\n",
			  _sys_errlist[errno]);
		goto err_close;
	}

	priv->fd.fd = mnl_socket_get_fd(priv->nls);
	priv->fd.cb = &read_cb;
	priv->fd.data = spi;
	priv->fd.when = ULOGD_FD_READ;
	ulogd_register_fd(&priv->fd);

	return ULOGD_IRET_OK;

err_close:
	mnl_socket_close(priv->nls);
err_exit:
	return ULOGD_IRET_ERR;
}

static int stop_nft(struct ulogd_source_pluginstance *spi)
{
	struct nft_priv *priv = (struct nft_priv *)spi->private;
	int ret = 0;

	ret |= mnl_socket_close(priv->nls);
	ret |= ulogd_unregister_fd(&priv->fd);

	if (ret == 0)
		return ULOGD_IRET_OK;
	return ULOGD_IRET_ERR;
}

static struct ulogd_source_plugin nft_plugin = {
	.name = "NFT",
	.output = {
		.keys = nft_okeys,
		.num_keys = ARRAY_SIZE(nft_okeys),
		/* XXX: introduce ULOGD_DTYPE_TABLE? */
		.type = ULOGD_DTYPE_FLOW,
	},
	.config_kset 	= &nft_config_kset,
	.configure	= &configure_nft,
	.start		= &start_nft,
	.stop		= &stop_nft,
	.priv_size	= sizeof(struct nft_priv),
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_source_plugin(&nft_plugin);
}
