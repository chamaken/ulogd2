/* ulogd_XML2.c.
 *
 * ulogd output target for XML logging.
 *
 * (C) 2010 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <inttypes.h>
#include "../config.h"
#ifdef BUILD_NFLOG
#include <libnetfilter_log/libnetfilter_log.h>
#endif /* BUILD_NFLOG */
#ifdef BUILD_NFCT
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif /* BUILD_NFCT */
#ifdef BUILD_NFACCT
#include <libnetfilter_acct/libnetfilter_acct.h>
#endif /* BUILD_NFACCT */
#ifdef BUILD_NFT
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/gen.h>
#include <libnftnl/common.h>
#endif /* BUILD_NFT */
#include <ulogd/ulogd.h>
#include <sys/param.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

enum {
	KEY_CT,
	KEY_PCKT,
	KEY_SUM,
	KEY_NFT_EVENT,
	KEY_NFT_TABLE,
	KEY_NFT_RULE,
	KEY_NFT_CHAIN,
	KEY_NFT_SET,
	KEY_NFT_SET_ELEM,
	KEY_NFT_GEN,
};

static struct ulogd_key xml_inp[] = {
	[KEY_CT] = {
                .type = ULOGD_RET_RAW,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "ct",
	},
	[KEY_PCKT] = {
                .type = ULOGD_RET_RAW,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "raw",
	},
	[KEY_SUM] = {
                .type = ULOGD_RET_RAW,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "sum",
	},
	[KEY_NFT_EVENT] = {
                .type = ULOGD_RET_UINT32,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "nft.event",
	},
	[KEY_NFT_TABLE] = {
                .type = ULOGD_RET_RAW,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "nft.table.object",
	},
	[KEY_NFT_RULE] = {
                .type = ULOGD_RET_RAW,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "nft.rule.object",
	},
	[KEY_NFT_CHAIN] = {
                .type = ULOGD_RET_RAW,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "nft.chain.object",
	},
	[KEY_NFT_SET] = {
                .type = ULOGD_RET_RAW,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "nft.set.object",
	},
	[KEY_NFT_SET_ELEM] = {
                .type = ULOGD_RET_RAW,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "nft.set_elem.object",
	},
	[KEY_NFT_GEN] = {
                .type = ULOGD_RET_RAW,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "nft.gen.object",
	},
};

enum {
	XML_CONF_FILENAME,
	XML_CONF_SYNC,
	XML_CONF_TIMESTAMP,
	XML_CONF_MAX,
};

static struct config_keyset xml_kset = {
	.num_ces = XML_CONF_MAX,
	.ces = {
		[XML_CONF_FILENAME] = {
			.key = "filename", 
			.type = CONFIG_TYPE_STRING, 
			.options = CONFIG_OPT_NONE,
		},
		[XML_CONF_SYNC] = {
			.key = "sync",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = 0 },
		},
		[XML_CONF_TIMESTAMP] = {
			.key = "timestamp",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = 0 },
		},
	},
};

#define filename_ce(x)		(((x)->config_kset->ces[XML_CONF_FILENAME]).u.string)
#define sync_ce(x)		(((x)->config_kset->ces[XML_CONF_SYNC]).u.value)
#define timestamp_ce(x)		(((x)->config_kset->ces[XML_CONF_TIMESTAMP]).u.value)

struct xml_priv {
        FILE *of;
	int (*output_ts)(char *buf, ssize_t size);
};

static int xml_output_ts_none(char *buf, ssize_t size)
{
	return 0;
}

static int xml_output_ts(char *buf, ssize_t size)
{
	struct timeval tv;
	struct tm tm;
	char tmp[64];

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	strftime(tmp, sizeof(tmp), "%FT%T", &tm);

	return snprintf(buf, size, "<ts>%s.%06lu</ts>", tmp, tv.tv_usec);
}

static int
xml_output_flow(struct xml_priv *priv, struct ulogd_key *inp,
		char *buf, ssize_t size)
{
#ifdef BUILD_NFCT
	struct nf_conntrack *ct = ikey_get_ptr(&inp[KEY_CT]);
	int tmp;

	tmp = snprintf(buf, size, "<conntrack>");
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;
	size -= tmp; buf += tmp;

	tmp = priv->output_ts(buf, tmp);
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;
	size -= tmp; buf += tmp;
	
	tmp = nfct_snprintf(buf, size, ct, 0, NFCT_O_XML,
			    NFCT_OF_SHOW_LAYER3 | NFCT_OF_ID | NFCT_OF_TIME);
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;
	size -= tmp; buf += tmp;

	tmp = snprintf(buf, size, "</conntrack>");
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;

	return ULOGD_IRET_OK;
#else
	return ULOGD_IRET_ERR;
#endif
}

static int
xml_output_packet(struct xml_priv *priv, struct ulogd_key *inp,
		  char *buf, ssize_t size)
{
#ifdef BUILD_NFLOG
	struct nflog_data *ldata = ikey_get_ptr(&inp[KEY_PCKT]);
	int tmp;

	tmp = snprintf(buf, size, "<packet>");
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;
	size -= tmp; buf += tmp;

	tmp = priv->output_ts(buf, tmp);
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;
	size -= tmp; buf += tmp;
	
	tmp = nflog_snprintf_xml(buf, size, ldata, NFLOG_XML_ALL);
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;
	size -= tmp; buf += tmp;

	tmp = snprintf(buf, size, "</packet>");
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;

	return ULOGD_IRET_OK;
#else
	return ULOGD_IRET_ERR;
#endif
}

static int
xml_output_sum(struct xml_priv *priv, struct ulogd_key *inp,
	       char *buf, ssize_t size)
{
#ifdef BUILD_NFACCT
	struct nfacct *nfacct = ikey_get_ptr(&inp[KEY_SUM]);
	int tmp;

	tmp = snprintf(buf, size, "<sum>");
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;
	size -= tmp; buf += tmp;

	tmp = priv->output_ts(buf, tmp);
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;
	size -= tmp; buf += tmp;
	
	tmp = nfacct_snprintf(buf, size, nfacct, NFACCT_SNPRINTF_T_XML,
						 NFACCT_SNPRINTF_F_TIME);
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;
	size -= tmp; buf += tmp;

	tmp = snprintf(buf, size, "</sum>");
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;

	return ULOGD_IRET_OK;
#else
	return ULOGD_IRET_ERR;
#endif
}

#ifdef BUILD_NFT
static uint32_t event2flag(uint32_t event)
{
	switch (event) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_NEWRULE:
	case NFT_MSG_NEWSET:
	case NFT_MSG_NEWSETELEM:
	case NFT_MSG_NEWGEN:
		return NFT_OF_EVENT_NEW;
	case NFT_MSG_DELTABLE:
	case NFT_MSG_DELCHAIN:
	case NFT_MSG_DELRULE:
	case NFT_MSG_DELSET:
	case NFT_MSG_DELSETELEM:
		return NFT_OF_EVENT_DEL;
	}

	return 0;
}
#endif

static int
xml_output_nft(struct xml_priv *priv, struct ulogd_key *inp,
	       char *buf, ssize_t size)
{
#ifdef BUILD_NFT
	uint32_t event = ikey_get_u32(&inp[KEY_NFT_EVENT]);
	int tmp;

	if (event == 0) {
		ulogd_log(ULOGD_ERROR, "unknown event: %d\n", event);
		return ULOGD_IRET_ERR;
	}

	tmp = snprintf(buf, size, "<table>");
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;
	size -= tmp; buf += tmp;

	tmp = priv->output_ts(buf, tmp);
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;
	size -= tmp; buf += tmp;

	if (pp_is_valid(inp, KEY_NFT_TABLE)) {
		struct nft_table *t = ikey_get_ptr(&inp[KEY_NFT_TABLE]);
		tmp = nft_table_snprintf(buf, size, t, NFT_OUTPUT_XML,
					 event2flag(event));
	} else if (pp_is_valid(inp, KEY_NFT_RULE)) {
		struct nft_rule *t = ikey_get_ptr(&inp[KEY_NFT_RULE]);
		tmp = nft_rule_snprintf(buf, size, t, NFT_OUTPUT_XML,
					event2flag(event));
	} else if (pp_is_valid(inp, KEY_NFT_CHAIN)) {
		struct nft_chain *t = ikey_get_ptr(&inp[KEY_NFT_CHAIN]);
		tmp = nft_chain_snprintf(buf, size, t, NFT_OUTPUT_XML,
					 event2flag(event));
	} else if (pp_is_valid(inp, KEY_NFT_SET)) {
		struct nft_set *t = ikey_get_ptr(&inp[KEY_NFT_SET]);
		tmp = nft_set_snprintf(buf, size, t, NFT_OUTPUT_XML,
				       event2flag(event));
	} else if (pp_is_valid(inp, KEY_NFT_SET_ELEM)) {
		struct nft_set *t = ikey_get_ptr(&inp[KEY_NFT_SET_ELEM]);
		tmp = nft_set_snprintf(buf, size, t, NFT_OUTPUT_XML,
				       event2flag(event));
	} else if (pp_is_valid(inp, KEY_NFT_GEN)) {
		struct nft_gen *t = ikey_get_ptr(&inp[KEY_NFT_GEN]);
		tmp = nft_gen_snprintf(buf, size, t, NFT_OUTPUT_XML,
				       event2flag(event));
	} else {
		ulogd_log(ULOGD_ERROR, "unknown nft event: %d\n", event);
		return ULOGD_IRET_ERR;
	}
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;
	size -= tmp; buf += tmp;

	tmp = snprintf(buf, size, "</table>");
	if (tmp < 0 || tmp >= size)
		return ULOGD_IRET_ERR;

	return ULOGD_IRET_OK;
#endif
	return ULOGD_IRET_ERR;
}

/* may not escape */
static int xml_output(struct ulogd_pluginstance *upi,
		      struct ulogd_keyset *input, struct ulogd_keyset *output)
{
	struct ulogd_key *inp = input->keys;
	struct xml_priv *priv = (struct xml_priv *)&upi->private;
	static char buf[4096];
	int ret = ULOGD_IRET_ERR;

	if (pp_is_valid(inp, KEY_CT))
		ret = xml_output_flow(priv, inp, buf, sizeof(buf));
	else if (pp_is_valid(inp, KEY_PCKT))
		ret = xml_output_packet(priv, inp, buf, sizeof(buf));
	else if (pp_is_valid(inp, KEY_SUM))
		ret = xml_output_sum(priv, inp, buf, sizeof(buf));
	else if (pp_is_valid(inp, KEY_NFT_EVENT))
		ret = xml_output_nft(priv, inp, buf, sizeof(buf));

	if (ret != ULOGD_IRET_OK)
		return ret;

	fprintf(priv->of, "%s\n", buf);
	if (sync_ce(upi) != 0)
		fflush(priv->of);

	return ULOGD_IRET_OK;
}

static int xml_configure(struct ulogd_pluginstance *upi)
{
	return config_parse_file(upi->id, upi->config_kset);
}

static int xml_fini(struct ulogd_pluginstance *pi)
{
	struct xml_priv *priv = (struct xml_priv *)&pi->private;

	fprintf(priv->of, "</netfilter>\n");
	if (priv->of != stdout)
		fclose(priv->of);

	return ULOGD_IRET_OK;
}

static int xml_open_file(struct ulogd_pluginstance *upi)
{
	struct xml_priv *priv = (struct xml_priv *)&upi->private;

	if (strncmp(filename_ce(upi), "-", 1) == 0) {
		priv->of = stdout;
	} else {
		priv->of = fopen(filename_ce(upi), "a");
		if (priv->of == NULL) {
			ulogd_log(ULOGD_FATAL, "can't open XML file - %s: %s\n",
				  filename_ce(upi), _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
	}

	return ULOGD_IRET_OK;
}

static void xml_print_header(struct ulogd_pluginstance *upi)
{
	struct xml_priv *priv = (struct xml_priv *)&upi->private;

	fprintf(priv->of, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
	fprintf(priv->of, "<netfilter>\n");
	if (sync_ce(upi) != 0)
		fflush(priv->of);
}

static int xml_start(struct ulogd_pluginstance *upi, struct ulogd_keyset *input)
{
	struct xml_priv *priv = (struct xml_priv *)&upi->private;

	if (xml_open_file(upi) != ULOGD_IRET_OK)
		return ULOGD_IRET_ERR;
	xml_print_header(upi);

	if (timestamp_ce(upi))
		priv->output_ts = xml_output_ts;
	else
		priv->output_ts = xml_output_ts_none;

	return ULOGD_IRET_OK;
}

static void
xml_signal_handler(struct ulogd_pluginstance *upi, int signal)
{
	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "XML: reopening logfile\n");
		xml_fini(upi);
		if (xml_open_file(upi) < 0) {
			ulogd_log(ULOGD_FATAL, "can't open XML file - %s: %s\n",
				  filename_ce(upi), _sys_errlist[errno]);
			return;
		}
		xml_print_header(upi);
		break;
	default:
		break;
	}
}

static struct ulogd_plugin xml_plugin = {
	.name = "XML2",
	.input = {
		.keys = xml_inp,
		.num_keys = ARRAY_SIZE(xml_inp),
		.type = ULOGD_DTYPE_FLOW | ULOGD_DTYPE_SUM,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset	= &xml_kset,
	.priv_size	= sizeof(struct xml_priv),
	
	.configure	= &xml_configure,
	.start		= &xml_start,
	.stop		= &xml_fini,
	.interp		= &xml_output,
	.signal		= &xml_signal_handler,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&xml_plugin);
}
