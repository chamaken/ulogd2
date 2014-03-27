/* ulogd_filter_IP2STR.c
 *
 * ulogd interpreter plugin for internal IP storage format to string conversion
 *
 * (C) 2008 by Eric Leblond <eric@inl.fr>
 *
 * Based on ulogd_filter_IFINDEX.c Harald Welte <laforge@gnumonks.org>
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ulogd/ulogd.h>
#include <netinet/if_ether.h>

#define IPADDR_LENGTH 128

enum input_keys {
	KEY_OOB_FAMILY,
	KEY_OOB_PROTOCOL,
	KEY_IP_SADDR,
	START_KEY = KEY_IP_SADDR,
	KEY_IP_DADDR,
	KEY_ORIG_IP_SADDR,
	KEY_ORIG_IP_DADDR,
	KEY_REPLY_IP_SADDR,
	KEY_REPLY_IP_DADDR,
	KEY_ARP_SPA,
	KEY_ARP_TPA,
	MAX_KEY = KEY_ARP_TPA,
};

static struct ulogd_key ip2str_inp[] = {
	[KEY_OOB_FAMILY] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.family",
	},
	[KEY_OOB_PROTOCOL] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.protocol",
	},
	[KEY_IP_SADDR] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "ip.saddr",
	},
	[KEY_IP_DADDR] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "ip.daddr",
	},
	[KEY_ORIG_IP_SADDR] = {
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name	= "orig.ip.saddr",
	},
	[KEY_ORIG_IP_DADDR] = {
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name	= "orig.ip.daddr",
	},
	[KEY_REPLY_IP_SADDR] = {
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name	= "reply.ip.saddr",
	},
	[KEY_REPLY_IP_DADDR] = {
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name	= "reply.ip.daddr",
	},
	[KEY_ARP_SPA] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "arp.saddr",
	},
	[KEY_ARP_TPA] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "arp.daddr",
	},
};

static struct ulogd_key ip2str_keys[] = {
	{
		.type = ULOGD_RET_STRING,
		.name = "ip.saddr.str",
		.cim_name = "src_ip",
	},
	{
		.type = ULOGD_RET_STRING,
		.name = "ip.daddr.str",
		.cim_name = "dest_ip",
	},
	{
		.type = ULOGD_RET_STRING,
		.name = "orig.ip.saddr.str",
		.cim_name = "src_ip",
	},
	{
		.type = ULOGD_RET_STRING,
		.name = "orig.ip.daddr.str",
		.cim_name = "dest_ip",
	},
	{
		.type = ULOGD_RET_STRING,
		.name = "reply.ip.saddr.str",
	},
	{
		.type = ULOGD_RET_STRING,
		.name = "reply.ip.daddr.str",
	},
	{
		.type = ULOGD_RET_STRING,
		.name = "arp.saddr.str",
	},
	{
		.type = ULOGD_RET_STRING,
		.name = "arp.daddr.str",
	},
};

enum ip2str_conf {
	IP2STR_CONF_V6SEP = 0,
	IP2STR_CONF_V4SEP,
	IP2STR_CONF_MAX
};

static struct config_keyset ip2str_config_kset = {
	.num_ces = 2,
	.ces = {
		[IP2STR_CONF_V6SEP] = {
			.key = "v6sep",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u = {.string = ":"},
		},
		[IP2STR_CONF_V4SEP] = {
			.key = "v4sep",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u = {.string = "."},
		},
	},
};

#define v6sep_ce(x)	(x->ces[IP2STR_CONF_V6SEP])
#define v4sep_ce(x)	(x->ces[IP2STR_CONF_V4SEP])

static char ipstr_array[MAX_KEY-START_KEY][IPADDR_LENGTH];

void change_separator(char family, char *addr, char to)
{
	char from;
	char *cur;

	switch(family) {
	case AF_INET6: from = ':'; break;
	case AF_INET: from = '.'; break;
	default:
		ulogd_log(ULOGD_NOTICE, "Unknown protocol family\n");
		return;
	}

	for (cur = strchr(addr, from); cur != NULL; cur = strchr(cur + 1, from))
		*cur = to;
}

static int ip2str(struct ulogd_pluginstance *upi, int index, int oindex)
{
	struct ulogd_key *inp = upi->input.keys;
	char family = ikey_get_u8(&inp[KEY_OOB_FAMILY]);
	char convfamily = family;

	if (family == AF_BRIDGE) {
		if (!pp_is_valid(inp, KEY_OOB_PROTOCOL)) {
			ulogd_log(ULOGD_NOTICE,
				  "No protocol inside AF_BRIDGE packet\n");
			return ULOGD_IRET_ERR;
		}
		switch (ikey_get_u16(&inp[KEY_OOB_PROTOCOL])) {
		case ETH_P_IPV6:
			convfamily = AF_INET6;
			break;
		case ETH_P_IP:
			convfamily = AF_INET;
			break;
		case ETH_P_ARP:
			convfamily = AF_INET;
			break;
		default:
			ulogd_log(ULOGD_NOTICE,
				  "Unknown protocol inside AF_BRIDGE packet\n");
			return ULOGD_IRET_ERR;
		}
	}

	switch (convfamily) {
		u_int32_t ip;
	case AF_INET6:
		inet_ntop(AF_INET6,
			  ikey_get_u128(&inp[index]),
			  ipstr_array[oindex], sizeof(ipstr_array[oindex]));
		if (*v6sep_ce(upi->config_kset).u.string != ':')
			change_separator(convfamily, ipstr_array[oindex],
					 *v6sep_ce(upi->config_kset).u.string);
		break;
	case AF_INET:
		ip = ikey_get_u32(&inp[index]);
		inet_ntop(AF_INET, &ip,
			  ipstr_array[oindex], sizeof(ipstr_array[oindex]));
		if (*v4sep_ce(upi->config_kset).u.string != '.')
			change_separator(convfamily, ipstr_array[oindex],
					 *v4sep_ce(upi->config_kset).u.string);
		break;
	default:
		/* TODO error handling */
		ulogd_log(ULOGD_NOTICE, "Unknown protocol family\n");
		return ULOGD_IRET_ERR;
	}
	return ULOGD_IRET_OK;
}

static int interp_ip2str(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output.keys;
	struct ulogd_key *inp = pi->input.keys;
	int i;
	int fret;

	/* Iter on all addr fields */
	for (i = START_KEY; i <= MAX_KEY; i++) {
		if (pp_is_valid(inp, i)) {
			fret = ip2str(pi, i, i-START_KEY);
			if (fret != ULOGD_IRET_OK)
				return fret;
			okey_set_ptr(&ret[i-START_KEY],
				     ipstr_array[i-START_KEY]);
		}
	}

	return ULOGD_IRET_OK;
}

static int configure_ip2str(struct ulogd_pluginstance *upi,
			    struct ulogd_pluginstance_stack *stack)
{
	int ret = config_parse_file(upi->id, upi->config_kset);

	if (ret < 0)
		return ret;

	if (strlen(v6sep_ce(upi->config_kset).u.string) > 1)
		ulogd_log(ULOGD_NOTICE, "only one char v6 separator is allowed,"
			  " using: %c\n", *v6sep_ce(upi->config_kset).u.string);
	if (strlen(v4sep_ce(upi->config_kset).u.string) > 1)
		ulogd_log(ULOGD_NOTICE, "only one char v4 separator is allowed,"
			  " using: %c\n", *v4sep_ce(upi->config_kset).u.string);
	return ret;
}

static struct ulogd_plugin ip2str_pluging = {
	.name = "IP2STR",
	.input = {
		.keys = ip2str_inp,
		.num_keys = ARRAY_SIZE(ip2str_inp),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.output = {
		.keys = ip2str_keys,
		.num_keys = ARRAY_SIZE(ip2str_keys),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.config_kset = &ip2str_config_kset,
	.interp = &interp_ip2str,
	.configure = &configure_ip2str,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&ip2str_pluging);
}
