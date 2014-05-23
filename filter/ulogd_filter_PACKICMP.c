/* ulogd_filter_PACKICMP.c
 *
 * ulogd interpreter plugin for IPFIX / Netflow v9 to create
 * icmpTypeCodeIPv4
 *
 * (C) 2014 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
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

#include <arpa/inet.h>

#include <ulogd/ulogd.h>
#include <ulogd/ipfix_protocol.h>

enum input_key_index {
	IKEY_ICMP_CODE,
	IKEY_ICMP_TYPE,
	IKEY_MAX = IKEY_ICMP_TYPE,
};

static struct ulogd_key input_keys[] = {
	[IKEY_ICMP_CODE] = {
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "icmp.code",
	},
	[IKEY_ICMP_TYPE] = {
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "icmp.type",
	},
};

enum output_key_index {
	OKEY_V4,
	OKEY_MAX = OKEY_V4,
};

static struct ulogd_key output_keys[] = {
	[OKEY_V4] = {
		.type	= ULOGD_RET_UINT16,
		.flags	= ULOGD_RETF_NONE,
		.name	= "icmp.typecode4",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_icmpTypeCodeIPv4,
		},
	},
};

static int interp_packicmp(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output.keys;
	struct ulogd_key *inp = pi->input.keys;

	if (!pp_is_valid(inp, IKEY_ICMP_TYPE)
	    || !pp_is_valid(inp, IKEY_ICMP_CODE))
		return ULOGD_IRET_OK;

	okey_set_u16(&ret[OKEY_V4],
		     ikey_get_u8(&inp[IKEY_ICMP_TYPE]) << 8
		     | ikey_get_u8(&inp[IKEY_ICMP_CODE]));

	return ULOGD_IRET_OK;
}

static struct ulogd_plugin packicmp_plugin = {
	.name = "PACKICMP",
	.input = {
		.keys = input_keys,
		.num_keys = ARRAY_SIZE(input_keys),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.output = {
		.keys = output_keys,
		.num_keys = ARRAY_SIZE(output_keys),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.interp = &interp_packicmp,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&packicmp_plugin);
}
