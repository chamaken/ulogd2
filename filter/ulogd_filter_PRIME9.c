/* ulogd_filter_PRIME9.c
 *
 * ulogd interpreter plugin for Netflow v9 to add counter and ifindex
 * fields which has default length.
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

#define _GNU_SOURCE	/* for memmem() */

#include <ulogd/ulogd.h>

enum {
	IKEY_ORIG_PKTLEN_DELTA,
	IKEY_ORIG_PKTCOUNT_DELTA,
	IKEY_REPLY_PKTLEN_DELTA,
	IKEY_REPLY_PKTCOUNT_DELTA,
	IKEY_IF_INGRESS,
	IKEY_IF_EGRESS,
	IKEY_MAX = IKEY_IF_EGRESS,
};

static struct ulogd_key input_keys[] = {
	[IKEY_ORIG_PKTLEN_DELTA] = {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.raw.pktlen.delta",
	},
	[IKEY_ORIG_PKTCOUNT_DELTA] = {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.raw.pktcount.delta",
	},
	[IKEY_REPLY_PKTLEN_DELTA] = {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.raw.pktlen.delta",
	},
	[IKEY_REPLY_PKTCOUNT_DELTA] = {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.raw.pktcount.delta",
	},
	[IKEY_IF_INGRESS] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "oob.ifindex_in",
	},
	[IKEY_IF_EGRESS] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "oob.ifindex_out",
	},
};

enum {
	OKEY_ORIG_PKTLEN_DELTA,
	OKEY_ORIG_PKTCOUNT_DELTA,
	OKEY_REPLY_PKTLEN_DELTA,
	OKEY_REPLY_PKTCOUNT_DELTA,
	OKEY_IF_INGRESS,
	OKEY_IF_EGRESS,
	OKEY_MAX = OKEY_IF_EGRESS,
};

static struct ulogd_key output_keys[] = {
	[IKEY_ORIG_PKTLEN_DELTA] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.raw.pktlen.delta32",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_octetDeltaCount,
		},
	},
	[IKEY_ORIG_PKTCOUNT_DELTA] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.raw.pktcount.delta32",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_packetDeltaCount,
		},
	},
	[IKEY_REPLY_PKTLEN_DELTA] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.raw.pktlen.delta32",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_REVERSE,
			.field_id 	= IPFIX_octetDeltaCount,
		},
	},
	[IKEY_REPLY_PKTCOUNT_DELTA] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.raw.pktcount.delta32",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_REVERSE,
			.field_id 	= IPFIX_packetDeltaCount,
		},
	},
	[IKEY_IF_INGRESS] = {
		.type	= ULOGD_RET_UINT16,
		.flags	= ULOGD_RETF_NONE,
		.name	= "oob.ifindex_in16",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_ingressInterface,
		},
	},
	[IKEY_IF_EGRESS] = {
		.type	= ULOGD_RET_UINT16,
		.flags	= ULOGD_RETF_NONE,
		.name	= "oob.ifindex_out16",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_egressInterface,
		},
	},
};

static int interp_prime9(struct ulogd_pluginstance *upi)
{
	struct ulogd_key *inp = upi->input.keys;
	struct ulogd_key *ret = upi->output.keys;

	if (!pp_is_valid(inp, IKEY_ORIG_PKTLEN_DELTA)
	    || !pp_is_valid(inp, IKEY_ORIG_PKTCOUNT_DELTA)
	    || !pp_is_valid(inp, IKEY_REPLY_PKTLEN_DELTA)
	    || !pp_is_valid(inp, IKEY_REPLY_PKTCOUNT_DELTA)
	    || !pp_is_valid(inp, IKEY_IF_INGRESS)
	    || !pp_is_valid(inp, IKEY_IF_EGRESS))
		return ULOGD_IRET_ERR;

	okey_set_u32(&ret[OKEY_ORIG_PKTLEN_DELTA],
		     (uint32_t)ikey_get_u64(&inp[IKEY_ORIG_PKTLEN_DELTA]));
	okey_set_u32(&ret[OKEY_ORIG_PKTCOUNT_DELTA],
		     (uint32_t)ikey_get_u64(&inp[IKEY_ORIG_PKTCOUNT_DELTA]));
	okey_set_u32(&ret[OKEY_REPLY_PKTLEN_DELTA],
		     (uint32_t)ikey_get_u64(&inp[IKEY_REPLY_PKTLEN_DELTA]));
	okey_set_u32(&ret[OKEY_REPLY_PKTCOUNT_DELTA],
		     (uint32_t)ikey_get_u64(&inp[IKEY_REPLY_PKTCOUNT_DELTA]));
	okey_set_u16(&ret[OKEY_IF_INGRESS],
		     (uint16_t)ikey_get_u32(&inp[IKEY_IF_INGRESS]));
	okey_set_u16(&ret[OKEY_IF_EGRESS],
		     (uint16_t)ikey_get_u32(&inp[IKEY_IF_EGRESS]));

	return ULOGD_IRET_OK;
}

static struct ulogd_plugin prime9_plugin = {
	.name = "PRIME9",
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
	.interp	= &interp_prime9,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&prime9_plugin);
}
