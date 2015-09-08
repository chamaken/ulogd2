/* ulogd_filter_MARKIF.c
 *
 * ulogd filter plugin for IPFIX / Netflow v9 to create
 * IPFIX_(egress|ingress)Interface from NCFT MARK mask
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

#define _GNU_SOURCE	/* for strstr() */

#include <stdlib.h>
#include <string.h>

#include <ulogd/ulogd.h>
#include <ulogd/ipfix_protocol.h>

struct markif_priv {
	uint32_t	in_mask, out_mask;
	uint32_t	in_shift, out_shift;
};

/*
 *       LAN              WAN
 *              +---+
 * ---- eth1 -- | B | -- eth2 ----
 *              | O |
 *              | X | -- eth3 ----
 *              +---+
 *
 * interface eth1
 *   ip flow ingress
 *   ip flow egress
 *
 * *nat
 * # indev
 * -A PREROUTING  -i eth1 -j CONNMARK --set-mark 0x000001/0x0100ff
 * -A PREROUTING  -i eth2 -j CONNMARK --set-mark 0x010002/0x0100ff
 * -A PREROUTING  -i eth3 -j CONNMARK --set-mark 0x010003/0x0100ff
 * # outdev
 * -A POSTROUTING -o eth1 -j CONNMARK --set-mark 0x000100/0x00ff00
 * -A POSTROUTING -o eth2 -j CONNMARK --set-mark 0x000200/0x00ff00
 * -A POSTROUTING -o eth3 -j CONNMARK --set-mark 0x000300/0x00ff00
 *
 * config:
 * mask_ingress="0xff"
 * mask_egress="0xff00 >> 8"
 * mask_flow=0x10000
 *
 * Then:           ingressInterface         egressInterface        flowDirection
 *   eth1->eth2            1                       2                    0 ingress
 *   eth1->eth3            1                       3                    0 ingress
 *   eth2->eth1            2                       1                    1 egress
 *   eth3->eth1            3                       1                    1 egress
 *   eth2->eth3            2                       3                    1 egress?
 *
 * http://patchwork.ozlabs.org/patch/278213/
 */

enum {
	CONFKEY_MASK_IN,
	CONFKEY_MASK_OUT,
	CONFKEY_MASK_FLOW,
	CONFKEY_MAX = CONFKEY_MASK_FLOW,
};

static struct config_keyset config_keys = {
	.num_ces = CONFKEY_MAX + 1,
	.ces = {
		{
			.key	 = "mask_ingress",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key	 = "mask_egress",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			/* & == 0: ingress flow, 0
			 *   != 0: egress flow,  1 */
			.key	 = "mask_flow",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
		},
	},
};

#define maskin_ce(x)	((x)->ces[CONFKEY_MASK_IN])
#define maskout_ce(x)	((x)->ces[CONFKEY_MASK_OUT])
#define maskflow_ce(x)	((x)->ces[CONFKEY_MASK_FLOW])

enum {
	IKEY_CT_MARK,
	IKEY_MAX = IKEY_CT_MARK,
};

static struct ulogd_key input_keys[] = {
	[IKEY_CT_MARK] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ct.mark",
	},
};

enum output_key_index {
	OKEY_OOB_IFINDEX_IN,
	OKEY_OOB_IFINDEX_OUT,
	OKEY_FLOW_DIRECTION,
	OKEY_MAX = OKEY_OOB_IFINDEX_OUT,
};

static struct ulogd_key output_keys[] = {
	[OKEY_OOB_IFINDEX_IN] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "oob.ifindex_in",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_ingressInterface,
		},
	},
	[OKEY_OOB_IFINDEX_OUT] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "oob.ifindex_out",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_egressInterface,
		},
	},
	[OKEY_FLOW_DIRECTION] = {
		.type 	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.direction",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowDirection,
		},
	},
};

static int interp_markif(struct ulogd_pluginstance *upi,
			 struct ulogd_keyset *input,
			 struct ulogd_keyset *output)
{
	struct markif_priv *priv =
			(struct markif_priv *)upi->private;
	struct ulogd_key *inp = input->keys;
	struct ulogd_key *ret = output->keys;
	uint32_t ctmark;

	if (!pp_is_valid(inp, IKEY_CT_MARK))
		return ULOGD_IRET_ERR;
	ctmark = ikey_get_u32(&inp[IKEY_CT_MARK]);

	okey_set_u32(&ret[OKEY_OOB_IFINDEX_IN],
		     (ctmark & priv->in_mask) >> priv->in_shift);
	okey_set_u32(&ret[OKEY_OOB_IFINDEX_OUT],
		     (ctmark & priv->out_mask) >> priv->out_shift);
	okey_set_u8(&ret[OKEY_FLOW_DIRECTION],
		    (ctmark & maskflow_ce(upi->config_kset).u.value) != 0);

	return ULOGD_IRET_OK;
}

static int configure_markif(struct ulogd_pluginstance *upi)
{
        return config_parse_file(upi->id, upi->config_kset);
}

static int extract_param(char *s, uint32_t *mask, uint32_t *shift)
{
	char *t = NULL;
	uintmax_t v;

	if ((t = strstr(s, ">>")) != NULL) {
		*t = '\0';
		t += 2;
		v = strtoumax(t, NULL, 0);
	} else {
		v = 0;
	}
	*shift = v;
	v = strtoumax(s, NULL, 0);
	*mask = v;
	return 0;
}

static int start_markif(struct ulogd_pluginstance *upi,
		       struct ulogd_keyset *input)
{
	struct markif_priv *priv =
			(struct markif_priv *)upi->private;

	if (strlen(maskin_ce(upi->config_kset).u.string) == 0) {
		ulogd_log(ULOGD_FATAL, "no mask_ingress specified\n");
		return -1;
	}
	if (extract_param(maskin_ce(upi->config_kset).u.string,
			  &priv->in_mask, &priv->in_shift) != 0) {
		ulogd_log(ULOGD_FATAL, "invalid mask_ingress\n");
		return -1;
	}
	ulogd_log(ULOGD_INFO, "ingress mask: %#x >> %#x\n",
		  priv->in_mask, priv->in_shift);

	if (strlen(maskout_ce(upi->config_kset).u.string) == 0) {
		ulogd_log(ULOGD_FATAL, "no mask_egress spcefied\n");
		return -1;
	}
	if (extract_param(maskout_ce(upi->config_kset).u.string,
			  &priv->out_mask, &priv->out_shift) != 0) {
		ulogd_log(ULOGD_FATAL, "invalid mask_egress\n");
		return -1;
	}
	ulogd_log(ULOGD_INFO, "egress mask: %#x >> %#x\n",
		  priv->out_mask, priv->out_shift);

	ulogd_log(ULOGD_INFO, "direction mask: %#x\n",
		  maskflow_ce(upi->config_kset).u.value);

	return 0;
}

static struct ulogd_plugin markif_plugin = {
	.name = "MARKIF",
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
	.config_kset 	= &config_keys,
	.interp		= &interp_markif,
	.configure	= &configure_markif,
	.start		= &start_markif,
	.priv_size	= sizeof(struct markif_priv),
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&markif_plugin);
}
