/* ulogd_inppkt_NFLOG2.c
 *
 * ulogd input plugin for mmaped nflog
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */
#define _GNU_SOURCE /* _sys_errlist[] */

#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <endian.h>	/* be64toh */

#include <linux/netlink.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_log/libnetfilter_log.h>

#include <ulogd/ulogd.h>
#include <ulogd/ring.h>

struct nflog_priv {
	struct mnl_socket	*nl;
	uint32_t		portid;
	struct ulogd_fd		ufd;
	struct mnl_ring		*nlr;
	bool			skipped;
};

/* configuration entries */
enum nflog_conf {
	NFLOG_CONF_BLOCK_SIZE	= 0,
	NFLOG_CONF_BLOCK_NR,
	NFLOG_CONF_FRAME_SIZE,
	NFLOG_CONF_ONESHOT,
	NFLOG_CONF_BIND,
	NFLOG_CONF_UNBIND,
	NFLOG_CONF_GROUP,
	NFLOG_CONF_SEQ_LOCAL,
	NFLOG_CONF_SEQ_GLOBAL,
	NFLOG_CONF_NUMLABEL,
	NFLOG_CONF_QTHRESH,
	NFLOG_CONF_QTIMEOUT,
	NFLOG_CONF_COPY_MODE,		/* NFULNL_COPY_ NONE / META / PACKET */
	NFLOG_CONF_COPY_RANGE,
	NFLOG_CONF_CONNTRACK,
	NFLOG_CONF_MAX,
};

static struct config_keyset nflog_kset = {
	.num_ces = NFLOG_CONF_MAX,
	.ces = {
		[NFLOG_CONF_BLOCK_SIZE] = {
			.key	 = "block_size",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 8192,
		},
		[NFLOG_CONF_BLOCK_NR] = {
			.key	 = "block_nr",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 32,
		},
		[NFLOG_CONF_FRAME_SIZE] = {
			.key	 = "frame_size",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 8192,
		},
		[NFLOG_CONF_ONESHOT] = {
			.key	 = "oneshot",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFLOG_CONF_BIND] = {
			.key	 = "bind",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFLOG_CONF_UNBIND] = {
			.key	 = "unbind",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 1,
		},
		[NFLOG_CONF_GROUP] = {
                        .key     = "group",
			.type    = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFLOG_CONF_SEQ_LOCAL] = {
			.key	 = "seq_local",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFLOG_CONF_SEQ_GLOBAL] = {
			.key	 = "seq_global",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFLOG_CONF_NUMLABEL] = {
			.key	 = "numeric_label",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFLOG_CONF_QTHRESH] = {
			.key     = "qthreshold",
			.type    = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFLOG_CONF_QTIMEOUT] = {
			.key     = "qtimeout",
			.type    = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFLOG_CONF_COPY_MODE] = {
			.key	 = "copy_mode",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u.string = "packet",
		},
		[NFLOG_CONF_COPY_RANGE] = {
			.key	 = "copy_range",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0xFFFF - NLA_HDRLEN,
		},
		[NFLOG_CONF_CONNTRACK] = {
			.key     = "conntrack",
			.type    = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
	}
};

#define block_size_ce(x)	(((x)->config_kset->ces[NFLOG_CONF_BLOCK_SIZE]).u.value)
#define block_nr_ce(x)		(((x)->config_kset->ces[NFLOG_CONF_BLOCK_NR]).u.value)
#define frame_size_ce(x)	(((x)->config_kset->ces[NFLOG_CONF_FRAME_SIZE]).u.value)
#define oneshot_ce(x)		(((x)->config_kset->ces[NFLOG_CONF_ONESHOT]).u.value)
#define bind_ce(x)		(((x)->config_kset->ces[NFLOG_CONF_BIND]).u.value)
#define unbind_ce(x)		(((x)->config_kset->ces[NFLOG_CONF_UNBIND]).u.value)
#define group_ce(x)		(((x)->config_kset->ces[NFLOG_CONF_GROUP]).u.value)
#define seq_ce(x)		(((x)->config_kset->ces[NFLOG_CONF_SEQ_LOCAL]).u.value)
#define seq_global_ce(x)	(((x)->config_kset->ces[NFLOG_CONF_SEQ_GLOBAL]).u.value)
#define label_ce(x)		(((x)->config_kset->ces[NFLOG_CONF_NUMLABEL]).u.value)
#define qthresh_ce(x)		(((x)->config_kset->ces[NFLOG_CONF_QTHRESH]).u.value)
#define qtimeout_ce(x)		(((x)->config_kset->ces[NFLOG_CONF_QTIMEOUT]).u.value)
#define copy_mode_ce(x)		(((x)->config_kset->ces[NFLOG_CONF_COPY_MODE]).u.string)
#define copy_range_ce(x)	(((x)->config_kset->ces[NFLOG_CONF_COPY_RANGE]).u.value)
#define conntrack_ce(x)		(((x)->config_kset->ces[NFLOG_CONF_CONNTRACK]).u.value)

enum nflog_keys {
	NFLOG_KEY_RAW_MAC = 0,
	NFLOG_KEY_RAW_PCKT,
	NFLOG_KEY_RAW_PCKTLEN,
	NFLOG_KEY_RAW_PCKTCOUNT,
	NFLOG_KEY_OOB_PREFIX,
	NFLOG_KEY_OOB_TIME_SEC,
	NFLOG_KEY_OOB_TIME_USEC,
	NFLOG_KEY_OOB_MARK,
	NFLOG_KEY_OOB_IFINDEX_IN,
	NFLOG_KEY_OOB_IFINDEX_OUT,
	NFLOG_KEY_OOB_HOOK,
	NFLOG_KEY_RAW_MAC_LEN,
	NFLOG_KEY_OOB_SEQ_LOCAL,
	NFLOG_KEY_OOB_SEQ_GLOBAL,
	NFLOG_KEY_OOB_FAMILY,
	NFLOG_KEY_OOB_PROTOCOL,
	NFLOG_KEY_OOB_UID,
	NFLOG_KEY_OOB_GID,
	NFLOG_KEY_RAW_LABEL,
	NFLOG_KEY_RAW_TYPE,
	NFLOG_KEY_RAW_MAC_SADDR,
	NFLOG_KEY_RAW_MAC_ADDRLEN,
	NFLOG_KEY_RAW,
	NFLOG_KEY_NLATTRS,
	NFLOG_KEY_FRAME,
	NFLOG_KEY_MAX,
};

static void frame_destructor(void *data);

static struct ulogd_key output_keys[] = {
	[NFLOG_KEY_RAW_MAC] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac",
	},
	[NFLOG_KEY_RAW_MAC_SADDR] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac.saddr",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceMacAddress,
		},
	},
	[NFLOG_KEY_RAW_PCKT] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pkt",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_rawpacket,
		},
	},
	[NFLOG_KEY_RAW_PCKTLEN] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktlen",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_rawpacket_length,
		},
	},
	[NFLOG_KEY_RAW_PCKTCOUNT] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktcount",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_packetDeltaCount,
		},
	},
	[NFLOG_KEY_OOB_PREFIX] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.prefix",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_prefix,
		},
	},
	[NFLOG_KEY_OOB_TIME_SEC] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.time.sec",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_flowStartSeconds,
		},
	},
	[NFLOG_KEY_OOB_TIME_USEC] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.time.usec",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_flowStartMicroSeconds,
		},
	},
	[NFLOG_KEY_OOB_MARK] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.mark",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_mark,
		},
	},
	[NFLOG_KEY_OOB_IFINDEX_IN] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.ifindex_in",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_ingressInterface,
		},
	},
	[NFLOG_KEY_OOB_IFINDEX_OUT] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.ifindex_out",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_egressInterface,
		},
	},
	[NFLOG_KEY_OOB_HOOK] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.hook",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_hook,
		},
	},
	[NFLOG_KEY_RAW_MAC_LEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac_len",
	},
	[NFLOG_KEY_RAW_MAC_ADDRLEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac.addrlen",
	},

	[NFLOG_KEY_OOB_SEQ_LOCAL] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.seq.local",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_seq_local,
		},
	},
	[NFLOG_KEY_OOB_SEQ_GLOBAL] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.seq.global",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_seq_global,
		},
	},
	[NFLOG_KEY_OOB_FAMILY] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.family",
	},
	[NFLOG_KEY_OOB_PROTOCOL] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.protocol",
	},
	[NFLOG_KEY_OOB_UID] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.uid",
	},
	[NFLOG_KEY_OOB_GID] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.gid",
	},
	[NFLOG_KEY_RAW_LABEL] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.label",
	},
	[NFLOG_KEY_RAW_TYPE] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.type",
	},
	[NFLOG_KEY_NLATTRS] = {
		/* struct nlattr *attr[NFULA_MAX+1] = {}; */
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_RETF_EMBED,
		.name	= "nflog.attrs",
		.len	= sizeof(struct nlattr *) * (NFULA_MAX + 1),
	},
	[NFLOG_KEY_FRAME] = {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_RETF_NONE | ULOGD_RETF_DESTRUCT,
		.name	= "nflog.frame",
		.destruct = frame_destructor,
	},
};

static void frame_destructor(void *data)
{
	struct nl_mmap_hdr *frame = data;
	frame->nm_status = NL_MMAP_STATUS_UNUSED;
}

static int nflog_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	struct ulogd_source_pluginstance *spi = data;
	struct ulogd_keyset *output = ulogd_get_output_keyset(spi);
	struct ulogd_key *ret = output->keys;
	struct nlattr **attrs;
	struct nl_mmap_hdr *frame = (void *)nlh - NL_MMAP_HDRLEN;
	
	attrs = (struct nlattr **)okey_get_ptr(&ret[NFLOG_KEY_NLATTRS]);
	if (nflog_nlmsg_parse(nlh, attrs) == MNL_CB_ERROR) {
		ulogd_log(ULOGD_ERROR, "could not parse nflog message: %s\n",
			  _sys_errlist[errno]);
		ulogd_put_output_keyset(output);
		return MNL_CB_ERROR;
	}
	okey_set_valid(&ret[NFLOG_KEY_NLATTRS]);

	okey_set_ptr(&ret[NFLOG_KEY_FRAME], frame);
	okey_set_u8(&ret[NFLOG_KEY_OOB_FAMILY], nfg->nfgen_family);
	okey_set_u8(&ret[NFLOG_KEY_RAW_LABEL], label_ce(spi)); /* ??? */

	if (attrs[NFULA_PACKET_HDR]) {
		struct nfulnl_msg_packet_hdr *ph
			= mnl_attr_get_payload(attrs[NFULA_PACKET_HDR]);
		okey_set_u8(&ret[NFLOG_KEY_OOB_HOOK], ph->hook);
		okey_set_u16(&ret[NFLOG_KEY_OOB_PROTOCOL],
			     ntohs(ph->hw_protocol));
	}

	if (attrs[NFULA_HWHEADER]) {
		okey_set_ptr(&ret[NFLOG_KEY_RAW_MAC], 
			     mnl_attr_get_payload(attrs[NFULA_HWHEADER]));
		okey_set_u16(&ret[NFLOG_KEY_RAW_MAC_LEN],
			     ntohs(mnl_attr_get_u16(attrs[NFULA_HWLEN])));
		okey_set_u16(&ret[NFLOG_KEY_RAW_TYPE],
			     ntohs(mnl_attr_get_u16(attrs[NFULA_HWTYPE])));
	}

	if (attrs[NFULA_HWADDR]) {
		struct nfulnl_msg_packet_hw *hw
			= mnl_attr_get_payload(attrs[NFULA_HWADDR]);
		okey_set_ptr(&ret[NFLOG_KEY_RAW_MAC_SADDR], hw->hw_addr);
		okey_set_u16(&ret[NFLOG_KEY_RAW_MAC_ADDRLEN], 
			     ntohs(hw->hw_addrlen));
	}

	if (attrs[NFULA_PAYLOAD]) {
		/* include pointer to raw packet */
		okey_set_ptr(&ret[NFLOG_KEY_RAW_PCKT],
			     mnl_attr_get_payload(attrs[NFULA_PAYLOAD]));
		okey_set_u32(&ret[NFLOG_KEY_RAW_PCKTLEN],
			     mnl_attr_get_payload_len(attrs[NFULA_PAYLOAD]));
	}

	/* number of packets */
	okey_set_u32(&ret[NFLOG_KEY_RAW_PCKTCOUNT], 1);

	if (attrs[NFULA_PREFIX])
		okey_set_ptr(&ret[NFLOG_KEY_OOB_PREFIX],
			     mnl_attr_get_payload(attrs[NFULA_PREFIX]));

	if (attrs[NFULA_TIMESTAMP]) {
		struct nfulnl_msg_packet_timestamp *ts
			= mnl_attr_get_payload(attrs[NFULA_TIMESTAMP]);
		okey_set_u32(&ret[NFLOG_KEY_OOB_TIME_SEC],
			     ts->sec & 0xffffffff);
		okey_set_u32(&ret[NFLOG_KEY_OOB_TIME_USEC],
			     ts->usec & 0xffffffff);
	}

	if (attrs[NFULA_MARK])
		okey_set_u32(&ret[NFLOG_KEY_OOB_MARK],
			     ntohl(mnl_attr_get_u32(attrs[NFULA_MARK])));
	if (attrs[NFULA_IFINDEX_INDEV])
		okey_set_u32(&ret[NFLOG_KEY_OOB_IFINDEX_IN],
			     ntohl(mnl_attr_get_u32(attrs[NFULA_IFINDEX_INDEV])));
	if (attrs[NFULA_IFINDEX_OUTDEV])
		okey_set_u32(&ret[NFLOG_KEY_OOB_IFINDEX_OUT],
			     ntohl(mnl_attr_get_u32(attrs[NFULA_IFINDEX_OUTDEV])));
	if (attrs[NFULA_UID])
		okey_set_u32(&ret[NFLOG_KEY_OOB_UID],
			     ntohl(mnl_attr_get_u32(attrs[NFULA_UID])));
	if (attrs[NFULA_GID])
		okey_set_u32(&ret[NFLOG_KEY_OOB_GID],
			     ntohl(mnl_attr_get_u32(attrs[NFULA_GID])));
	if (attrs[NFULA_SEQ])
		okey_set_u32(&ret[NFLOG_KEY_OOB_SEQ_LOCAL],
			     ntohl(mnl_attr_get_u32(attrs[NFULA_SEQ])));
	if (attrs[NFULA_SEQ_GLOBAL])
		okey_set_u32(&ret[NFLOG_KEY_OOB_SEQ_LOCAL],
			     ntohl(mnl_attr_get_u32(attrs[NFULA_SEQ_GLOBAL])));

	ulogd_propagate_results(output);

	return MNL_CB_OK;
}

static int handle_valid_frame(struct ulogd_source_pluginstance *upi,
			      struct nl_mmap_hdr *frame)
{
	struct nflog_priv *priv = (struct nflog_priv *)upi->private;
	int ret;

	if (frame->nm_len == 0) {
		/* an error may occured in kernel */
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		return ULOGD_IRET_OK;
	}

	frame->nm_status = NL_MMAP_STATUS_SKIP;
	ret = mnl_cb_run(MNL_FRAME_PAYLOAD(frame), frame->nm_len,
			 0, priv->portid, nflog_cb, upi);
	if (ret == MNL_CB_ERROR) {
		ulogd_log(ULOGD_ERROR, "mnl_cb_run: %d %s\n",
			  errno, _sys_errlist[errno]);
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		return ULOGD_IRET_ERR;
	}

	return ULOGD_IRET_OK;
}

/* callback called from ulogd core when fd is readable */
static int nflog_read_cb(int fd, unsigned int what, void *param)
{
	struct ulogd_source_pluginstance *upi = param;
	struct nflog_priv *priv = (struct nflog_priv *)upi->private;
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

static int configure(struct ulogd_source_pluginstance *upi)
{
	return config_parse_file(upi->id, upi->config_kset);
}

static int nflog_config_response(struct nflog_priv *priv)
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

static int become_system_logging(struct ulogd_source_pluginstance *upi,
				 uint8_t family)
{
	struct nflog_priv *priv = (struct nflog_priv *)upi->private;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	if (unbind_ce(upi) > 0) {
		ulogd_log(ULOGD_NOTICE, "forcing unbind of existing log "
				"handler for protocol %d\n", family);
		nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, family, 0);
		nlh->nlmsg_flags |= NLM_F_ACK;
		if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_UNBIND) < 0) {
			ulogd_log(ULOGD_ERROR, "nflog_attr_put_cfg_cmd: %s\n",
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
		if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
			ulogd_log(ULOGD_ERROR, "mnl_socket_sendto: %s\n",
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
		if (nflog_config_response(priv) != ULOGD_IRET_OK) {
			ulogd_log(ULOGD_ERROR, "request PF_UNBIND: %s\n",
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
	}

	ulogd_log(ULOGD_DEBUG, "binding to protocol family %d\n", family);
	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, family, 0);
	nlh->nlmsg_flags |= NLM_F_ACK;
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_BIND) < 0) {
		ulogd_log(ULOGD_ERROR, "nflog_attr_put_cfg_cmd: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_sendto: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}
	if (nflog_config_response(priv) != ULOGD_IRET_OK) {
		ulogd_log(ULOGD_ERROR, "request command PF_BIND: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}

	return ULOGD_IRET_OK;
}

static int nflog_prepare_request(struct ulogd_source_pluginstance *upi)
{
	struct nflog_priv *priv = (struct nflog_priv *)upi->private;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint16_t group = group_ce(upi);
	char *copy_mode = copy_mode_ce(upi);
	uint16_t flags = 0;

	/* This is the system logging (conntrack, ...) facility */
	if (group_ce(upi) == 0 || bind_ce(upi) > 0) {
		if (become_system_logging(upi, AF_INET) == -1)
			return ULOGD_IRET_ERR;
		if (become_system_logging(upi, AF_INET6) == -1)
			return ULOGD_IRET_ERR;
		if (become_system_logging(upi, AF_BRIDGE) == -1)
			return ULOGD_IRET_ERR;
	}

	ulogd_log(ULOGD_DEBUG, "binding to log group %d\n", group);
	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
	nlh->nlmsg_flags |= NLM_F_ACK;
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_BIND) < 0) {
		ulogd_log(ULOGD_ERROR, "nflog_attr_put_cfg_cmd: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_sendto: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}
	if (nflog_config_response(priv) != 0) {
		ulogd_log(ULOGD_ERROR, "request command BIND: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}

	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
	nlh->nlmsg_flags |= NLM_F_ACK;
	if (strcasecmp(copy_mode, "packet") == 0) {
		uint32_t copy_range;
		if (frame_size_ce(upi) < copy_range_ce(upi))
			ulogd_log(ULOGD_NOTICE, "may cause COPY status"
				  " - frame size: %d, copy_range: %d\n",
				  frame_size_ce(upi), copy_range_ce(upi));
		copy_range = htonl(copy_range_ce(upi));
		if (nflog_attr_put_cfg_mode(nlh, NFULNL_COPY_PACKET,
					    copy_range) < 0) {
			ulogd_log(ULOGD_ERROR, "nflog_attr_put_cfg_mode: %s\n",
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
	} else if (strcasecmp(copy_mode, "meta") == 0) {
		if (nflog_attr_put_cfg_mode(nlh, NFULNL_COPY_META, 0) < 0) {
			ulogd_log(ULOGD_ERROR, "nflog_attr_put_cfg_mode: %s\n",
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
	} else if (strcasecmp(copy_mode, "none") == 0) {
		if (nflog_attr_put_cfg_mode(nlh, NFULNL_COPY_NONE, 0) < 0) {
			ulogd_log(ULOGD_ERROR, "nflog_attr_put_cfg_mode: %s\n",
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
	} else {
		ulogd_log(ULOGD_ERROR, "unknown copy_mode: %s\n", copy_mode);
		return ULOGD_IRET_ERR;
	}
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_sendto: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}
	if (nflog_config_response(priv) != 0) {
		ulogd_log(ULOGD_ERROR, "request config COPY_PACKET: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}

	if (qthresh_ce(upi) != 0) {
		nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
		nlh->nlmsg_flags |= NLM_F_ACK;
		mnl_attr_put_u32(nlh, NFULA_CFG_QTHRESH, htonl(qthresh_ce(upi)));
		if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
			ulogd_log(ULOGD_ERROR, "mnl_socket_sendto: %s\n",
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
		if (nflog_config_response(priv) != ULOGD_IRET_OK) {
			ulogd_log(ULOGD_NOTICE,
				  "NFLOG netlink queue threshold can't "
				  "be set to %d: %s\n", qthresh_ce(upi),
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
	}

	if (qtimeout_ce(upi) != 0) {
		nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
		nlh->nlmsg_flags |= NLM_F_ACK;
		mnl_attr_put_u32(nlh, NFULA_CFG_TIMEOUT, htonl(qtimeout_ce(upi)));
		if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
			ulogd_log(ULOGD_ERROR, "mnl_socket_sendto: %s\n",
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
		if (nflog_config_response(priv) != ULOGD_IRET_OK) {
			ulogd_log(ULOGD_NOTICE,
				  "NFLOG netlink queue timeout can't "
				  "be set to %d: %s\n", qtimeout_ce(upi),
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
	}

	/* set log flags based on configuration */
	if (seq_ce(upi) != 0)
		flags = NFULNL_CFG_F_SEQ;
	if (seq_global_ce(upi) != 0)
		flags |= NFULNL_CFG_F_SEQ_GLOBAL;
	if (conntrack_ce(upi) != 0)
		flags |= NFULNL_CFG_F_CONNTRACK;
	if (flags) {
		nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
		nlh->nlmsg_flags |= NLM_F_ACK;
		mnl_attr_put_u16(nlh, NFULA_CFG_FLAGS, htons(flags));
		if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
			ulogd_log(ULOGD_ERROR, "mnl_socket_sendto: %s\n",
				  _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
		if (nflog_config_response(priv) != ULOGD_IRET_OK) {
			ulogd_log(ULOGD_ERROR, "unable to set flags 0x%x: %s\n",
				  flags, _sys_errlist[errno]);
			return ULOGD_IRET_ERR;
		}
	}

	return ULOGD_IRET_OK;
}

static int unbind_all(struct mnl_socket *nl)
{
	char buf[MNL_SOCKET_BUFFER_SIZE * 2];
	struct nlmsghdr *nlh;
	struct mnl_nlmsg_batch *b;
	int ret = ULOGD_IRET_ERR;

	b = mnl_nlmsg_batch_start(buf, MNL_SOCKET_BUFFER_SIZE);
	nlh = nflog_nlmsg_put_header(mnl_nlmsg_batch_current(b),
				     NFULNL_MSG_CONFIG, AF_INET, 0);
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_UNBIND) < 0) {
		ulogd_log(ULOGD_ERROR, "nflog_attr_put_cfg_cmd: %s\n",
			  _sys_errlist[errno]);
		goto batch_stop;
	}

	mnl_nlmsg_batch_next(b);
	nlh = nflog_nlmsg_put_header(mnl_nlmsg_batch_current(b),
				     NFULNL_MSG_CONFIG, AF_INET6, 0);
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_UNBIND) < 0) {
		ulogd_log(ULOGD_ERROR, "nflog_attr_put_cfg_cmd: %s\n",
			  _sys_errlist[errno]);
		goto batch_stop;
	}

	mnl_nlmsg_batch_next(b);
	nlh = nflog_nlmsg_put_header(mnl_nlmsg_batch_current(b),
				     NFULNL_MSG_CONFIG, AF_BRIDGE, 0);
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_UNBIND) < 0) {
		ulogd_log(ULOGD_ERROR, "nflog_attr_put_cfg_cmd: %s\n",
			  _sys_errlist[errno]);
		goto batch_stop;
	}

	mnl_nlmsg_batch_next(b);
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_sendto: %s\n",
			  _sys_errlist[errno]);
		goto batch_stop;
	}
	ret = ULOGD_IRET_OK;

batch_stop:	
	mnl_nlmsg_batch_stop(b);
	return ret;
}

static int start(struct ulogd_source_pluginstance *upi)
{
	struct nflog_priv *priv = (struct nflog_priv *)upi->private;
	int optval = 1;
	struct nl_mmap_req req = {
		.nm_block_size	= block_size_ce(upi),
		.nm_block_nr	= block_nr_ce(upi),
		.nm_frame_size	= frame_size_ce(upi),
		.nm_frame_nr	= block_size_ce(upi) / frame_size_ce(upi)
				* block_nr_ce(upi)
	};

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

	if (nflog_prepare_request(upi) != 0)
		goto error_unbind;

	priv->ufd.fd = mnl_socket_get_fd(priv->nl);
	priv->ufd.cb = &nflog_read_cb;
	priv->ufd.data = upi;
	priv->ufd.when = ULOGD_FD_READ;
	if (ulogd_register_fd(&priv->ufd) < 0) {
		ulogd_log(ULOGD_FATAL, "ulogd_register_fd: %s\n",
			  _sys_errlist[errno]);
		goto error_unbind;
	}

	return ULOGD_IRET_OK;

error_unbind:
	if (group_ce(upi) == 0)
		unbind_all(priv->nl);
error_unmap:
	mnl_socket_unmap(priv->nlr);
error_close_sock:
	mnl_socket_close(priv->nl);
	return ULOGD_IRET_ERR;
}

static int stop(struct ulogd_source_pluginstance *upi)
{
	struct nflog_priv *priv = (struct nflog_priv *)upi->private;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	ulogd_unregister_fd(&priv->ufd);
	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG,
				     AF_UNSPEC, group_ce(upi));
	nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_UNBIND);
	mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len);
	if (group_ce(upi) == 0)
		unbind_all(priv->nl);
	mnl_socket_unmap(priv->nlr);
	mnl_socket_close(priv->nl);

	return 0;
}

struct ulogd_source_plugin nflog_plugin = {
	.name = "NFLOG2",
	.output = {
		.type = ULOGD_DTYPE_RAW,
		.keys = output_keys,
		.num_keys = ARRAY_SIZE(output_keys),
	},
	.priv_size 	= sizeof(struct nflog_priv),
	.configure 	= &configure,
	.start 		= &start,
	.stop 		= &stop,
	.config_kset 	= &nflog_kset,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_source_plugin(&nflog_plugin);
}
