/* ulogd_input_CTNL.c, Version $Revision$
 *
 * ulogd input plugin for ctnetlink
 *
 * (C) 2005 by Harald Welte <laforge@netfilter.org>
 * (C) 2008-2010 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * 10 Jan 2005, Christian Hentschel <chentschel@people.netfilter.org>
 *      Added timestamp accounting support of the conntrack entries,
 *      reworked by Harald Welte.
 *
 * 11 May 2008, Pablo Neira Ayuso <pablo@netfilter.org>
 * 	Use a generic hashtable to store the existing flows
 * 	Add netlink overrun handling
 *
 * TODO:
 * 	- add nanosecond-accurate packet receive timestamp of event-changing
 * 	  packets to {ip,nf}_conntrack_netlink, so we can have accurate IPFIX
 *	  flowStart / flowEnd NanoSeconds.
 *	- SIGHUP for reconfiguration without loosing hash table contents, but
 *	  re-read of config and reallocation / rehashing of table, if required
 *	- Split hashtable code into separate [filter] plugin, so we can run 
 * 	  small non-hashtable ulogd installations on the firewall boxes, send
 * 	  the messages via IPFX to one aggregator who then runs ulogd with a 
 * 	  network wide connection hash table.
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <ulogd/ipfix_protocol.h>
#include <ulogd/ring.h>
#include <ulogd/timer.h>
#include <ulogd/ulogd.h>

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC    1000000000L
#endif

/* flowEndReason
 *   (none)		0x01: idle timeout
 *   NFCT_T_UPDATE	0x02: active timeout
 *   NFCT_T_DESTROY	0x03: end of Flow detected
 *   (none)		0x04: forced end
 *   (none)		0x05: lack of resources
 */
static uint8_t flowReasons[] = {
	[NFCT_T_UPDATE]		= 0x02,
	[NFCT_T_DESTROY]	= 0x03,
};

struct nfct_priv {
	struct mnl_socket	*eventnl;
	struct mnl_socket	*dumpnl;
	uint32_t		eventpid;
	uint32_t		dumppid;
	struct mnl_ring		*nlr;
	struct ulogd_fd		eventfd;
	struct ulogd_fd		dumpfd;	
	struct ulogd_timer	timer;
	struct nlmsghdr		*dump_request;
};

enum nfct_conf {
	NFCT_CONF_BLOCK_SIZE = 0,	/* 8192 */
	NFCT_CONF_BLOCK_NR,		/* 128 */
	NFCT_CONF_FRAME_SIZE,		/* 8192 */
	NFCT_CONF_ACTIVE_TIMEOUT,
	NFCT_CONF_RELIABLE,
	NFCT_CONF_MARK_FILTER,
	NFCT_CONF_MAX,
};

static struct config_keyset nfct_kset = {
	.num_ces = NFCT_CONF_MAX,
	.ces = {
		[NFCT_CONF_BLOCK_SIZE] = {
			.key	 = "block_size",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 8192,
		},
		[NFCT_CONF_BLOCK_NR] = {
			.key	 = "block_nr",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 128,
		},
		[NFCT_CONF_FRAME_SIZE] = {
			.key	 = "frame_size",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 8192,
		},
		[NFCT_CONF_ACTIVE_TIMEOUT] = {
			.key	 = "active_timeout",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 300,
		},
		[NFCT_CONF_RELIABLE] = {
			.key	 = "reliable",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFCT_CONF_MARK_FILTER] = {
			.key	 = "mark_filter",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
	},
};

#define block_size_ce(x)	((x)->ces[NFCT_CONF_BLOCK_SIZE])
#define block_nr_ce(x)		((x)->ces[NFCT_CONF_BLOCK_NR])
#define frame_size_ce(x)	((x)->ces[NFCT_CONF_FRAME_SIZE])
#define active_timeout_ce(x)	((x)->ces[NFCT_CONF_ACTIVE_TIMEOUT])
#define reliable_ce(x)		((x)->ces[NFCT_CONF_RELIABLE])
#define mark_filter_ce(x)	((x)->ces[NFCT_CONF_MARK_FILTER])

enum nfct_keys {
	NFCT_ORIG_IP_SADDR = 0,
	NFCT_ORIG_IP_DADDR,
	NFCT_ORIG_IP_PROTOCOL,
	NFCT_ORIG_L4_SPORT,
	NFCT_ORIG_L4_DPORT,
	NFCT_ORIG_RAW_PKTLEN,
	NFCT_ORIG_RAW_PKTCOUNT,
	NFCT_REPLY_IP_SADDR,
	NFCT_REPLY_IP_DADDR,
	NFCT_REPLY_IP_PROTOCOL,
	NFCT_REPLY_L4_SPORT,
	NFCT_REPLY_L4_DPORT,
	NFCT_REPLY_RAW_PKTLEN,
	NFCT_REPLY_RAW_PKTCOUNT,
	NFCT_ICMP_CODE,
	NFCT_ICMP_TYPE,
	NFCT_CT_MARK,
	NFCT_CT_ID,
	NFCT_CT_EVENT,
	NFCT_FLOW_START_SEC,
	NFCT_FLOW_START_USEC,
	NFCT_FLOW_END_SEC,
	NFCT_FLOW_END_USEC,
	NFCT_OOB_FAMILY,
	NFCT_CT,
	NFCT_ORIG_IP6_SADDR,
	NFCT_ORIG_IP6_DADDR,
	NFCT_REPLY_IP6_SADDR,
	NFCT_REPLY_IP6_DADDR,
	NFCT_FLOW_END_REASON,
};

static struct ulogd_key nfct_okeys[] = {
	[NFCT_ORIG_IP_SADDR]	= {
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "orig.ip.saddr",
		.ipfix	= {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceIPv4Address,
		},
	},
	[NFCT_ORIG_IP_DADDR]	= {
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.ip.daddr",
		.ipfix	= {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_destinationIPv4Address,
		},
	},
	[NFCT_ORIG_IP_PROTOCOL]	= {
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.ip.protocol",
		.ipfix	= {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_protocolIdentifier,
		},
	},
	[NFCT_ORIG_L4_SPORT]	= {
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "orig.l4.sport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_sourceTransportPort,
		},
	},
	[NFCT_ORIG_L4_DPORT]	= {
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "orig.l4.dport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_destinationTransportPort,
		},
	},
	[NFCT_ORIG_RAW_PKTLEN]	= {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.raw.pktlen.delta",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_octetDeltaCount,
		},
	},
	[NFCT_ORIG_RAW_PKTCOUNT]	= {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.raw.pktcount.delta",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_packetDeltaCount,
		},
	},
	[NFCT_REPLY_IP_SADDR]	= {
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "reply.ip.saddr",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_postNATSourceIPv4Address,
		},
	},
	[NFCT_REPLY_IP_DADDR]	= {
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.ip.daddr",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_postNATDestinationIPv4Address,
		},
	},
	[NFCT_REPLY_IP_PROTOCOL]	= {
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.ip.protocol",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_protocolIdentifier,
		},
	},
	[NFCT_REPLY_L4_SPORT]	= {
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "reply.l4.sport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_postNAPTSourceTransportPort,
		},
	},
	[NFCT_REPLY_L4_DPORT]	= {
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "reply.l4.dport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_postNAPTDestinationTransportPort,
		},
	},
	[NFCT_REPLY_RAW_PKTLEN]	= {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.raw.pktlen.delta",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_REVERSE,
			.field_id 	= IPFIX_octetDeltaCount,
		},
	},
	[NFCT_REPLY_RAW_PKTCOUNT]	= {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.raw.pktcount.delta",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_REVERSE,
			.field_id 	= IPFIX_packetDeltaCount,
		},
	},
	[NFCT_ICMP_CODE]	= {
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "icmp.code",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_icmpCodeIPv4,
		},
	},
	[NFCT_ICMP_TYPE]	= {
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "icmp.type",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_icmpTypeIPv4,
		},
	},
	[NFCT_CT_MARK]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ct.mark",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_NETFILTER,
			.field_id	= IPFIX_NF_mark,
		},
	},
	[NFCT_CT_ID]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ct.id",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_NETFILTER,
			.field_id	= IPFIX_NF_conntrack_id,
		},
	},
	[NFCT_CT_EVENT]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ct.event",
	},
	[NFCT_FLOW_START_SEC]	= {
		.type 	= ULOGD_RET_UINT32,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "flow.start.sec",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowStartSeconds,
		},
	},
	[NFCT_FLOW_START_USEC]	= {
		.type 	= ULOGD_RET_UINT32,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "flow.start.usec",
	},
	[NFCT_FLOW_END_SEC]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.end.sec",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowEndSeconds,
		},
	},
	[NFCT_FLOW_END_USEC]	= {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.end.usec",
	},
	[NFCT_OOB_FAMILY]	= {
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "oob.family",
	},
	[NFCT_CT]	= {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_RETF_NONE | ULOGD_RETF_DESTRUCT,
		.name	= "ct",
		.destruct = (void (*)(void *))nfct_destroy,
	},
	[NFCT_ORIG_IP6_SADDR]	= {
		.type 	= ULOGD_RET_IP6ADDR,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "orig.ip6.saddr",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_sourceIPv6Address,
		},
	},
	[NFCT_ORIG_IP6_DADDR]	= {
		.type	= ULOGD_RET_IP6ADDR,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.ip6.daddr",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_destinationIPv6Address,
		},
	},
	[NFCT_REPLY_IP6_SADDR]	= {
		.type 	= ULOGD_RET_IP6ADDR,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "reply.ip6.saddr",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_postNATSourceIPv6Address,
		},
	},
	[NFCT_REPLY_IP6_DADDR]	= {
		.type	= ULOGD_RET_IP6ADDR,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.ip6.daddr",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_postNATDestinationIPv6Address,
		},
	},
	[NFCT_FLOW_END_REASON]	= {
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.end.reason",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowEndReason,
		},
	},
};

static int propagate_ct(struct ulogd_source_pluginstance *spi,
			int type, struct nf_conntrack *ct,
			struct timeval *recent)
{
	struct ulogd_keyset *output = ulogd_get_output_keyset(spi);
	struct ulogd_key *ret = output->keys;
	uint64_t ts;
	
	okey_set_u32(&ret[NFCT_CT_EVENT], type);
	okey_set_u8(&ret[NFCT_OOB_FAMILY], nfct_get_attr_u8(ct, ATTR_L3PROTO));

	switch (nfct_get_attr_u8(ct, ATTR_L3PROTO)) {
	case AF_INET:
		okey_set_u32(&ret[NFCT_ORIG_IP_SADDR],
			     nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC));
		okey_set_u32(&ret[NFCT_ORIG_IP_DADDR],
			     nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST));
		okey_set_u32(&ret[NFCT_REPLY_IP_SADDR],
			     nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC));
		okey_set_u32(&ret[NFCT_REPLY_IP_DADDR],
			     nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST));
		break;
	case AF_INET6:
		okey_set_u128(&ret[NFCT_ORIG_IP6_SADDR],
			      nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC));
		okey_set_u128(&ret[NFCT_ORIG_IP6_DADDR],
			      nfct_get_attr(ct, ATTR_ORIG_IPV6_DST));
		okey_set_u128(&ret[NFCT_REPLY_IP6_SADDR],
			      nfct_get_attr(ct, ATTR_REPL_IPV6_SRC));
		okey_set_u128(&ret[NFCT_REPLY_IP6_DADDR],
			      nfct_get_attr(ct, ATTR_REPL_IPV6_DST));
		break;
	default:
		ulogd_log(ULOGD_NOTICE, "Unknown protocol family (%d)\n",
			  nfct_get_attr_u8(ct, ATTR_L3PROTO));
	}
	okey_set_u8(&ret[NFCT_ORIG_IP_PROTOCOL],
		    nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO));
	okey_set_u8(&ret[NFCT_REPLY_IP_PROTOCOL],
		    nfct_get_attr_u8(ct, ATTR_REPL_L4PROTO));

	switch (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO)) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
		okey_set_u16(&ret[NFCT_ORIG_L4_SPORT],
			     htons(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)));
		okey_set_u16(&ret[NFCT_ORIG_L4_DPORT],
			     htons(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)));
		break;
	case IPPROTO_ICMP:
		okey_set_u8(&ret[NFCT_ICMP_CODE],
			    nfct_get_attr_u8(ct, ATTR_ICMP_CODE));
		okey_set_u8(&ret[NFCT_ICMP_TYPE],
			    nfct_get_attr_u8(ct, ATTR_ICMP_TYPE));
		break;
	}

	switch (nfct_get_attr_u8(ct, ATTR_REPL_L4PROTO)) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
		okey_set_u16(&ret[NFCT_REPLY_L4_SPORT],
			     htons(nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC)));
		okey_set_u16(&ret[NFCT_REPLY_L4_DPORT],
			     htons(nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST)));
	}

	okey_set_u64(&ret[NFCT_ORIG_RAW_PKTLEN],
		     nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES));
	okey_set_u64(&ret[NFCT_ORIG_RAW_PKTCOUNT],
		     nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS));
	okey_set_u64(&ret[NFCT_REPLY_RAW_PKTLEN],
		     nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES));
	okey_set_u64(&ret[NFCT_REPLY_RAW_PKTCOUNT],
		     nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_PACKETS));

	okey_set_u32(&ret[NFCT_CT_MARK], nfct_get_attr_u32(ct, ATTR_MARK));
	okey_set_u32(&ret[NFCT_CT_ID], nfct_get_attr_u32(ct, ATTR_ID));

	ts = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_START);
	okey_set_u32(&ret[NFCT_FLOW_START_SEC], ts / NSEC_PER_SEC);
	okey_set_u32(&ret[NFCT_FLOW_START_USEC], ts % NSEC_PER_SEC / 1000);

	ts = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_STOP);
	if (ts) {
		okey_set_u32(&ret[NFCT_FLOW_END_SEC], ts / NSEC_PER_SEC);
		okey_set_u32(&ret[NFCT_FLOW_END_USEC],
			     ts % NSEC_PER_SEC / 1000);
	} else {
		okey_set_u32(&ret[NFCT_FLOW_END_SEC], recent->tv_sec);
		okey_set_u32(&ret[NFCT_FLOW_END_USEC], recent->tv_usec);
	}

	okey_set_ptr(&ret[NFCT_CT], ct);
	if (flowReasons[type])
		okey_set_u8(&ret[NFCT_FLOW_END_REASON], flowReasons[type]);

	if (ulogd_propagate_results(output) == 0)
		return MNL_CB_OK;
	return MNL_CB_ERROR;
}

static uint32_t nfct_type(const struct nlmsghdr *nlh)
{
	switch(nlh->nlmsg_type & 0xFF) {
	case IPCTNL_MSG_CT_NEW:
		if (nlh->nlmsg_flags & (NLM_F_CREATE|NLM_F_EXCL))
			return NFCT_T_NEW;
		else
			return NFCT_T_UPDATE;
		break;
	case IPCTNL_MSG_CT_DELETE:
		return NFCT_T_DESTROY;
		break;
	}
	return NFCT_T_UNKNOWN;
}
	
struct _cbarg {
	struct ulogd_source_pluginstance *spi;
	struct timeval *recent;
};

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct _cbarg *cbarg = data;
	struct ulogd_source_pluginstance *spi = cbarg->spi;
	struct timeval *recent = cbarg->recent;
	struct nf_conntrack *ct = nfct_new();

	if (ct == NULL)
		return MNL_CB_ERROR;

	if (nfct_nlmsg_parse(nlh, ct) == -1) {
		ulogd_log(ULOGD_ERROR, "nfct_nlmsg_parse: %s\n",
			  _sys_errlist[errno]);
		nfct_destroy(ct);
		return MNL_CB_ERROR;
	}
	if (nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES) == 0
	    && nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES) == 0) {
		nfct_destroy(ct);
		return MNL_CB_OK;
	}
	
	return propagate_ct(spi, nfct_type(nlh), ct, recent);
}

static int nfct_event_cb(int fd, unsigned int what, void *param)
{
	struct ulogd_source_pluginstance *spi = param;
	struct nfct_priv *priv = (struct nfct_priv *)spi->private;
	struct timeval tv;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	ssize_t nrecv;
	int ret;
	struct _cbarg cbarg = {.spi = spi, .recent = &tv};
	
	if (!(what & ULOGD_FD_READ))
		return 0;

	gettimeofday(&tv, NULL);
	/* recv(mnl_socket_get_fd(priv->eventnl), buf, len, MSG_DONTWAIT); */
	nrecv = mnl_socket_recvfrom(priv->eventnl, buf, sizeof(buf));
	if (nrecv == -1) {
		ulogd_log(ULOGD_ERROR, "recv: %s\n", _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}

	ret = mnl_cb_run(buf, nrecv, 0, priv->eventpid, data_cb, &cbarg);
	if (ret == MNL_CB_ERROR) {
		ulogd_log(ULOGD_ERROR, "mnl_cb_run: %d %s\n",
			  errno, _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}

	return ULOGD_IRET_OK;
}

static int handle_valid_frame(struct ulogd_source_pluginstance *spi,
			      struct nl_mmap_hdr *frame,
			      struct timeval *tv)
{
	struct nfct_priv *priv = (struct nfct_priv *)spi->private;
	struct _cbarg cbarg = {.spi = spi, .recent = tv};
	int ret;

	ret = mnl_cb_run(MNL_FRAME_PAYLOAD(frame), frame->nm_len,
			 priv->dump_request->nlmsg_seq, priv->dumppid,
			 data_cb, &cbarg);
	if (ret == MNL_CB_ERROR) {
		ulogd_log(ULOGD_ERROR, "mnl_cb_run: %d %s\n",
			  errno, _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}

	return ULOGD_IRET_OK;
}

static int nfct_dump_cb(int fd, unsigned int what, void *param)
{
	struct ulogd_source_pluginstance *spi = param;
	struct nfct_priv *priv = (struct nfct_priv *)spi->private;
	struct nl_mmap_hdr *frame;
	struct timeval tv;
	int ret;
	
	if (!(what & ULOGD_FD_READ))
		return 0;

	gettimeofday(&tv, NULL);
	while (1) {
		frame = mnl_ring_get_frame(priv->nlr);
		switch (frame->nm_status) {
		case NL_MMAP_STATUS_VALID:
			frame->nm_status = NL_MMAP_STATUS_SKIP;
			ret = handle_valid_frame(spi, frame, &tv);
			frame->nm_status = NL_MMAP_STATUS_UNUSED;
			mnl_ring_advance(priv->nlr);
			if (ret != ULOGD_IRET_OK)
				return ret;
			break;
		case NL_MMAP_STATUS_RESERVED:
			return ULOGD_IRET_OK;
		case NL_MMAP_STATUS_COPY:
			/* XXX: only consuming message, may cause segfault */
			frame->nm_status = NL_MMAP_STATUS_SKIP;
			recv(fd, alloca(frame->nm_len), frame->nm_len,
			     MSG_DONTWAIT);
			ulogd_log(ULOGD_ERROR, "exceeded the frame size: %d\n",
				  frame->nm_len);
			frame->nm_status = NL_MMAP_STATUS_UNUSED;
			mnl_ring_advance(priv->nlr);
			return ULOGD_IRET_ERR;
		case NL_MMAP_STATUS_UNUSED:
			return ULOGD_IRET_OK;
		case NL_MMAP_STATUS_SKIP:
			ulogd_log(ULOGD_ERROR, "found SKIP status frame,"
				  " ENOBUFS maybe\n");
			return ULOGD_IRET_ERR;
		}
	}

	return ULOGD_IRET_ERR;
}

static void nfct_itimer_cb(struct ulogd_timer *t, void *data)
{
	struct ulogd_source_pluginstance *spi = data;
	struct nfct_priv *priv = (struct nfct_priv *)spi->private;
	ssize_t ret;

	priv->dump_request->nlmsg_seq = time(NULL);
	ret = mnl_socket_sendto(priv->dumpnl, priv->dump_request,
				priv->dump_request->nlmsg_len);
	if (ret == -1) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_sendto: %s\n",
			  _sys_errlist[errno]);
	}
}

static int configure_nfct(struct ulogd_source_pluginstance *spi)
{
	return config_parse_file(spi->id, spi->config_kset);
}

static struct nlmsghdr *alloc_init_dump_request(uint32_t mark, uint32_t mask)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *ret, *nlh = mnl_nlmsg_put_header(buf);
	struct nfgenmsg *nfh;
	
	nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8)
			| IPCTNL_MSG_CT_GET_CTRZERO;
	nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP;
	
	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_UNSPEC;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	if (mark != 0 && mask != 0) {
		mnl_attr_put_u32(nlh, CTA_MARK, mark);
		mnl_attr_put_u32(nlh, CTA_MARK_MASK, mask);
	}

	ret = calloc(1, nlh->nlmsg_len);
	if (ret == NULL)
		return NULL;
	memcpy(ret, nlh, nlh->nlmsg_len);

	return ret;
}

static int build_nfct_filter_mark(struct ulogd_source_pluginstance *spi,
				  struct nfct_filter *filter)
{
	struct nfct_priv *priv = (struct nfct_priv *)spi->private;
	char *p, *endptr;
	uintmax_t v;
	char *filter_string = mark_filter_ce(spi->config_kset).u.string;
	struct nfct_filter_dump_mark attr;
	
	if (strlen(filter_string) == 0) {
		priv->dump_request = alloc_init_dump_request(0, 0);
		return 0;
	}

	errno = 0;
	for (p = filter_string; isspace(*p); ++p)
		;
	v = strtoumax(p, &endptr, 0);
	if (endptr == p)
		goto invalid_error;
	if ((errno == ERANGE && v == UINTMAX_MAX) || errno != 0)
		goto invalid_error;
	attr.val = (uint32_t)v;

	if (*endptr != '\0') {
		for (p = endptr; isspace(*p); ++p)
			;
		if (*p++ != '/')
			goto invalid_error;
		for (; isspace(*p); ++p)
			;
		v = strtoumax(p, &endptr, 0);
		if (endptr == p)
			goto invalid_error;
		if ((errno == ERANGE && v == UINTMAX_MAX) || errno != 0)
			goto invalid_error;
		attr.mask = (uint32_t)v;
		if (*endptr != '\0')
			goto invalid_error;
	} else {
		attr.mask = UINT32_MAX;
	}

	priv->dump_request = alloc_init_dump_request(attr.val, attr.mask);
	if (priv->dump_request == NULL) {
		ulogd_log(ULOGD_ERROR, "alloc_init_dump_request\n");
		return -1;
	}

	nfct_filter_add_attr(filter, NFCT_FILTER_MARK, &attr);
	ulogd_log(ULOGD_NOTICE, "adding mark to event filter: \"%u/%u\"\n",
		  attr.val, attr.mask);

	return 0;

invalid_error:
	ulogd_log(ULOGD_ERROR, "invalid val/mask %s\n", filter_string);
	return -1;
}

static int build_nfct_filter(struct ulogd_source_pluginstance *spi)
{
	struct nfct_priv *priv = (struct nfct_priv *)spi->private;
	struct nfct_filter *filter = NULL;

	filter = nfct_filter_create();
	if (!filter) {
		ulogd_log(ULOGD_FATAL, "error creating NFCT filter\n");
		goto err_init;
	}

	if (build_nfct_filter_mark(spi, filter) != 0) {
		ulogd_log(ULOGD_FATAL, "Unable to create mark filter\n");
		goto err_filter;
	}

	if (nfct_filter_attach(mnl_socket_get_fd(priv->eventnl), filter) == -1) {
		ulogd_log(ULOGD_FATAL, "nfct_filter_attach");
		goto err_filter;
	}

	/* release the filter object, this does not detach the filter */
	nfct_filter_destroy(filter);

	return 0;

err_filter:
	nfct_filter_destroy(filter);
err_init:
	return -1;
}

static int set_reliable(struct mnl_socket *nl)
{
	int on = 1;

	if (mnl_socket_setsockopt(nl, NETLINK_BROADCAST_SEND_ERROR,
				  &on, sizeof(int)) == -1)
		return -1;
	if (mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS,
				  &on, sizeof(int)) == -1)
		return -1;
	return 0;
}

static int init_eventnl(struct ulogd_source_pluginstance *spi)
{
	struct nfct_priv *priv = (struct nfct_priv *)spi->private;

	priv->eventnl = mnl_socket_open(NETLINK_NETFILTER);
	if (priv->eventnl == NULL) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_open: %s\n",
			  _sys_errlist[errno]);
		return ULOGD_IRET_ERR;
	}

	if (mnl_socket_bind(priv->eventnl,
			    NF_NETLINK_CONNTRACK_DESTROY,
			    MNL_SOCKET_AUTOPID) < 0) {
		ulogd_log(ULOGD_ERROR, "mnl_sockt_bind: %s\n",
			  _sys_errlist[errno]);
		goto error_close;
	}
	priv->eventpid = mnl_socket_get_portid(priv->eventnl);

	if (reliable_ce(spi->config_kset).u.value != 0) {
		if (set_reliable(priv->eventnl)) {
			ulogd_log(ULOGD_ERROR, "set_reliable: %s\n",
				  _sys_errlist[errno]);
			goto error_close;
		}
	}

	priv->eventfd.fd = mnl_socket_get_fd(priv->eventnl);
	priv->eventfd.cb = &nfct_event_cb;
	priv->eventfd.data = spi;
	priv->eventfd.when = ULOGD_FD_READ;

	return ULOGD_IRET_OK;

error_close:
	mnl_socket_close(priv->eventnl);
	return ULOGD_IRET_ERR;
}

static int init_dumpnl(struct ulogd_source_pluginstance *spi)
{
	struct nfct_priv *priv = (struct nfct_priv *)spi->private;
	struct nl_mmap_req req = {
		.nm_block_size	= block_size_ce(spi->config_kset).u.value,
		.nm_block_nr	= block_nr_ce(spi->config_kset).u.value,
		.nm_frame_size	= frame_size_ce(spi->config_kset).u.value,
		.nm_frame_nr	= block_size_ce(spi->config_kset).u.value
				/ frame_size_ce(spi->config_kset).u.value
				* block_nr_ce(spi->config_kset).u.value,
	};

	priv->dumpnl = mnl_socket_open(NETLINK_NETFILTER);
	if (priv->dumpnl == NULL) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_open: %s\n",
			  _sys_errlist[errno]);
		goto error_close;
	}

	priv->nlr = mnl_socket_rx_mmap(priv->dumpnl, &req, MAP_SHARED);
	if (priv->nlr == NULL) {
		ulogd_log(ULOGD_FATAL, "mnl_socket_mmap: %s\n",
			  _sys_errlist[errno]);
		goto error_close;
	}

	if (mnl_socket_bind(priv->dumpnl, 0, MNL_SOCKET_AUTOPID) < 0) {
		ulogd_log(ULOGD_ERROR, "mnl_sockt_bind: %s\n",
			  _sys_errlist[errno]);
		goto error_unmap;
	}
	priv->dumppid = mnl_socket_get_portid(priv->dumpnl);

	if (reliable_ce(spi->config_kset).u.value != 0) {
		if (set_reliable(priv->dumpnl)) {
			ulogd_log(ULOGD_ERROR, "set_reliable: %s\n",
				  _sys_errlist[errno]);
			goto error_unmap;
		}
	}

	priv->dumpfd.fd = mnl_socket_get_fd(priv->dumpnl);
	priv->dumpfd.cb = &nfct_dump_cb;
	priv->dumpfd.data = spi;
	priv->dumpfd.when = ULOGD_FD_READ;

	return ULOGD_IRET_OK;

error_unmap:
	mnl_socket_unmap(priv->nlr);
error_close:
	mnl_socket_close(priv->dumpnl);
	return ULOGD_IRET_ERR;
}

static int constructor_nfct(struct ulogd_source_pluginstance *spi)
{
	struct nfct_priv *priv = (struct nfct_priv *)spi->private;
	unsigned long interval = active_timeout_ce(spi->config_kset).u.value;

	if (init_eventnl(spi))
		return ULOGD_IRET_ERR;
	if (init_dumpnl(spi))
		goto error_close_event;

	if (build_nfct_filter(spi) != 0) {
		ulogd_log(ULOGD_FATAL, "error creating NFCT filter\n");
		goto error_unmap;
	}
	
	if (ulogd_register_fd(&priv->eventfd) != 0) {
		ulogd_log(ULOGD_ERROR, "ulogd_register_fd: %s\n",
			  _sys_errlist[errno]);
		goto error_unmap;
	}
	if (ulogd_register_fd(&priv->dumpfd) != 0) {
		ulogd_log(ULOGD_ERROR, "ulogd_register_fd: %s\n",
			  _sys_errlist[errno]);
		goto error_unregister_eventfd;
	}

	if (ulogd_init_timer(&priv->timer, spi, nfct_itimer_cb) != 0) {
		ulogd_log(ULOGD_ERROR, "ulogd_init_timer: %s\n",
			  _sys_errlist[errno]);
		goto error_unregister_dumpfd;
	}
	if (ulogd_add_itimer(&priv->timer, interval, interval) != 0) {
		ulogd_log(ULOGD_ERROR, "ulogd_add_itimer: %s\n",
			  _sys_errlist[errno]);
		goto error_fini_timer;
	}

	return ULOGD_IRET_OK;

error_fini_timer:
	ulogd_fini_timer(&priv->timer);
error_unregister_dumpfd:
	ulogd_unregister_fd(&priv->dumpfd);
error_unregister_eventfd:
	ulogd_unregister_fd(&priv->eventfd);
error_unmap:
	mnl_socket_unmap(priv->nlr);
	mnl_socket_close(priv->dumpnl);
error_close_event:
	mnl_socket_close(priv->eventnl);
	return ULOGD_IRET_ERR;
}

static int destructor_nfct(struct ulogd_source_pluginstance *spi)
{
	struct nfct_priv *priv = (struct nfct_priv *)spi->private;
	int ret = ULOGD_IRET_OK;

	free(priv->dump_request);

	if (ulogd_del_timer(&priv->timer) != 0) {
		ulogd_log(ULOGD_ERROR, "ulogd_del_timer: %s\n",
			  _sys_errlist[errno]);
		ret = ULOGD_IRET_ERR;
	}
	if (ulogd_fini_timer(&priv->timer) != 0) {
		ulogd_log(ULOGD_ERROR, "ulogd_fini_timer: %s\n",
			  _sys_errlist[errno]);
		ret = ULOGD_IRET_ERR;
	}
	if (ulogd_unregister_fd(&priv->dumpfd) != 0) {
		ulogd_log(ULOGD_ERROR, "ulogd_unregister_fd: %s\n",
			  _sys_errlist[errno]);
		ret = ULOGD_IRET_ERR;
	}
	if (ulogd_unregister_fd(&priv->eventfd) != 0) {
		ulogd_log(ULOGD_ERROR, "ulogd_unregister_fd: %s\n",
			  _sys_errlist[errno]);
		ret = ULOGD_IRET_ERR;
	}
	if (mnl_socket_unmap(priv->nlr) == -1) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_unmap: %s\n",
			  _sys_errlist[errno]);
		ret = ULOGD_IRET_ERR;
	}
	free(priv->nlr);
	if (mnl_socket_close(priv->dumpnl) == -1) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_close: %s\n",
			  _sys_errlist[errno]);
		ret = ULOGD_IRET_ERR;
	}
	if (mnl_socket_close(priv->eventnl) == -1) {
		ulogd_log(ULOGD_ERROR, "mnl_socket_close: %s\n",
			  _sys_errlist[errno]);
		ret = ULOGD_IRET_ERR;
	}

	return ret;
}

static void signal_nfct(struct ulogd_source_pluginstance *spi, int signal)
{
	switch (signal) {
	default:
		ulogd_log(ULOGD_DEBUG, "receive signal: %d\n", signal);
		break;
	}
}

static struct ulogd_source_plugin nfct_plugin = {
	.name = "NFCT2",
	.output = {
		.keys = nfct_okeys,
		.num_keys = ARRAY_SIZE(nfct_okeys),
		.type = ULOGD_DTYPE_FLOW,
	},
	.config_kset 	= &nfct_kset,
	.configure	= &configure_nfct,
	.start		= &constructor_nfct,
	.stop		= &destructor_nfct,
	.signal		= &signal_nfct,
	.priv_size	= sizeof(struct nfct_priv),
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_source_plugin(&nfct_plugin);
}
