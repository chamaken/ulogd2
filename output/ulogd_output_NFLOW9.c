/* ulogd_output_NFLOW9.c
 *
 * ulogd output plugin for NetFlow version9
 *
 * This target produces a NetFlow v9 data and send it.
 *
 * (C) 2014 Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
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
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/uio.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <ulogd/linuxlist.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/ipfix_protocol.h>
#include <ulogd/ipfix_util.h>

/* #define DEBUG_TMMAP */
#ifdef DEBUG_TMMAP
#include <sys/mman.h>
int mmfd;
void *mmaddr;
#endif

/*
 * This implementation sends NetFlow v9 entry only if ORIG or REPLY counter is
 * greater than 0. Single NFCT entry contains duplex data, orig and reply but
 * NetFlow v9 can represents simplex entry only, so that sigle NFCT entry may
 * create two NetFlow v9 data entries. for example:
 *
 * 192.168.1.1 -> 172.16.1.1 will nat 1.1.1.1 -> 2.2.2.2
 *
 * NFCT:
 *	orig.ip.saddr		192.168.1.1
 *	orig.ip.daddr		172.16.1.1
 *	reply.ip.saddr		2.2.2.2
 *	reply.ip.daddr		1.1.1.1
 *	orig.raw.pktcount	111
 *	reply.raw.pktcount	222
 *
 * NFLOW9:
 *	SRC_ADDR		192.168.1.1	172.16.1.1
 *	DST_ADDR		172.16.1.1	192.168.1.1
 *	XLATE_SRC_ADDR		1.1.1.1		2.2.2.2
 *	XLATE_DST_ADDR		2.2.2.2		1.1.1.1
 *	IN_PKTS			111		222
 *
 * then:
 *	orig.raw.pktcount.delta > 0:	swap reply.*
 *	reply.raw.pktcount.delta > 0:	swap orig.* and ifindex.
 *					invert flowDirection
 *
 * This means a NetFlow v9 entry has only one conter and same can be said to
 * ip.protocol. corksets_max should be greater than 3 since added to
 * bidirectional handling, a template may be added.
 *
 * There are two assumption about NFCT:
 * - To use same template, assume the number of keys starting with "orig." and
 *   "reply." is the same.
 * - not propagate both Count and DeltaCount, only either of them.
 */

/* index for ikey which needs special handling */
enum {
	CII_ORIG_RAW_PKTLEN_DELTA,
	CII_ORIG_RAW_PKTCOUNT_DELTA,
	CII_REPLY_RAW_PKTLEN_DELTA,
	CII_REPLY_RAW_PKTCOUNT_DELTA,
	CII_REPLY_IP_PROTOCOL,	/* use only orig ip.protocol */
	CII_FAMILY,		/* illigal dirty hack */
	CII_MAX,
};

char *count_keys[] = {
	[CII_ORIG_RAW_PKTLEN_DELTA]	= "orig.raw.pktlen.delta",
	[CII_ORIG_RAW_PKTCOUNT_DELTA]	= "orig.raw.pktcount.delta",
	[CII_REPLY_RAW_PKTLEN_DELTA]	= "reply.raw.pktlen.delta",
	[CII_REPLY_RAW_PKTCOUNT_DELTA]	= "reply.raw.pktcount.delta",
	[CII_REPLY_IP_PROTOCOL]		= "reply.ip.protocol",
	[CII_FAMILY]			= "oob.family",
};

/* index for data field offset to swap by direction */
enum {
	FOI_ORIG_IP_SADDR = 0,
	FOI_ORIG_IP_DADDR,
	FOI_ORIG_IP6_SADDR,
	FOI_ORIG_IP6_DADDR,
	FOI_ORIG_L4_SPORT,
	FOI_ORIG_L4_DPORT,
	FOI_REPLY_IP_SADDR,
	FOI_REPLY_IP_DADDR,
	FOI_REPLY_IP6_SADDR,
	FOI_REPLY_IP6_DADDR,
	FOI_REPLY_L4_SPORT,
	FOI_REPLY_L4_DPORT,
	FOI_IF_INPUT,
	FOI_IF_OUTPUT,
	FOI_FLOW_DIR,
	FOI_IN_BYTES,
	FOI_IN_PKTS,
	FOI_MAX,
};

char *dir_keys[] = {
	[FOI_ORIG_IP_SADDR]		= "orig.ip.saddr",
	[FOI_ORIG_IP_DADDR]		= "orig.ip.daddr",
	[FOI_ORIG_IP6_SADDR]		= "orig.ip6.saddr",
	[FOI_ORIG_IP6_DADDR]		= "orig.ip6.daddr",
	[FOI_ORIG_L4_SPORT]		= "orig.l4.sport",
	[FOI_ORIG_L4_DPORT]		= "orig.l4.dport",
	[FOI_REPLY_IP_SADDR]		= "reply.ip.saddr",
	[FOI_REPLY_IP_DADDR]		= "reply.ip.daddr",
	[FOI_REPLY_IP6_SADDR]		= "reply.ip6.saddr",
	[FOI_REPLY_IP6_DADDR]		= "reply.ip6.daddr",
	[FOI_REPLY_L4_SPORT]		= "reply.l4.sport",
	[FOI_REPLY_L4_DPORT]		= "reply.l4.dport",
	[FOI_IF_INPUT]			= "oob.ifindex_in",
	[FOI_IF_OUTPUT]			= "oob.ifindex_out",
	[FOI_FLOW_DIR]			= "flow.direction",
	[FOI_IN_BYTES]			= "orig.raw.pktlen.delta",
	[FOI_IN_PKTS]			= "orig.raw.pktcount.delta",
};

enum {
	NFLOW9_DIR_NONE		= 0,
	NFLOW9_DIR_ORIG		= 1,
	NFLOW9_DIR_REPLY	= 2,
	NFLOW9_DIR_BOTH		= NFLOW9_DIR_ORIG | NFLOW9_DIR_REPLY,
};

enum {
	NFLOW9_CONF_DEST = 0,
	NFLOW9_CONF_DOMAIN_ID,
	NFLOW9_CONF_NTH_TEMPLATE,
	NFLOW9_CONF_CORKSETS_MAX,
	NFLOW9_CONF_MAX = NFLOW9_CONF_CORKSETS_MAX,
};

static struct config_keyset netflow9_kset = {
	.num_ces = NFLOW9_CONF_MAX + 1,
	.ces = {
		[NFLOW9_CONF_DEST] = {
			.key	 = "dest",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	 = { .string = "udp://localhost:9996" },
		},
		[NFLOW9_CONF_DOMAIN_ID] = {
			.key	 = "domain_id",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[NFLOW9_CONF_NTH_TEMPLATE] = {
			.key	 = "nth_template",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 16,
		},
		[NFLOW9_CONF_CORKSETS_MAX] = {
			.key	 = "corksets_max",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 3,
		},
	},
};

#define dest_ce(x)		((x)->ces[NFLOW9_CONF_DEST])
#define domain_ce(x)		((x)->ces[NFLOW9_CONF_DOMAIN_ID])
#define nth_template_ce(x)	((x)->ces[NFLOW9_CONF_NTH_TEMPLATE])
#define corksets_max_ce(x)	((x)->ces[NFLOW9_CONF_CORKSETS_MAX])

/* Section 5.1 */
struct netflow9_msg_hdr {
	uint16_t	version;
	uint16_t	count;
	uint32_t	sys_uptime;
	uint32_t	unix_secs;
	uint32_t	sequence_number;
	uint32_t	source_id;
};

/* Section 5.2, 5.3 */
struct netflow9_set_hdr {
	uint16_t	set_id;
	uint16_t	length;
};

/* Section 5.2 */
struct netflow9_templ_hdr {
	uint16_t	template_id;
	uint16_t	field_count;
};

/* Section 5.2 */
struct netflow9_templ_rec {
	uint16_t	type;
	uint16_t	length;
};

/* 8.  Field Type Definitions			octet (or default)*/
enum {
	NETFLOW9_IN_BYTES		= 1,	/* (4)	octetDeltaCount			*/
	NETFLOW9_IN_PKTS		= 2,	/* (4)	packetDeltaCount		*/
	NETFLOW9_FLOWS			= 3,	/* (4) */
	NETFLOW9_PROTOCOL		= 4,	/* 1	protocolIdentifier		*/
	NETFLOW9_TOS			= 5,	/* 1	classOfServiceIPv4		*/
	NETFLOW9_TCP_FLAGS		= 6,	/* 1	tcpControlBits			*/
	NETFLOW9_L4_SRC_PORT		= 7,	/* 2	sourceTransportPort		*/
	NETFLOW9_IPV4_SRC_ADDR		= 8,	/* 4	sourceIPv4Address		*/
	NETFLOW9_SRC_MASK		= 9,	/* 1	sourceIPv4Mask			*/
	NETFLOW9_INPUT_SNMP		= 10,	/* (2)	ingressInterface		*/
	NETFLOW9_L4_DST_PORT		= 11,	/* 2	destinationTransportPort	*/
	NETFLOW9_IPV4_DST_ADDR		= 12,	/* 4	destinationIPv4Address		*/
	NETFLOW9_DST_MASK		= 13,	/* 1	destinationIPv4Mask		*/
	NETFLOW9_OUTPUT_SNMP		= 14,	/* (2)	egressInterface			*/
	NETFLOW9_IPV4_NEXT_HOP		= 15,	/* 4	ipNextHopIPv4Address		*/
	NETFLOW9_SRC_AS			= 16,	/* (2)	bgpSourceAsNumber		*/
	NETFLOW9_DST_AS			= 17,	/* (2)	bgpDestinationAsNumber		*/
	NETFLOW9_BGP_IPV4_NEXT_HOP	= 18,	/* 4	bgpNextHopIPv4Address		*/
	NETFLOW9_MUL_DST_PKTS		= 19,	/* (4)	postMCastPacketDeltaCount	*/
	NETFLOW9_MUL_DST_BYTES		= 20,	/* (4)	postMCastOctetDeltaCount	*/
	NETFLOW9_LAST_SWITCHED		= 21,	/* 4	flowEndSysUpTime		*/
	NETFLOW9_FIRST_SWITCHED		= 22,	/* 4	flowStartSysUpTime		*/
	NETFLOW9_OUT_BYTES		= 23,	/* (4)	postOctetDeltaCount		*/
	NETFLOW9_OUT_PKTS		= 24,	/* (4)	postPacketDeltaCount		*/
	/* reserved */
	/* reserved */
	NETFLOW9_IPV6_SRC_ADDR		= 27,	/* 16	sourceIPv6Address		*/
	NETFLOW9_IPV6_DST_ADDR		= 28,	/* 16	destinationIPv6Address		*/
	NETFLOW9_IPV6_SRC_MASK		= 29,	/* 1	sourceIPv6Mask			*/
	NETFLOW9_IPV6_DST_MASK		= 30,	/* 1	destinationIPv6Mask		*/
	NETFLOW9_FLOW_LABEL		= 31,	/* 3	flowLabelIPv6			*/
	NETFLOW9_ICMP_TYPE		= 32,	/* 2	icmpTypeCodeIPv4		*/
	NETFLOW9_MUL_IGMP_TYPE		= 33,	/* 1	igmpType			*/
	NETFLOW9_SAMPLING_INTERVAL	= 34,	/* 4					*/
	/* reserved */
	NETFLOW9_SAMPLING_ALGORITHM	= 35,	/* 1					*/
	NETFLOW9_FLOW_ACTIVE_TIMEOUT	= 36,	/* 2	flowActiveTimeOut		*/
	NETFLOW9_FLOW_INAVTIVE_TIMEOUT	= 37,	/* 2	flowInactiveTimeout		*/
	NETFLOW9_ENGINE_TYPE		= 38,	/* 1					*/
	NETFLOW9_ENGINE_ID		= 39,	/* 1					*/
	NETFLOW9_TOTAL_BYTES_EXP	= 40,	/* (4)	exportedOctetTotalCount		*/
	NETFLOW9_TOTAL_PKTS_EXP		= 41,	/* (4)	exportedMessageTotalCount	*/
	NETFLOW9_TOTAL_FLOWS_EXP	= 42,	/* (4)	exportedFlowTotalCount		*/
	/* reserved */
	/* reserved */
	/* reserved */
	NETFLOW9_MPLS_TOP_LABEL_TYPE	= 46,	/* 1	mplsTopLabelType		*/
	NETFLOW9_MPLS_TOP_LABEL_IP_ADDR	= 47,	/* 4	mplsTopLabelIPv4Address		*/
	NETFLOW9_FLOW_SAMPLER_ID	= 48,	/* 1					*/
	NETFLOW9_FLOW_SAMPLER_MODE	= 49,	/* 1					*/
	NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL = 50,	/* 4				*/
	/* reserved */
	/* reserved */
	/* reserved */
	/* reserved */
	NETFLOW9_DST_TOS		= 55,	/* 1	postClassOfServiceIPv4		*/
	NETFLOW9_SRC_MAC		= 56,	/* 6	sourceMacAddress		*/
	NETFLOW9_DST_MAC		= 57,	/* 6	postDestinationMacAddr		*/
	NETFLOW9_SRC_VLAN		= 58,	/* 2	vlanId				*/
	NETFLOW9_DST_VLAN		= 59,	/* 2	postVlanId			*/
	NETFLOW9_IP_PROTOCOL_VERSION	= 60,	/* 1	ipVersion			*/
	NETFLOW9_DIRECTION		= 61,	/* 1	flowDirection			*/
	NETFLOW9_IPV6_NEXT_HOP		= 62,	/* 16	ipNextHopIPv6Address		*/
	NETFLOW9_BGP_IPV6_NEXT_HOP	= 63,	/* 16	bgpNexthopIPv6Address		*/
	NETFLOW9_IPV6_OPTION_HEADERS	= 64,	/* 4	ipv6ExtensionHeaders		*/
	/* reserved */
	/* reserved */
	/* reserved */
	/* reserved */
	/* reserved */
	NETFLOW9_MPLS_LABEL_1		= 70,	/* 3	mplsTopLabelStackEntry		*/
	NETFLOW9_MPLS_LABEL_2		= 71,	/* 3	mplsLabelStackEntry2		*/
	NETFLOW9_MPLS_LABEL_3		= 72,	/* 3	mplsLabelStackEntry3		*/
	NETFLOW9_MPLS_LABEL_4		= 73,	/* 3	mplsLabelStackEntry4		*/
	NETFLOW9_MPLS_LABEL_5		= 74,	/* 3	mplsLabelStackEntry5		*/
	NETFLOW9_MPLS_LABEL_6		= 75,	/* 3	mplsLabelStackEntry6		*/
	NETFLOW9_MPLS_LABEL_7		= 76,	/* 3	mplsLabelStackEntry7		*/
	NETFLOW9_MPLS_LABEL_8		= 77,	/* 3	mplsLabelStackEntry8		*/
	NETFLOW9_MPLS_LABEL_9		= 78,	/* 3	mplsLabelStackEntry9		*/
	NETFLOW9_MPLS_LABEL_10		= 79,	/* 3	mplsLabelStackEntry10		*/

	/* pick up usefuls from:
	 * http://www.cisco.com/c/en/us/td/docs/security/asa/special/netflow/guide/asa_netflow.html */
	NETFLOW9_IPV4_XLATE_SRC_ADDR	= 225,	/* 4	NF_F_XLATE_SRC_ADDR_IPV4	*/
	NETFLOW9_IPV4_XLATE_DST_ADDR	= 226,	/* 4	NF_F_XLATE_DST_ADDR_IPV4	*/
	NETFLOW9_L4_XLATE_SRC_PORT	= 227,	/* 2	NF_F_XLATE_SRC_PORT		*/
	NETFLOW9_L4_XLATE_DST_PORT	= 228,	/* 2	NF_F_XLATE_DST_PORT		*/
	NETFLOW9_IPV6_XLATE_SRC_ADDR	= 281,	/* 16	NF_F_XLATE_SRC_ADDR_IPV6	*/
	NETFLOW9_IPV6_XLATE_DST_ADDR	= 282,	/* 16	NF_F_XLATE_DST_ADDR_IPV6	*/

	NETFLOW9_FIELD_MAX		= NETFLOW9_IPV6_XLATE_DST_ADDR,
};

static int ipfix_map[] = {
	[IPFIX_octetDeltaCount]			= NETFLOW9_IN_BYTES,
	[IPFIX_packetDeltaCount]		= NETFLOW9_IN_PKTS,
	/* [3]					= NETFLOW9_FLOWS,		*/
	[IPFIX_protocolIdentifier]		= NETFLOW9_PROTOCOL,
	[IPFIX_classOfServiceIPv4]		= NETFLOW9_TOS,
	[IPFIX_tcpControlBits]			= NETFLOW9_TCP_FLAGS,
	[IPFIX_sourceTransportPort]		= NETFLOW9_L4_SRC_PORT,
	[IPFIX_sourceIPv4Address]		= NETFLOW9_IPV4_SRC_ADDR,
	[IPFIX_sourceIPv4Mask]			= NETFLOW9_SRC_MASK,
	[IPFIX_ingressInterface]		= NETFLOW9_INPUT_SNMP,
	[IPFIX_destinationTransportPort]	= NETFLOW9_L4_DST_PORT,
	[IPFIX_destinationIPv4Address]		= NETFLOW9_IPV4_DST_ADDR,
	[IPFIX_destinationIPv4Mask]		= NETFLOW9_DST_MASK,
	[IPFIX_egressInterface]			= NETFLOW9_OUTPUT_SNMP,
	[IPFIX_ipNextHopIPv4Address]		= NETFLOW9_IPV4_NEXT_HOP,
	[IPFIX_bgpSourceAsNumber]		= NETFLOW9_SRC_AS,
	[IPFIX_bgpDestinationAsNumber]		= NETFLOW9_DST_AS,
	[IPFIX_bgpNextHopIPv4Address]		= NETFLOW9_BGP_IPV4_NEXT_HOP,
	[IPFIX_postMCastPacketDeltaCount]	= NETFLOW9_MUL_DST_PKTS,
	[IPFIX_postMCastOctetDeltaCount]	= NETFLOW9_MUL_DST_BYTES,
	[IPFIX_flowEndSysUpTime]		= NETFLOW9_LAST_SWITCHED,
	[IPFIX_flowStartSysUpTime]		= NETFLOW9_FIRST_SWITCHED,
	[IPFIX_postOctetDeltaCount]		= NETFLOW9_OUT_BYTES,
	[IPFIX_postPacketDeltaCount]		= NETFLOW9_OUT_PKTS,
	[IPFIX_minimumPacketLength]		= 0,
	[IPFIX_maximumPacketLength]		= 0,
	[IPFIX_sourceIPv6Address]		= NETFLOW9_IPV6_SRC_ADDR,
	[IPFIX_destinationIPv6Address]		= NETFLOW9_IPV6_DST_ADDR,
	[IPFIX_sourceIPv6Mask]			= NETFLOW9_IPV6_SRC_MASK,
	[IPFIX_destinationIPv6Mask]		= NETFLOW9_IPV6_DST_MASK,
	[IPFIX_flowLabelIPv6]			= NETFLOW9_FLOW_LABEL,
	[IPFIX_icmpTypeCodeIPv4]		= NETFLOW9_ICMP_TYPE,
	[IPFIX_igmpType]			= NETFLOW9_MUL_IGMP_TYPE,
	/* [34]					= [NETFLOW9_SAMPLING_INTERVAL],	*/
	/* [35]					= [NETFLOW9_SAMPLING_ALGORITHM],*/
	[IPFIX_flowActiveTimeOut]		= NETFLOW9_FLOW_ACTIVE_TIMEOUT,
	[IPFIX_flowInactiveTimeout]		= NETFLOW9_FLOW_INAVTIVE_TIMEOUT,
	/* [38]					= NETFLOW9_ENGINE_TYPE,		*/
	/* [39]					= NETFLOW9_ENGINE_ID,		*/
	[IPFIX_exportedOctetTotalCount]		= NETFLOW9_TOTAL_BYTES_EXP,
	[IPFIX_exportedMessageTotalCount]	= NETFLOW9_TOTAL_PKTS_EXP,
	[IPFIX_exportedFlowTotalCount]		= NETFLOW9_TOTAL_FLOWS_EXP,
	/* [43]					= ,				*/
	[IPFIX_sourceIPv4Prefix]		= 0,
	[IPFIX_destinationIPv4Prefix]		= 0,
	[IPFIX_mplsTopLabelType]		= NETFLOW9_MPLS_TOP_LABEL_TYPE,
	[IPFIX_mplsTopLabelIPv4Address]		= NETFLOW9_MPLS_TOP_LABEL_IP_ADDR,
	/* [48]					= NETFLOW9_FLOW_SAMPLER_ID,	*/
	/* [49]					= NETFLOW9_FLOW_SAMPLER_MODE,	*/
	/* [50]					= NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL, */
	/* [51]					= ,				*/
	[IPFIX_minimumTtl]			= 0,
	[IPFIX_maximumTtl]			= 0,
	[IPFIX_identificationIPv4]		= 0,
	[IPFIX_postClassOfServiceIPv4]		= NETFLOW9_DST_TOS,
	[IPFIX_sourceMacAddress]		= NETFLOW9_SRC_MAC,
	[IPFIX_postDestinationMacAddr]		= NETFLOW9_DST_MAC,
	[IPFIX_vlanId]				= NETFLOW9_SRC_VLAN,
	[IPFIX_postVlanId]			= NETFLOW9_DST_VLAN,
	[IPFIX_ipVersion]			= NETFLOW9_IP_PROTOCOL_VERSION,
	[IPFIX_flowDirection]			= NETFLOW9_DIRECTION,
	[IPFIX_ipNextHopIPv6Address]		= NETFLOW9_IPV6_NEXT_HOP,
	[IPFIX_bgpNexthopIPv6Address]		= NETFLOW9_BGP_IPV6_NEXT_HOP,
	[IPFIX_ipv6ExtensionHeaders]		= NETFLOW9_IPV6_OPTION_HEADERS,
	/* [65]					= ,				*/
	/* [66]					= ,				*/
	/* [67]					= ,				*/
	/* [68]					= ,				*/
	/* [69]					= ,				*/
	[IPFIX_mplsTopLabelStackEntry]		= NETFLOW9_MPLS_LABEL_1,
	[IPFIX_mplsLabelStackEntry2]		= NETFLOW9_MPLS_LABEL_2,
	[IPFIX_mplsLabelStackEntry3]		= NETFLOW9_MPLS_LABEL_3,
	[IPFIX_mplsLabelStackEntry4]		= NETFLOW9_MPLS_LABEL_4,
	[IPFIX_mplsLabelStackEntry5]		= NETFLOW9_MPLS_LABEL_5,
	[IPFIX_mplsLabelStackEntry6]		= NETFLOW9_MPLS_LABEL_6,
	[IPFIX_mplsLabelStackEntry7]		= NETFLOW9_MPLS_LABEL_7,
	[IPFIX_mplsLabelStackEntry8]		= NETFLOW9_MPLS_LABEL_8,
	[IPFIX_mplsLabelStackEntry9]		= NETFLOW9_MPLS_LABEL_9,
	[IPFIX_mplsLabelStackEntry10]		= NETFLOW9_MPLS_LABEL_10,
	/* [80 - 224]				= ,				*/
	[IPFIX_postNATSourceIPv4Address]	= NETFLOW9_IPV4_XLATE_SRC_ADDR,
	[IPFIX_postNATDestinationIPv4Address]	= NETFLOW9_IPV4_XLATE_DST_ADDR,
	[IPFIX_postNAPTSourceTransportPort]	= NETFLOW9_L4_XLATE_SRC_PORT,
	[IPFIX_postNAPTDestinationTransportPort]= NETFLOW9_L4_XLATE_DST_PORT,
	[IPFIX_postNATSourceIPv6Address]	= NETFLOW9_IPV6_XLATE_SRC_ADDR,
	[IPFIX_postNATDestinationIPv6Address]	= NETFLOW9_IPV6_XLATE_DST_ADDR,
};

struct ulogd_netflow9_template {
	struct llist_head list;
	struct nfct_bitmask *bitmask;
	int until_template;		/* decide if it's time to retransmit our template */
	int offset[FOI_MAX];		/* direction related field offset from data head */
	int tmplset_len, dataset_len;
	struct netflow9_set_hdr *template;
	struct netflow9_set_hdr *databuf;
	int datapos;
};

struct netflow9_instance {
	int fd;		/* socket that we use for sending NetFlow v9 data  */
	int uptime_fd;	/* /proc/uptime to set sysUpTime */
	uint16_t next_template_id;
	struct llist_head template_list;	/* ulogd_netflow9_template */
	struct nfct_bitmask *valid_bitmask;	/* bitmask of valid keys   */
	uint32_t seq;
	unsigned int ikey_count[CII_MAX];	/* ikey indexes to counter fields  */
	struct netflow9_msg_hdr nflow9_msghdr;
	struct iovec *iovecs;	/* index 0 is reserved for nflow9_msghdr   */
	unsigned int iovcnt;
	unsigned int corksets_max;	/* cork limit include template	   */
	unsigned int msglen;
};

#define UPTIME_FILE  "/proc/uptime"	/* for uptime_fd */
#define ULOGD_NETFLOW9_TEMPL_BASE 256	/* 5.2 Template FlowSet Format
					 * for next_template_id */
#ifdef DEBUG_TMMAP
static int nflow9_fprintf_header(FILE *fd, const struct netflow9_instance *ii);
#endif

static struct ulogd_netflow9_template *
alloc_ulogd_netflow9_template(struct ulogd_pluginstance *upi,
			      struct ulogd_keyset *input,
			      struct nfct_bitmask *bm)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&upi->private;
	struct ulogd_netflow9_template *tmpl;
	unsigned int i;
	int tmpl_len = 0, data_len = 0;

	for (i = 0; i < input->num_keys; i++) {
		if (!nfct_bitmask_test_bit(bm, i))
			continue;

		/* ignore reply for unidirection */
		if (i == ii->ikey_count[CII_REPLY_RAW_PKTLEN_DELTA]
		    || i == ii->ikey_count[CII_REPLY_RAW_PKTCOUNT_DELTA]
		    || i == ii->ikey_count[CII_REPLY_IP_PROTOCOL])
			continue;

		tmpl_len += sizeof(struct netflow9_templ_rec);
		data_len += ulogd_key_size(&input->keys[i]);
	}

	tmpl = calloc(1, sizeof(struct ulogd_netflow9_template));
	if (tmpl == NULL)
		return NULL;

	for (i = 0; i < FOI_MAX; i++)
		tmpl->offset[i] = -1;

	tmpl->bitmask = nfct_bitmask_clone(bm);
	if (!tmpl->bitmask)
		goto free_tmpl;

	tmpl->dataset_len = sizeof(struct netflow9_set_hdr) + data_len;
	tmpl->tmplset_len = sizeof(struct netflow9_set_hdr)
		+ sizeof(struct netflow9_templ_hdr) + tmpl_len;
	/* 5.3.	 Data FlowSet Format / Padding */
	tmpl->dataset_len = (tmpl->dataset_len + 3U) & ~3U;
	tmpl->tmplset_len = (tmpl->tmplset_len + 3U) & ~3U;

	tmpl->template = calloc(1, tmpl->tmplset_len);
	if (tmpl->template == NULL)
		goto free_bitmask;
	tmpl->databuf = calloc(ii->corksets_max, tmpl->dataset_len);
	if (tmpl->databuf == NULL)
		goto free_template;

	return tmpl;

free_template:
	free(tmpl->template);
free_bitmask:
	free(tmpl->bitmask);
free_tmpl:
	free(tmpl);

	return NULL;
}

/* Build the NetFlow v9 template from the input keys */
static struct ulogd_netflow9_template *
build_template_for_bitmask(struct ulogd_pluginstance *upi,
			   struct ulogd_keyset *input,
			   struct nfct_bitmask *bm)
{
	struct netflow9_instance *ii
		= (struct netflow9_instance *)&upi->private;
	struct ulogd_netflow9_template *tmpl;
	struct netflow9_templ_hdr *tmpl_hdr;
	struct netflow9_templ_rec *tmpl_rec;
	struct netflow9_set_hdr *set_hdr;
	uint16_t field_count = 0;
	unsigned int i, j, offset = 0;

	tmpl = alloc_ulogd_netflow9_template(upi, input, bm);
	if (tmpl == NULL)
		return NULL;

	/* build template records */
	tmpl_rec = (void *)tmpl->template
		+ sizeof(struct netflow9_set_hdr)
		+ sizeof(struct netflow9_templ_hdr);
	for (i = 0; i < input->num_keys; i++) {
		struct ulogd_key *key = &input->keys[i];
		int length = ulogd_key_size(key);

		if (!nfct_bitmask_test_bit(tmpl->bitmask, i))
			continue;

		/* XXX: search swap related field and set its offset */
		for (j = 0; j < FOI_MAX; j++) {
			if (!strncmp(key->name, dir_keys[j],
				     strlen(dir_keys[j]))) {
				tmpl->offset[j] = offset;
				break;
			}
		}

		if (i == ii->ikey_count[CII_REPLY_RAW_PKTLEN_DELTA]
		    || i == ii->ikey_count[CII_REPLY_RAW_PKTCOUNT_DELTA]
		    || i == ii->ikey_count[CII_REPLY_IP_PROTOCOL])
			continue;

		tmpl_rec->type = htons(ipfix_map[key->ipfix.field_id]);
		tmpl_rec->length = htons(length);
		tmpl_rec++;
		field_count++;
		offset += length;
	}

	/* initialize template set header */
	tmpl->template->set_id = htons(0); /* 5.2 Template FlowSet Format */
	tmpl->template->length = htons(tmpl->tmplset_len);

	/* initialize template record header */
	tmpl_hdr = (void *)tmpl->template + sizeof(struct netflow9_set_hdr);
	tmpl_hdr->template_id = htons(ii->next_template_id++);
	tmpl_hdr->field_count = htons(field_count);

	/* initialize data buffer */
	for (i = 0; i < ii->corksets_max; i++) {
		set_hdr = (void *)tmpl->databuf + i * tmpl->dataset_len;
		set_hdr->set_id = tmpl_hdr->template_id;
		set_hdr->length = htons(tmpl->dataset_len);
	}

	return tmpl;
}

static struct ulogd_netflow9_template *
find_template_for_bitmask(struct ulogd_pluginstance *upi,
			  struct nfct_bitmask *bm)
{
	struct netflow9_instance *ii
		= (struct netflow9_instance *)&upi->private;
	struct ulogd_netflow9_template *tmpl;

	/* FIXME: this can be done more efficient! */
	llist_for_each_entry(tmpl, &ii->template_list, list) {
		if (nfct_bitmask_equal(bm, tmpl->bitmask))
			return tmpl;
	}
	return NULL;
}

static int put_data_records(struct ulogd_pluginstance *upi,
			    struct ulogd_keyset *input,
			    struct ulogd_netflow9_template *tmpl,
			    void *buf, int buflen)
{
	struct ulogd_key *keys = input->keys;
	struct netflow9_instance
		*ii = (struct netflow9_instance *)&upi->private;
	unsigned int i;
	int ret, len = 0;

	for (i = 0; i < input->num_keys; i++) {
		if (!nfct_bitmask_test_bit(tmpl->bitmask, i))
			continue;

		/* store orig temporarily to (unidirectional) counter */
		if (i == ii->ikey_count[CII_REPLY_RAW_PKTLEN_DELTA]
		    || i == ii->ikey_count[CII_REPLY_RAW_PKTCOUNT_DELTA]
		    || i == ii->ikey_count[CII_REPLY_IP_PROTOCOL])
			continue;

		ret = ulogd_key_putn(&keys[i], buf + len, buflen);
		if (ret < 0)
			return ret;

		len += ret;
		buflen -= ret;
		if (buflen < 0)
			return buflen;
	}

	return len;
}

static void swap(void *data, ssize_t size, int pos1, int pos2)
{
	uint8_t tmp[16] = {}; /* 16: ip6 addr len */
	memcpy(tmp, data + pos1, size);
	memcpy(data + pos1, data +pos2, size);
	memcpy(data + pos2, tmp, size);
}

#define TOF(i)	tmpl->offset[(i)]

static int orig_swap(struct ulogd_netflow9_template *tmpl,
		     uint8_t family, void *buf)
{
	switch (family) {
	case AF_INET:
		swap(buf, sizeof(struct in_addr ),
		     TOF(FOI_REPLY_IP_SADDR), TOF(FOI_REPLY_IP_DADDR));
		break;
	case AF_INET6:
		swap(buf, sizeof(struct in6_addr ),
		     TOF(FOI_REPLY_IP6_SADDR), TOF(FOI_REPLY_IP6_DADDR));
		break;
	default:
		ulogd_log(ULOGD_ERROR, "unknown family: %d", family);
		return -1;
	}
	if (TOF(FOI_REPLY_L4_SPORT) >= 0
	    && TOF(FOI_REPLY_L4_DPORT) >= 0)
		swap(buf, sizeof(uint16_t),
		     TOF(FOI_REPLY_L4_SPORT), TOF(FOI_REPLY_L4_DPORT));

	return 0;
}

static int reply_swap(struct ulogd_netflow9_template *tmpl,
		      uint8_t family, void *buf)
{
	switch (family) {
	case AF_INET:
		swap(buf, sizeof(struct in_addr),
		     TOF(FOI_ORIG_IP_SADDR), TOF(FOI_ORIG_IP_DADDR));
		break;
	case AF_INET6:
		swap(buf, sizeof(struct in6_addr ),
		     TOF(FOI_ORIG_IP_SADDR), TOF(FOI_ORIG_IP_DADDR));
		break;
	default:
		ulogd_log(ULOGD_ERROR, "unknown family: %d", family);
		return -1;
	}
	if (TOF(FOI_ORIG_L4_SPORT) >= 0
	    && TOF(FOI_ORIG_L4_DPORT) >= 0)
		swap(buf, sizeof(uint16_t),
		     TOF(FOI_ORIG_L4_SPORT), TOF(FOI_ORIG_L4_DPORT));
	if (TOF(FOI_IF_INPUT) >= 0 && TOF(FOI_IF_OUTPUT) >= 0)
		swap(buf, sizeof(uint32_t),
		     TOF(FOI_IF_INPUT), TOF(FOI_IF_OUTPUT));
	if (TOF(FOI_FLOW_DIR) >= 0)
		*(uint8_t *)(buf + TOF(FOI_FLOW_DIR))
			= !*(uint8_t *)(buf + TOF(FOI_FLOW_DIR));

	return 0;
}

static int swap_by_dir(struct ulogd_netflow9_template *tmpl,
		       void *buf, uint8_t family,
		       int direction,
		       uint64_t bytes, uint64_t packets)
{
	switch (direction) {
	case NFLOW9_DIR_ORIG:
		if (orig_swap(tmpl, family, buf) < 0)
			return -1;
		break;

	case NFLOW9_DIR_REPLY:
		if (reply_swap(tmpl, family, buf) < 0)
			return -1;
		break;
	default:
		ulogd_log(ULOGD_ERROR, "unknown dir: %d", direction);
		return -1;
	}

	if (TOF(FOI_IN_BYTES) >= 0)
		*(uint64_t *)(buf + TOF(FOI_IN_BYTES)) = __cpu_to_be64(bytes);
	if (TOF(FOI_IN_PKTS) >= 0)
		*(uint64_t *)(buf + TOF(FOI_IN_PKTS)) = __cpu_to_be64(packets);

	return 0;
}
#undef TOF

static int nflow9_direction(struct ulogd_pluginstance *upi,
			    struct ulogd_keyset *input, uint8_t *family,
			    uint64_t *orig_bytes, uint64_t *orig_packets,
			    uint64_t *reply_bytes, uint64_t *reply_packets)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&upi->private;
	struct ulogd_key *keys = input->keys;
	unsigned int sentry = input->num_keys;
	int ret = 0;

#define IKC(i)	ii->ikey_count[(i)]
	if (IKC(CII_ORIG_RAW_PKTLEN_DELTA) != sentry
	    && pp_is_valid(keys, IKC(CII_ORIG_RAW_PKTLEN_DELTA))) {
		*orig_bytes
			= ikey_get_u64(&keys[IKC(CII_ORIG_RAW_PKTLEN_DELTA)]);
		if (*orig_bytes > 0) {
			*orig_packets
				= ikey_get_u64(&keys[IKC(CII_ORIG_RAW_PKTCOUNT_DELTA)]);
			ret |= NFLOW9_DIR_ORIG;
		}
	}
	if (IKC(CII_REPLY_RAW_PKTLEN_DELTA) != sentry
	    && pp_is_valid(keys, IKC(CII_REPLY_RAW_PKTLEN_DELTA))) {
		*reply_bytes
			= ikey_get_u64(&keys[IKC(CII_REPLY_RAW_PKTLEN_DELTA)]);
		if (*reply_bytes > 0) {
			*reply_packets
				= ikey_get_u64(&keys[IKC(CII_REPLY_RAW_PKTCOUNT_DELTA)]);
			ret |= NFLOW9_DIR_REPLY;
		}
	}
	*family = ikey_get_u8(&keys[IKC(CII_FAMILY)]);
#undef IKC
	return ret;
}

static void *data_record(struct netflow9_instance *ii,
			 struct ulogd_netflow9_template *tmpl)
{
	void *records;

	/* data flowset */
	ii->iovecs[ii->iovcnt].iov_base = (void *)tmpl->databuf
		+ tmpl->datapos * tmpl->dataset_len;
	ii->iovecs[ii->iovcnt].iov_len = tmpl->dataset_len;

	/* clear data records */
	records = ii->iovecs[ii->iovcnt].iov_base
		+ sizeof(struct netflow9_set_hdr);
	memset(records, 0,
	       tmpl->dataset_len - sizeof(struct netflow9_set_hdr));

	/* increment position */
	ii->iovcnt++;
	tmpl->datapos++;

	return records;
}

static int insert_template(struct ulogd_pluginstance *upi,
			   struct ulogd_netflow9_template *tmpl)
{
	struct netflow9_instance *ii
		= (struct netflow9_instance *)&upi->private;

	if (tmpl->until_template != 0) {
		tmpl->until_template--;
		return 0;
	}
	tmpl->until_template = nth_template_ce(upi->config_kset).u.value;

	ii->iovecs[ii->iovcnt].iov_base = tmpl->template;
	ii->iovecs[ii->iovcnt].iov_len = tmpl->tmplset_len;

	ii->iovcnt++;
	ii->msglen += tmpl->tmplset_len;

	return 1;
}

static int build_netflow9_msg(struct ulogd_pluginstance *upi,
			      struct ulogd_keyset *input,
			      struct ulogd_netflow9_template *tmpl)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&upi->private;
	uint8_t family = 0;
	uint64_t obytes = 0, opackets = 0;
	uint64_t rbytes = 0, rpackets = 0;
	int dir;
	void *buf;

	insert_template(upi, tmpl);
	buf = data_record(ii, tmpl);
	if (put_data_records(upi, input, tmpl, buf, tmpl->dataset_len) < 0) {
		ulogd_log(ULOGD_ERROR, "could not build netflow v9 dataset\n");
		return -1;
	}

	dir = nflow9_direction(upi, input, &family,
			       &obytes, &opackets, &rbytes, &rpackets);
	switch (dir) {
	case NFLOW9_DIR_ORIG:
		swap_by_dir(tmpl, buf, family, dir, obytes, opackets);
		break;

	case NFLOW9_DIR_REPLY:
		swap_by_dir(tmpl, buf, family, dir, rbytes, rpackets);
		break;

	case NFLOW9_DIR_BOTH:
		swap_by_dir(tmpl, buf, family, NFLOW9_DIR_ORIG,
			    obytes, opackets);
		ii->msglen += tmpl->dataset_len;
		buf = data_record(ii, tmpl);
		if (put_data_records(upi, input, tmpl, buf,
				     tmpl->dataset_len) < 0) {
			ulogd_log(ULOGD_ERROR,
				  "could not build netflow v9 dataset");
			return -1;
		}
		swap_by_dir(tmpl, buf, family, NFLOW9_DIR_REPLY,
			    rbytes, rpackets);
		break;

	case NFLOW9_DIR_NONE:
		ulogd_log(ULOGD_DEBUG, "receive zero counter data\n");
		return 0;
		break;

	default:
		ulogd_log(ULOGD_ERROR, "nflow9_direction() returns invalid");
		return -1;
		break;
	}

	ii->msglen += tmpl->dataset_len;
	return 1;
}

static uint32_t uptime_millis(int fd)
{
	char buf[1024] = {0};
	double up;
	int nread;

	lseek(fd, 0, SEEK_SET);
	nread = read(fd, buf, sizeof(buf) - 1);
	if (nread == -1)
		return 0;
	if (sscanf(buf, "%lf", &up) != 1)
		return 0;
	return (uint32_t)(up * 1000);
}

static uint32_t get_seqnum(struct netflow9_instance *ii)
{
	return ii->seq++;
}

static void reset_counters(struct netflow9_instance *ii)
{
	struct ulogd_netflow9_template *tmpl;

	llist_for_each_entry(tmpl, &ii->template_list, list) {
		tmpl->datapos = 0;
	}
	ii->msglen = 0;
	/* pos 0 is reserved for netflow9_msg_hdr */
	ii->iovcnt = 1;
}

static ssize_t send_netflow9(struct netflow9_instance *ii)
{
	ssize_t nsent;

	ii->nflow9_msghdr.sys_uptime
		= htonl((uint32_t)uptime_millis(ii->uptime_fd));
	ii->nflow9_msghdr.unix_secs = htonl((uint32_t)(time(NULL)));
	ii->nflow9_msghdr.count = htons(ii->iovcnt - 1);
	ii->nflow9_msghdr.sequence_number = htonl(get_seqnum(ii));
	ii->msglen += sizeof(struct netflow9_msg_hdr);

#ifdef DEBUG_TMMAP
	nflow9_fprintf_header(stdout, ii);
	fflush(stdout);
#endif
	nsent = writev(ii->fd, ii->iovecs, ii->iovcnt);
	if (nsent != ii->msglen) {
		if (nsent == -1) {
			ulogd_log(ULOGD_ERROR, "send: %s\n", strerror(errno));
		} else {
			ulogd_log(ULOGD_ERROR, "send - arg: %d, ret: %d\n",
				  ii->msglen, nsent);
		}
	}

	return nsent;
}

static int output_netflow9(struct ulogd_pluginstance *upi,
			   struct ulogd_keyset *input,
			   struct ulogd_keyset *output)
{
	struct netflow9_instance *ii
		= (struct netflow9_instance *)&upi->private;
	struct ulogd_netflow9_template *template;
	unsigned int i;
	int ret;

	/* FIXME: it would be more cache efficient if the IS_VALID
	 * flags would be a separate bitmask outside of the array.
	 * ulogd core could very easily flush it after every packet,
	 * too. */
	nfct_bitmask_clear(ii->valid_bitmask);

	for (i = 0; i < input->num_keys; i++) {
		struct ulogd_key *key = &input->keys[i];
		int length = ulogd_key_size(key);

		if (length < 0 || length > 0xfffe)
			continue;
		if (!(key->u.source->flags & ULOGD_RETF_VALID))
			continue;
		if (key->ipfix.vendor != IPFIX_VENDOR_IETF
		    && key->ipfix.vendor != IPFIX_VENDOR_REVERSE)
			continue;
		if (ipfix_map[key->ipfix.field_id] == 0)
			continue;

		/* include both orig. reply. */
		nfct_bitmask_set_bit(ii->valid_bitmask, i);
	}

	/* lookup template ID for this bitmask */
	template = find_template_for_bitmask(upi, ii->valid_bitmask);
	if (!template) {
		ulogd_log(ULOGD_INFO, "building new template\n");
		template = build_template_for_bitmask(upi, input,
						      ii->valid_bitmask);
		if (!template) {
			ulogd_log(ULOGD_ERROR, "can't build new template!\n");
			return ULOGD_IRET_ERR;
		}
		llist_add(&template->list, &ii->template_list);
	}

	ret = build_netflow9_msg(upi, input, template);
	if (ret == -1) {
		ulogd_log(ULOGD_ERROR, "can't build message\n");
		reset_counters(ii);
		return ULOGD_IRET_ERR;
	}

	/* XXX: magic number. practical UDP max */
	if (ii->msglen > 65507 - sizeof(struct netflow9_msg_hdr)) {
		ulogd_log(ULOGD_NOTICE, "We may have lost data since message "
			  "length exceeds practical UDP max size, then reducing "
			  "corksets_max to %d\n", ii->iovcnt);
		ii->corksets_max = ii->iovcnt;
	} else if (ii->iovcnt - 1 + 3 < ii->corksets_max) {
		/* - 1 reserved for header
		 * + 3 for sending template, orig and reply on next */
		return ULOGD_IRET_OK;
	}

	ret = send_netflow9(ii);
	reset_counters(ii);
	if (ret < 0)
		return ULOGD_IRET_ERR;

	return ULOGD_IRET_OK;
}

static int start_netflow9(struct ulogd_pluginstance *pi,
			  struct ulogd_keyset *input)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&pi->private;
	int ret = -ENOMEM;
	unsigned int i, j;

	ulogd_log(ULOGD_DEBUG, "starting netflow9\n");

	/* +1 for nflow9_msghdr */
	ii->iovecs = calloc(ii->corksets_max + 1, sizeof(struct iovec));
	if (ii->iovecs == NULL)
		return ret;

	ii->valid_bitmask = nfct_bitmask_new(input->num_keys);
	if (!ii->valid_bitmask)
		goto out_iovecs_free;

	INIT_LLIST_HEAD(&ii->template_list);

	ii->fd = open_connect_descriptor(dest_ce(pi->config_kset).u.string);
	if (ii->fd < 0) {
		ulogd_log(ULOGD_ERROR, "could not connect: %s\n",
			  strerror(errno));
		goto out_bm_free;
	}

	ii->uptime_fd = open(UPTIME_FILE, O_RDONLY);
	if (ii->uptime_fd == -1) {
		ulogd_log(ULOGD_ERROR, "cound not open file: %s\n",
			  UPTIME_FILE);
		goto out_close_sock;
	}

	/* initialize netflow v9 message header */
	ii->nflow9_msghdr.version = htons(9);
	ii->nflow9_msghdr.source_id = htonl(domain_ce(pi->config_kset).u.value);
	ii->iovecs[0].iov_base = &ii->nflow9_msghdr;
	ii->iovecs[0].iov_len = sizeof(ii->nflow9_msghdr);

	ii->next_template_id = ULOGD_NETFLOW9_TEMPL_BASE;
	reset_counters(ii);

	/* search key index for direction conditions and converts */
	for (i = 0; i < CII_MAX; i++)
		ii->ikey_count[i] = input->num_keys;
	for (i = 0; i < input->num_keys; i++) {
		for (j = 0; j < CII_MAX; j++) {
			if (!strncmp(input->keys[i].name, count_keys[j],
				     strlen(count_keys[j]))) {
				ii->ikey_count[j] = i;
				break;
			}
		}
	}
	/* XXX: check ii->ikey_count validity */
	
#ifdef DEBUG_TMMAP
	mmfd = fileno(tmpfile());
	if (mmfd == -1) {
		perror("could not open tmp mmap file");
		exit(EXIT_FAILURE);
	}
	mmaddr = mmap(NULL, 65507, PROT_READ | PROT_WRITE, MAP_PRIVATE, mmfd, 0);
	if (mmaddr == MAP_FAILED) {
		perror("could not mmap");
		exit(EXIT_FAILURE);
	}
#endif
	return 0;

out_close_sock:
	close(ii->fd);
out_bm_free:
	nfct_bitmask_destroy(ii->valid_bitmask);
	ii->valid_bitmask = NULL;
out_iovecs_free:
	free(ii->iovecs);

	return ret;
}

static int stop_netflow9(struct ulogd_pluginstance *pi)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&pi->private;
	struct ulogd_netflow9_template *tmpl, *n;

	if (ii->iovcnt > 1)
		send_netflow9(ii); /* ignore retval, log error only */
	reset_counters(ii);

	llist_for_each_entry_safe(tmpl, n, &ii->template_list, list) {
		nfct_bitmask_destroy(tmpl->bitmask);
		free(tmpl->template);
		free(tmpl->databuf);
		llist_del(&tmpl->list);
		free(tmpl);
	}
	close(ii->uptime_fd);
	close(ii->fd);
	nfct_bitmask_destroy(ii->valid_bitmask);
	ii->valid_bitmask = NULL;
	free(ii->iovecs);

	return 0;
}

static void
signal_handler_netflow9(struct ulogd_pluginstance *pi, uint32_t signal)
{
	switch (signal) {
	default:
		ulogd_log(ULOGD_DEBUG, "receive signal: %d\n", signal);
		break;
	}
}

static int configure_netflow9(struct ulogd_pluginstance *pi)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&pi->private;
	int ret;

	/* FIXME: error handling */
	ulogd_log(ULOGD_DEBUG, "parsing config file section %s\n", pi->id);
	ret = config_parse_file(pi->id, pi->config_kset);
	if (ret < 0)
		return ret;

	if (corksets_max_ce(pi->config_kset).u.value < 3) {
		ulogd_log(ULOGD_ERROR, "corksets_max is required "
			  "more than 3 from implementation perspective\n");
		return -EINVAL;
	}
	ii->corksets_max
		= (unsigned int)corksets_max_ce(pi->config_kset).u.value;

	return 0;
}

static struct ulogd_plugin netflow9_plugin = {
	.name = "NFLOW9",
	.input = {
		.type = ULOGD_DTYPE_FLOW | ULOGD_DTYPE_WILDCARD,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset	= &netflow9_kset,
	.priv_size	= sizeof(struct netflow9_instance),

	.configure	= &configure_netflow9,
	.start		= &start_netflow9,
	.stop		= &stop_netflow9,

	.interp		= &output_netflow9,
	.signal		= &signal_handler_netflow9,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&netflow9_plugin);
}

#ifdef DEBUG_TMMAP
static char *nflow9_field_name[] = {
	[NETFLOW9_IN_BYTES]			= "IN_BYTES",
	[NETFLOW9_IN_PKTS]			= "IN_PKTS",
	[NETFLOW9_FLOWS]			= "FLOWS",
	[NETFLOW9_PROTOCOL]			= "PROTOCOL",
	[NETFLOW9_TOS]				= "TOS",
	[NETFLOW9_TCP_FLAGS]			= "TCP_FLAGS",
	[NETFLOW9_L4_SRC_PORT]			= "L4_SRC_PORT",
	[NETFLOW9_IPV4_SRC_ADDR]		= "IPV4_SRC_ADDR",
	[NETFLOW9_SRC_MASK]			= "SRC_MASK",
	[NETFLOW9_INPUT_SNMP]			= "INPUT_SNMP",
	[NETFLOW9_L4_DST_PORT]			= "L4_DST_PORT",
	[NETFLOW9_IPV4_DST_ADDR]		= "IPV4_DST_ADDR",
	[NETFLOW9_DST_MASK]			= "DST_MASK",
	[NETFLOW9_OUTPUT_SNMP]			= "OUTPUT_SNMP",
	[NETFLOW9_IPV4_NEXT_HOP]		= "IPV4_NEXT_HOP",
	[NETFLOW9_SRC_AS]			= "SRC_AS",
	[NETFLOW9_DST_AS]			= "DST_AS",
	[NETFLOW9_BGP_IPV4_NEXT_HOP]		= "BGP_IPV4_NEXT_HOP",
	[NETFLOW9_MUL_DST_PKTS]			= "MUL_DST_PKTS",
	[NETFLOW9_MUL_DST_BYTES]		= "MUL_DST_BYTES",
	[NETFLOW9_LAST_SWITCHED]		= "LAST_SWITCHED",
	[NETFLOW9_FIRST_SWITCHED]		= "FIRST_SWITCHED",
	[NETFLOW9_OUT_BYTES]			= "OUT_BYTES",
	[NETFLOW9_OUT_PKTS]			= "OUT_PKTS",
	[NETFLOW9_IPV6_SRC_ADDR]		= "IPV6_SRC_ADDR",
	[NETFLOW9_IPV6_DST_ADDR]		= "IPV6_DST_ADDR",
	[NETFLOW9_IPV6_SRC_MASK]		= "IPV6_SRC_MASK",
	[NETFLOW9_IPV6_DST_MASK]		= "IPV6_DST_MASK",
	[NETFLOW9_FLOW_LABEL]			= "FLOW_LABEL",
	[NETFLOW9_ICMP_TYPE]			= "ICMP_TYPE",
	[NETFLOW9_MUL_IGMP_TYPE]		= "MUL_IGMP_TYPE",
	[NETFLOW9_SAMPLING_INTERVAL]		= "SAMPLING_INTERVAL",
	[NETFLOW9_SAMPLING_ALGORITHM]		= "SAMPLING_ALGORITHM",
	[NETFLOW9_FLOW_ACTIVE_TIMEOUT]		= "FLOW_ACTIVE_TIMEOUT",
	[NETFLOW9_FLOW_INAVTIVE_TIMEOUT]	= "FLOW_INAVTIVE_TIMEOUT",
	[NETFLOW9_ENGINE_TYPE]			= "ENGINE_TYPE",
	[NETFLOW9_ENGINE_ID]			= "ENGINE_ID",
	[NETFLOW9_TOTAL_BYTES_EXP]		= "TOTAL_BYTES_EXP",
	[NETFLOW9_TOTAL_PKTS_EXP]		= "TOTAL_PKTS_EXP",
	[NETFLOW9_TOTAL_FLOWS_EXP]		= "TOTAL_FLOWS_EXP",
	[NETFLOW9_MPLS_TOP_LABEL_TYPE]		= "MPLS_TOP_LABEL_TYPE",
	[NETFLOW9_MPLS_TOP_LABEL_IP_ADDR]	= "MPLS_TOP_LABEL_IP_ADDR",
	[NETFLOW9_FLOW_SAMPLER_ID]		= "FLOW_SAMPLER_ID",
	[NETFLOW9_FLOW_SAMPLER_MODE]		= "FLOW_SAMPLER_MODE",
	[NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL] = "FLOW_SAMPLER_RANDOM_INTERVAL",
	[NETFLOW9_DST_TOS]			= "DST_TOS",
	[NETFLOW9_SRC_MAC]			= "SRC_MAC",
	[NETFLOW9_DST_MAC]			= "DST_MAC",
	[NETFLOW9_SRC_VLAN]			= "SRC_VLAN",
	[NETFLOW9_DST_VLAN]			= "DST_VLAN",
	[NETFLOW9_IP_PROTOCOL_VERSION]		= "IP_PROTOCOL_VERSION",
	[NETFLOW9_DIRECTION]			= "DIRECTION",
	[NETFLOW9_IPV6_NEXT_HOP]		= "IPV6_NEXT_HOP",
	[NETFLOW9_BGP_IPV6_NEXT_HOP]		= "BGP_IPV6_NEXT_HOP",
	[NETFLOW9_IPV6_OPTION_HEADERS]		= "IPV6_OPTION_HEADERS",
	[NETFLOW9_MPLS_LABEL_1]			= "MPLS_LABEL_1",
	[NETFLOW9_MPLS_LABEL_2]			= "MPLS_LABEL_2",
	[NETFLOW9_MPLS_LABEL_3]			= "MPLS_LABEL_3",
	[NETFLOW9_MPLS_LABEL_4]			= "MPLS_LABEL_4",
	[NETFLOW9_MPLS_LABEL_5]			= "MPLS_LABEL_5",
	[NETFLOW9_MPLS_LABEL_6]			= "MPLS_LABEL_6",
	[NETFLOW9_MPLS_LABEL_7]			= "MPLS_LABEL_7",
	[NETFLOW9_MPLS_LABEL_8]			= "MPLS_LABEL_8",
	[NETFLOW9_MPLS_LABEL_9]			= "MPLS_LABEL_9",
	[NETFLOW9_MPLS_LABEL_10]		= "MPLS_LABEL_10",
	[NETFLOW9_IPV4_XLATE_SRC_ADDR]		= "IPV4_XLATE_SRC_ADDR",
	[NETFLOW9_IPV4_XLATE_DST_ADDR]		= "IPV4_XLATE_DST_ADDR",
	[NETFLOW9_L4_XLATE_SRC_PORT]		= "L4_XLATE_SRC_PORT",
	[NETFLOW9_L4_XLATE_DST_PORT]		= "L4_XLATE_DST_PORT",
	[NETFLOW9_IPV6_XLATE_SRC_ADDR]		= "IPV6_XLATE_SRC_ADDR",
	[NETFLOW9_IPV6_XLATE_DST_ADDR]		= "IPV6_XLATE_DST_ADDR",
};

static int nflow9_fprintf_field(FILE *fd, const struct netflow9_templ_rec *field, int len)
{
	int ret;
	void *ptr;

	if (len < (int)sizeof(*field)) {
		fprintf(fd, "ERROR ietf field: too short buflen: %d\n", len);
		return -1;
	}

	fprintf(fd, "+---------------------------------+---------------------------------+\n");
	fprintf(fd, "| Field Type: %19s |             Field Length: %5d |\n",
		nflow9_field_name[ntohs(field->type)], ntohs(field->length));

	len -= sizeof(*field);
	if (len == 0)
		return sizeof(*field);

	ptr = (void *)field + sizeof(*field);
	ret = nflow9_fprintf_field(fd, ptr, len);
	if (ret == -1)
		return -1;
	return ret + sizeof(*field);
}

static int nflow9_fprintf_data_records(FILE *fd, const void *data, int len)
{
	int i;

	fprintf(fd, "+-------------------------------------------------------------------+\n");
	/* don't say messy...*/
	for (i = 0; i < len; i += 4) {
		switch (len - i - 4) {
		case -3:
			fprintf(fd, "|          0x%02x                                                   |\n",
				*(uint8_t *)(data + i));
			break;
		case -2:
			fprintf(fd, "|          0x%02x           0x%02x                                     |\n",
				*(uint8_t *)(data + i), *(uint8_t *)(data + i + 1));
			break;
		case -1:
			fprintf(fd, "|          0x%02x           0x%02x          0x%02x                       |\n",
				*(uint8_t *)(data + i), *(uint8_t *)(data + i + 1), *(uint8_t *)(data + i + 2));
			break;
		default:
			fprintf(fd, "|          0x%02x           0x%02x          0x%02x           0x%02x         |\n",
				*(uint8_t *)(data + i), *(uint8_t *)(data + i + 1),
				*(uint8_t *)(data + i + 2), *(uint8_t *)(data + i + 3));
			break;
		}
	}
	return len;
}

static int nflow9_fprintf_template_records(FILE *fd, const struct netflow9_templ_hdr *hdr,
					   int len)
{
	int ret;
	void *field;

	if (len < (int)sizeof(*hdr)) {
		fprintf(fd, "ERROR template records: too short buflen for template record: %d\n", len);
		return -1;
	}

	fprintf(fd, "+---------------------------------+---------------------------------+\n");
	fprintf(fd, "|              Template ID: %5d |              Field Count: %5d |\n",
		ntohs(hdr->template_id), ntohs(hdr->field_count));

	len -= sizeof(*hdr);
	if (len == 0)
		return sizeof(*hdr);

	field = (void *)hdr + sizeof(*hdr);
	ret = nflow9_fprintf_field(fd, field, len);
	if (ret == -1)
		return -1;
	return ret + sizeof(*hdr);
}

static int nflow9_fprintf_set_header(FILE *fd, const struct netflow9_set_hdr *hdr, int len)
{
	int ret, setlen, total_len;
	void *ptr;

	if (len < (int)sizeof(*hdr)) {
		fprintf(fd, "ERROR set header: too short buflen for set header: %d\n", len);
		return -1;
	}
	setlen = ntohs(hdr->length);
	if (len < setlen) {
		fprintf(fd, "ERROR set header: buflen: %d is smaller than set length field: %d\n", len, setlen);
		/* return -1; */
	}
	if (setlen < (int)sizeof(*hdr)) {
		fprintf(fd, "ERROR set header: too short set length field: %d\n", setlen);
		return -1;
	}

	fprintf(fd, "+---------------------------------+---------------------------------+\n");
	fprintf(fd, "|                   Set ID: %5d |                   Length: %5d |\n",
		ntohs(hdr->set_id), setlen);

	setlen -= sizeof(*hdr);
	ptr = (void *)hdr + sizeof(*hdr);
	total_len = sizeof(*hdr);

	switch (ntohs(hdr->set_id)) {
	case 0:
		ret = nflow9_fprintf_template_records(fd, ptr, setlen);
		break;
	case 1:
		/* XXX: ret = nflow9_fprintf_options_template_records(fd, ptr, setlen); */
		fprintf(fd, "ERROR: options template is not implemented yet, sorry");
		ret = setlen;
		break;
	default:
		ret = nflow9_fprintf_data_records(fd, ptr, setlen);
		break;
	}

	if (ret == -1 || ret != setlen)
		return -1;

	fprintf(fd, "+-------------------------------------------------------------------+\n");
	return total_len + ret;
}

static int _nflow9_fprintf_header(FILE *fd, const struct netflow9_msg_hdr *hdr,
				  int msglen)
{
	int ret, len;
	char outstr[20];
	void *ptr;
	time_t t = (time_t)(ntohl(hdr->unix_secs));
	struct tm *tmp = localtime(&t);

	/* XXX: tmp == NULL and strftime == 0 */
	strftime(outstr, sizeof(outstr), "%F %T", tmp);

	fprintf(fd, "+---------------------------------+---------------------------------+\n");
	fprintf(fd, "|           Version Number: %5d |                    Count: %5d | (Length: %d) \n",
		ntohs(hdr->version), ntohs(hdr->count), msglen);
	fprintf(fd, "+-------------------------------------------------------------------+\n");
	fprintf(fd, "|                        sysUpTime: %10u                      |\n",
		ntohl(hdr->sys_uptime));
	fprintf(fd, "+---------------------------------+---------------------------------+\n");
	fprintf(fd, "|                        UNIX Secs: %10u                      |\t%s\n",
		ntohl(hdr->unix_secs), outstr);
	fprintf(fd, "+-------------------------------------------------------------------+\n");
	fprintf(fd, "|                  Sequence Number: %10d                      |\n",
		ntohl(hdr->sequence_number));
	fprintf(fd, "+-------------------------------------------------------------------+\n");
	fprintf(fd, "|                        Source ID: %10d                      |\n",
		ntohl(hdr->source_id));
	fprintf(fd, "+-------------------------------------------------------------------+\n");

	len = msglen - sizeof(*hdr);
	ptr = (void *)hdr + sizeof(*hdr);

	while (len > 0) {
		ret = nflow9_fprintf_set_header(fd, ptr, len);
		if (ret == -1)
			return -1;
		len -= ret;
		ptr += ret;
	}

	return msglen - len;
}

static int nflow9_fprintf_header(FILE *fd, const struct netflow9_instance *ii)
{
	lseek(mmfd, 0, SEEK_SET);
	writev(mmfd, ii->iovecs, ii->iovcnt);
	return _nflow9_fprintf_header(fd, mmaddr, ii->msglen);
}
#endif
