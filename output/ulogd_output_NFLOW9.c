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

#define DEBUG_OUTBK_DIR "/tmp/bk"

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

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <ulogd/linuxlist.h>

#include <byteswap.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#  ifndef __be64_to_cpu
#  define __be64_to_cpu(x)	(x)
#  endif
# else
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  ifndef __be64_to_cpu
#  define __be64_to_cpu(x)	__bswap_64(x)
#  endif
# endif
#endif

#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/linuxlist.h>
#include <ulogd/ipfix_protocol.h>

/*
 * This implementation sends netflow v9 entry only if IN or OUT counter is
 * greater than 0. Single NFCT entry contains duplex data, orig and reply, but
 * NetFlow v9 can represents simplex entry, then sigle NFCT entry may create two
 * NetFlow v9 entries. IN or OUT decisions is made by cheking
 * orig.raw.pktcount.delta and reply.raw.pktcount.delta. (see data_direction())
 * Either counter, for example orig.raw.pktcount.delta contains greater than 0,
 * keys which starts with "reply." is excluded. Since it uses same template, the
 * number of keys starting with "orig." and "reply." is assumed to the same.
 */
#define ORIG_PRE	"orig."
#define ORIG_PRELEN	5
#define REPLY_PRE	"reply."
#define REPLY_PRELEN	6
#define ORIGCOUNT_KEYNAME	"orig.raw.pktcount.delta"
#define REPLYCOUNT_KEYNAME	"reply.raw.pktcount.delta"

enum nflow9_field_dir {
	NFLOW9_DIR_NONE		= 0,
	NFLOW9_DIR_ORIG		= 1,
	NFLOW9_DIR_REPLY	= 2,
	NFLOW9_DIR_BOTH		= 3,
};

static struct config_keyset netflow9_kset = {
	.num_ces = 6,
	.ces = {
		{
			.key 	 = "host",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key	 = "port",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	 = { .string = "2055" },
		},
		{
			.key	 = "protocol",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	= { .string = "udp" },
		},
		{
			.key	 = "domain_id",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key	 = "send_template_per",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 16,
		},
		{
			.key	 = "prime9",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
	},
};

#define host_ce(x)	(x->ces[0])
#define port_ce(x)	(x->ces[1])
#define proto_ce(x)	(x->ces[2])
#define domain_ce(x)	(x->ces[3])
#define template_per_ce(x)	(x->ces[4])
#define prime9_ce(x)	(x->ces[5])

/* Section 5.1 */
struct netflow9_msg_hdr {
	u_int16_t	version;
	u_int16_t	count;
	u_int32_t	sys_uptime;
	u_int32_t	unix_secs;
	u_int32_t	sequence_number;
	u_int32_t	source_id;
};

/* Section 5.2, 5.3 */
struct netflow9_set_hdr {
	u_int16_t	set_id;
	u_int16_t	length;
};

/* Section 5.2 */
struct netflow9_templ_hdr {
	u_int16_t	template_id;
	u_int16_t	field_count;
};

/* Section 5.2 */
struct netflow9_templ_rec {
	u_int16_t	type;
	u_int16_t	length;
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
};

#define NETFLOW9_FIELD_MAX NETFLOW9_MPLS_LABEL_10

static int ipfix_map[] = {
	[NETFLOW9_IN_BYTES]		= IPFIX_octetDeltaCount,
	[NETFLOW9_IN_PKTS]		= IPFIX_packetDeltaCount,
	[NETFLOW9_FLOWS]		= 0,
	[NETFLOW9_PROTOCOL]		= IPFIX_protocolIdentifier,
	[NETFLOW9_TOS]			= IPFIX_classOfServiceIPv4,
	[NETFLOW9_TCP_FLAGS]		= IPFIX_tcpControlBits,
	[NETFLOW9_L4_SRC_PORT]		= IPFIX_sourceTransportPort,
	[NETFLOW9_IPV4_SRC_ADDR]	= IPFIX_sourceIPv4Address,
	[NETFLOW9_SRC_MASK]		= IPFIX_sourceIPv4Mask,
	[NETFLOW9_INPUT_SNMP]		= IPFIX_ingressInterface,
	[NETFLOW9_L4_DST_PORT]		= IPFIX_destinationTransportPort,
	[NETFLOW9_IPV4_DST_ADDR]	= IPFIX_destinationIPv4Address,
	[NETFLOW9_DST_MASK]		= IPFIX_destinationIPv4Mask,
	[NETFLOW9_OUTPUT_SNMP]		= IPFIX_egressInterface,
	[NETFLOW9_IPV4_NEXT_HOP]	= IPFIX_ipNextHopIPv4Address,
	[NETFLOW9_SRC_AS]		= IPFIX_bgpSourceAsNumber,
	[NETFLOW9_DST_AS]		= IPFIX_bgpDestinationAsNumber,
	[NETFLOW9_BGP_IPV4_NEXT_HOP]	= IPFIX_bgpNextHopIPv4Address,
	[NETFLOW9_MUL_DST_PKTS]		= IPFIX_postMCastPacketDeltaCount,
	[NETFLOW9_MUL_DST_BYTES]	= IPFIX_postMCastOctetDeltaCount,
	[NETFLOW9_LAST_SWITCHED]	= IPFIX_flowEndSysUpTime,
	[NETFLOW9_FIRST_SWITCHED]	= IPFIX_flowStartSysUpTime,
	[NETFLOW9_OUT_BYTES]		= IPFIX_postOctetDeltaCount,
	[NETFLOW9_OUT_PKTS]		= IPFIX_postPacketDeltaCount,
	[NETFLOW9_IPV6_SRC_ADDR]	= IPFIX_sourceIPv6Address,
	[NETFLOW9_IPV6_DST_ADDR]	= IPFIX_destinationIPv6Address,
	[NETFLOW9_IPV6_SRC_MASK]	= IPFIX_sourceIPv6Mask,
	[NETFLOW9_IPV6_DST_MASK]	= IPFIX_destinationIPv6Mask,
	[NETFLOW9_FLOW_LABEL]		= IPFIX_flowLabelIPv6,
	[NETFLOW9_ICMP_TYPE]		= IPFIX_icmpTypeCodeIPv4,
	[NETFLOW9_MUL_IGMP_TYPE]	= IPFIX_igmpType,
	[NETFLOW9_SAMPLING_INTERVAL]	= 0,
	[NETFLOW9_SAMPLING_ALGORITHM]	= 0,
	[NETFLOW9_FLOW_ACTIVE_TIMEOUT]	= IPFIX_flowActiveTimeOut,
	[NETFLOW9_FLOW_INAVTIVE_TIMEOUT]	= IPFIX_flowInactiveTimeout,
	[NETFLOW9_ENGINE_TYPE]		= 0,
	[NETFLOW9_ENGINE_ID]		= 0,
	[NETFLOW9_TOTAL_BYTES_EXP]	= IPFIX_exportedOctetTotalCount,
	[NETFLOW9_TOTAL_PKTS_EXP]	= IPFIX_exportedMessageTotalCount,
	[NETFLOW9_TOTAL_FLOWS_EXP]	= IPFIX_exportedFlowTotalCount,
	[NETFLOW9_MPLS_TOP_LABEL_TYPE]	= IPFIX_mplsTopLabelType,
	[NETFLOW9_MPLS_TOP_LABEL_IP_ADDR]	= IPFIX_mplsTopLabelIPv4Address,
	[NETFLOW9_FLOW_SAMPLER_ID]	= 0,
	[NETFLOW9_FLOW_SAMPLER_MODE]	= 0,
	[NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL] = 0,
	[NETFLOW9_DST_TOS]		= IPFIX_postClassOfServiceIPv4,
	[NETFLOW9_SRC_MAC]		= IPFIX_sourceMacAddress,
	[NETFLOW9_DST_MAC]		= IPFIX_postDestinationMacAddr,
	[NETFLOW9_SRC_VLAN]		= IPFIX_vlanId,
	[NETFLOW9_DST_VLAN]		= IPFIX_postVlanId,
	[NETFLOW9_IP_PROTOCOL_VERSION]	= IPFIX_ipVersion,
	[NETFLOW9_DIRECTION]		= IPFIX_flowDirection,
	[NETFLOW9_IPV6_NEXT_HOP]	= IPFIX_ipNextHopIPv6Address,
	[NETFLOW9_BGP_IPV6_NEXT_HOP]	= IPFIX_bgpNexthopIPv6Address,
	[NETFLOW9_IPV6_OPTION_HEADERS]	= IPFIX_ipv6ExtensionHeaders,
	[NETFLOW9_MPLS_LABEL_1]		= IPFIX_mplsTopLabelStackEntry,
	[NETFLOW9_MPLS_LABEL_2]		= IPFIX_mplsLabelStackEntry2,
	[NETFLOW9_MPLS_LABEL_3]		= IPFIX_mplsLabelStackEntry3,
	[NETFLOW9_MPLS_LABEL_4]		= IPFIX_mplsLabelStackEntry4,
	[NETFLOW9_MPLS_LABEL_5]		= IPFIX_mplsLabelStackEntry5,
	[NETFLOW9_MPLS_LABEL_6]		= IPFIX_mplsLabelStackEntry6,
	[NETFLOW9_MPLS_LABEL_7]		= IPFIX_mplsLabelStackEntry7,
	[NETFLOW9_MPLS_LABEL_8]		= IPFIX_mplsLabelStackEntry8,
	[NETFLOW9_MPLS_LABEL_9]		= IPFIX_mplsLabelStackEntry9,
	[NETFLOW9_MPLS_LABEL_10]	= IPFIX_mplsLabelStackEntry10,
};

static char *field_name[] = {
	[NETFLOW9_IN_BYTES]		= "IN_BYTES",
	[NETFLOW9_IN_PKTS]		= "IN_PKTS",
	[NETFLOW9_FLOWS]		= "FLOWS",
	[NETFLOW9_PROTOCOL]		= "PROTOCOL",
	[NETFLOW9_TOS]			= "TOS",
	[NETFLOW9_TCP_FLAGS]		= "TCP_FLAGS",
	[NETFLOW9_L4_SRC_PORT]		= "L4_SRC_PORT",
	[NETFLOW9_IPV4_SRC_ADDR]	= "IPV4_SRC_ADDR",
	[NETFLOW9_SRC_MASK]		= "SRC_MASK",
	[NETFLOW9_INPUT_SNMP]		= "INPUT_SNMP",
	[NETFLOW9_L4_DST_PORT]		= "L4_DST_PORT",
	[NETFLOW9_IPV4_DST_ADDR]	= "IPV4_DST_ADDR",
	[NETFLOW9_DST_MASK]		= "DST_MASK",
	[NETFLOW9_OUTPUT_SNMP]		= "OUTPUT_SNMP",
	[NETFLOW9_IPV4_NEXT_HOP]	= "IPV4_NEXT_HOP",
	[NETFLOW9_SRC_AS]		= "SRC_AS",
	[NETFLOW9_DST_AS]		= "DST_AS",
	[NETFLOW9_BGP_IPV4_NEXT_HOP]	= "BGP_IPV4_NEXT_HOP",
	[NETFLOW9_MUL_DST_PKTS]		= "MUL_DST_PKTS",
	[NETFLOW9_MUL_DST_BYTES]	= "MUL_DST_BYTES",
	[NETFLOW9_LAST_SWITCHED]	= "LAST_SWITCHED",
	[NETFLOW9_FIRST_SWITCHED]	= "FIRST_SWITCHED",
	[NETFLOW9_OUT_BYTES]		= "OUT_BYTES",
	[NETFLOW9_OUT_PKTS]		= "OUT_PKTS",
	[NETFLOW9_IPV6_SRC_ADDR]	= "IPV6_SRC_ADDR",
	[NETFLOW9_IPV6_DST_ADDR]	= "IPV6_DST_ADDR",
	[NETFLOW9_IPV6_SRC_MASK]	= "IPV6_SRC_MASK",
	[NETFLOW9_IPV6_DST_MASK]	= "IPV6_DST_MASK",
	[NETFLOW9_FLOW_LABEL]		= "FLOW_LABEL",
	[NETFLOW9_ICMP_TYPE]		= "ICMP_TYPE",
	[NETFLOW9_MUL_IGMP_TYPE]	= "MUL_IGMP_TYPE",
	[NETFLOW9_SAMPLING_INTERVAL]	= "SAMPLING_INTERVAL",
	[NETFLOW9_SAMPLING_ALGORITHM]	= "SAMPLING_ALGORITHM",
	[NETFLOW9_FLOW_ACTIVE_TIMEOUT]	= "FLOW_ACTIVE_TIMEOUT",
	[NETFLOW9_FLOW_INAVTIVE_TIMEOUT]	= "FLOW_INAVTIVE_TIMEOUT",
	[NETFLOW9_ENGINE_TYPE]		= "ENGINE_TYPE",
	[NETFLOW9_ENGINE_ID]		= "ENGINE_ID",
	[NETFLOW9_TOTAL_BYTES_EXP]	= "TOTAL_BYTES_EXP",
	[NETFLOW9_TOTAL_PKTS_EXP]	= "TOTAL_PKTS_EXP",
	[NETFLOW9_TOTAL_FLOWS_EXP]	= "TOTAL_FLOWS_EXP",
	[NETFLOW9_MPLS_TOP_LABEL_TYPE]	= "MPLS_TOP_LABEL_TYPE",
	[NETFLOW9_MPLS_TOP_LABEL_IP_ADDR]	= "MPLS_TOP_LABEL_IP_ADDR",
	[NETFLOW9_FLOW_SAMPLER_ID]	= "FLOW_SAMPLER_ID",
	[NETFLOW9_FLOW_SAMPLER_MODE]	= "FLOW_SAMPLER_MODE",
	[NETFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL] = "FLOW_SAMPLER_RANDOM_INTERVAL",
	[NETFLOW9_DST_TOS]		= "DST_TOS",
	[NETFLOW9_SRC_MAC]		= "SRC_MAC",
	[NETFLOW9_DST_MAC]		= "DST_MAC",
	[NETFLOW9_SRC_VLAN]		= "SRC_VLAN",
	[NETFLOW9_DST_VLAN]		= "DST_VLAN",
	[NETFLOW9_IP_PROTOCOL_VERSION]	= "IP_PROTOCOL_VERSION",
	[NETFLOW9_DIRECTION]		= "DIRECTION",
	[NETFLOW9_IPV6_NEXT_HOP]	= "IPV6_NEXT_HOP",
	[NETFLOW9_BGP_IPV6_NEXT_HOP]	= "BGP_IPV6_NEXT_HOP",
	[NETFLOW9_IPV6_OPTION_HEADERS]	= "IPV6_OPTION_HEADERS",
	[NETFLOW9_MPLS_LABEL_1]		= "MPLS_LABEL_1",
	[NETFLOW9_MPLS_LABEL_2]		= "MPLS_LABEL_2",
	[NETFLOW9_MPLS_LABEL_3]		= "MPLS_LABEL_3",
	[NETFLOW9_MPLS_LABEL_4]		= "MPLS_LABEL_4",
	[NETFLOW9_MPLS_LABEL_5]		= "MPLS_LABEL_5",
	[NETFLOW9_MPLS_LABEL_6]		= "MPLS_LABEL_6",
	[NETFLOW9_MPLS_LABEL_7]		= "MPLS_LABEL_7",
	[NETFLOW9_MPLS_LABEL_8]		= "MPLS_LABEL_8",
	[NETFLOW9_MPLS_LABEL_9]		= "MPLS_LABEL_9",
	[NETFLOW9_MPLS_LABEL_10]	= "MPLS_LABEL_10",
};

struct ulogd_netflow9_template {
	struct llist_head list;
	struct nfct_bitmask *bitmask;
	int until_template;		/* decide if it's time to retransmit our template */
	int tmplset_len, dataset_len;
	struct netflow9_msg_hdr *tmpl_data_msg;	/* include records, set header of template, data */
	struct netflow9_msg_hdr *data_only_msg;	/* include records, set header of data */
};

enum {
	IKEY_IDX_ORIG_PKTCOUNT,
	IKEY_IDX_REPLY_PKTCOUNT,
	IKEY_IDX_IF_INPUT,
	IKEY_IDX_IF_OUTPUT,
	IKEY_IDX_FLOW_DIR,
	IKEY_IDX_MAX = IKEY_IDX_FLOW_DIR,
};

struct netflow9_instance {
	int fd;		/* socket that we use for sending NetFlow v9 data */
	int sock_type;	/* type (SOCK_*) */
	int sock_proto;	/* protocol (IPPROTO_*) */
#define UPTIME_FILE  "/proc/uptime"
	int uptime_fd;
	uint16_t next_template_id;
	struct llist_head template_list;
	struct nfct_bitmask *valid_bitmask;	/* bitmask of valid keys */
	uint32_t seq;
	/* 5.2 Template FlowSet Format */
#define ULOGD_NETFLOW9_TEMPL_BASE 256
	int ikey_idx[IKEY_IDX_MAX + 1];
};

#define orig_pktcount_ii(x)	(x)->ikey_idx[IKEY_IDX_ORIG_PKTCOUNT]
#define reply_pktcount_ii(x)	(x)->ikey_idx[IKEY_IDX_REPLY_PKTCOUNT]
#define if_input_ii(x)		(x)->ikey_idx[IKEY_IDX_IF_INPUT]
#define if_output_ii(x)		(x)->ikey_idx[IKEY_IDX_IF_OUTPUT]
#define flow_dir_ii(x)		(x)->ikey_idx[IKEY_IDX_FLOW_DIR]

static int nflow9_fprintf_header(FILE *fd, const struct netflow9_msg_hdr *hdr,
				 int msglen);

struct ulogd_netflow9_template *
alloc_ulogd_netflow9_template(struct ulogd_pluginstance *upi,
			      struct nfct_bitmask *bm)
{
	struct ulogd_netflow9_template *tmpl;
	unsigned int i;
	int tmpl_len = 0, data_len = 0;

	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = &upi->input.keys[i];
		int length = ulogd_key_size(key);

		if (!nfct_bitmask_test_bit(bm, i))
			continue;
		if (!strncmp(key->name, ORIG_PRE, ORIG_PRELEN))
			continue;

		tmpl_len += sizeof(struct netflow9_templ_rec);
		data_len += length;
	}

	tmpl = calloc(sizeof(struct ulogd_netflow9_template), 1);
	if (tmpl == NULL)
		return NULL;

	tmpl->bitmask = nfct_bitmask_clone(bm);
	if (!tmpl->bitmask)
		goto free_tmpl;

	tmpl->dataset_len = sizeof(struct netflow9_set_hdr) + data_len;
	tmpl->tmplset_len = sizeof(struct netflow9_set_hdr)
		+ sizeof(struct netflow9_templ_hdr) + tmpl_len;
	/* 5.3.  Data FlowSet Format / Padding */
	tmpl->dataset_len = (tmpl->dataset_len + 3U) & ~3U;
	tmpl->tmplset_len = (tmpl->tmplset_len + 3U) & ~3U;

	tmpl->tmpl_data_msg = calloc(sizeof(struct netflow9_msg_hdr)
				     + tmpl->tmplset_len
				     + tmpl->dataset_len * 2, 1);
	if (tmpl->tmpl_data_msg == NULL)
		goto free_bitmask;
	tmpl->data_only_msg = calloc(sizeof(struct netflow9_msg_hdr)
				     + tmpl->dataset_len * 2, 1);
	if (tmpl->data_only_msg == NULL)
		goto free_tmpl_data_msg;

	return tmpl;

free_tmpl_data_msg:
	free(tmpl->tmpl_data_msg);
free_bitmask:
	free(tmpl->bitmask);
free_tmpl:
	free(tmpl);

	return NULL;
}

/* Build the NetFlow v9 template from the input keys */
struct ulogd_netflow9_template *
build_template_for_bitmask(struct ulogd_pluginstance *upi,
			   struct nfct_bitmask *bm)
{
	struct netflow9_instance *ii
		= (struct netflow9_instance *)&upi->private;
	struct ulogd_netflow9_template *tmpl;
	struct netflow9_msg_hdr *msg_hdr;
	struct netflow9_templ_hdr *tmpl_hdr;
	struct netflow9_templ_rec *tmpl_field;
	struct netflow9_set_hdr *set_hdr;
	uint16_t field_count = 0;
	unsigned int i;
	void *ptr;

	tmpl = alloc_ulogd_netflow9_template(upi, bm);
	if (tmpl == NULL)
		return NULL;

	/* build template records */
	ptr = (void *)tmpl->tmpl_data_msg + sizeof(struct netflow9_msg_hdr)
		+ sizeof(struct netflow9_set_hdr) + sizeof(struct netflow9_templ_hdr);
	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = &upi->input.keys[i];
		int length = ulogd_key_size(key);

		if (!nfct_bitmask_test_bit(tmpl->bitmask, i))
			continue;
		if (!strncmp(key->name, ORIG_PRE, ORIG_PRELEN))
			continue;

		tmpl_field = (struct netflow9_templ_rec *)ptr;
		tmpl_field->type = htons(key->ipfix.field_id);
		tmpl_field->length = htons(length);
		ptr += sizeof(struct netflow9_templ_rec);
		field_count++;
	}

	/** initialize netflow v9 message header with template and data */
	msg_hdr = tmpl->tmpl_data_msg;
	msg_hdr->version = htons(9);
	msg_hdr->source_id = htonl(domain_ce(upi->config_kset).u.value);

	/* initialize template set header */
	set_hdr = (void *)msg_hdr + sizeof(*msg_hdr);
	set_hdr->set_id = htons(0); /* 5.2 Template FlowSet Format */
	set_hdr->length = htons(tmpl->tmplset_len);

	/* initialize template record header */
	tmpl_hdr = (void *)set_hdr + sizeof(*set_hdr);
	tmpl_hdr->template_id = htons(ii->next_template_id++);
	tmpl_hdr->field_count = htons(field_count);

	/* initialize data set header 1 */
	set_hdr = (void *)set_hdr + tmpl->tmplset_len;
	set_hdr->set_id = tmpl_hdr->template_id;
	set_hdr->length = htons(tmpl->dataset_len);

	/* initialize data set header 2 */
	set_hdr = (void *)set_hdr + tmpl->dataset_len;
	set_hdr->set_id = tmpl_hdr->template_id;
	set_hdr->length = htons(tmpl->dataset_len);

	/** initialize netflow v9 message header with data only */
	msg_hdr = tmpl->data_only_msg;
	msg_hdr->version = htons(9);
	msg_hdr->source_id = htonl(domain_ce(upi->config_kset).u.value);

	/* initialize data set header 1 */
	set_hdr = (void *)msg_hdr + sizeof(*msg_hdr);
	set_hdr->set_id = tmpl_hdr->template_id;
	set_hdr->length = htons(tmpl->dataset_len);

	/* initialize data set header 2 */
	set_hdr = (void *)set_hdr + tmpl->dataset_len;
	set_hdr->set_id = tmpl_hdr->template_id;
	set_hdr->length = htons(tmpl->dataset_len);

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

static int ulogd_key_putn(struct ulogd_key *key, void *buf)
{
	int ret;

	switch (key->type) {
	case ULOGD_RET_INT8:
	case ULOGD_RET_UINT8:
	case ULOGD_RET_BOOL:
		*(u_int8_t *)buf = ikey_get_u8(key);
		ret = sizeof(u_int8_t);
		break;
	case ULOGD_RET_INT16:
	case ULOGD_RET_UINT16:
		*(u_int16_t *)buf = htons(ikey_get_u16(key));
		ret = sizeof(u_int16_t);
		break;
	case ULOGD_RET_INT32:
	case ULOGD_RET_UINT32:
		*(u_int32_t *)buf = htonl(ikey_get_u32(key));
		ret = sizeof(u_int32_t);
		break;
	case ULOGD_RET_IPADDR:
		*(u_int32_t *)buf = ikey_get_u32(key);
		ret = sizeof(u_int32_t);
		break;
	case ULOGD_RET_INT64:
	case ULOGD_RET_UINT64:
		*(u_int64_t *)buf = __be64_to_cpu(ikey_get_u64(key));
		ret = sizeof(u_int64_t);
		break;
	case ULOGD_RET_IP6ADDR:
		memcpy(buf, ikey_get_u128(key), 16);
		ret = 16;
		break;
	case ULOGD_RET_STRING:
		ret = strlen(key->u.value.ptr);
		memcpy(buf, key->u.value.ptr, ret);
		break;
	case ULOGD_RET_RAW:
		ulogd_log(ULOGD_NOTICE, "put raw data in network byte order "
			  "`%s' type 0x%x\n", key->name, key->type);
		ret = key->len;
		memcpy(buf, key->u.value.ptr, ret);
		break;
	default:
		ulogd_log(ULOGD_ERROR, "unknown size - key "
			  "`%s' type 0x%x\n", key->name, key->type);
		ret = -1;
		break;
	}

	return ret;
}

static int put_data_records(struct ulogd_pluginstance *upi,
			    struct ulogd_netflow9_template *tmpl,
			    char *exprefix, size_t exlen, void *buf)
{
	struct ulogd_key *keys = upi->input.keys;
	int ret;
	unsigned int i, len = 0;

	for (i = 0; i < upi->input.num_keys; i++) {
		if (!nfct_bitmask_test_bit(tmpl->bitmask, i))
			continue;
		if (!strncmp(keys[i].name, exprefix, exlen))
			continue;
		ret = ulogd_key_putn(&keys[i], buf + len);
		if (ret < 0)
			return ret;
		len += ret;
	}

	return len;
}

static enum nflow9_field_dir data_direction(struct ulogd_pluginstance *upi)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&upi->private;
	struct ulogd_key *keys = upi->input.keys;
	int ret = 0;

	ret |= pp_is_valid(keys, orig_pktcount_ii(ii))
		&& ikey_get_u64(&keys[orig_pktcount_ii(ii)]) != 0
		? NFLOW9_DIR_ORIG : 0;
	ret |= pp_is_valid(keys, reply_pktcount_ii(ii))
		&& ikey_get_u64(&keys[reply_pktcount_ii(ii)]) != 0
		? NFLOW9_DIR_REPLY : 0;
	return ret;
}

/*
 * XXX: overwrite ikeys
 */
int reverse_direction(struct netflow9_instance *ii, struct ulogd_key *keys)
{
	if (if_input_ii(ii) >= 0 && if_output_ii(ii) >= 0) {
		int ifin = ikey_get_u32(&keys[if_input_ii(ii)]);
		keys[if_input_ii(ii)].u.source->u.value.ui32
			= ikey_get_u32(&keys[if_output_ii(ii)]);
		keys[if_output_ii(ii)].u.source->u.value.ui32 = ifin;
	}
	if (flow_dir_ii(ii) >= 0)
		keys[flow_dir_ii(ii)].u.source->u.value.ui8
			= !keys[flow_dir_ii(ii)].u.source->u.value.ui8;
	return 0;
}

static struct netflow9_msg_hdr
*build_netflow9_msg(struct ulogd_pluginstance *upi,
		    struct ulogd_netflow9_template *template,
		    enum nflow9_field_dir dir, bool need_template)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&upi->private;
	struct netflow9_msg_hdr *msg_hdr;
	void *data_records;
	int ret, maxlen;

	maxlen = template->dataset_len - sizeof(struct netflow9_set_hdr);
	if (need_template) {
		msg_hdr = template->tmpl_data_msg;
		data_records = (void *)msg_hdr
			+ sizeof(struct netflow9_msg_hdr)
			+ template->tmplset_len
			+ sizeof(struct netflow9_set_hdr);
	} else {
		msg_hdr = template->data_only_msg;
		data_records = (void *)msg_hdr
			+ sizeof(struct netflow9_msg_hdr)
			+ sizeof(struct netflow9_set_hdr);
	}
	memset(data_records, 0, maxlen);

	switch (dir) {
	case 0:
		ulogd_log(ULOGD_NOTICE, "receive zero counter data");
		return NULL;
		break;
	case NFLOW9_DIR_ORIG:
		ret = put_data_records(upi, template,
				       REPLY_PRE, REPLY_PRELEN, data_records);
		break;
	case NFLOW9_DIR_REPLY:
		reverse_direction(ii, upi->input.keys);
		ret = put_data_records(upi, template,
				       ORIG_PRE, ORIG_PRELEN, data_records);
		break;
	case NFLOW9_DIR_BOTH:
		ret = put_data_records(upi, template,
				       REPLY_PRE, REPLY_PRELEN, data_records);
		if (ret < 0) {
			ulogd_log(ULOGD_ERROR, "could not build netflow v9 dataset");
			return NULL;
		} else if (ret > maxlen) {
			ulogd_log(ULOGD_ERROR, "overflowed on building"
				  "netflow v9 dataset - expect: < %d but: %d\n",
				  maxlen, ret);
			return NULL;
		}
		data_records += template->dataset_len;
		memset(data_records, 0, maxlen);
		reverse_direction(ii, upi->input.keys);
		ret = put_data_records(upi, template,
				       ORIG_PRE, ORIG_PRELEN, data_records);
		break;
	default:
		ulogd_log(ULOGD_ERROR, "data_direction() returns invalid");
		return NULL;
	}
	if (ret < 0) {
		ulogd_log(ULOGD_ERROR, "could not build netflow v9 dataset");
		return NULL;
	} else if (ret > maxlen) {
		ulogd_log(ULOGD_ERROR, "overflowed on building"
			  "netflow v9 dataset - expect: < %d but: %d\n",
			  maxlen, ret);
		return NULL;
	}

	return msg_hdr;
}

static uint32_t uptime_millis(int fd)
{
	char buf[1024];
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

static int output_netflow9(struct ulogd_pluginstance *upi)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&upi->private;
	struct ulogd_netflow9_template *template;
	struct netflow9_msg_hdr *netflow9_msg;
	unsigned int i;
	int nsent;
	uint16_t msglen;
	uint16_t flowset_count;
	enum nflow9_field_dir dir = data_direction(upi);
	bool need_template = false;

	/* FIXME: it would be more cache efficient if the IS_VALID
	 * flags would be a separate bitmask outside of the array.
	 * ulogd core could very easily flush it after every packet,
	 * too. */

	nfct_bitmask_clear(ii->valid_bitmask);

	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = &upi->input.keys[i];
		int length = ulogd_key_size(key);

		if (length < 0 || length > 0xfffe)
			continue;
		if (!(key->u.source->flags & ULOGD_RETF_VALID))
			continue;
		if (key->ipfix.field_id == 0
		    || key->ipfix.field_id > NETFLOW9_FIELD_MAX
		    || (key->ipfix.vendor != IPFIX_VENDOR_IETF
			&& key->ipfix.vendor != IPFIX_VENDOR_REVERSE)
		    || ipfix_map[key->ipfix.field_id] == 0)
			continue;

		nfct_bitmask_set_bit(ii->valid_bitmask, i);
	}

	/* lookup template ID for this bitmask */
	template = find_template_for_bitmask(upi, ii->valid_bitmask);
	if (!template) {
		ulogd_log(ULOGD_INFO, "building new template\n");
		template = build_template_for_bitmask(upi, ii->valid_bitmask);
		if (!template) {
			ulogd_log(ULOGD_ERROR, "can't build new template!\n");
			return ULOGD_IRET_ERR;
		}
		llist_add(&template->list, &ii->template_list);
	}

	msglen = sizeof(struct netflow9_msg_hdr);
	if (template->until_template == 0) {
		need_template = true;
		template->until_template
			= template_per_ce(upi->config_kset).u.value;
		msglen += template->tmplset_len;
		if (dir == NFLOW9_DIR_BOTH) {
			flowset_count = 3;
			msglen += template->dataset_len * 2;
		} else {
			flowset_count = 2;
			msglen += template->dataset_len;
		}
	} else if (dir == NFLOW9_DIR_BOTH) {
		flowset_count = 2;
		msglen += template->dataset_len * 2;
	} else {
		flowset_count = 1;
		msglen += template->dataset_len;
	}
	template->until_template--;

	netflow9_msg = build_netflow9_msg(upi, template, dir, need_template);
	if (netflow9_msg == NULL)
		return ULOGD_IRET_ERR;

	netflow9_msg->sys_uptime = htonl((u_int32_t)uptime_millis(ii->uptime_fd));
	netflow9_msg->unix_secs = htonl((u_int32_t)(time(NULL)));
	netflow9_msg->count = htons(flowset_count);
	netflow9_msg->sequence_number = htonl(ii->seq++);

	nflow9_fprintf_header(stdout, netflow9_msg, msglen);

	nsent = send(ii->fd, netflow9_msg, msglen, 0);
	if (nsent != msglen) {
		if (nsent == -1)
			ulogd_log(ULOGD_ERROR, "send: %s\n", strerror(errno));
		ulogd_log(ULOGD_ERROR, "send - arg: %d, ret: %d\n", msglen, nsent);
		return ULOGD_IRET_ERR;
	}

#ifdef DEBUG_OUTBK_DIR
	{
		int bkfd;
		char bkname[4096];

		snprintf(bkname, sizeof(bkname),
			 DEBUG_OUTBK_DIR "/%03d.bk", ii->seq);
		bkfd = open(bkname, O_CREAT|O_WRONLY|O_TRUNC, S_IWUSR);
		if (bkfd >= 0) {
			write(bkfd, netflow9_msg, msglen);
			close(bkfd);
		}
	}
#endif
	return ULOGD_IRET_OK;
}

static int open_connect_socket(struct ulogd_pluginstance *pi)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&pi->private;
	struct addrinfo hint, *res, *resave;
	int ret;

	memset(&hint, 0, sizeof(hint));
	hint.ai_socktype = ii->sock_type;
	hint.ai_protocol = ii->sock_proto;
	hint.ai_flags = AI_ADDRCONFIG;

	ret = getaddrinfo(host_ce(pi->config_kset).u.string,
			  port_ce(pi->config_kset).u.string,
			  &hint, &res);
	if (ret != 0) {
		ulogd_log(ULOGD_ERROR, "can't resolve host/service: %s\n",
			  gai_strerror(ret));
		return -1;
	}

	resave = res;

	for (; res; res = res->ai_next) {
		ii->fd = socket(res->ai_family, res->ai_socktype,
				res->ai_protocol);
		if (ii->fd < 0) {
			switch (errno) {
			case EACCES:
			case EAFNOSUPPORT:
			case EINVAL:
			case EPROTONOSUPPORT:
				/* try next result */
				continue;
			default:
				ulogd_log(ULOGD_ERROR, "error: %s\n",
					  strerror(errno));
				break;
			}
		}

		if (connect(ii->fd, res->ai_addr, res->ai_addrlen) != 0) {
			close(ii->fd);
			/* try next result */
			continue;
		}

		/* if we reach this, we have a working connection */
		ulogd_log(ULOGD_NOTICE, "connection established\n");
		freeaddrinfo(resave);
		return 0;
	}

	freeaddrinfo(resave);
	return -1;
}

static int start_netflow9(struct ulogd_pluginstance *pi)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&pi->private;
	int ret;

	ulogd_log(ULOGD_DEBUG, "starting netflow9\n");

	ii->valid_bitmask = nfct_bitmask_new(pi->input.num_keys);
	if (!ii->valid_bitmask)
		return -ENOMEM;

	INIT_LLIST_HEAD(&ii->template_list);

	ret = open_connect_socket(pi);
	if (ret < 0) {
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

	ii->next_template_id = ULOGD_NETFLOW9_TEMPL_BASE;

	return 0;

out_close_sock:
	close(ii->fd);
out_bm_free:
	nfct_bitmask_destroy(ii->valid_bitmask);
	ii->valid_bitmask = NULL;

	return ret;
}

static int stop_netflow9(struct ulogd_pluginstance *pi)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&pi->private;

	close(ii->uptime_fd);
	close(ii->fd);
	nfct_bitmask_destroy(ii->valid_bitmask);
	ii->valid_bitmask = NULL;

	return 0;
}

static void signal_handler_netflow9(struct ulogd_pluginstance *pi, int signal)
{
	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "netflow9: reopening connection\n");
		stop_netflow9(pi);
		start_netflow9(pi);
		break;
	default:
		break;
	}
}

static int configure_netflow9(struct ulogd_pluginstance *pi,
			      struct ulogd_pluginstance_stack *stack)
{
	struct netflow9_instance *ii = (struct netflow9_instance *)&pi->private;
	char *proto_str = proto_ce(pi->config_kset).u.string;
	unsigned int i;
	int ret;

	/* FIXME: error handling */
	ulogd_log(ULOGD_DEBUG, "parsing config file section %s\n", pi->id);
	ret = config_parse_file(pi->id, pi->config_kset);
	if (ret < 0)
		return ret;

	/* determine underlying protocol */
	if (!strcasecmp(proto_str, "udp")) {
		ii->sock_type = SOCK_DGRAM;
		ii->sock_proto = IPPROTO_UDP;
	} else {
		ulogd_log(ULOGD_ERROR, "only udp is supported, sorry\n",
			  proto_ce(pi->config_kset));
		return -EINVAL;
	}

	/* postpone address lookup to ->start() time, since we want to
	 * re-lookup an address on SIGHUP */

	ret = ulogd_wildcard_inputkeys(pi);
	if (ret < 0)
		return ret;

	for (i = 0; i < sizeof(ii->ikey_idx); i++)
		ii->ikey_idx[i] = -1;
	for (i = 0; i < pi->input.num_keys; i++) {
		if (!strcmp(pi->input.keys[i].name, ORIGCOUNT_KEYNAME))
			orig_pktcount_ii(ii) = i;
		else if (!strcmp(pi->input.keys[i].name, REPLYCOUNT_KEYNAME))
			reply_pktcount_ii(ii) = i;
		else
			switch (pi->input.keys[i].ipfix.field_id) {
			case IPFIX_ingressInterface:
				if_input_ii(ii) = i;
				break;
			case IPFIX_egressInterface:
				if_output_ii(ii) = i;
				break;
			case IPFIX_flowDirection:
				flow_dir_ii(ii) = i;
				break;
			default:
				break;
			}
		if (!prime9_ce(pi->config_kset).u.value)
			continue;
		if (!strcmp(pi->input.keys[i].name,
			    "orig.raw.pktlen.delta")
		    || !strcmp(pi->input.keys[i].name,
			       "orig.raw.pktcount.delta")
		    || !strcmp(pi->input.keys[i].name,
			       "reply.raw.pktlen.delta")
		    || !strcmp(pi->input.keys[i].name,
			       "reply.raw.pktcount.delta")
		    || !strcmp(pi->input.keys[i].name,
			       "oob.ifindex_in")
		    || !strcmp(pi->input.keys[i].name,
			       "oob.ifindex_out"))
			pi->input.keys[i].ipfix.field_id = 0;
	}
	if (orig_pktcount_ii(ii) == 0 || reply_pktcount_ii(ii) == 0) {
		ulogd_log(ULOGD_ERROR, "requires both input keys - %s and %s\n",
			  ORIGCOUNT_KEYNAME, REPLYCOUNT_KEYNAME);
		return -1;
	}
	return 0;
}

static struct ulogd_plugin netflow9_plugin = {
	.name = "NFLOW9",
	.input = {
		.type = ULOGD_DTYPE_FLOW,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset 	= &netflow9_kset,
	.priv_size 	= sizeof(struct netflow9_instance),

	.configure	= &configure_netflow9,
	.start	 	= &start_netflow9,
	.stop	 	= &stop_netflow9,

	.interp 	= &output_netflow9,
	.signal 	= &signal_handler_netflow9,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&netflow9_plugin);
}

static int nflow9_fprintf_field(FILE *fd, const struct netflow9_templ_rec *field, int len)
{
	int ret;
	void *ptr;

	if (len < (int)sizeof(*field)) {
		fprintf(fd, "ERROR ietf field: too short buflen: %d\n", len);
		return -1;
	}

	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "| Field Type: %18s |            Field Length: %5d |\n",
		field_name[ntohs(field->type)], ntohs(field->length));

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

	fprintf(fd, "+-----------------------------------------------------------------+\n");
	/* don't say messy...*/
	for (i = 0; i < len; i += 4) {
		switch (len - i - 4) {
		case -3:
			fprintf(fd, "|          0x%02x                                                   |\n",
				*(u_int8_t *)(data + i));
			break;
		case -2:
			fprintf(fd, "|          0x%02x          0x%02x                                     |\n",
				*(u_int8_t *)(data + i), *(u_int8_t *)(data + i + 1));
			break;
		case -1:
			fprintf(fd, "|          0x%02x          0x%02x          0x%02x                       |\n",
				*(u_int8_t *)(data + i), *(u_int8_t *)(data + i + 1), *(u_int8_t *)(data + i + 2));
			break;
		default:
			fprintf(fd, "|          0x%02x          0x%02x          0x%02x          0x%02x         |\n",
				*(u_int8_t *)(data + i), *(u_int8_t *)(data + i + 1),
				*(u_int8_t *)(data + i + 2), *(u_int8_t *)(data + i + 3));
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

	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|             Template ID: %5d |             Field Count: %5d |\n",
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

	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|                  Set ID: %5d |                  Length: %5d |\n",
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

	fprintf(fd, "+-----------------------------------------------------------------+\n");
	return total_len + ret;
}

static int nflow9_fprintf_header(FILE *fd, const struct netflow9_msg_hdr *hdr,
				 int msglen)
{
	int ret, len;
	char outstr[20];
	void *ptr;
	time_t t = (time_t)(ntohl(hdr->unix_secs));
	struct tm *tmp = localtime(&t);

	/* XXX: tmp == NULL and strftime == 0 */
	strftime(outstr, sizeof(outstr), "%F %T", tmp);

	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|          Version Number: %5d |                   Count: %5d | (Length: %d) \n",
		ntohs(hdr->version), ntohs(hdr->count), msglen);
	fprintf(fd, "+-----------------------------------------------------------------+\n");
	fprintf(fd, "|                       sysUpTime: %10u                     |\n",
		ntohl(hdr->sys_uptime));
	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|                       UNIX Secs: %10u                     |\t%s\n",
		ntohl(hdr->unix_secs), outstr);
	fprintf(fd, "+-----------------------------------------------------------------+\n");
	fprintf(fd, "|                 Sequence Number: %10d                     |\n",
		ntohl(hdr->sequence_number));
	fprintf(fd, "+-----------------------------------------------------------------+\n");
	fprintf(fd, "|                       Source ID: %10d                     |\n",
		ntohl(hdr->source_id));
	fprintf(fd, "+-----------------------------------------------------------------+\n");

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
