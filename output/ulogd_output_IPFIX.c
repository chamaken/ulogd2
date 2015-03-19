/* ulogd_output_IPFIX.c
 *
 * ulogd output plugin for IPFIX
 *
 * This target produces a file which looks the same like the syslog-entries
 * of the LOG target.
 *
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
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
 * TODO:
 * - where to get a useable <sctp.h> for linux ?
 * - implement PR-SCTP (no api definition in draft sockets api)
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

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <ulogd/linuxlist.h>

#ifdef IPPROTO_SCTP
/* temporarily disable sctp until we know which headers to use */
#undef IPPROTO_SCTP
#endif

#ifdef IPPROTO_SCTP
typedef u_int32_t sctp_assoc_t;

/* glibc doesn't yet have this, as defined by
 * draft-ietf-tsvwg-sctpsocket-11.txt */
struct sctp_sndrcvinfo {
	u_int16_t	sinfo_stream;
	u_int16_t	sinfo_ssn;
	u_int16_t	sinfo_flags;
	u_int32_t	sinfo_ppid;
	u_int32_t	sinfo_context;
	u_int32_t	sinfo_timetolive;
	u_int32_t	sinfo_tsn;
	u_int32_t	sinfo_cumtsn;
	sctp_assoc_t	sinfo_assoc_id;
};
#endif

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

#define IPFIX_DEFAULT_TCPUDP_PORT	4739

enum {
	IPFIX_CONF_HOST	= 0,
	IPFIX_CONF_PORT,
	IPFIX_CONF_PROTO,
	IPFIX_CONF_DOMAIN_ID,
	IPFIX_CONF_NTH_TEMPLATE,
	IPFIX_CONF_MAX = IPFIX_CONF_NTH_TEMPLATE,
};

static struct config_keyset ipfix_kset = {
	.num_ces = 5,
	.ces = {
		[IPFIX_CONF_HOST] = {
			.key 	 = "host",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		[IPFIX_CONF_PORT] = {
			.key	 = "port",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	 = { .string = "4739" },
		},
		[IPFIX_CONF_PROTO] = {
			.key	 = "protocol",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	= { .string = "udp" },
		},
		[IPFIX_CONF_DOMAIN_ID] = {
			.key	 = "domain_id",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[IPFIX_CONF_NTH_TEMPLATE] = {
			.key	 = "nth_template",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 16,
		},
	},
};

#define host_ce(x)	(x->ces[IPFIX_CONF_HOST])
#define port_ce(x)	(x->ces[IPFIX_CONF_PORT])
#define proto_ce(x)	(x->ces[IPFIX_CONF_PROTO])
#define domain_ce(x)	(x->ces[IPFIX_CONF_DOMAIN_ID])
#define nth_template_ce(x)	(x->ces[IPFIX_CONF_NTH_TEMPLATE])

struct ipfix_template {
	struct ipfix_templ_rec_hdr hdr;
	char buf[0];
};

struct ulogd_ipfix_template {
	struct llist_head list;
	struct nfct_bitmask *bitmask;
	unsigned int data_length;	/* length of the DATA */
	void *tmpl_cur;			/* cursor into current template position */
	struct ipfix_template tmpl;
	int until_template;			/* decide if it's time to retransmit our template */
};

struct ipfix_instance {
	int fd;		/* socket that we use for sending IPFIX data */
	int sock_type;	/* type (SOCK_*) */
	int sock_proto;	/* protocol (IPPROTO_*) */

	struct llist_head template_list;
	struct nfct_bitmask *valid_bitmask;	/* bitmask of valid keys */
	u_int32_t seq;
};

#define ULOGD_IPFIX_TEMPL_BASE 1024
static u_int16_t next_template_id = ULOGD_IPFIX_TEMPL_BASE;

static int ipfix_fprintf_header(FILE *fd, const struct ipfix_msg_hdr *hdr);

/* Build the IPFIX template from the input keys */
struct ulogd_ipfix_template *
build_template_for_bitmask(struct ulogd_pluginstance *upi,
			   struct nfct_bitmask *bm)
{
	struct ulogd_ipfix_template *tmpl;
	unsigned int i, j;
	int size = sizeof(struct ulogd_ipfix_template)
		   + (upi->input.num_keys * sizeof(struct ipfix_vendor_field));

	tmpl = malloc(size);
	if (!tmpl)
		return NULL;
	memset(tmpl, 0, size);

	tmpl->bitmask = nfct_bitmask_clone(bm);
	if (!tmpl->bitmask) {
		free(tmpl);
		return NULL;
	}

	/* initialize template header */
	tmpl->tmpl.hdr.templ_id = htons(next_template_id++);

	tmpl->tmpl_cur = tmpl->tmpl.buf;

	tmpl->data_length = 0;
	tmpl->until_template = nth_template_ce(upi->config_kset).u.value;

	for (i = 0, j = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = &upi->input.keys[i];
		int length = ulogd_key_size(key);

		if (!nfct_bitmask_test_bit(tmpl->bitmask, i))
			continue;

		if (key->ipfix.vendor == IPFIX_VENDOR_IETF) {
			struct ipfix_ietf_field *field = 
				(struct ipfix_ietf_field *) tmpl->tmpl_cur;

			field->type = htons(key->ipfix.field_id);
			field->length = htons(length);
			tmpl->tmpl_cur += sizeof(*field);
		} else {
			struct ipfix_vendor_field *field =
				(struct ipfix_vendor_field *) tmpl->tmpl_cur;

			field->type = htons(key->ipfix.field_id | 0x8000);
			field->enterprise_num = htonl(key->ipfix.vendor);
			field->length = htons(length);
			tmpl->tmpl_cur += sizeof(*field);
		}
		tmpl->data_length += length;
		j++;
	}

	tmpl->tmpl.hdr.field_count = htons(j);

	return tmpl;
}

static struct ulogd_ipfix_template *
find_template_for_bitmask(struct ulogd_pluginstance *upi,
			  struct nfct_bitmask *bm)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &upi->private;
	struct ulogd_ipfix_template *tmpl;
	
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
		ret = 1;
		break;
	case ULOGD_RET_INT16:
	case ULOGD_RET_UINT16:
		*(u_int16_t *)buf = htons(ikey_get_u16(key));
		ret = 2;
		break;
	case ULOGD_RET_INT32:
	case ULOGD_RET_UINT32:
		*(u_int32_t *)buf = htonl(ikey_get_u32(key));
		ret = 4;
		break;
	case ULOGD_RET_IPADDR:
		*(u_int32_t *)buf = ikey_get_u32(key);
		ret = 4;
		break;
	case ULOGD_RET_INT64:
	case ULOGD_RET_UINT64:
		*(u_int64_t *)buf = __be64_to_cpu(ikey_get_u64(key));
		ret = 8;
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
			    struct ulogd_ipfix_template *tmpl, void *buf)
{
	int ret;
	unsigned int i, len = 0;

	for (i = 0; i < upi->input.num_keys; i++) {
		if (!nfct_bitmask_test_bit(tmpl->bitmask, i))
			continue;
		ret = ulogd_key_putn(&upi->input.keys[i], buf + len);
		if (ret < 0)
			return ret;
		len += ret;
	}

	return len;
}

static struct ipfix_msg_hdr *build_ipfix_msg(struct ulogd_pluginstance *upi,
					     struct ulogd_ipfix_template *template,
					     bool need_template)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &upi->private;
	u_int16_t tmpl_len;
	struct ipfix_msg_hdr *msg_hdr;
	struct ipfix_templ_rec_hdr *tmpl_hdr;
	struct ipfix_set_hdr *data_hdr, *tmpl_set_hdr;
	void *buf;
	int msglen, ret;

	msglen = sizeof(struct ipfix_msg_hdr) + sizeof(struct ipfix_set_hdr)
		+ template->data_length;
	if (need_template)
		msglen = msglen + sizeof(struct ipfix_set_hdr)
			+ (template->tmpl_cur - (void *)&template->tmpl);
	buf = malloc(msglen);
	if (buf == NULL)
		return NULL;
	memset(buf, 0, msglen);

	/* ipfix msg header */
	msg_hdr = buf;
	msg_hdr->version = htons(10);
	msg_hdr->length = htons(msglen);
	msg_hdr->seq = htonl(ii->seq++);
	msg_hdr->domain_id = htonl(domain_ce(upi->config_kset).u.value);
	if (need_template) {
		/* put set header and template records */
		tmpl_set_hdr = buf + sizeof(*msg_hdr);
		tmpl_set_hdr->set_id = htons(2);
		tmpl_len = template->tmpl_cur - (void *)&template->tmpl;
		tmpl_set_hdr->length = htons(sizeof(*tmpl_set_hdr) + tmpl_len);
		tmpl_hdr = (void *)tmpl_set_hdr + sizeof(*tmpl_set_hdr);
		memcpy((void *)tmpl_hdr, (void *)&template->tmpl, tmpl_len);
		data_hdr = (void *)tmpl_hdr + tmpl_len;
	} else {
		data_hdr = buf + sizeof(*msg_hdr);
	}

	/* put set header and data records */
	data_hdr->set_id = template->tmpl.hdr.templ_id; /* already ordered */
	data_hdr->length = htons(sizeof(*data_hdr) + template->data_length);
	ret = put_data_records(upi, template, (void *)data_hdr + sizeof(*data_hdr));
	if (ret < 0) {
		ulogd_log(ULOGD_ERROR, "could not build ipfix dataset");
		goto free_buf;
	} else if (ret > msglen) {
		ulogd_log(ULOGD_ERROR, "overflowed on building ipfix dataset");
		goto free_buf;
	}

	return msg_hdr;

free_buf:
	free(buf);
	return NULL;
}

static int output_ipfix(struct ulogd_pluginstance *upi)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &upi->private;
	struct ulogd_ipfix_template *template;
	struct ipfix_msg_hdr *ipfix_msg;
	unsigned int i;
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
		if (key->ipfix.field_id == 0)
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
		need_template = true;
	}
	
	if (template->until_template-- == 0) {
		need_template = true;
		template->until_template = nth_template_ce(upi->config_kset).u.value;
	}

	ipfix_msg = build_ipfix_msg(upi, template, need_template);
	if (ipfix_msg == NULL)
		return ULOGD_IRET_ERR;

	ipfix_msg->export_time = htonl((u_int32_t)(time(NULL)));
	ipfix_fprintf_header(stdout, ipfix_msg);
	fprintf(stdout, "\n");

	free(ipfix_msg);
	return ULOGD_IRET_OK;
}

static int open_connect_socket(struct ulogd_pluginstance *pi)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &pi->private;
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

#ifdef IPPROTO_SCTP
		/* Set the number of SCTP output streams */
		if (res->ai_protocol == IPPROTO_SCTP) {
			struct sctp_initmsg initmsg;
			int ret; 
			memset(&initmsg, 0, sizeof(initmsg));
			initmsg.sinit_num_ostreams = 2;
			ret = setsockopt(ii->fd, IPPROTO_SCTP, SCTP_INITMSG,
					 &initmsg, sizeof(initmsg));
			if (ret < 0) {
				ulogd_log(ULOGD_ERROR, "cannot set number of"
					  "sctp streams: %s\n",
					  strerror(errno));
				close(ii->fd);
				freeaddrinfo(resave);
				return ret;
			}
		}
#endif

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

static int start_ipfix(struct ulogd_pluginstance *pi)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &pi->private;
	int ret;

	ulogd_log(ULOGD_DEBUG, "starting ipfix\n");

	ii->valid_bitmask = nfct_bitmask_new(pi->input.num_keys);
	if (!ii->valid_bitmask)
		return -ENOMEM;

	INIT_LLIST_HEAD(&ii->template_list);

	ret = open_connect_socket(pi);
	if (ret < 0)
		goto out_bm_free;

	return 0;

out_bm_free:
	nfct_bitmask_destroy(ii->valid_bitmask);
	ii->valid_bitmask = NULL;

	return ret;
}

static int stop_ipfix(struct ulogd_pluginstance *pi) 
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &pi->private;

	close(ii->fd);

	nfct_bitmask_destroy(ii->valid_bitmask);
	ii->valid_bitmask = NULL;

	return 0;
}

static void signal_handler_ipfix(struct ulogd_pluginstance *pi, int signal)
{
	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "ipfix: reopening connection\n");
		stop_ipfix(pi);
		start_ipfix(pi);
		break;
	default:
		break;
	}
}
	
static int configure_ipfix(struct ulogd_pluginstance *pi,
			    struct ulogd_pluginstance_stack *stack)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &pi->private;
	char *proto_str = proto_ce(pi->config_kset).u.string;
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
	} else if (!strcasecmp(proto_str, "tcp")) {
		ii->sock_type = SOCK_STREAM;
		ii->sock_proto = IPPROTO_TCP;
#ifdef IPPROTO_SCTP
	} else if (!strcasecmp(proto_str, "sctp")) {
		ii->sock_type = SOCK_SEQPACKET;
		ii->sock_proto = IPPROTO_SCTP;
#endif
#ifdef _HAVE_DCCP
	} else if (!strcasecmp(proto_str, "dccp")) {
		ii->sock_type = SOCK_SEQPACKET;
		ii->sock_proto = IPPROTO_DCCP;
#endif
	} else {
		ulogd_log(ULOGD_ERROR, "unknown protocol `%s'\n",
			  proto_ce(pi->config_kset));
		return -EINVAL;
	}

	/* postpone address lookup to ->start() time, since we want to 
	 * re-lookup an address on SIGHUP */

	return ulogd_wildcard_inputkeys(pi);
}

static struct ulogd_plugin ipfix_plugin = { 
	.name = "IPFIX",
	.input = {
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW, 
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset 	= &ipfix_kset,
	.priv_size 	= sizeof(struct ipfix_instance),

	.configure	= &configure_ipfix,
	.start	 	= &start_ipfix,
	.stop	 	= &stop_ipfix,

	.interp 	= &output_ipfix, 
	.signal 	= &signal_handler_ipfix,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&ipfix_plugin);
}

static int ipfix_fprintf_ietf_field(FILE *fd, const struct ipfix_ietf_field *field, int len);
static int ipfix_fprintf_vendor_field(FILE *fd, const struct ipfix_vendor_field *field, int len);

static int ipfix_fprintf_ietf_field(FILE *fd, const struct ipfix_ietf_field *field,
				    int len)
{
	int ret;
	void *ptr;

	if (len < (int)sizeof(*field)) {
		fprintf(fd, "ERROR ietf field: too short buflen for IETF field: %d\n", len);
		return -1;
	}

	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|0 Information Emement id: %5d |            Field Length: %5d |\n",
		ntohs(field->type), ntohs(field->length));

	len -= sizeof(*field);
	if (len == 0)
		return sizeof(*field);

	ptr = (void *)field + sizeof(*field);
	if (*(u_int8_t *)ptr & 0x80)
		ret = ipfix_fprintf_vendor_field(fd, ptr, len);
	else
		ret = ipfix_fprintf_ietf_field(fd, ptr, len);

	if (ret == -1)
		return -1;
	return ret + sizeof(*field);
}

static int ipfix_fprintf_vendor_field(FILE *fd, const struct ipfix_vendor_field *field,
				      int len)
{
	int ret;
	void *ptr;

	if (len < (int)sizeof(*field)) {
		fprintf(fd, "ERROR vendor field: too short buflen for vendor field: %d\n", len);
		return -1;
	}

	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|1 Information Emement id: %5d |            Field Length: %5d |\n",
		ntohs(field->type) & 0x7fff, ntohs(field->length));
	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|               Enterprise Number: %10d                     |\n",
		ntohl(field->enterprise_num));

	len -= sizeof(*field);
	if (len == 0)
		return sizeof(*field);

	ptr = (void *)field + sizeof(*field);
	if (*(u_int8_t *)ptr & 0x80) /* vendor */
		ret = ipfix_fprintf_vendor_field(fd, ptr, len);
	else /* ietf */
		ret = ipfix_fprintf_ietf_field(fd, ptr, len);

	if (ret == -1)
		return -1;
	return ret + sizeof(*field);
}

static int ipfix_fprintf_data_records(FILE *fd, const void *data, int len)
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

static int ipfix_fprintf_template_records(FILE *fd, const struct ipfix_templ_rec_hdr *hdr,
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
		ntohs(hdr->templ_id), ntohs(hdr->field_count));

	len -= sizeof(*hdr);
	if (len == 0)
		return sizeof(*hdr);

	field = (void *)hdr + sizeof(*hdr);
	if (*(u_int8_t *)field & 0x80)
		ret = ipfix_fprintf_vendor_field(fd, field, len);
	else
		ret = ipfix_fprintf_ietf_field(fd, field, len);

	if (ret == -1)
		return -1;
	return ret + sizeof(*hdr);
}

static int ipfix_fprintf_set_header(FILE *fd, const struct ipfix_set_hdr *hdr, int len)
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
	case 2:
		ret = ipfix_fprintf_template_records(fd, ptr, setlen);
		break;
	case 3:
		/* XXX: ret = ipfix_fprintf_options_template_records(fd, ptr, setlen); */
		fprintf(fd, "ERROR: options template is not implemented yet, sorry");
		ret = setlen;
		break;
	default:
		ret = ipfix_fprintf_data_records(fd, ptr, setlen);
		break;
	}

	if (ret == -1 || ret != setlen)
		return -1;

	fprintf(fd, "+-----------------------------------------------------------------+\n");
	return total_len + ret;
}

static int ipfix_fprintf_header(FILE *fd, const struct ipfix_msg_hdr *hdr)
{
	int ret, len;
	char outstr[20];
	void *ptr;
	time_t t = (time_t)(ntohl(hdr->export_time));
	struct tm *tmp = localtime(&t);

	/* XXX: tmp == NULL and strftime == 0 */
	strftime(outstr, sizeof(outstr), "%F %T", tmp);

	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|          Version Number: %5d |                  Length: %5d |\n",
		ntohs(hdr->version), ntohs(hdr->length));
	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|                     Exoprt Time: %10d                     |\t%s\n",
		ntohl(hdr->export_time), outstr);
	fprintf(fd, "+-----------------------------------------------------------------+\n");
	fprintf(fd, "|                 Sequence Number: %10d                     |\n",
		ntohl(hdr->seq));
	fprintf(fd, "+-----------------------------------------------------------------+\n");
	fprintf(fd, "|           Observation Domain ID: %10d                     |\n",
		ntohl(hdr->domain_id));
	fprintf(fd, "+-----------------------------------------------------------------+\n");

	len = ntohs(hdr->length) - sizeof(*hdr);
	ptr = (void *)hdr + sizeof(*hdr);

	while (len > 0) {
		ret = ipfix_fprintf_set_header(fd, ptr, len);
		if (ret == -1)
			return -1;
		len -= ret;
		ptr += ret;
	}

	return ntohs(hdr->length) - len;
}
