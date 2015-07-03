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
typedef uint32_t sctp_assoc_t;

/* glibc doesn't yet have this, as defined by
 * draft-ietf-tsvwg-sctpsocket-11.txt */
struct sctp_sndrcvinfo {
	uint16_t	sinfo_stream;
	uint16_t	sinfo_ssn;
	uint16_t	sinfo_flags;
	uint32_t	sinfo_ppid;
	uint32_t	sinfo_context;
	uint32_t	sinfo_timetolive;
	uint32_t	sinfo_tsn;
	uint32_t	sinfo_cumtsn;
	sctp_assoc_t	sinfo_assoc_id;
};
#endif

#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/linuxlist.h>
#include <ulogd/ipfix_protocol.h>
#include <ulogd/ipfix_util.h>

/* #define DEBUG_TMMAP */
#ifdef DEBUG_TMMAP
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
int mmfd;
void *mmaddr;
#endif

#define IPFIX_DEFAULT_TCPUDP_PORT	4739

enum {
	IPFIX_CONF_DEST	= 0,
	IPFIX_CONF_DOMAIN_ID,
	IPFIX_CONF_NTH_TEMPLATE,
	IPFIX_CONF_CORKSETS_MAX,
	IPFIX_CONF_MAX = IPFIX_CONF_CORKSETS_MAX,
};

static struct config_keyset ipfix_kset = {
	.num_ces = 4,
	.ces = {
		[IPFIX_CONF_DEST] = {
			.key 	 = "dest",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
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
		[IPFIX_CONF_CORKSETS_MAX] = {
			.key	 = "corksets_max",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 16,
		},
	},
};

#define dest_ce(x)	((x)->ces[IPFIX_CONF_DEST])
#define domain_ce(x)	((x)->ces[IPFIX_CONF_DOMAIN_ID])
#define nth_template_ce(x)	((x)->ces[IPFIX_CONF_NTH_TEMPLATE])
#define corksets_max_ce(x)	((x)->ces[IPFIX_CONF_CORKSETS_MAX])

struct ulogd_ipfix_template {
	struct llist_head list;
	struct nfct_bitmask *bitmask;
	int until_template;		/* decide if it's time to retransmit our template */
	int tmplset_len, dataset_len;
	struct ipfix_set_hdr *template;
	struct ipfix_set_hdr *databuf;
	int datapos;
};

struct ipfix_instance {
	int fd;		/* socket that we use for sending IPFIX data */
	int socktype;	/* socket type */

	struct llist_head template_list;
	struct nfct_bitmask *valid_bitmask;	/* bitmask of valid keys */
	uint32_t hdr_seq;
	uint32_t seq;
#define ULOGD_IPFIX_TEMPL_BASE 1024
	uint16_t next_template_id;
	struct ipfix_msg_hdr ipfix_msghdr;
	struct iovec *iovecs;	/* index 0 is reserved for ipfix_msg_hdr */
	unsigned int iovcnt;
	unsigned int corksets_max;	/* cork limit include template */
	unsigned int msglen;
};

#ifdef DEBUG_TMMAP
static int ipfix_fprintf_header(FILE *fd, const struct ipfix_instance *ii);
#endif

struct ulogd_ipfix_template *
alloc_ulogd_ipfix_template(struct ulogd_pluginstance *upi,
			   struct ulogd_keyset *input,
			   struct nfct_bitmask *bm)
{
	struct ipfix_instance *ii = (struct ipfix_instance *)&upi->private;
	struct ulogd_ipfix_template *tmpl;
	unsigned int i;
	int tmpl_len = 0, data_len = 0;

	for (i = 0; i < input->num_keys; i++) {
		struct ulogd_key *key = &input->keys[i];
		int length = ulogd_key_size(key);

		if (!nfct_bitmask_test_bit(bm, i))
			continue;

		if (key->ipfix.vendor == IPFIX_VENDOR_IETF)
			tmpl_len += sizeof(struct ipfix_ietf_field);
		else
			tmpl_len += sizeof(struct ipfix_vendor_field);

		data_len += length;
	}

	tmpl = calloc(sizeof(struct ulogd_ipfix_template), 1);
	if (tmpl == NULL)
		return NULL;

	tmpl->bitmask = nfct_bitmask_clone(bm);
	if (!tmpl->bitmask)
		goto free_tmpl;

	tmpl->dataset_len = sizeof(struct ipfix_set_hdr) + data_len;
	tmpl->tmplset_len = sizeof(struct ipfix_set_hdr)
		+ sizeof(struct ipfix_templ_rec_hdr) + tmpl_len;
	/* XXX: no alignment? confirm 3.3.1. Set Format */

	tmpl->template = calloc(tmpl->tmplset_len, 1);
	if (tmpl->template == NULL)
		goto free_bitmask;
	/* for worst case: all sets are this template's data */
	tmpl->databuf = calloc(tmpl->dataset_len, ii->corksets_max);
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

static void reset_counters(struct ipfix_instance *ii)
{
	struct ulogd_ipfix_template *tmpl;

	llist_for_each_entry(tmpl, &ii->template_list, list) {
		tmpl->datapos = 0;
	}
	ii->msglen = 0;
	/* pos 0 is reserved for ipfix_msg_hdr */
	ii->iovcnt = 1;
}

/* Build the IPFIX template from the input keys */
struct ulogd_ipfix_template *
build_template_for_bitmask(struct ulogd_pluginstance *upi,
			   struct ulogd_keyset *input,
			   struct nfct_bitmask *bm)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &upi->private;
	struct ulogd_ipfix_template *tmpl;
	struct ipfix_templ_rec_hdr *tmpl_hdr;
	struct ipfix_set_hdr *set_hdr;
	unsigned int i, field_count;
	void *ptr;

	tmpl = alloc_ulogd_ipfix_template(upi, input, bm);
	if (tmpl == NULL)
		return NULL;

	/* build template records */
	ptr = (void *)tmpl->template
		+ sizeof(struct ipfix_set_hdr)
		+ sizeof(struct ipfix_templ_rec_hdr);
	for (i = 0, field_count = 0; i < input->num_keys; i++) {
		struct ulogd_key *key = &input->keys[i];
		int length = ulogd_key_size(key);

		if (!nfct_bitmask_test_bit(tmpl->bitmask, i))
			continue;

		if (key->ipfix.vendor == IPFIX_VENDOR_IETF) {
			struct ipfix_ietf_field *field = (struct ipfix_ietf_field *)ptr;

			field->type = htons(key->ipfix.field_id);
			field->length = htons(length);
			ptr += sizeof(*field);
		} else {
			struct ipfix_vendor_field *field =(struct ipfix_vendor_field *)ptr;

			field->type = htons(key->ipfix.field_id | 0x8000);
			field->length = htons(length);
			field->enterprise_num = htonl(key->ipfix.vendor);
			ptr += sizeof(*field);
		}
		field_count++;
	}

	/* initialize template set header */
	tmpl->template->set_id = htons(2);
	tmpl->template->length = htons(tmpl->tmplset_len);

	/* initialize template record header */
	tmpl_hdr = (void *)tmpl->template + sizeof(struct ipfix_set_hdr);
	tmpl_hdr->templ_id = htons(ii->next_template_id++);
	tmpl_hdr->field_count = htons(field_count);

	/* initialize data buffer */
	for (i = 0; i < ii->corksets_max; i++) {
		set_hdr = (void *)tmpl->databuf + i * tmpl->dataset_len;
		set_hdr->set_id = tmpl_hdr->templ_id;
		set_hdr->length = htons(tmpl->dataset_len);
	}

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

static int put_data_records(struct ulogd_pluginstance *upi,
			    struct ulogd_keyset *input,
			    struct ulogd_ipfix_template *tmpl,
			    void *buf, int buflen)
{
	struct ipfix_instance *ii = (struct ipfix_instance *)&upi->private;
	int ret;
	unsigned int i, len = 0;

	for (i = 0; i < input->num_keys; i++) {
		if (!nfct_bitmask_test_bit(tmpl->bitmask, i))
			continue;
		ret = ulogd_key_putn(&input->keys[i], buf + len, buflen);
		if (ret < 0)
			return ret;
		len += ret;
		buflen -= ret;
	}
	ii->seq++;
	return len;
}

static void *data_record(struct ipfix_instance *ii,
			 struct ulogd_ipfix_template *tmpl)
{
	void *p;

	ii->iovecs[ii->iovcnt].iov_base = (void *)tmpl->databuf
		+ tmpl->datapos * tmpl->dataset_len;
	ii->iovecs[ii->iovcnt].iov_len = tmpl->dataset_len;
	p = ii->iovecs[ii->iovcnt].iov_base + sizeof(struct ipfix_set_hdr);
	memset(p, 0, tmpl->dataset_len - sizeof(struct ipfix_set_hdr));
	ii->iovcnt++;
	tmpl->datapos++;

	return p;
}

static int put_template(struct ulogd_pluginstance *upi,
			struct ulogd_ipfix_template *tmpl)
{
	struct ipfix_instance *ii = (struct ipfix_instance *)&upi->private;

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

static int build_ipfix_msg(struct ulogd_pluginstance *upi,
			   struct ulogd_keyset *input,
			   struct ulogd_ipfix_template *tmpl)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &upi->private;
	int ret;

	put_template(upi, tmpl);
	ret = put_data_records(upi, input, tmpl, data_record(ii, tmpl),
			       tmpl->dataset_len);
	if (ret < 0) {
		ulogd_log(ULOGD_ERROR, "could not build ipfix dataset");
		return -1;
	}

	ii->msglen += tmpl->dataset_len;
	return 1;
}

static ssize_t send_ipfix(struct ipfix_instance *ii)
{
	ssize_t nsent;

	ii->msglen += sizeof(struct ipfix_msg_hdr);
	ii->ipfix_msghdr.export_time = htonl((uint32_t)(time(NULL)));
	ii->ipfix_msghdr.length = htons(ii->msglen);
	ii->ipfix_msghdr.seq = htonl(ii->hdr_seq);
	ii->hdr_seq = ii->seq;

#ifdef DEBUG_TMMAP
	ipfix_fprintf_header(stdout, ii);
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

static int output_ipfix(struct ulogd_pluginstance *upi,
			   struct ulogd_keyset *input,
			   struct ulogd_keyset *output)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &upi->private;
	struct ulogd_ipfix_template *template;
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
		if (key->ipfix.field_id == 0)
			continue;

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

	ret = build_ipfix_msg(upi, input, template);
	if (ret == -1) {
		ulogd_log(ULOGD_ERROR, "can't build message\n");
		reset_counters(ii);
		return ULOGD_IRET_ERR;
	}

	/* XXX: magic number. practical UDP max */
	if (ii->msglen > 65507 - sizeof(struct ipfix_msg_hdr)) {
		ulogd_log(ULOGD_NOTICE, "We may have lost data since message "
			  "length exceeds practical UDP max size, then "
			  "reducing corksets_max to: %d\n", ii->iovcnt);
		ii->corksets_max = ii->iovcnt;
	} else if (ii->iovcnt - 1 + 2 < ii->corksets_max) {
		/* - 1 reserved for header
		 * + 2 for sending template and data on next time */
		return ULOGD_IRET_OK;
	}

	ret = send_ipfix(ii);
	reset_counters(ii);
	if (ret < 0)
		return ULOGD_IRET_ERR;

	return ULOGD_IRET_OK;
}

static int start_ipfix(struct ulogd_pluginstance *pi,
		       struct ulogd_keyset *input)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &pi->private;
	int ret = -ENOMEM;

	ulogd_log(ULOGD_DEBUG, "starting ipfix\n");

	/* + 1 for ipfix_msg_hdr */
	ii->iovecs = calloc(sizeof(struct iovec), ii->corksets_max + 1);
	if (ii->iovecs == NULL)
		return ret;

	ii->valid_bitmask = nfct_bitmask_new(input->num_keys);
	if (!ii->valid_bitmask)
		goto out_iovecs_free;

	INIT_LLIST_HEAD(&ii->template_list);

	ii->fd = open_connect_descriptor(pi->config_kset->ces[0].u.string);
	if (ii->fd < 0) {
		ret = -errno;
		goto out_bm_free;
	}

	ii->ipfix_msghdr.version = htons(10);
	ii->ipfix_msghdr.domain_id = htonl(domain_ce(pi->config_kset).u.value);
	ii->iovecs[0].iov_base = &ii->ipfix_msghdr;
	ii->iovecs[0].iov_len = sizeof(ii->ipfix_msghdr);

	ii->next_template_id = ULOGD_IPFIX_TEMPL_BASE;
	reset_counters(ii);

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

out_bm_free:
	nfct_bitmask_destroy(ii->valid_bitmask);
	ii->valid_bitmask = NULL;

out_iovecs_free:
	free(ii->iovecs);

	return ret;
}

static int stop_ipfix(struct ulogd_pluginstance *pi)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &pi->private;
	struct ulogd_ipfix_template *tmpl, *n;

	if (ii->iovcnt > 1) /* exclude header */
		send_ipfix(ii); /* ignore retval, log error only */
	reset_counters(ii);

	llist_for_each_entry_safe(tmpl, n, &ii->template_list, list) {
		nfct_bitmask_destroy(tmpl->bitmask);
		free(tmpl->template);
		free(tmpl->databuf);
		free(tmpl);
	}
	close(ii->fd);
	nfct_bitmask_destroy(ii->valid_bitmask);
	ii->valid_bitmask = NULL;
	free(ii->iovecs);

	return 0;
}

static void signal_handler_ipfix(struct ulogd_pluginstance *pi, int signal)
{
	switch (signal) {
	default:
		ulogd_log(ULOGD_DEBUG, "receive signal: %d\n", signal);
		break;
	}
}

static int configure_ipfix(struct ulogd_pluginstance *pi)
{
	struct ipfix_instance *ii = (struct ipfix_instance *)&pi->private;
	int ret;

	/* FIXME: error handling */
	ulogd_log(ULOGD_DEBUG, "parsing config file section %s\n", pi->id);
	ret = config_parse_file(pi->id, pi->config_kset);
	if (ret < 0)
		return ret;

	if (corksets_max_ce(pi->config_kset).u.value < 2) {
		ulogd_log(ULOGD_ERROR, "corksets_max is required "
			  "more than 2 from implementation perspective\n");
		return -EINVAL;
	}
	ii->corksets_max = (unsigned int)corksets_max_ce(pi->config_kset).u.value;

	return ULOGD_IRET_OK;
}

static struct ulogd_plugin ipfix_plugin = {
	.name = "IPFIX",
	.input = {
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW
			| ULOGD_KEYF_WILDCARD,
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

#ifdef DEBUG_TMMAP
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
	if (*(uint8_t *)ptr & 0x80)
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
	if (*(uint8_t *)ptr & 0x80) /* vendor */
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
				*(uint8_t *)(data + i));
			break;
		case -2:
			fprintf(fd, "|          0x%02x          0x%02x                                     |\n",
				*(uint8_t *)(data + i), *(uint8_t *)(data + i + 1));
			break;
		case -1:
			fprintf(fd, "|          0x%02x          0x%02x          0x%02x                       |\n",
				*(uint8_t *)(data + i), *(uint8_t *)(data + i + 1), *(uint8_t *)(data + i + 2));
			break;
		default:
			fprintf(fd, "|          0x%02x          0x%02x          0x%02x          0x%02x         |\n",
				*(uint8_t *)(data + i), *(uint8_t *)(data + i + 1),
				*(uint8_t *)(data + i + 2), *(uint8_t *)(data + i + 3));
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
	if (*(uint8_t *)field & 0x80)
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

static int _ipfix_fprintf_header(FILE *fd, const struct ipfix_msg_hdr *hdr)
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

static int ipfix_fprintf_header(FILE *fd, const struct ipfix_instance *ii)
{
	lseek(mmfd, 0, SEEK_SET);
	writev(mmfd, ii->iovecs, ii->iovcnt);
	return _ipfix_fprintf_header(fd, (struct ipfix_msg_hdr *)mmaddr);
}
#endif
