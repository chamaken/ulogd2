/* ulogd_filter_TIMECONV.c
 *
 * ulogd interpreter plugin for IPFIX / Netflow v9 to create
 * IPFIX_flow(Start|End)MicroSeconds, IPFIX_flow(Start|End)SysUpTime
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

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <ulogd/ulogd.h>
#include <ulogd/ipfix_protocol.h>

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC	1000000000L
#endif

#define PROC_TIMER_LIST "/proc/timer_list"

struct timeconv_priv {
	uint64_t rtoffset;		/* in ns */
	void (*setfunc)(struct ulogd_key *, uint64_t,
			uint32_t, uint32_t, uint32_t, uint32_t);
};

enum {
	CONFKEY_USEC64,
	CONFKEY_UPTIME,
};

static struct config_keyset config_keys = {
	.num_ces = 2,
	.ces = {
		{
			.key	 = "usec64",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 1,
		},
		{
			.key	 = "uptime",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 1,
		},
	},
};

#define usec64_ce(x)	((x)->ces[CONFKEY_USEC64])
#define uptime_ce(x)	((x)->ces[CONFKEY_UPTIME])

enum {
	IKEY_FLOW_START_SEC,
	IKEY_FLOW_START_USEC,
	IKEY_FLOW_END_SEC,
	IKEY_FLOW_END_USEC,
	IKEY_MAX = IKEY_FLOW_END_USEC,
};

static struct ulogd_key input_keys[] = {
	[IKEY_FLOW_START_SEC] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.start.sec",
	},
	[IKEY_FLOW_START_USEC] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.start.usec",
	},
	[IKEY_FLOW_END_SEC] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.end.sec",
	},
	[IKEY_FLOW_END_USEC] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.end.usec",
	},
};

enum output_key_index {
	OKEY_FLOW_START_USEC64,
	OKEY_FLOW_END_USEC64,
	OKEY_FLOW_START_UPTIME,
	OKEY_FLOW_END_UPTIME,
	OKEY_MAX = OKEY_FLOW_END_UPTIME,
};

static struct ulogd_key output_keys[] = {
	[OKEY_FLOW_START_USEC64] = {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.start.useconds",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowStartMicroSeconds,
		},
	},
	[OKEY_FLOW_END_USEC64] = {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.end.useconds",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowEndMicroSeconds,
		},
	},
	[OKEY_FLOW_START_UPTIME] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.start.uptime",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowStartSysUpTime,
		},
	},
	[OKEY_FLOW_END_UPTIME] = {
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.end.uptime",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowEndSysUpTime,
		},
	},
};

static inline uint64_t conv_ntp_us(uint32_t sec, uint32_t usec)
{
	/* RFC7011 - 6.1.10. dateTimeMicroseconds */
	return (((uint64_t) sec << 32)
		+ ((uint64_t) usec << 32) / (NSEC_PER_SEC / 1000))
		& ~0x7ff;
}

void set_ntp(struct ulogd_key *okeys, uint64_t offset,
	     uint32_t start_sec, uint32_t start_usec,
	     uint32_t end_sec, uint32_t end_usec)
{
	okey_set_u64(&okeys[OKEY_FLOW_START_USEC64],
		     conv_ntp_us(start_sec, start_usec));
	okey_set_u64(&okeys[OKEY_FLOW_END_USEC64],
		     conv_ntp_us(end_sec, end_usec));

}

static inline uint32_t conv_uptime(uint64_t offset, uint32_t sec, uint32_t usec)
{
	return (sec - offset / NSEC_PER_SEC) * 1000
		+ usec / 1000 - (offset % NSEC_PER_SEC) / 1000000;
}

void set_uptime(struct ulogd_key *okeys, uint64_t offset,
		uint32_t start_sec, uint32_t start_usec,
		uint32_t end_sec, uint32_t end_usec)
{
	okey_set_u32(&okeys[OKEY_FLOW_START_UPTIME],
		     conv_uptime(offset, start_sec, start_usec));
	okey_set_u32(&okeys[OKEY_FLOW_END_UPTIME],
		     conv_uptime(offset, end_sec, end_usec));
}

void set_ntp_uptime(struct ulogd_key *okeys, uint64_t offset,
		    uint32_t start_sec, uint32_t start_usec,
		    uint32_t end_sec, uint32_t end_usec)
{
	set_ntp(okeys, offset, start_sec, start_usec, end_sec, end_usec);
	set_uptime(okeys, offset, start_sec, start_usec, end_sec, end_usec);
}

static int interp_timeconv(struct ulogd_pluginstance *upi,
			   struct ulogd_keyset *input,
			   struct ulogd_keyset *output)
{
	struct timeconv_priv *priv =
			(struct timeconv_priv *)upi->private;
	struct ulogd_key *inp = input->keys;

	if (!pp_is_valid(inp, IKEY_FLOW_START_SEC)
	    || !pp_is_valid(inp, IKEY_FLOW_START_USEC)
	    || !pp_is_valid(inp, IKEY_FLOW_END_SEC)
	    || !pp_is_valid(inp, IKEY_FLOW_END_USEC)) {
		char buf[4096];

		snprintf(buf, sizeof(buf), "%s%s%s%s",
			 pp_is_valid(inp, IKEY_FLOW_START_SEC)
				? "" : " flow.start.sec",
			 pp_is_valid(inp, IKEY_FLOW_START_USEC)
				? "" : " flow.start.usec",
			 pp_is_valid(inp, IKEY_FLOW_END_SEC)
				? "" : " flow.end.sec",
			 pp_is_valid(inp, IKEY_FLOW_END_USEC)
				? "" : " flow.end.usec");

		ulogd_log(ULOGD_ERROR, "could not find key(s):%s\n", buf);
		return ULOGD_IRET_ERR;
	}

	priv->setfunc(output->keys, priv->rtoffset,
		      ikey_get_u32(&inp[IKEY_FLOW_START_SEC]),
		      ikey_get_u32(&inp[IKEY_FLOW_START_USEC]),
		      ikey_get_u32(&inp[IKEY_FLOW_END_SEC]),
		      ikey_get_u32(&inp[IKEY_FLOW_END_USEC]));

	return ULOGD_IRET_OK;
}

static int configure_timeconv(struct ulogd_pluginstance *upi)
{
	return config_parse_file(upi->id, upi->config_kset);
}

static int start_timeconv(struct ulogd_pluginstance *upi,
			  struct ulogd_keyset *input)
{
	struct timeconv_priv *priv =
			(struct timeconv_priv *)upi->private;
	int fd;
	ssize_t nread;
	char buf[4096] = {0}; /* XXX: MAGIC NUMBER */
	char *s = "ktime_get_real\n  .offset: ";
	void *p;
	size_t slen = strlen(s);

	/* get rt offset */
	fd = open(PROC_TIMER_LIST, O_RDONLY);
	if (fd == -1)
		return -1;
	nread = read(fd, buf, sizeof(buf));
	close(fd);
	if (nread == -1)
		return -1;
	p = memmem(buf, nread, s, slen);
	if (p == NULL)
		return -1;
	if (sscanf(p + slen, " %"PRIu64, &priv->rtoffset) == EOF)
		return -1;

	/* select set function */
	if (usec64_ce(upi->config_kset).u.value)
		if (uptime_ce(upi->config_kset).u.value)
			priv->setfunc = &set_ntp_uptime;
		else
			priv->setfunc = &set_ntp;
	else if (uptime_ce(upi->config_kset).u.value)
		priv->setfunc = &set_uptime;
	else
		return -1;

	return 0;
}

static struct ulogd_plugin timeconv_plugin = {
	.name = "TIMECONV",
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
	.config_kset	= &config_keys,
	.interp		= &interp_timeconv,
	.configure	= &configure_timeconv,
	.start		= &start_timeconv,
	.priv_size	= sizeof(struct timeconv_priv),
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&timeconv_plugin);
}
