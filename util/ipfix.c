/* IPFIX utility functions
 *
 * (C) 2014 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
 *
 * This code is distributed under the terms of GNU GPL version 2
 */

#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ulogd/ulogd.h>
#include <ulogd/ipfix_util.h>

#include "config.h"

/*
 * This function returns file or connected socket descriptor
 * specified by URL like dest:
 *     <proto>://<filename or address>[:port]
 * proto is either one of tcp, udp, sctp and file. port is required
 * in case of socket. file will be stdout if proto is file and
 * no filename specified.
 */
int open_connect_descriptor(const char *dest)
{
	char *proto = NULL, *host, *port;
	struct addrinfo hint, *result = NULL, *rp = NULL;
	int ret, fd = -1;

	proto = strdup(dest);
	if (proto == NULL) {
		ulogd_log(ULOGD_ERROR, "strdup: %s\n", strerror(errno));
		return -1;
	}
	host = strchr(proto, ':');
	if (host == NULL) {
		ulogd_log(ULOGD_ERROR, "invalid dest\n");
		goto error;
	}
	*host++ = '\0';
	if (*host++ != '/') {
		ulogd_log(ULOGD_ERROR, "invalid dest\n");
		goto error;
	}
	if (*host++ != '/') {
		ulogd_log(ULOGD_ERROR, "invalid dest\n");
		goto error;
	}

	/* file */
	if (!strcasecmp(proto, "file")) {
		if (strlen(host) == 0)
			fd = STDOUT_FILENO;
		else
			fd = open(host, O_CREAT|O_WRONLY|O_APPEND);
		free(proto);
		return fd;
	}

	/* socket */
	port = strrchr(host, ':');
	if (port == NULL) {
		ulogd_log(ULOGD_ERROR, "no destination port\n");
		goto error;
	}
	*port++ = '\0';

	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_UNSPEC;
	if (!strcasecmp(proto, "udp")) {
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP;
	} else if (!strcasecmp(proto, "tcp")) {
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_TCP;
#ifdef HAVE_PR_SCTP
	} else if (!strcasecmp(proto, "sctp")) {
		/* XXX: SOCK_SEQPACKET for PR-SCTP? */
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_SCTP;
#endif
	} else {
		ulogd_log(ULOGD_ERROR, "unknown protocol `%s'\n",
			  proto);
		goto error;
	}

	ret = getaddrinfo(host, port, &hint, &result);
	if (ret != 0) {
		ulogd_log(ULOGD_ERROR, "can't resolve host/service: %s\n",
			  gai_strerror(ret));
		if (ret != EAI_SYSTEM)
			errno = EINVAL;
		goto error;
	}

	/* rp == NULL indicates could not get valid sockfd */
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		int on = 1;

		fd = socket(rp->ai_family, rp->ai_socktype,
			    rp->ai_protocol);
		if (fd == -1) {
			switch (errno) {
			case EACCES:
			case EAFNOSUPPORT:
			case EINVAL:
			case EPROTONOSUPPORT:
				/* try next result */
				continue;
			default:
				ulogd_log(ULOGD_ERROR, "socket error: %s\n",
					  strerror(errno));
				rp = NULL;
				goto error;
			}
		}
		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
				 (void *)&on, sizeof(on));
		if (ret < 0) {
			ulogd_log(ULOGD_ERROR, "error on set SO_REUSEADDR: %s",
				  strerror(errno));
			close(fd);
			rp = NULL;
			break;
		}

#ifdef HAVE_PR_SCTP
		/* Set the number of SCTP output streams */
		if (rp->ai_protocol == IPPROTO_SCTP) {
			struct sctp_initmsg initmsg;
			int ret;
			memset(&initmsg, 0, sizeof(initmsg));
			initmsg.sinit_num_ostreams = 2;
			ret = setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG,
					 &initmsg, sizeof(initmsg));
			if (ret < 0) {
				ulogd_log(ULOGD_ERROR, "cannot set number of"
					  "sctp streams: %s\n",
					  strerror(errno));
				close(fd);
				rp = NULL;
				break;
			}
		}
#endif
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(fd);
	}

error:
	if (proto)
		free(proto);
	if (result)
		freeaddrinfo(result);

	if (rp == NULL) {
		ulogd_log(ULOGD_ERROR, "could not connect\n");
		fd = -1;
	}

	return fd;
}

/*
 * This functions stores ulogd key value, specifued by key into
 * buf. buflen means buf len and is checked exceeds. This function
 * returns the copied length or -1 on error.
 */
int ulogd_key_putn(struct ulogd_key *key, void *buf, int buflen)
{
	int ret = -1;

	switch (key->type) {
	case ULOGD_RET_INT8:
	case ULOGD_RET_UINT8:
	case ULOGD_RET_BOOL:
		ret = sizeof(u_int8_t);
		if (buflen - ret >= 0)
			*(u_int8_t *)buf = ikey_get_u8(key);
		break;
	case ULOGD_RET_INT16:
	case ULOGD_RET_UINT16:
		ret = sizeof(u_int16_t);
		if (buflen - ret >= 0)
			*(u_int16_t *)buf = htons(ikey_get_u16(key));
		break;
	case ULOGD_RET_INT32:
	case ULOGD_RET_UINT32:
		ret = sizeof(u_int32_t);
		if (buflen - ret >= 0)
			*(u_int32_t *)buf = htonl(ikey_get_u32(key));
		break;
	case ULOGD_RET_IPADDR:
		ret = sizeof(u_int32_t);
		if (buflen - ret >= 0)
			*(u_int32_t *)buf = ikey_get_u32(key);
		break;
	case ULOGD_RET_INT64:
	case ULOGD_RET_UINT64:
		ret = sizeof(u_int64_t);
		if (buflen - ret >= 0)
			*(u_int64_t *)buf = __be64_to_cpu(ikey_get_u64(key));
		break;
	case ULOGD_RET_IP6ADDR:
		ret = 16;
		if (buflen - ret >= 0)
			memcpy(buf, ikey_get_u128(key), 16);
		break;
	case ULOGD_RET_STRING:
		ret = strlen(key->u.value.ptr);
		if (buflen - ret >= 0)
			memcpy(buf, key->u.value.ptr, ret);
		break;
	case ULOGD_RET_RAW:
		ulogd_log(ULOGD_NOTICE, "put raw data in network byte order "
			  "`%s' type 0x%x\n", key->name, key->type);
		ret = key->len;
		if (buflen - ret >= 0)
			memcpy(buf, key->u.value.ptr, ret);
		break;
	default:
		ulogd_log(ULOGD_ERROR, "unknown size - key "
			  "`%s' type 0x%x\n", key->name, key->type);
		return -1;
		break;
	}

	if (buflen < 0)
		ulogd_log(ULOGD_ERROR, "excess buflen, do nothing.\n");

	return ret;
}
