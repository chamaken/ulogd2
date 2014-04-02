/* ulogd_output_SPRINT.c
 *
 * ulogd output target for sending value specified `form' in config.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>

#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#include "ulogd_output_SPRINT.h"

#ifndef ULOGD_SPRINT_DEFAULT
#define ULOGD_SPRINT_DEFAULT	"/var/log/ulogd.sprint"
#endif

struct sprint_priv {
	int ofd;
	struct llist_head form_head;
};

enum sprint_conf {
	SPRINT_CONF_FORM = 0,
	SPRINT_CONF_DEST,
	SPRINT_CONF_MAX
};

static struct config_keyset sprint_kset = {
	.num_ces = SPRINT_CONF_MAX,
	.ces = {
		[SPRINT_CONF_FORM] = {
			.key = "form",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		[SPRINT_CONF_DEST] = {
			.key = "dest",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u = {.string = ULOGD_SPRINT_DEFAULT },
		},
	},
};

static int open_connect_descriptor(struct ulogd_pluginstance *upi)
{
	char *proto, *host, *port;
	struct addrinfo hint, *result, *rp;
	int ret, fd;

	proto = upi->config_kset->ces[SPRINT_CONF_DEST].u.string;
	host = strchr(proto, ':');
	if (host == NULL) {
		ulogd_log(ULOGD_ERROR, "invalid dest\n");
		return -1;
	}
	*host++ = '\0';
	if (*host++ != '/') {
		ulogd_log(ULOGD_ERROR, "invalid dest\n");
		return -1;
	}
	if (*host++ != '/') {
		ulogd_log(ULOGD_ERROR, "invalid dest\n");
		return -1;
	}

	/* file */
	if (!strcasecmp(proto, "file")) {
		if (strlen(host) == 0)
			return STDOUT_FILENO;
		return open(host, O_CREAT|O_WRONLY|O_APPEND);
	}

	/* socket */
	port = strrchr(host, ':');
	if (port == NULL) {
		ulogd_log(ULOGD_ERROR, "no port in dest\n");
		errno = EINVAL;
		return -1;
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
	} else {
		ulogd_log(ULOGD_ERROR, "unknown protocol `%s'\n",
			  proto);
		errno = EINVAL;
		return -1;
	}

	ret = getaddrinfo(host, port, &hint, &result);
	if (ret != 0) {
		ulogd_log(ULOGD_ERROR, "can't resolve host/service: %s\n",
			  gai_strerror(ret));
		if (ret != EAI_SYSTEM)
			errno = EINVAL;
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		int on = 1;

		fd = socket(rp->ai_family, rp->ai_socktype,
			     rp->ai_protocol);
		if (fd == -1)
			continue;

		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
			   (void *)&on, sizeof(on));
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
	}
	freeaddrinfo(result);

	if (rp == NULL) {
		ulogd_log(ULOGD_ERROR, "could not connect\n");
		/* XXX: errno? */
		return -1;
	}

	return fd;
}

static double sprint_key_calc(struct ulogd_key *keys, struct node *node,
			      bool *is_valid)
{
	*is_valid = false;
	if (node->type == NODE_KEY) {
		struct ulogd_key *key = keys[node->kindex].u.source;
		if (!(key->flags & ULOGD_RETF_VALID))
			return 0.0;

		switch (key->type) {
		case ULOGD_RET_BOOL:
		case ULOGD_RET_INT8:
		case ULOGD_RET_INT16:
		case ULOGD_RET_INT32:
			*is_valid = true;
			return (double)key->u.value.i32;
			break;
		case ULOGD_RET_UINT8:
		case ULOGD_RET_UINT16:
		case ULOGD_RET_UINT32:
		case ULOGD_RET_UINT64:
			*is_valid = true;
			return (double)key->u.value.ui64;
			break;
		default:
			ulogd_log(ULOGD_INFO, "could not calc"
				  " key: %s type: %d\n", key->name, key->type);
		}
	} else if (node->type == NODE_KEYCALC) {
		bool lvalid, rvalid;
		double lval = sprint_key_calc(keys, node->keycalc.l, &lvalid),
			rval = sprint_key_calc(keys, node->keycalc.r, &rvalid);

		if (!lvalid || !rvalid)
			return 0.0; /* without setting is_valid */

		switch (node->keycalc.opcode) {
		case '+':
			*is_valid = true;
			return lval + rval;
			break;
		default:
			ulogd_log(ULOGD_NOTICE, "unknown opcode: %c\n",
				  node->keycalc.opcode);
			break;
		}
	} else {
		ulogd_log(ULOGD_NOTICE, "invalid node type in keycalc: %d\n",
			  node->type);
	}

	return 0.0; /* without setting is_valid */
}

static int sprint_keycalc_puts(char *buf, size_t size, bool in_group,
			       struct ulogd_key *keys, struct node *node)
{
	bool is_valid;
	double ret = sprint_key_calc(keys, node, &is_valid);

	if (!is_valid && in_group)
		return 0;

	return snprintf(buf, size, "%.0f", ret);
}

static int sprint_key_puts(char *buf, size_t size, bool in_group,
			   struct ulogd_key *keys, struct node *node)
{
	struct ulogd_key *key = keys[node->kindex].u.source;

	if (!(key->flags & ULOGD_RETF_VALID)) {
		if (!in_group) {
			ulogd_log(ULOGD_INFO, "no key value: %s\n", key->name);
			return printf("<>");
		}
		return 0;
	}

	switch (key->type) {
	case ULOGD_RET_STRING:
		return snprintf(buf, size, "%s", (char *)key->u.value.ptr);
		break;
	case ULOGD_RET_BOOL:
	case ULOGD_RET_INT8:
	case ULOGD_RET_INT16:
	case ULOGD_RET_INT32:
		return snprintf(buf, size, "%d", key->u.value.i32);
		break;
	case ULOGD_RET_UINT8:
	case ULOGD_RET_UINT16:
	case ULOGD_RET_UINT32:
	case ULOGD_RET_UINT64:
		return snprintf(buf, size, "%" PRIu64, key->u.value.ui64);
		break;
	default:
		ulogd_log(ULOGD_INFO, "could not interpret"
			  " key: %s, type: %d\n", key->name, key->type);
		break;
	}
	return 0; /* default */
}

static int sprint_term_puts(char *buf, size_t size, bool in_group,
			    struct ulogd_key *keys, struct node *node)
{
	struct node *n;
	int ret;
	size_t len = 0;

	switch (node->type) {
	case NODE_KEY:
		return sprint_key_puts(buf, size, in_group, keys, node);
		break;
	case NODE_STRING:
		return snprintf(buf, size, "%s", node->string);
		break;
	case NODE_KEYCALC:
		return sprint_keycalc_puts(buf, size, in_group, keys, node);
		break;
	case NODE_CONCAT:
		llist_for_each_entry(n, &node->group, list) {
			ret = sprint_term_puts(buf + len, size - len,
					       in_group, keys, n);
			if ((n->type == NODE_KEY || n->type == NODE_KEYCALC)
			    && ret <= 0) {
				/* no key value found in a group */
				return 0;
			}
			len += ret;
			if (len >= size) {
				ulogd_log(ULOGD_NOTICE, "exceeds bufsize\n");
				return len;
			}
		}
		return len;
		break;
	default:
		ulogd_log(ULOGD_NOTICE, "unknown node type: %d\n",
			  node->type);
		break;
	}

	return 0; /* unknown node type */
}

static int sprint_group_puts(char *buf, size_t size,
			     struct ulogd_key *keys, struct node *node)
{
	int ret;
	struct node *n;

	llist_for_each_entry(n, &node->group, list) {
		ret = sprint_term_puts(buf, size, true, keys, n);
		if (ret > 0) /* put first valid value and return */
			return ret;
	}

	ulogd_log(ULOGD_NOTICE, "no value found in group\n");
	return snprintf(buf, size, "()");
}

static int sprint_interp(struct ulogd_pluginstance *upi)
{
	struct sprint_priv *sp = (struct sprint_priv *)&upi->private;
	struct node *cur;
	char buf[4096];
	int rem = sizeof(buf) - 1, len = 0, ret;

	llist_for_each_entry(cur, &sp->form_head, list) {
		switch (cur->type) {
		case NODE_KEY:
		case NODE_STRING:
		case NODE_CONCAT:
		case NODE_KEYCALC:
			len += sprint_term_puts(buf + len, rem, false,
						upi->input.keys, cur);
			break;
		case NODE_GROUP:
			len += sprint_group_puts(buf + len, rem,
						 upi->input.keys, cur);
			break;
		default:
			ulogd_log(ULOGD_NOTICE, "unknown node type: %d\n",
				  cur->type);
		}
		rem -= len;
		if (rem <= 0) {
			ulogd_log(ULOGD_NOTICE,
				  "sprint_term_puts exceeds bufsize\n");
			len = sizeof(buf);
			break;
		}
	}

	ret = write(sp->ofd, buf, len);
	if (ret != len) {
		buf[len] = '\0';
		ulogd_log(ULOGD_ERROR, "Failure sending message: %s\n", buf);
		if (ret == -1) {
			sp->ofd = open_connect_descriptor(upi);
			if (sp->ofd == -1)
				return ULOGD_IRET_ERR;
		}
	}
	return ULOGD_IRET_OK;
}

static void sighup_handler_print(struct ulogd_pluginstance *upi, int signal)
{
	struct sprint_priv *sp = (struct sprint_priv *)&upi->private;
	int old = sp->ofd;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "SPRINT: reopening logfile\n");
		sp->ofd = open_connect_descriptor(upi);
		if (sp->ofd == -1) {
			ulogd_log(ULOGD_ERROR, "can't open SPRINT "
					       "log file: %s\n",
				  strerror(errno));
			sp->ofd = old;
		} else {
			close(old);
		}
		break;
	default:
		break;
	}
}

static int sprint_set_inputkeys(struct ulogd_pluginstance *upi)
{
	struct sprint_priv *priv = (struct sprint_priv *)&upi->private;
	struct keysym *sym, *nsym;
	struct ulogd_key *ikey;
	int ret;
	struct outform form;

	INIT_LLIST_HEAD(&priv->form_head);
	INIT_LLIST_HEAD(&form.keysyms);
	INIT_LLIST_HEAD(&form.head.list);
	form.head.type = NODE_HEAD;
	form.yy_fatal_errno = 0;

	ret = parse_form(upi->config_kset->ces[SPRINT_CONF_FORM].u.string,
			 &form);
	if (ret > 0) {
		/* parser error, already logged by yyerror */
		return -ret;
	} else if (ret < 0) { /* errno */
		ulogd_log(ULOGD_ERROR, "could not parse form: %s\n",
			  strerror(-ret));
		return ret;
	}

	llist_add(&priv->form_head, &form.head.list);
	llist_del(&form.head.list);

	ulogd_log(ULOGD_DEBUG, "allocating %u input keys for SPRINT\n",
		  form.num_keys);
	upi->input.keys = ikey = calloc(sizeof(struct ulogd_key),
					form.num_keys);

	if (!upi->input.keys)
		return -ENOMEM;

	/* create input keys from key symbol list created by form parsing */
	llist_for_each_entry_safe(sym, nsym, &form.keysyms, list) {
		ikey->flags = ULOGD_RETF_NONE;
		strncpy(ikey->name, sym->name, strlen(sym->name));
		free(sym->name);
		free(sym);
		ikey++;
	}
	upi->input.num_keys = form.num_keys;

	return ret;
}

static int sprint_configure(struct ulogd_pluginstance *upi,
			    struct ulogd_pluginstance_stack *stack)
{
	int ret;

	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0)
		return ret;

	ret = sprint_set_inputkeys(upi);
	if (ret < 0)
		return ret;

	return 0;
}

static int sprint_init(struct ulogd_pluginstance *upi)
{
	struct sprint_priv *sp = (struct sprint_priv *) &upi->private;

	sp->ofd = open_connect_descriptor(upi);
	if (sp->ofd < 0) {
		ulogd_log(ULOGD_FATAL, "can't open SPRINT destination: %s\n",
			  strerror(errno));
		return -1;
	}

	return 0;
}

static int sprint_fini(struct ulogd_pluginstance *pi)
{
	struct sprint_priv *sp = (struct sprint_priv *) &pi->private;

	if (sp->ofd != STDOUT_FILENO)
		close(sp->ofd);

	return 0;
}

static struct ulogd_plugin sprint_plugin = {
	.name = "SPRINT",
	.input = {
		.type	= ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW | ULOGD_DTYPE_SUM,
	},
	.output = {
		.type	= ULOGD_DTYPE_SINK,
	},
	.configure	= &sprint_configure,
	.interp		= &sprint_interp,
	.start		= &sprint_init,
	.stop		= &sprint_fini,
	.signal		= &sighup_handler_print,
	.config_kset	= &sprint_kset,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&sprint_plugin);
}
