/* ulogd_output_SPRINT.c
 *
 * ulogd output target for sending value specified `form' in config.
 *
 * (C) 2014 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
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
#include <arpa/inet.h>
#include <ctype.h>

#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#define IPADDR_LENGTH 128

#ifndef ULOGD_SPRINT_DEFAULT
#define ULOGD_SPRINT_DEFAULT	"file:///var/log/ulogd.sprint"
#endif

struct sprint_priv {
	int ofd;
	struct llist_head form_head;
};

enum sprint_conf {
	SPRINT_CONF_FORM = 0,
	SPRINT_CONF_DEST,
	SPRINT_CONF_ADDRSEP,
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
		[SPRINT_CONF_ADDRSEP] = {
			.key = "addrsep",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u = {.string = "" },
		},
	},
};

enum sprint_node_type {
	NODE_HEAD,
	NODE_STRING,
	NODE_KEY,
	NODE_CONCAT,
	NODE_GROUP,
	NODE_KEYCALC,
};

enum {
	TOKEN_STRING = 256,
	TOKEN_KEY,
	TOKEN_ERROR,
};

struct keyop {
	int opcode;
	struct node *l;
	struct node *r;
};

struct node {
	enum sprint_node_type type;
	struct llist_head list;
	union {
		char *string;			/* NODE_STRING */
		int kindex;			/* NODE_KEY */
		struct llist_head group;	/* NODE_CONCAT, NODE_GROUP */
		struct keyop keycalc;		/* NODE_KEYCALC */
	};
};

struct keysym {
	struct llist_head list;
	char *name;
};

struct outform {
	char *formstr;
	char *cur;
	char *prev;		/* for unput */
	char *prev_lval;
	struct llist_head form_head;
	int num_keys;
	struct llist_head keysyms;
};

static int unput(struct outform *scan)
{
	if (scan->cur == scan->prev)
		return -1;
	scan->cur = scan->prev;
	if (scan->prev_lval)
		free(scan->prev_lval);

	return 0;
}

static int lval_term(struct outform *scan, int type,
		     char **dst, char *from, char *to, char *prev)
{
	char c;

	if (to == NULL) {
		*dst = scan->prev_lval = strdup(from);
	} else {
		c = *to;
		*to = '\0';
		*dst = scan->prev_lval = strdup(from);
		*to = c;
	}
	if (*dst == NULL) {
		ulogd_log(ULOGD_ERROR, "%s\n", strerror(errno));
		return TOKEN_ERROR;
	}
	scan->prev = prev;
	return type;
}

static int lval_char(struct outform *scan, int type, char *prev)
{
	scan->prev = prev;
	scan->prev_lval = NULL;
	return type;
}

static int lval_error(struct outform *scan, char **dst, char *msg)
{
	/* *dst = msg */
	ulogd_log(ULOGD_ERROR, "%s around %d\n",
		  msg, scan->cur - scan->formstr);
	scan->prev_lval = NULL;
	return TOKEN_ERROR;
}

static int lex_key(struct outform *scan, char **lval)
{
	char c, *start;

	for (start = scan->cur; (c = *scan->cur) != '\0'; scan->cur++) {
		if (c == '>') {
			scan->cur++;
			return lval_term(scan, TOKEN_KEY, lval,
					 start - 1, scan->cur - 1, start - 2);
		}
		if (!isascii(c) && !isalnum(c)
		    && c != '.' && c != '_' && c != '-')
			return lval_error(scan, lval,
					  "invalid key char");
	}

	return lval_error(scan, lval, "EOF in key");
}

static int lex_escape(struct outform *scan, char **lval)
{
	char sbuf[2];
	char c = *scan->cur++;

	switch (c) {
	case 'n':
		return lval_term(scan, TOKEN_STRING, lval,
				 "\n", NULL, scan->cur - 2);
	case 't':
		return lval_term(scan, TOKEN_STRING, lval,
				 "\t", NULL, scan->cur - 2);
	case '\\':
	case '<':
	case '>':
	case '(':
	case ')':
	case '|':
	case '+':
		snprintf(sbuf, 2, "%c", c);
		return lval_term(scan, TOKEN_STRING, lval,
				 sbuf, NULL, scan->cur - 2);
	case '\0':
		return lval_error(scan, lval, "EOF in escape");
	default:
		return lval_error(scan, lval,
				  "invalid escape char");
	}
}

static int lex(struct outform *scan, char **lval)
{
	char c, *start = scan->cur;

	while ((c = *scan->cur) != '\0') {
		switch(c) {
		case '\\':
			if (scan->cur != start)
				return lval_term(scan, TOKEN_STRING, lval,
						 start, scan->cur, start);
			scan->cur++;
			return lex_escape(scan, lval);
			break;
		case '<':
			if (scan->cur != start)
				return lval_term(scan, TOKEN_STRING, lval,
						 start, scan->cur, start);
			scan->cur++;
			if (!isascii(*scan->cur) && !isalpha(*scan->cur))
				return lval_error(scan, lval,
						  "invalid key start");
			scan->cur++; /* consume key's first char */
			return lex_key(scan, lval);
			break;
		case '>':
			return lval_error(scan, lval,
					  "unexpected key end");
		case ')':
		case '(':
		case '|':
			if (scan->cur != start)
				return lval_term(scan, TOKEN_STRING, lval,
						 start, scan->cur, start);
			scan->cur++;
			return lval_char(scan, c, start);
		case '+':
			do
				scan->cur++;
			while (*scan->cur == ' ' || *scan->cur == '\t');
			return lval_char(scan, c, start);
		case ' ':
		case '\t':
		default:
			scan->cur++;
			break;
		}
	}

	if (scan->cur != start)
		return lval_term(scan, TOKEN_STRING, lval,
				 start, scan->cur, start);

	return 0;
}

static void *sprint_calloc(size_t len)
{
	void *p = calloc(len, 1);
	if (p == NULL) {
		ulogd_log(ULOGD_ERROR, "%s\n", strerror(errno));
		return NULL;
	}
	return p;
}

static struct node *sprint_string_node(char *string)
{
	struct node *node = sprint_calloc(sizeof(struct node));

	if (node == NULL)
		return NULL;

	node->type = NODE_STRING;
	node->string = string;

	return node;
}

static int sprint_key_index(struct outform *form, char *name)
{
	struct keysym *cur;
	int i = 0;

	llist_for_each_entry(cur, &form->keysyms, list) {
		if (!strcmp(cur->name, name))
			return i;
		i++;
	}

	return -1;
}

static struct node *sprint_key_node(struct outform *form, char *name)
{
	struct node *node;
	struct keysym *sym;

	if (strlen(name) > ULOGD_MAX_KEYLEN) {
		ulogd_log(ULOGD_ERROR, "too long key: %s\n", name);
		return NULL;
	}

	node = sprint_calloc(sizeof(struct node));
	if (node == NULL)
		return NULL;

	node->type = NODE_KEY;
	node->kindex = sprint_key_index(form, name);
	if (node->kindex < 0) {
		sym = sprint_calloc(sizeof(struct keysym));
		if (sym == NULL) {
			free(node);
			return NULL;
		}
		sym->name = name;
		node->kindex = form->num_keys++;
		llist_add_tail(&sym->list, &form->keysyms);
	}

	return node;
}

static struct node *sprint_list_node(enum sprint_node_type type,
				     struct node *term)
{
	struct node *node = sprint_calloc(sizeof(struct node));

	if (node == NULL)
		return NULL;

	node->type = type;
	INIT_LLIST_HEAD(&node->group);
	llist_add_tail(&term->list, &node->group);
	return node;
}

static struct node *sprint_keycalc_node(int opcode,
					struct node *l, struct node *r)
{
	struct node *node = sprint_calloc(sizeof(struct node));

	if (node == NULL)
		return NULL;

	node->type = NODE_KEYCALC;
	node->keycalc.opcode = opcode;
	node->keycalc.l = l;
	node->keycalc.r = r;

	return node;
}

static void sprint_free_nodes(struct llist_head *nodes);

static void sprint_free_node(struct node *node)
{
	switch (node->type) {
	case NODE_STRING:
		free(node->string);
		break;
	case NODE_KEY:
		break;
	case NODE_GROUP:
	case NODE_CONCAT:
		sprint_free_nodes(&node->group);
		break;
	case NODE_KEYCALC:
		sprint_free_node(node->keycalc.l);
		sprint_free_node(node->keycalc.r);
		break;
	default:
		ulogd_log(ULOGD_ERROR, "unknown node: %p"
			  " type: %d\n", node, node->type);
		break;
	}
}

static void sprint_free_nodes(struct llist_head *nodes)
{
	struct node *node, *nnode;

	llist_for_each_entry_safe(node, nnode, nodes, list) {
		sprint_free_node(node);
		llist_del(&node->list);
		free(node);
	}
}

static void sprint_free_keysyms(struct llist_head *head)
{
	struct keysym *sym, *nsym;

	llist_for_each_entry_safe(sym, nsym, head, list) {
		llist_del(&sym->list);
		free(sym->name);
		free(sym);
	}
}

/*
 * form		:=	part*
 * part		:=	concat | '(' selector ')'
 * selector	:=	concat ('|' concat)*
 * concat	:=	term term*
 * term		:=	STRING | KEY ('+' KEY)*
 */
static struct node *term(struct outform *form)
{
	char *lval;
	struct node *nl, *nr;
	int opcode, ret = lex(form, &lval);

	if (ret == TOKEN_ERROR)
		return NULL;
	if (ret == TOKEN_STRING)
		return sprint_string_node(lval);
	if (ret != TOKEN_KEY) {
		ulogd_log(ULOGD_ERROR,
			  "form char: %d, invalid meta char: %c\n",
			  form->cur - form->formstr, ret);
		return NULL;
	}

	/* ret == TOKEN_KEY */
	nl = sprint_key_node(form, lval);
	if (nl == NULL)
		return NULL;

	opcode = lex(form, &lval);
	if (opcode == TOKEN_ERROR)
		return NULL;
	if (opcode != '+') {
		if (opcode != '\0')
			unput(form);
		return nl;
	}

	ret = lex(form, &lval);
	if (ret == TOKEN_ERROR)
		return NULL;
	if (ret != TOKEN_KEY) {
		ulogd_log(ULOGD_ERROR,
			  "form char: %d, right operand must be a KEY\n",
			  form->cur - form->formstr);
		return NULL;
	}
	unput(form);

	nr = term(form);
	if (nr == NULL)
		return NULL;

	return sprint_keycalc_node(opcode, nl, nr);
}

static struct node *concat(struct outform *form)
{
	char *lval;
	int ret;
	struct node *terms, *last, *n = term(form);

	if (n == NULL)
		return NULL;

	terms = sprint_list_node(NODE_CONCAT, n);
	if (terms == NULL)
		return NULL;

	ret = lex(form, &lval);
	while (ret == TOKEN_STRING || ret == TOKEN_KEY) {
		unput(form);
		n = term(form);
		if (n == NULL)
			return NULL;
		last = llist_entry(terms->group.prev, struct node, list);
		if (last->type == NODE_STRING && n->type == NODE_STRING) {
			/* a little bit optimize */
			int len1 = strlen(last->string),
				len2 = strlen(n->string);

			last->string = realloc(last->string, len1 + len2 + 1);
			if (last->string == NULL) {
				ulogd_log(ULOGD_ERROR, "%s\n", strerror(errno));
				return NULL;
			}
			strncpy(last->string + len1, n->string, len2);
			sprint_free_node(n);
			free(n);
		} else {
			llist_add_tail(&n->list, &terms->group);
		}
		ret = lex(form, &lval);
	}
	if (ret != '\0')
		unput(form);

	return terms;
}

static struct node *selector(struct outform *form)
{
	int ret;
	char *lval;
	struct node *concats, *n = concat(form);

	if (n == NULL)
		return NULL;

	concats = sprint_list_node(NODE_GROUP, n);
	if (concats == NULL)
		return NULL;

	while ((ret = lex(form, &lval)) == '|') {
		n = concat(form);
		if (n == NULL)
			return NULL;
		llist_add_tail(&n->list, &concats->group);
	}
	if (ret != '\0')
		unput(form);

	return concats;
}

static struct node *part(struct outform *form)
{
	char *lval;
	struct node *n;
	int ret = lex(form, &lval);

	if (ret == TOKEN_ERROR)
		return NULL;

	if (ret == '(') {
		n = selector(form);
		ret = lex(form, &lval);
		if (ret != ')') {
			ulogd_log(ULOGD_ERROR,
				  "form char: %d, no right parenthesis\n",
				  form->cur - form->formstr);
			return NULL;
		}
	} else {
		unput(form);
		n = concat(form);
	}

	return n;
}

static int parse_form(struct outform *form)
{
	struct node *n;

	while (*form->cur) {
		n = part(form);
		if (n == NULL)
			return -1;
		llist_add_tail(&n->list, &form->form_head);
	}

	return 0;
}

static int init_outform(struct outform *form, char *s)
{
	struct keysym *oob_family = calloc(sizeof(struct keysym), 1);

	if (oob_family == NULL)
		return -1;

	form->formstr = form->cur = form->prev = s;
	INIT_LLIST_HEAD(&form->form_head);

	INIT_LLIST_HEAD(&form->keysyms);
	/* for ULOGD_RET_IPADDR in sprint_key_puts() */
	oob_family->name = strdup("oob.family");
	if (oob_family->name == NULL)
		return -1;
	llist_add_tail(&oob_family->list, &form->keysyms);
	form->num_keys = 1;

	return 0;
}

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
			   struct ulogd_key *keys, struct node *node,
			   int addrsep)
{
	struct ulogd_key *key = keys[node->kindex].u.source;
	char family, *p;
	int i;

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
	case ULOGD_RET_IPADDR:
		family = ikey_get_u8(keys);
		if (family == AF_INET6) {
			inet_ntop(AF_INET6, ikey_get_u128(&keys[node->kindex]),
				  buf, size);
			i = ':';
		} else if (family == AF_INET) {
			u_int32_t ip = ikey_get_u32(&keys[node->kindex]);
			inet_ntop(AF_INET, &ip, buf, size);
			i = '.';
		} else {
			ulogd_log(ULOGD_ERROR,
				  "unknown address family: %d\n", family);
			return 0;
		}
		if (addrsep)
			for (p = strchr(buf, i); p; p = strchr(p + 1, i))
				*p = addrsep;
		for (i = 0, p = buf; *p != '\0'; p++, i++)
			;
		return i;
	default:
		ulogd_log(ULOGD_INFO, "could not interpret"
			  " key: %s, type: %d\n", key->name, key->type);
		break;
	}
	return 0; /* default */
}

static int sprint_term_puts(char *buf, size_t size, bool in_group,
			    struct ulogd_key *keys, struct node *node,
			    int addrsep)
{
	struct node *n;
	int ret;
	size_t len = 0;

	switch (node->type) {
	case NODE_KEY:
		return sprint_key_puts(buf, size, in_group, keys, node,
				       addrsep);
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
					       in_group, keys, n, addrsep);
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

static int sprint_group_puts(char *buf, size_t size, struct ulogd_key *keys,
			     struct node *node, int addrsep)
{
	int ret;
	struct node *n;

	llist_for_each_entry(n, &node->group, list) {
		ret = sprint_term_puts(buf, size, true, keys, n, addrsep);
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
	int addrsep = *upi->config_kset->ces[SPRINT_CONF_ADDRSEP].u.string;

	llist_for_each_entry(cur, &sp->form_head, list) {
		switch (cur->type) {
		case NODE_KEY:
		case NODE_STRING:
		case NODE_CONCAT:
		case NODE_KEYCALC:
			len += sprint_term_puts(buf + len, rem, false,
						upi->input.keys, cur, addrsep);
			break;
		case NODE_GROUP:
			len += sprint_group_puts(buf + len, rem,
						 upi->input.keys, cur, addrsep);
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

static int sprint_configure_form(struct ulogd_pluginstance *upi)
{
	struct sprint_priv *priv = (struct sprint_priv *)&upi->private;
	struct keysym *sym, *nsym;
	struct ulogd_key *ikey;
	int ret;
	struct outform form;

	if (init_outform(&form,
			 upi->config_kset->ces[SPRINT_CONF_FORM].u.string)) {
		ulogd_log(ULOGD_FATAL, "could not init form data\n");
		return ULOGD_IRET_ERR;
	}

	ret = parse_form(&form);
	if (ret == -1) {
		/* parser error, already logged */
		sprint_free_nodes(&form.form_head);
		sprint_free_keysyms(&form.keysyms);
		return ULOGD_IRET_ERR;
	}

	llist_add(&priv->form_head, &form.form_head);
	llist_del(&form.form_head);

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

	ret = sprint_configure_form(upi);
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

	/* sprint_priv->form_head is initialized at configure pharse.
	 * Should it be released here? by:
	 *     sprint_free_nodes(&sp->form_head);
	 */

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
