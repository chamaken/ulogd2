#ifndef _SPRINT_H
#define _SPRINT_H

/* ulogd_output_SPRINT.h
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

#include "ulogd_output_SPRINT-parser.h"

enum sprint_node_type {
	NODE_HEAD,
	NODE_STRING,
	NODE_KEY,
	NODE_CONCAT,
	NODE_GROUP,
	NODE_KEYCALC,
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
	int num_keys;			/* number of keys */
	struct node head;		/* list of sprint node */
	struct llist_head keysyms;	/* key symbol list generating ulogd_key */
};

void yyerror(YYLTYPE *loc, yyscan_t scanner, const char *msg, ...);
int parse_form(char *str, struct outform *form);
#endif
