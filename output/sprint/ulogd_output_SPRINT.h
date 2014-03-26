#ifndef _SPRINT_H
#define _SPRINT_H

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
  	int yy_fatal_errno;		/* ugly way of avoiding YY_FATAL_ERROR exit() call */
	int num_keys;			/* number of keys */
	struct node head;		/* list of sprint node */
	struct llist_head keysyms;	/* key symbol list generating ulogd_key */
};

int parse_form(char *str, struct outform *form);
#endif
