/*
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

%{
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ulogd/ulogd.h>
#include <ulogd/linuxlist.h>
#include "ulogd_output_SPRINT.h"
#include "ulogd_output_SPRINT-scanner.h"

static int yyerror(YYLTYPE *loc, yyscan_t scanner, const char *msg, ...);

static struct node *sprint_string_node(char *string)
{
	struct node *node = calloc(sizeof(struct node), 1);

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

	node = calloc(sizeof(struct node), 1);
	if (node == NULL)
		return NULL;

	node->type = NODE_KEY;
	node->kindex = sprint_key_index(form, name);
	if (node->kindex < 0) {
		sym = calloc(sizeof(struct keysym), 1);
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

static struct node *sprint_list_node(enum sprint_node_type type, struct node *term)
{
	struct node *node = calloc(sizeof(struct node), 1);

	if (node == NULL)
		return NULL;

	node->type = type;
	INIT_LLIST_HEAD(&node->group);
	llist_add_tail(&term->list, &node->group);
	return node;
}

static struct node *sprint_group_add(struct node *group, struct node *term)
{
	llist_add_tail(&term->list, &group->group);
	return group;
}

static struct node *sprint_keycalc_node(int opcode, struct node *l, struct node *r)
{
	struct node *node = calloc(sizeof(struct node), 1);

	if (node == NULL)
		return NULL;

	node->type = NODE_KEYCALC;
	node->keycalc.opcode = opcode;
	node->keycalc.l = l;
	node->keycalc.r = r;

	return node;
}
%}

%code requires {
	#ifndef YY_TYPEDEF_YY_SCANNER_T
	#define YY_TYPEDEF_YY_SCANNER_T
	typedef void* yyscan_t;
	#endif

	#ifndef YY_TYPEDEF_YY_BUFFER_STATE
	#define YY_TYPEDEF_YY_BUFFER_STATE
	typedef struct yy_buffer_state *YY_BUFFER_STATE;
	#endif
}

%debug
%pure-parser
%lex-param { scanner }
%parse-param { yyscan_t scanner }
%error-verbose
%locations

%union {
	char *string;
	struct node *node;
}

%token <string> STRING
%token <string> KEY
%token <string> ERR_TERM /* just notifying from scanner */

%type <node> form part selector group term key

%%

form:
	  /* empty */		{
		$$ = &(yyget_extra(scanner))->head;
	  }
	| form part		{
		llist_add_tail(&$2->list, &$1->list);
		$$ = $1;
	  }
	;

part:
	  term
	| group
	;

group:
	  '(' selector ')'	{
		$$ = $2;
	  }
	;

selector:
	  term			{
		$$ = sprint_list_node(NODE_GROUP, $1);
		if ($$ == NULL) {
			yyerror(&yylloc, scanner, "could not create group node");
			YYABORT;
		}
	  }
	| selector '|' term	{
		$$ = sprint_group_add($1, $3);
	  }
	;

term:
	  key
	| STRING		{
		$$ = sprint_string_node($1);
		if ($$ == NULL) {
			yyerror(&yylloc, scanner, "could not create string node");
			YYABORT;
		}
	  }
	| term key		{
		if ($1->type != NODE_CONCAT) {
			$1 = sprint_list_node(NODE_CONCAT, $1);
			if ($1 == NULL) {
				yyerror(&yylloc, scanner, "could not concat term");
				YYABORT;
			}
		}
		$$ = sprint_group_add($1, $2);
	  }
	| term STRING		{
		if ($1->type == NODE_STRING) { /* concat string by using realloc */
			int len1 = strlen($1->string), len2 = strlen($2);
			$1->string = realloc($1->string, len1 + len2);
			if ($1->string == NULL) {
				yyerror(&yylloc, scanner, "could not reallocate string area");
				YYABORT;
			}
			strncpy($1->string + len1, $2, len2);
		} else {
			struct node *n = sprint_string_node($2);
			if ($1->type != NODE_CONCAT) {
				$1 = sprint_list_node(NODE_CONCAT, $1);
				if ($1 == NULL) {
					yyerror(&yylloc, scanner, "could not concat term\n");
					YYABORT;
				}
			}
			$$ = sprint_group_add($1, n);
		}
	  }
	| ERR_TERM		{
		$$ = NULL; /* supress warning */
		yyerror(&yylloc, scanner, $1);
		YYABORT;
	  }
	;

key:
	KEY			{
		$$ = sprint_key_node(yyget_extra(scanner), $1);
		if ($$ == NULL) {
			yyerror(&yylloc, scanner, "could not create key node");
			YYABORT;
		}
	  }
	| key '+' key		{
		$$ = sprint_keycalc_node('+', $1, $3);
		if ($$ == NULL) {
			yyerror(&yylloc, scanner, "could not create key calc node");
			YYABORT;
		}
	  }
	;
%%

int yyerror(YYLTYPE *loc, yyscan_t scanner, const char *msg, ...)
{
	va_list ap;
	char buf[4096];

	va_start(ap, msg);
	snprintf(buf, sizeof(buf), msg, ap);
	va_end(ap);

	ulogd_log(ULOGD_ERROR, "form error - %s, at: %d\n", buf, yyget_column(scanner));

	return 0;
}

char *sprint_key_name(struct llist_head *head, int kindex)
{
	struct keysym *sym;
	int i = 0;

	llist_for_each_entry(sym, head, list) {
		if (i++ == kindex)
			return sym->name;
	}

	return NULL;
}

void sprint_free_nodes(struct llist_head *nodes);

void sprint_free_node(struct node *node)
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

void sprint_free_nodes(struct llist_head *nodes)
{
	struct node *node, *nnode;

	llist_for_each_entry_safe(node, nnode, nodes, list) {
		sprint_free_node(node);
		llist_del(&node->list);
		free(node);
	}
}

void sprint_free_keysyms(struct llist_head *head)
{
	struct keysym *sym, *nsym;

	llist_for_each_entry_safe(sym, nsym, head, list) {
		llist_del(&sym->list);
		free(sym->name);
		free(sym);
	}
}

/*
 * This function returns 0 on success
 * error on parsing: > 0
 * otherwise < 0 means negative errno
 */
int parse_form(char *str, struct outform *form)
{
	yyscan_t scanner;
	YY_BUFFER_STATE buf;
	int ret = 0;

	if (yylex_init_extra(form, &scanner))
		return -errno;
	buf = yy_scan_string(str, scanner);
	if (buf == NULL) {
		ret = -errno;
		/* XXX: needs free? what's the status of extra data and buffer */
		goto free_scanner;
	}

	ret = yyparse(scanner);
	if (ret == 0)
		ret = form->yy_fatal_errno;
	if (ret != 0) {
		sprint_free_nodes(&form->head.list);
		sprint_free_keysyms(&form->keysyms);
	}

	yy_delete_buffer(buf, scanner);
free_scanner:
	yylex_destroy(scanner);

	return ret;
}
