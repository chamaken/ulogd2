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
#include <string.h>
#include <ulogd/ulogd.h>
#include <ulogd/linuxlist.h>
#include "ulogd_output_SPRINT.h"
#include "ulogd_output_SPRINT-parser.h"

#define YY_USER_ACTION \
	yyset_column(yyget_column(yyscanner) \
	+ yyget_leng(yyscanner), yyscanner);

#define YY_FATAL_ERROR(msg) { \
	ulogd_log(ULOGD_FATAL, msg);\
	yyget_extra(yyscanner)->yy_fatal_errno = \
		errno != 0 ? -errno : 1;\
}
%}

%option debug
%option warn

%option reentrant
%option noyywrap
%option nounput
%option noinput
%option bison-bridge
%option bison-locations
%option nodefault
%option never-interactive
%option extra-type="struct outform *"

%x escape
%x key

%%

<INITIAL>"\\"	{ BEGIN(escape); }
<INITIAL>"<"	{ BEGIN(key); }
<INITIAL>">"	{
		yylval->string = "unexpected key end";
		return ERR_TERM;
	}
<INITIAL>[()|]	{
		return *yytext;
	}

<INITIAL>[ \t]*"+"[ \t]*	{
		return '+';
	}
<INITIAL>[^\\<>()|]+	{
		yylval->string = strdup(yytext);
		return STRING;
	}

<escape><<EOF>>	{ 
		yylval->string = "EOF in escaped char";
		BEGIN(INITIAL);
		return ERR_TERM;
	}
<escape>[nt\\<>()|\+] {
		switch(*yytext) {
		case 'n':
			yylval->string = strdup("\n");
			break;
		case 't':
			yylval->string = strdup("\t");
			break;
		default:
			yylval->string = strdup(yytext);
			break;
		}
		BEGIN(INITIAL);
		return STRING;
	}
<escape>(.|"\n")	{
		yylval->string = "invalid escape char";
		BEGIN(INITIAL);
		return ERR_TERM;
	}

	/* XXX: no empty key `<>' handling. */
<key><<EOF>>	{
		yylval->string = "EOF in key";
		BEGIN(INITIAL);
		return ERR_TERM;
	}
<key>[a-zA-Z][a-zA-Z0-9\._-]* {
		yylval->string = strdup(yytext);
		return KEY;
	}
<key>">"	{ BEGIN(INITIAL); }
<key>(.|"\n")	{
		yylval->string = "invalid key char";
		BEGIN(INITIAL);
		return ERR_TERM;
	}
%%
