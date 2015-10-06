/* config file parser functions
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 * (C) 2013 by Eric Leblond <eric@regit.org>
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
 */

#include <limits.h>
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/conffile.h>
#include <unistd.h>

/* points to config entry with error */
struct config_entry *config_errce = NULL;

/* Filename of the config file */
static char *ulogd_config_fname = NULL;

/* get_word() - Function to parse a line into words.
 * Arguments:	line	line to parse
 * 		delim	possible word delimiters
 * 		buf	pointer to buffer where word is returned
 * Return value:	pointer to first char after word
 * This function can deal with "" quotes 
 */
static char *get_word(char *line, char *delim, char *buf)
{
	char *p, *start = NULL, *stop = NULL;
	int inquote = 0;

	for (p = line; *p; p++) {
		if (*p == '"') {
			start  = p + 1;
			inquote = 1;
			break;
		}
		if (!strchr(delim, *p)) {
			start = p;
			break;
		}
	}
	if (!start)
		return NULL;

	/* determine pointer to one char after word */
	for (p = start; *p; p++) {
		if (inquote) {
			if (*p == '"') {
				stop = p;
				break;
			}
		} else {
			if (strchr(delim, *p)) {
				stop = p;
				break;
			}
		}
	}
	if (!stop)
		return NULL;

	strncpy(buf, start, (size_t)(stop - start));
	*(buf + (stop - start)) = '\0';

	/* skip quote character */
	if (inquote)
		/* yes, we can return stop + 1. If " was the last 
		 * character in string, it now points to NULL-term */
		return stop + 1;

	return stop;
}

/***********************************************************************
 * PUBLIC INTERFACE
 ***********************************************************************/

/* register config file with us */
int config_register_file(const char *file)
{
	if (ulogd_config_fname) {
		ulogd_log(ULOGD_ERROR, "already registerd file: %s\n",
			  ulogd_config_fname);
		return EALREADY; /* not negative, it's not critical */
	}

	if (access(file, R_OK) != 0) {
		ulogd_log(ULOGD_ERROR,
			 "unable to read configfile \"%s\": %s\n",
			 file,
			 strerror(errno));
		return -errno;
	}

	ulogd_log(ULOGD_DEBUG, "registering config file: %s\n", file);
	ulogd_config_fname = (char *)malloc(strlen(file) + 1);
	if (!ulogd_config_fname)
		return -ERROOM;

	strcpy(ulogd_config_fname, file);

	return 0;
}

/* parse config file */
int config_parse_file(const char *section, struct config_keyset *kset)
{
	FILE *cfile;
	char line[LINE_LEN + 1];
	int linenum = 0;
	char wordbuf[LINE_LEN];
	char *wordend;
	struct config_entry *ce;
	int err = 0, found = 0;
	long val;
	unsigned int i;

	ulogd_log(ULOGD_DEBUG, "section: %s, file: %s\n",
		  section, ulogd_config_fname);
	cfile = fopen(ulogd_config_fname, "r");
	if (!cfile) {
		ulogd_log(ULOGD_ERROR, "could not open file - %s: %s\n",
			  ulogd_config_fname, strerror(errno));
		return -ERROPEN;
	}

	/* Search for correct section */
	while (fgets(line, LINE_LEN, cfile)) {
		linenum++;
		if (line[0] == '#')
			continue;

		/* if line was fetch completely, string ends with '\n' */
		if (!strchr(line, '\n')) {
			ulogd_log(ULOGD_ERROR, "line %d too long.\n", linenum);
			err = -ERRTOOLONG;
			goto cpf_error;
		}

		wordend = get_word(line, " \t\n\r[]", wordbuf);
		if (!wordend) {
			ulogd_log(ULOGD_ERROR,
				  "ignore invalid line: %s\n", line);
			continue;
		}

		ulogd_log(ULOGD_DEBUG, "section: %s\n", wordbuf);
		if (!strcmp(wordbuf, section)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		ulogd_log(ULOGD_ERROR, "no section found: %s\n", section);
		err = -ERRSECTION;
		goto cpf_error;
	}

	/* Parse this section until next section */
	while (fgets(line, LINE_LEN, cfile)) {
		linenum++;
		if (line[0] == '#')
			continue;

		/* if line was fetch completely, string ends with '\n' */
		if (!strchr(line, '\n')) {
			ulogd_log(ULOGD_ERROR, "line %d too long.\n", linenum);
			err = -ERRTOOLONG;
			goto cpf_error;
		}

		wordend = get_word(line, " =\t\n\r", wordbuf);
		if (!wordend) {
			ulogd_log(ULOGD_ERROR,
				  "ignore invalid line: %s\n", line);
			continue;
		}

		if (wordbuf[0] == '[' ) {
			pr_debug("Next section '%s' encountered\n", wordbuf);
			break;
		}

		for (i = 0; i < kset->num_ces; i++) {
			ce = &kset->ces[i];
			if (strcmp(ce->key, wordbuf) ||
			    ce->flag & CONFIG_FLAG_VAL_PROTECTED)
				continue;

			wordend = get_word(wordend, " =\t\n\r", wordbuf);
			if (ce->hit && !(ce->options & CONFIG_OPT_MULTI)) {
				ulogd_log(ULOGD_ERROR,
					  "multi entry is not allowed: %s\n",
					  ce->key);
				config_errce = ce;
				err = -ERRMULT;
				goto cpf_error;
			}
			ce->hit++;

			switch (ce->type) {
			case CONFIG_TYPE_STRING:
				if (strlen(wordbuf) > CONFIG_VAL_STRING_LEN ) {
					ulogd_log(ULOGD_ERROR,
						  "too long value: %s\n",
						  wordbuf);
					config_errce = ce;
					err = -ERRTOOLONG;
					goto cpf_error;
				}
				strcpy(ce->u.string, wordbuf);
				break;
			case CONFIG_TYPE_INT:
				val = strtol(wordbuf, NULL, 0);
				if (val >= INT_MAX || val <= INT_MIN) {
					ulogd_log(ULOGD_ERROR,
						  "over int range: %s\n",
						  wordbuf);
					err = -ERANGE;
					goto cpf_error;
				}
				if (errno != 0 && val) {
					ulogd_log(ULOGD_ERROR,
						  "invalid integer: %s\n",
						  wordbuf);
 					err = -errno;
 					goto cpf_error;
 				}
				ce->u.value = (int)val;
 				break;
			case CONFIG_TYPE_CALLBACK:
				err = (ce->u.parser)(wordbuf);
				if (err) {
					ulogd_log(ULOGD_ERROR,
						  "parser %s, returns: %d\n",
						  ce->key, err);
					goto cpf_error;
				}
				break;
			}
		}
	}

	/* check mandatory */
	for (i = 0; i < kset->num_ces; i++) {
		ce = &kset->ces[i];
		if (ce->options & CONFIG_OPT_MANDATORY && !ce->hit) {
			ulogd_log(ULOGD_ERROR,
				  "no mandatory entry: %s\n", ce->key);
			config_errce = ce;
			err = -ERRMAND;
			goto cpf_error;
		}

	}

cpf_error:
	fclose(cfile);
	return err;
}

void config_stop(void)
{
	free(ulogd_config_fname);
	ulogd_config_fname = NULL;
}
