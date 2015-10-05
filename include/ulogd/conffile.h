/* config file parser functions
 *
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * This code is distributed under the terms of GNU GPL */

#ifndef _CONFFILE_H
#define _CONFFILE_H

#include <stdint.h>

/* errors returned by config functions */
enum {
	ERRNONE = 0,
	ERROPEN,	/* unable to open config file */
	ERROOM,		/* out of memory */
	ERRMULT,	/* non-multiple option occured more  than once */
	ERRMAND,	/* mandatory option not found */
	ERRUNKN,	/* unknown config key */
	ERRSECTION,	/* section not found */
	ERRTOOLONG,	/* string too long */
};

/* maximum line length of config file entries */
#define LINE_LEN 		255

/* maximum length of config key name */
#define CONFIG_KEY_LEN		31

/* maximum length of string config value */
#define CONFIG_VAL_STRING_LEN	255

/* valid config types */
#define CONFIG_TYPE_INT		0x0001
#define CONFIG_TYPE_STRING	0x0002
#define CONFIG_TYPE_CALLBACK	0x0003

/* valid config options */
#define CONFIG_OPT_NONE		0x0000
#define CONFIG_OPT_MANDATORY	0x0001
#define CONFIG_OPT_MULTI	0x0002

/* valid flag part */
#define CONFIG_FLAG_VAL_PROTECTED	(1<<0)

/* return negative errno on error */
typedef int (*config_parser_t)(const char *const argstr);

struct config_entry {
	char key[CONFIG_KEY_LEN + 1];	/* name of config directive */
	uint8_t type;			/* type; see above */
	uint8_t options;		/* options; see above  */
	uint8_t hit;			/* found? */
	uint8_t flag;			/* tune setup of option */
	union {
		char string[CONFIG_VAL_STRING_LEN + 1];
		int value;
		config_parser_t parser;
	} u;
};

struct config_keyset {
	uint8_t num_ces;
	struct config_entry ces[];
};

/* if an error occurs, config_errce is set to the erroneous ce */
extern struct config_entry *config_errce;

/* tell us the name of the config file */
int config_register_file(const char *file);

/* parse the config file */
int config_parse_file(const char *section, struct config_keyset *kset);

/* release ressource allocated by config file handling */
void config_stop(void);


struct ulogd_plugin *
ulogd_plugin_json_config(const char *const fname);
struct ulogd_source_plugin *
ulogd_source_plugin_json_config(const char *const fname);

int ulogd_config_int(const struct config_keyset *configs,
		     const char *const name);
const char *ulogd_config_str(const struct config_keyset *configs,
			     const char *const name);
int ulogd_config_id_int(const struct config_keyset *configs, uint8_t id);
const char *ulogd_config_id_str(const struct config_keyset *configs, uint8_t id);

#endif /* ifndef _CONFFILE_H */
