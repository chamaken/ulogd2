/* ulogd
 *
 * unified network logging daemon for Linux.
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 * (C) 2013 by Eric Leblond <eric@regit.org>
 * (C) 2013 Chris Boot <bootc@bootc.net>
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
 * Modifications:
 *	14 Jun 2001 Martin Josefsson <gandalf@wlug.westbo.se>
 *		- added SIGHUP handler for logfile cycling
 *
 *	10 Feb 2002 Alessandro Bono <a.bono@libero.it>
 *		- added support for non-fork mode
 *		- added support for logging to stdout
 *
 *	09 Sep 2003 Magnus Boden <sarek@ozaba.cx>
 *		- added support for more flexible multi-section conffile
 *
 *	20 Apr 2004 Nicolas Pougetoux <nicolas.pougetoux@edelweb.fr>
 *		- added suppurt for seteuid()
 *
 *	22 Jul 2004 Harald Welte <laforge@gnumonks.org>
 *		- major restructuring for flow accounting / ipfix work
 *
 *	03 Oct 2004 Harald Welte <laforge@gnumonks.org>
 *		- further unification towards generic network event logging
 *		  and support for lnstat
 *
 *	07 Oct 2005 Harald Welte <laforge@gnumonks.org>
 *		- finally get ulogd2 into a running state
 *
 */

/* _sys_errlist */
# define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <pthread.h>

#include <ulogd/conffile.h>
#include <ulogd/ulogd.h>
#include <ulogd/keysets.h>
#include <ulogd/thread.h>

#ifdef DEBUG
#define DEBUGP(format, args...) fprintf(stderr, format, ## args)
#else
#define DEBUGP(format, args...)
#endif

#define COPYRIGHT					       \
	"(C) 2000-2006 Harald Welte <laforge@netfilter.org>\n"	  \
	"(C) 2008-2012 Pablo Neira Ayuso <pablo@netfilter.org>\n" \
	"(C) 2008-2012 Eric Leblond <eric@regit.org>\n"

/* global variables */
static FILE *logfile = NULL;		/* logfile pointer */
static char *ulogd_logfile = NULL;
static const char *ulogd_configfile = ULOGD_CONFIGFILE;
static const char *ulogd_pidfile = NULL;
static int ulogd_pidfile_fd = -1;
static FILE syslog_dummy;

static int info_mode = 0;

static int verbose = 0;
static int created_pidfile = 0;

struct ulogd_fd signal_ufd; /* XXX: close on err/exit */

/* linked list for all registered plugins */
static LLIST_HEAD(ulogd_plugins);
/* linked list for all registered source plugins */
static LLIST_HEAD(ulogd_source_plugins);

/* linked list for all plugins handle */
static LLIST_HEAD(ulogd_plugins_handle);

/* linked list for plug instances */
static LLIST_HEAD(ulogd_pluginstances);
/* linked list for source plug instances */
static LLIST_HEAD(ulogd_source_pluginstances);


/* function returns 0 on success */
static int load_plugin(const char *file);
static int create_stack(const char *file);
static int logfile_open(const char *name);
static void cleanup_pidfile();

static struct config_keyset ulogd_kset = {
	.num_ces = 4,
	.ces = {
		{
			.key = "logfile",
			.type = CONFIG_TYPE_CALLBACK,
			.options = CONFIG_OPT_NONE,
			.u.parser = &logfile_open,
		},
		{
			.key = "plugin",
			.type = CONFIG_TYPE_CALLBACK,
			.options = CONFIG_OPT_MULTI,
			.u.parser = &load_plugin,
		},
		{
			.key = "loglevel",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = ULOGD_NOTICE,
		},
		{
			.key = "stack",
			.type = CONFIG_TYPE_CALLBACK,
			.options = CONFIG_OPT_MULTI,
			.u.parser = &create_stack,
		},
	},
};

#define logfile_ce	ulogd_kset.ces[0]
#define plugin_ce	ulogd_kset.ces[1]
#define loglevel_ce	ulogd_kset.ces[2]
#define stack_ce	ulogd_kset.ces[3]

/***********************************************************************
 * UTILITY FUNCTIONS FOR PLUGINS
 ***********************************************************************/

int ulogd_key_size(struct ulogd_key *key)
{
	int ret;

	switch (key->type) {
	case ULOGD_RET_INT8:
	case ULOGD_RET_UINT8:
	case ULOGD_RET_BOOL:
		ret = 1;
		break;
	case ULOGD_RET_INT16:
	case ULOGD_RET_UINT16:
		ret = 2;
		break;
	case ULOGD_RET_INT32:
	case ULOGD_RET_UINT32:
	case ULOGD_RET_IPADDR:
		ret = 4;
		break;
	case ULOGD_RET_INT64:
	case ULOGD_RET_UINT64:
		ret = 8;
		break;
	case ULOGD_RET_IP6ADDR:
		ret = 16;
		break;
	case ULOGD_RET_STRING:
		ret = strlen(key->u.value.ptr);
		break;
	case ULOGD_RET_RAW:
		ret = key->len;
		break;
	default:
		ulogd_log(ULOGD_ERROR, "don't know sizeof unknown key "
			  "`%s' type 0x%x\n", key->name, key->type);
		ret = -1;
		break;
	}

	return ret;
}

/***********************************************************************
 * PLUGIN MANAGEMENT
 ***********************************************************************/

/* try to lookup a registered plugin for a given name
 * plugin may not be identified after its configuration */
static struct ulogd_plugin *find_plugin(const char *name)
{
	struct ulogd_plugin *pl;

	llist_for_each_entry(pl, &ulogd_plugins, list) {
		if (strcmp(name, pl->name) == 0) {
			pl->usage++;
			return pl;
		}
	}

	return NULL;
}

/* try to lookup a registered source plugin for a given name */
static struct ulogd_source_plugin *find_source_plugin(const char *name)
{
	struct ulogd_source_plugin *pl;

	llist_for_each_entry(pl, &ulogd_source_plugins, list) {
		if (strcmp(name, pl->name) == 0) {
			pl->usage++;
			return pl;
		}
	}

	return NULL;
}

char *type_to_string(int type)
{
	switch (type) {
	case ULOGD_RET_INT8:
		return strdup("int 8");
		break;
	case ULOGD_RET_INT16:
		return strdup("int 16");
		break;
	case ULOGD_RET_INT32:
		return strdup("int 32");
		break;
	case ULOGD_RET_INT64:
		return strdup("int 64");
		break;
	case ULOGD_RET_UINT8:
		return strdup("unsigned int 8");
		break;
	case ULOGD_RET_UINT16:
		return strdup("unsigned int 16");
		break;
	case ULOGD_RET_UINT32:
		return strdup("unsigned int 32");
		break;
	case ULOGD_RET_UINT64:
		return strdup("unsigned int 64");
		break;
	case ULOGD_RET_BOOL:
		return strdup("boolean");
		break;
	case ULOGD_RET_IPADDR:
		return strdup("IP addr");
		break;
	case ULOGD_RET_IP6ADDR:
		return strdup("IPv6 addr");
		break;
	case ULOGD_RET_STRING:
		return strdup("string");
		break;
	case ULOGD_RET_RAW:
		return strdup("raw data");
		break;
	default:
		return strdup("Unknown type");
	}
}

/* XXX: handle both plugin and source_plugin */
void get_plugin_infos(struct ulogd_plugin *me, int has_input)
{
	unsigned int i;
	printf("Name: %s\n", me->name);
	if (me->config_kset) {
		printf("Config options:\n");
		for(i = 0; i < me->config_kset->num_ces; i++) {
			printf("\tVar: %s (", me->config_kset->ces[i].key);
			switch (me->config_kset->ces[i].type) {
				case CONFIG_TYPE_STRING:
					printf("String");
					printf(", Default: %s", 
					       me->config_kset->ces[i].u.string);
					break;
				case CONFIG_TYPE_INT:
					printf("Integer");
					printf(", Default: %d",
					       me->config_kset->ces[i].u.value);
					break;
				case CONFIG_TYPE_CALLBACK:
					printf("Callback");
					break;
				default:
					printf("Unknown");
					break;
			}
			if (me->config_kset->ces[i].options == 
						CONFIG_OPT_MANDATORY) {
				printf(", Mandatory");
			}
			printf(")\n");
		}
	}
	printf("Input keys:\n");
	if (has_input) {
		if (me->input.num_keys == 0) {
			printf("\tNo statically defined keys\n");
		} else {
			for(i = 0; i < me->input.num_keys; i++) {
				char *tstring = 
					type_to_string(me->input.keys[i].type);
				printf("\tKey: %s (%s",
				       me->input.keys[i].name,
				       tstring);
				if (me->input.keys[i].flags
						& ULOGD_KEYF_OPTIONAL)
					printf(", optional)\n");
				else
					printf(")\n");
				free(tstring);
			}
		}
	} else {
		printf("\tInput plugin, No keys\n");
	}
	printf("Output keys:\n");
	if ((me->output.type & ULOGD_DTYPE_SINK) == 0) {
		if (me->output.num_keys == 0) {
			printf("\tNo statically defined keys\n");
		} else {
			for(i = 0; i < me->output.num_keys; i++) {
				char *tstring =
					type_to_string(me->output.keys[i].type);
				printf("\tKey: %s (%s)\n",
				       me->output.keys[i].name,
				       tstring);
				free(tstring);
			}
		}
	} else {
		printf("\tOutput plugin, No keys\n");
	}
}

/* the function called by all plugins for registering themselves */
void ulogd_register_plugin(struct ulogd_plugin *me)
{
	if (strcmp(me->version, VERSION)) {
		ulogd_log(ULOGD_NOTICE,
			  "plugin `%s' has incompatible version %s\n",
			  me->name, me->version);
		return;
	}
	if (info_mode == 0) {
		if (find_plugin(me->name)) {
			ulogd_log(ULOGD_NOTICE,
				  "plugin `%s' already registered\n",
				  me->name);
			exit(EXIT_FAILURE);
		}
		ulogd_log(ULOGD_DEBUG, "registering plugin `%s'\n", me->name);
		llist_add(&me->list, &ulogd_plugins);
	} else {
		get_plugin_infos(me, 1);
	}
}

/* the function called by all source plugins for registering themselves */
void ulogd_register_source_plugin(struct ulogd_source_plugin *me)
{
	if (strcmp(me->version, VERSION)) {
		ulogd_log(ULOGD_NOTICE,
			  "plugin `%s' has incompatible version %s\n",
			  me->name, me->version);
		return;
	}
	if (info_mode == 0) {
		if (find_source_plugin(me->name)) {
			ulogd_log(ULOGD_NOTICE,
				  "plugin `%s' already registered\n",
				  me->name);
			exit(EXIT_FAILURE);
		}
		ulogd_log(ULOGD_DEBUG, "registering source plugin `%s'\n",
			  me->name);
		llist_add(&me->list, &ulogd_source_plugins);
	} else {
		/* XXX: assume get_plugin_infos() not accessing diff part */
		get_plugin_infos((struct ulogd_plugin *)me, 0);
	}
}

struct ulogd_plugin *ulogd_plugin_copy_newkeys(struct ulogd_plugin *src,
					       size_t ikeys_num,
					       size_t okeys_num)
{
	struct ulogd_plugin *dst = calloc(1, sizeof(struct ulogd_plugin)
					  + (ikeys_num + okeys_num)
					  * sizeof(struct ulogd_key));

	if (dst == NULL)
		return NULL;

	memcpy(dst, src, sizeof(struct ulogd_plugin));

	dst->input.keys = (void *)dst + sizeof(struct ulogd_plugin);
	dst->input.num_keys = ikeys_num;
	dst->output.keys = &dst->input.keys[ikeys_num];
	dst->output.num_keys = okeys_num;

	return dst;
}

/***********************************************************************
 * MAIN PROGRAM
 ***********************************************************************/

static inline int ulogd2syslog_level(int level)
{
	int syslog_level = LOG_WARNING;

	switch (level) {
	case ULOGD_DEBUG:
		syslog_level = LOG_DEBUG;
		break;
	case ULOGD_INFO:
		syslog_level = LOG_INFO;
		break;
	case ULOGD_NOTICE:
		syslog_level = LOG_NOTICE;
		break;
	case ULOGD_ERROR:
		syslog_level = LOG_ERR;
		break;
	case ULOGD_FATAL:
		syslog_level = LOG_CRIT;
		break;
	}

	return syslog_level;
}

/* log message to the logfile */
void __ulogd_log(int level, char *file, int line, const char *format, ...)
{
	char *timestr;
	va_list ap;
	time_t tm;
	FILE *outfd;

	/* log only messages which have level at least as high as loglevel */
	if (level < loglevel_ce.u.value)
		return;

	if (logfile == &syslog_dummy) {
		/* FIXME: this omits the 'file' string */
		va_start(ap, format);
		vsyslog(ulogd2syslog_level(level), format, ap);
		va_end(ap);
	} else {
		if (logfile)
			outfd = logfile;
		else
			outfd = stderr;

		tm = time(NULL);
		timestr = ctime(&tm);
		timestr[strlen(timestr)-1] = '\0';
		fprintf(outfd, "%s <%1.1d> %s:%d ", timestr, level, file, line);
		if (verbose && outfd != stderr)
			fprintf(stderr, "%s <%1.1d> %s:%d ", timestr, level, file, line);

		va_start(ap, format);
		vfprintf(outfd, format, ap);
		va_end(ap);
		/* flush glibc's buffer */
		fflush(outfd);

		if (verbose && outfd != stderr) {
			va_start(ap, format);
			vfprintf(stderr, format, ap);
			va_end(ap);
			fflush(stderr);
		}

	}
}

static size_t ulogd_config_keysize(struct config_keyset *kset)
{
	if (kset != NULL)
		return sizeof(struct config_keyset)
			+ kset->num_ces * sizeof(struct config_entry);
	return 0;
}

static void ulogd_copy_config_keyset(struct config_keyset *dst,
				     struct config_keyset *src)
{
	dst->num_ces = src->num_ces;
	if (src->num_ces)
		memcpy(dst->ces, src->ces,
		       src->num_ces * sizeof(struct config_entry));
}

static struct ulogd_pluginstance *
pluginstance_alloc(struct ulogd_plugin *pl)
{
	return calloc(1, sizeof(struct ulogd_pluginstance)
		      + ulogd_config_keysize(pl->config_kset)
		      + pl->priv_size);
}

static struct ulogd_pluginstance *
pluginstance_alloc_init(struct ulogd_plugin *pl, const char *pi_id)
{
	struct ulogd_pluginstance *pi = pluginstance_alloc(pl);

	if (!pi)
		return NULL;

	/* initialize */
	pi->plugin = pl;
	memcpy(pi->id, pi_id, sizeof(pi->id));
	if (!pl->mtsafe) {
		if (pthread_mutex_init(&pi->interp_mutex, NULL)) {
			free(pi);
			return NULL;
		}
	}

	/* copy config keys */
	if (pl->config_kset) {
		pi->config_kset = (void *)pi + sizeof(*pi) + pl->priv_size;
		ulogd_copy_config_keyset(pi->config_kset, pl->config_kset);
	} else
		pi->config_kset = NULL;

	return pi;
}

static struct ulogd_source_pluginstance *
source_pluginstance_alloc(struct ulogd_source_plugin *pl)
{
	return calloc(1, sizeof(struct ulogd_source_pluginstance)
		      + ulogd_config_keysize(pl->config_kset)
		      + pl->priv_size);
}

static struct ulogd_source_pluginstance *
source_pluginstance_alloc_init(struct ulogd_source_plugin *pl,
			       const char *pi_id)
{
	struct ulogd_source_pluginstance *pi = source_pluginstance_alloc(pl);

	if (!pi)
		return NULL;

	/* initialize */
	INIT_LLIST_HEAD(&pi->keysets_bundles);
	INIT_LLIST_HEAD(&pi->stacks);
	pi->plugin = pl;
	memcpy(pi->id, pi_id, sizeof(pi->id));

	/* copy config keys */
	if (pl->config_kset) {
		pi->config_kset = (void *)pi + sizeof(*pi) + pl->priv_size;
		ulogd_copy_config_keyset(pi->config_kset, pl->config_kset);
	} else
		pi->config_kset = NULL;

	return pi;
}

/* plugin loader to dlopen() a plugins */
static int load_plugin(const char *file)
{
	void * handle;
	struct ulogd_plugin_handle *ph;
	if ((handle = dlopen(file, RTLD_NOW)) == NULL) {
		ulogd_log(ULOGD_ERROR, "load_plugin: '%s': %s\n", file,
			  dlerror());
		return -1;
	}

	ph = (struct ulogd_plugin_handle *)calloc(1, sizeof(*ph));
	ph->handle = handle;
	llist_add(&ph->list, &ulogd_plugins_handle);
	return 0;
}

/* try to lookup a registered pluginstance for a given id */
static struct ulogd_pluginstance *
find_pluginstance(struct ulogd_plugin *pl, const char *id)
{
	struct ulogd_pluginstance *pi;

	llist_for_each_entry(pi, &ulogd_pluginstances, list) {
		if (!strcmp(pi->id, id)) {
			if (pi->plugin != pl) {
				ulogd_log(ULOGD_ERROR, "found same id pluginstance, "
					  "but its plugin is differ - %s/%s\n",
					  pi->plugin->name, pl->name);
				return NULL;
			}
			return pi;
		}
	}

	return NULL;
}

/* try to lookup a registered source pluginstance for a given id */
static struct ulogd_source_pluginstance *
find_source_pluginstance(struct ulogd_source_plugin *pl, const char *id)
{
	struct ulogd_source_pluginstance *pi;

	llist_for_each_entry(pi, &ulogd_source_pluginstances, list) {
		if (!strcmp(pi->id, id)) {
			if (pi->plugin != pl) {
				ulogd_log(ULOGD_ERROR, "found same id pluginstance, "
					  "but its plugin is differ - %s/%s\n",
					  pi->plugin->name, pl->name);
				return NULL;
			}
			return pi;
		}
	}

	return NULL;
}

/* find or create new pluginstance */
static struct ulogd_pluginstance *
lookup_pluginstance(struct ulogd_plugin *pl, const char *id)
{
	struct ulogd_pluginstance *pi;

	pi = find_pluginstance(pl, id);
	if (pi) {
		pi->usage++;
		return pi;
	}

	pi = pluginstance_alloc_init(pl, id);
	if (pi == NULL)
		return NULL;

	llist_add(&pi->list, &ulogd_pluginstances);
	pi->usage = 1;
	return pi;
}

/* find or create new source pluginstance */
static struct ulogd_source_pluginstance *
lookup_source_pluginstance(struct ulogd_source_plugin *pl, const char *id)
{
	struct ulogd_source_pluginstance *spi;

	spi = find_source_pluginstance(pl, id);
	if (spi) {
		spi->usage++;
		return spi;
	}

	spi = source_pluginstance_alloc_init(pl, id);
	if (spi == NULL)
		return NULL;

	llist_add(&spi->list, &ulogd_source_pluginstances);
	spi->usage = 1;
	return spi;
}

static int ulogd_stacks_destroy(struct ulogd_source_pluginstance *spi)
{
	struct ulogd_stack *stack, *stmp;
	struct ulogd_stack_element *elem, *etmp;

	llist_for_each_entry_safe(stack, stmp, &spi->stacks, list) {
		llist_for_each_entry_safe(elem, etmp, &stack->elements, list)
			free(elem);
		free(stack->name);
		free(stack);
	}

	return 0;
}

static int check_last_output()
{
	struct ulogd_source_pluginstance *spi;
	struct ulogd_stack *stack;
	struct ulogd_stack_element *elem;

	llist_for_each_entry(spi, &ulogd_source_pluginstances, list) {
		llist_for_each_entry(stack, &spi->stacks, list) {
			elem = llist_entry(stack->elements.prev,
					   struct ulogd_stack_element, list);
			/* check the last output key type */
			if ((elem->pi->output_template->type
			     & ULOGD_DTYPE_SINK) == 0) {
				ulogd_log(ULOGD_ERROR, "last pluginstance in stack "
					  "has to be output plugin\n");
				return -EINVAL;
			}
		}
	}
	return 0;
}

static int start_pluginstances()
{
	struct ulogd_pluginstance *pi, *err_pi = NULL;
	struct ulogd_source_pluginstance *spi, *err_spi = NULL;
	int ret;

	llist_for_each_entry(spi, &ulogd_source_pluginstances, list) {
		if (spi->plugin->start) {
			ret = spi->plugin->start(spi);
			if (ret < 0) {
				ulogd_log(ULOGD_ERROR, "error during "
					  "start of plugin %s\n",
					  spi->plugin->name);
				err_spi = spi;
				goto call_stop;
			}
		}
	}
	err_spi = NULL;

	llist_for_each_entry(pi, &ulogd_pluginstances, list) {
		if (pi->plugin->start) {
			ret = pi->plugin->start(pi, pi->input_template);
			if (ret < 0) {
				ulogd_log(ULOGD_ERROR, "error during "
					  "start of plugin %s\n",
					  pi->plugin->name);
				err_pi = pi;
				goto call_stop;
			}
		}
	}

	return 0;

call_stop:
	if (err_spi != NULL) {
		llist_for_each_entry(spi, &ulogd_source_pluginstances, list) {
			if (spi == err_spi)
				break;
			if (spi->plugin->stop) {
				spi->plugin->stop(spi);
			}
		}
	}
	if (err_pi != NULL) {
		llist_for_each_entry(pi, &ulogd_pluginstances, list) {
			if (pi == err_pi)
				break;
			if (pi->plugin->stop) {
				pi->plugin->stop(pi);
			}
		}
	}
	return -1;
}

static int configure_pluginstances()
{
	struct ulogd_pluginstance *pi;
	struct ulogd_source_pluginstance *spi;
	int ret;

	/* reverse has less mean... */
	llist_for_each_entry_reverse(pi, &ulogd_pluginstances, list) {
		if (pi->plugin->configure) {
			ret = pi->plugin->configure(pi);
			if (ret < 0) {
				ulogd_log(ULOGD_ERROR, "error during "
					  "configure of plugin %s\n",
					  pi->plugin->name);
				return ULOGD_IRET_ERR;
			}
		}
	}

	llist_for_each_entry(spi, &ulogd_source_pluginstances, list) {
		if (spi->plugin->configure) {
			ret = spi->plugin->configure(spi);
			if (ret < 0) {
				ulogd_log(ULOGD_ERROR, "error during "
					  "configure of plugin %s\n",
					  spi->plugin->name);
				return ret;
			}
		}
	}
	return 0;
}

/* create a new stack of plugins */
static int create_stack(const char *option)
{
	struct ulogd_stack *stack;
	struct ulogd_plugin *pl = NULL;
	struct ulogd_pluginstance *pi = NULL, *pi_prev;
	struct ulogd_source_plugin *spl;
	struct ulogd_source_pluginstance *spi;
	struct ulogd_stack_element *elem, *elem2;

	char *buf = strdup(option);
	char pi_id[ULOGD_MAX_KEYLEN];
	char *tok, *plname, *equals;
	int ret = 0;

	if (!buf) {
		ulogd_log(ULOGD_ERROR, "");
		ret = -ENOMEM;
		goto out;
	}

	ulogd_log(ULOGD_NOTICE, "building new pluginstance stack: '%s'\n",
		  option);

	/* parse token into sub-tokens */
	tok = strtok(buf, ",\n");
	ulogd_log(ULOGD_DEBUG, "tok=`%s'\n", tok);
	equals = strchr(tok, ':');
	if (!equals || (equals - tok >= ULOGD_MAX_KEYLEN)) {
		ulogd_log(ULOGD_ERROR, "syntax error while parsing `%s'"
			  "of line `%s'\n", tok, buf);
		ret = -EINVAL;
		goto out_buf;
	}
	strncpy(pi_id, tok, ULOGD_MAX_KEYLEN-1);
	pi_id[equals - tok] = '\0';
	plname = equals + 1;

	/* PASS 1: find or instanciate source pluginstance */
	spl = find_source_plugin(plname);
	if (!spl) {
		ulogd_log(ULOGD_ERROR, "can't find requested source plugin "
			  "%s\n", plname);
		ret = -ENODEV;
		goto out_buf;
	}

	spi = lookup_source_pluginstance(spl, pi_id);
	if (!spi) {
		ulogd_log(ULOGD_ERROR,
			  "unable to allocate source pluginstance for %s\n",
			  pi_id);
		ret = -ENOMEM;
		goto out_buf;
	}

	stack = calloc(1, sizeof(struct ulogd_stack));
	if (!stack) {
		ret = -ENOMEM;
		goto out_buf;
	}
	INIT_LLIST_HEAD(&stack->elements);
	stack->name = strdup(option);
	if (stack->name == NULL) {
		ret = -ENOMEM;
		goto out_stack;
	}

	/* access source plugin as normal plugin for key consistency check */
	pi_prev = (struct ulogd_pluginstance *)spi;

	/* PASS 2: find and instanciate plugins of stack, link them together */
	tok = strtok(NULL, ",\n");
	for (; tok; tok = strtok(NULL, ",\n")) {
		ulogd_log(ULOGD_DEBUG, "tok=`%s'\n", tok);

		/* parse token into sub-tokens */
		equals = strchr(tok, ':');
		if (!equals || (equals - tok >= ULOGD_MAX_KEYLEN)) {
			ulogd_log(ULOGD_ERROR, "syntax error while parsing `%s'"
				  "of line `%s'\n", tok, buf);
			ret = -EINVAL;
			goto out_name;
		}
		strncpy(pi_id, tok, ULOGD_MAX_KEYLEN-1);
		pi_id[equals - tok] = '\0';
		plname = equals + 1;

		/* find matching plugin */
		pl = find_plugin(plname);
		if (!pl) {
			ulogd_log(ULOGD_ERROR, "can't find requested plugin "
				  "%s\n", plname);
			ret = -ENODEV;
			goto out_name;
		}
		pi = lookup_pluginstance(pl, pi_id);
		if (!pi) {
			ulogd_log(ULOGD_ERROR,
				  "unable to allocate pluginstance for %s\n",
				  pi_id);
			ret = -ENOMEM;
			goto out_name;
		}

		/* check input/output key consistency */
		if (UPI_INPUT_KEYSET(pi)->type
		    & UPI_OUTPUT_KEYSET(pi_prev)->type) {
			ulogd_log(ULOGD_ERROR, "type mismatch between "
				  "%s:%s and %s:%s in stack\n",
				  pi->id, pi->plugin->name,
				  pi_prev->id, pi_prev->plugin->name);
		}

		ulogd_log(ULOGD_DEBUG, "pushing `%s' on stack\n", pl->name);
		elem = calloc(1, sizeof(struct ulogd_stack_element));
		if (elem == NULL) {
			ulogd_log(ULOGD_ERROR,
				  "unable to allocate stack element header for %s\n",
				  pi_id);
			ret = -ENOMEM;
			goto out_elements;
		}
		elem->pi = pi;
		llist_add_tail(&elem->list, &stack->elements);
	}

	llist_add(&stack->list, &spi->stacks);
	spi->nstacks++;
	free(buf);
	return 0;

out_elements:
	llist_for_each_entry_safe(elem, elem2, &stack->elements, list) {
		llist_del(&elem->list);
		free(elem);
	}
out_name:
	free(stack->name);
out_stack:
	free(stack);
out_buf:
	free(buf);
out:
	return ret;
}

static void ulogd_main_loop(void)
{
	int ret;

	while (1) {
		/* XXX: signal blocking? */
		ret = ulogd_select_main();
		if (ret < 0 && errno != EINTR)
			ulogd_log(ULOGD_ERROR, "select says %s\n",
				  strerror(errno));
	}
}

/* open the logfile */
static int logfile_open(const char *name)
{
	if (name) {
		free(ulogd_logfile);
		ulogd_logfile = strdup(name);
	}

	if (!strcmp(name, "stdout")) {
		logfile = stdout;
	} else if (!strcmp(name, "syslog")) {
		openlog("ulogd", LOG_PID, LOG_DAEMON);
		logfile = &syslog_dummy;
	} else {
		logfile = fopen(ulogd_logfile, "a");
		if (!logfile) {
			fprintf(stderr, "ERROR: can't open logfile '%s': %s\n",
				name, strerror(errno));
			exit(2);
		}
	}
	ulogd_log(ULOGD_INFO, "ulogd Version %s (re-)starting\n", VERSION);
	return 0;
}

/* wrapper to handle conffile error codes */
static int parse_conffile(const char *section, struct config_keyset *ce)
{
	int err;

	err = config_parse_file(section, ce);

	switch(err) {
	case 0:
		return 0;
		break;
	case -ERROPEN:
		ulogd_log(ULOGD_ERROR,
			  "unable to open configfile: %s\n",
			  ulogd_configfile);
		break;
	case -ERRMAND:
		ulogd_log(ULOGD_ERROR,
			  "mandatory option \"%s\" not found\n",
			  config_errce->key);
		break;
	case -ERRMULT:
		ulogd_log(ULOGD_ERROR,
			  "option \"%s\" occurred more than once\n",
			  config_errce->key);
		break;
	case -ERRUNKN:
		ulogd_log(ULOGD_ERROR,
			  "unknown config key \"%s\"\n",
			  config_errce->key);
		break;
	case -ERRSECTION:
		ulogd_log(ULOGD_ERROR,
			  "section \"%s\" not found\n", section);
		break;
	case -ERRTOOLONG:
		if (config_errce->key)
			ulogd_log(ULOGD_ERROR,
				  "string value too long for key \"%s\"\n",
				  config_errce->key);
		else
			ulogd_log(ULOGD_ERROR,
				  "string value is too long\n");
		break;
	}
	return 1;
}

/*
 * Apply F_WRLCK to fd using fcntl().
 *
 * This function is copied verbatim from atd's daemon.c file, published under
 * the GPL2+ license with the following copyright statement:
 * Copyright (C) 1996 Thomas Koenig
 */
static int lock_fd(int fd, int wait)
{
	struct flock lock;

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (wait)
		return fcntl(fd, F_SETLKW, &lock);
	else
		return fcntl(fd, F_SETLK, &lock);
}

/*
 * Manage ulogd's pidfile.
 *
 * This function is based on atd's daemon.c:daemon_setup() function, published
 * under the GPL2+ license with the following copyright statement:
 * Copyright (C) 1996 Thomas Koenig
 */
static int create_pidfile()
{
	int fd;
	FILE *fp;
	pid_t pid = -1;

	if (!ulogd_pidfile)
		return 0;

	fd = open(ulogd_pidfile, O_RDWR | O_CREAT | O_EXCL, 0644);
	if (fd < 0) {
		if (errno != EEXIST) {
			ulogd_log(ULOGD_ERROR, "cannot open %s: %d\n",
				  ulogd_pidfile, errno);
			return -1;
		}

		fd = open(ulogd_pidfile, O_RDWR);
		if (fd < 0) {
			ulogd_log(ULOGD_ERROR, "cannot open %s: %d\n",
				  ulogd_pidfile, errno);
			return -1;
		}

		fp = fdopen(fd, "rw");
		if (fp == NULL) {
			ulogd_log(ULOGD_ERROR, "cannot fdopen %s: %d\n",
				  ulogd_pidfile, errno);
			close(fd);
			return -1;
		}

		if ((fscanf(fp, "%d", &pid) != 1) || (pid == getpid())
		    || (lock_fd(fd, 0) == 0)) {
			ulogd_log(ULOGD_NOTICE,
				  "removing stale pidfile for pid %d\n", pid);

			if (unlink(ulogd_pidfile) < 0) {
				ulogd_log(ULOGD_ERROR, "cannot unlink %s: %d\n",
					  ulogd_pidfile, errno);
				return -1;
			}
		} else {
			ulogd_log(ULOGD_FATAL,
				  "another ulogd already running with pid %d\n",
				  pid);
			fclose(fp);
			close(fd);
			return -1;
		}

		close(fd);
		fclose(fp);
		unlink(ulogd_pidfile);

		fd = open(ulogd_pidfile, O_RDWR | O_CREAT | O_EXCL, 0644);

		if (fd < 0) {
			ulogd_log(ULOGD_ERROR,
				  "cannot open %s (2nd time round): %d\n",
				  ulogd_pidfile, errno);
			return -1;
		}
	}

	if (lock_fd(fd, 0) < 0) {
		ulogd_log(ULOGD_ERROR, "cannot lock %s: %s\n", ulogd_pidfile,
			  strerror(errno));
		close(fd);
		return -1;
	}
	ulogd_pidfile_fd = fd;
	return 0;
}

static int write_pidfile(int daemonize)
{
	FILE *fp;
	if (!ulogd_pidfile)
		return 0;

	if (ulogd_pidfile_fd == -1) {
		ulogd_log(ULOGD_ERROR, "unset pid file fd\n");
		return -1;
	}

	if (daemonize) {
		/* relocking as lock is not inherited */
		if (lock_fd(ulogd_pidfile_fd, 1) < 0) {
			ulogd_log(ULOGD_ERROR, "cannot lock %s: %d\n", ulogd_pidfile,
				  errno);
			close(ulogd_pidfile_fd);
			return -1;
		}
	}

	fp = fdopen(ulogd_pidfile_fd, "w");
	if (fp == NULL) {
		ulogd_log(ULOGD_ERROR, "cannot fdopen %s: %d\n", ulogd_pidfile,
			  errno);
		close(ulogd_pidfile_fd);
		return -1;
	}

	fprintf(fp, "%d\n", getpid());
	fflush(fp);

	if (ftruncate(fileno(fp), ftell(fp)) < 0)
		ulogd_log(ULOGD_NOTICE, "cannot ftruncate %s: %d\n",
			  ulogd_pidfile, errno);

	/*
	 * We do NOT close fd, since we want to keep the lock. However, we don't
	 * want to keep the file descriptor in case of an exec().
	 */
	fcntl(ulogd_pidfile_fd, F_SETFD, FD_CLOEXEC);

	created_pidfile = 1;

	return 0;
}

static void cleanup_pidfile()
{
	if (!ulogd_pidfile || !created_pidfile)
		return;

	if (unlink(ulogd_pidfile) != 0)
		ulogd_log(ULOGD_ERROR, "PID file %s could not be deleted: %d\n",
			  ulogd_pidfile, errno);
}

static void deliver_signal_pluginstances(int signal)
{
	struct ulogd_source_pluginstance *spi;
	struct ulogd_pluginstance *pi;

	llist_for_each_entry(spi, &ulogd_source_pluginstances, list) {
		if (spi->plugin->signal)
			(*spi->plugin->signal)(spi, signal);
	}

	llist_for_each_entry(pi, &ulogd_pluginstances, list) {
		if (pi->plugin->signal)
			(*pi->plugin->signal)(pi, signal);
	}
}

static void stop_pluginstances(void)
{
	struct ulogd_source_pluginstance *spi, *s;
	struct ulogd_pluginstance *pi, *p;

	llist_for_each_entry_safe(spi, s, &ulogd_source_pluginstances, list) {
		if (spi->plugin->stop) {
			ulogd_log(ULOGD_DEBUG, "calling stop for %s:%s\n",
				  spi->id, spi->plugin->name);
			spi->plugin->stop(spi);
		}
		if (spi->plugin->priv_size > 0)
			spi->private[0] = 0;
		ulogd_stacks_destroy(spi);
		ulogd_keysets_bundles_destroy(spi);
		free(spi);
	}

	llist_for_each_entry_safe(pi, p, &ulogd_pluginstances, list) {
		if (pi->plugin->stop) {
			ulogd_log(ULOGD_DEBUG, "calling stop for %s:%s\n",
				  pi->id, pi->plugin->name);
			pi->plugin->stop(pi);
		}
		if (pi->plugin->priv_size > 0)
			pi->private[0] = 0;
		free(pi);
	}
}

static void warn_and_exit(int daemonize)
{
	cleanup_pidfile();

	if (!daemonize) {
		if (logfile && !verbose) {
			fprintf(stderr, "Fatal error, check logfile \"%s\""
				" or use '-v' flag.\n",
				ulogd_logfile);

		} else
			fprintf(stderr, "Fatal error.\n");
	}
	exit(1);
}

#ifndef DEBUG_VALGRIND
static void unload_plugins(void)
{
	struct ulogd_plugin_handle *ph, *nph;
	llist_for_each_entry_safe(ph, nph, &ulogd_plugins_handle, list) {
		dlclose(ph->handle);
		free(ph);
	}
}
#endif

static int signal_ufd_fini(void)
{
	ulogd_unregister_fd(&signal_ufd);
	return close(signal_ufd. fd);
}

static void sigterm_handler(int signal)
{

	ulogd_log(ULOGD_NOTICE, "Terminal signal received, exiting\n");

	/* XXX: not enough? */
	ulogd_stop_workers();

	deliver_signal_pluginstances(signal);

	stop_pluginstances();

	signal_ufd_fini();

#ifndef DEBUG_VALGRIND
	unload_plugins();
#endif

	if (logfile != NULL  && logfile != stdout && logfile != &syslog_dummy) {
		fclose(logfile);
		logfile = NULL;
	}

	if (ulogd_logfile)
		free(ulogd_logfile);

	config_stop();

	cleanup_pidfile();

	exit(0);
}

static int signal_handler(int fd, unsigned int what, void *data)
{
	struct signalfd_siginfo fdsi;
	ssize_t s;

	ulogd_log(ULOGD_NOTICE, "signal received, calling pluginstances\n");
	s = read(fd, &fdsi, sizeof(struct signalfd_siginfo));
	if (s != sizeof(struct signalfd_siginfo)) {
		ulogd_log(ULOGD_ERROR, "read: %s\n", strerror(errno));
		return ULOGD_IRET_ERR;
	}

	switch (fdsi.ssi_signo) {
	case SIGTERM:
	case SIGINT:
		sigterm_handler(fdsi.ssi_signo);
		break;
	case SIGHUP:
		/* reopen logfile */
		if (logfile != stdout && logfile != &syslog_dummy) {
			fclose(logfile);
			logfile = fopen(ulogd_logfile, "a");
			if (!logfile) {
				fprintf(stderr,
					"ERROR: can't open logfile %s: %s\n",
					ulogd_logfile, strerror(errno));
				sigterm_handler(fdsi.ssi_signo);
			}

		}
		break;
	default:
		break;
	}

	if (ulogd_sync_workers() < 0) {
		ulogd_log(ULOGD_FATAL, "ulogd_sync_workers\n");
		return ULOGD_IRET_ERR;
	}
	deliver_signal_pluginstances(fdsi.ssi_signo);

	return ULOGD_IRET_OK;
}

/* block signals in this function. threads creating after this function
 * has already block the signals */
static int signal_ufd_init()
{
	sigset_t mask;

	sigemptyset(&mask);
	if (sigaddset(&mask, SIGTERM)	!= 0 ||
	    sigaddset(&mask, SIGINT)	!= 0 ||
	    sigaddset(&mask, SIGHUP)	!= 0 ||
	    sigaddset(&mask, SIGALRM)	!= 0 ||
	    sigaddset(&mask, SIGUSR1)	!= 0 ||
	    sigaddset(&mask, SIGUSR2)	!= 0) {
		ulogd_log(ULOGD_FATAL, "sigaddset: %s\n", strerror(errno));
		return -1;
	}

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		ulogd_log(ULOGD_FATAL, "sigprocmask: %s\n", strerror(errno));
		return -1;
	}

	signal_ufd.fd = signalfd(-1, &mask, 0);
	if (signal_ufd.fd < 0) {
		ulogd_log(ULOGD_FATAL, "signalfd: %s\n", strerror(errno));
		return -1;
	}
	signal_ufd.cb = &signal_handler;
	signal_ufd.when = ULOGD_FD_READ;

	return ulogd_register_fd(&signal_ufd);
}

static void print_usage(void)
{
	printf("ulogd Version %s\n", VERSION);
	printf(COPYRIGHT);
	printf("This is free software with ABSOLUTELY NO WARRANTY.\n\n");
	printf("Parameters:\n");
	printf("\t-h --help\tThis help page\n");
	printf("\t-V --version\tPrint version information\n");
	printf("\t-d --daemon\tDaemonize (fork into background)\n");
	printf("\t-v --verbose\tOutput info on standard output\n");
	printf("\t-l --loglevel\tSet log level\n");
	printf("\t-c --configfile\tUse alternative Configfile\n");
	printf("\t-p --pidfile\tRecord ulogd PID in file\n");
	printf("\t-u --uid\tChange UID/GID\n");
	printf("\t-i --info\tDisplay infos about plugin\n");
}

static struct option opts[] = {
	{ "version", 0, NULL, 'V' },
	{ "daemon", 0, NULL, 'd' },
	{ "help", 0, NULL, 'h' },
	{ "configfile", 1, NULL, 'c'},
	{ "uid", 1, NULL, 'u' },
	{ "info", 1, NULL, 'i' },
	{ "verbose", 0, NULL, 'v' },
	{ "loglevel", 1, NULL, 'l' },
	{ "pidfile", 1, NULL, 'p' },
	{NULL, 0, NULL, 0}
};

int main(int argc, char* argv[])
{
	int argch;
	int daemonize = 0;
	int change_uid = 0;
	char *user = NULL;
	struct passwd *pw;
	uid_t uid = 0;
	gid_t gid = 0;
	int loglevel = 0;

	ulogd_logfile = strdup(ULOGD_LOGFILE_DEFAULT);

	while ((argch = getopt_long(argc, argv, "c:p:dvl:h::Vu:i:", opts, NULL)) != -1) {
		switch (argch) {
		default:
		case '?':
			if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n",
					optopt);
			else
				fprintf(stderr, "Unknown option character "
					"`\\x%x'.\n", optopt);

			print_usage();
			exit(1);
			break;
		case 'h':
			print_usage();
			exit(0);
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'V':
			printf("ulogd Version %s\n", VERSION);
			printf(COPYRIGHT);
			exit(0);
			break;
		case 'c':
			ulogd_configfile = optarg;
			break;
		case 'p':
			ulogd_pidfile = optarg;
			break;
		case 'u':
			change_uid = 1;
			user = strdup(optarg);
			pw = getpwnam(user);
			if (!pw) {
				printf("Unknown user %s.\n", user);
				free(user);
				exit(1);
			}
			uid = pw->pw_uid;
			gid = pw->pw_gid;
			break;
		case 'i':
			info_mode = 1;
			load_plugin(optarg);
			exit(0);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'l':
			loglevel = atoi(optarg);
			break;
		}
	}

	/* command line has precedence on config file */
	if (loglevel) {
		loglevel_ce.u.value = loglevel;
		loglevel_ce.flag |= CONFIG_FLAG_VAL_PROTECTED;
	}

	if (ulogd_pidfile) {
		if (create_pidfile() < 0)
			warn_and_exit(0);
	}

	if (daemonize && verbose) {
		verbose = 0;
		ulogd_log(ULOGD_ERROR,
			  "suppressing verbose output (not compatible"
			  " with daemon mode).\n");
	}

	if (daemonize){
		if (daemon(0, 0) < 0) {
			ulogd_log(ULOGD_FATAL, "can't daemonize: %s (%d)",
				  errno, strerror(errno));
			warn_and_exit(daemonize);
		}
	}

	if (ulogd_pidfile) {
		if (write_pidfile(daemonize) < 0)
			warn_and_exit(0);
	}

	if (config_register_file(ulogd_configfile)) {
		ulogd_log(ULOGD_FATAL, "error registering configfile \"%s\"\n",
			  ulogd_configfile);
		warn_and_exit(daemonize);
	}

	if (ulogd_init_fd()) {
		ulogd_log(ULOGD_FATAL, "ulogd_init_fd\n");
		warn_and_exit(daemonize);
		/* XXX: ulogd_fini_fd() after all on error? */
	}

	if (signal_ufd_init()) {
		ulogd_log(ULOGD_FATAL, "prepare_signal: %s\n",
			  _sys_errlist[errno]);
		warn_and_exit(daemonize);
	}

	/* parse config file */
	if (parse_conffile("global", &ulogd_kset)) {
		ulogd_log(ULOGD_FATAL, "unable to parse config file\n");
		warn_and_exit(daemonize);
	}

	if (llist_empty(&ulogd_source_pluginstances)) {
		ulogd_log(ULOGD_FATAL,
			  "not even a single working plugin stack\n");
		warn_and_exit(daemonize);
	}

	errno = 0;
	if (nice(-1) == -1) {
		if (errno != 0)
			ulogd_log(ULOGD_ERROR, "Could not nice process: %s\n",
				  strerror(errno));
	}

	if (change_uid) {
		ulogd_log(ULOGD_NOTICE, "Changing UID / GID\n");
		if (setgid(gid)) {
			ulogd_log(ULOGD_FATAL, "can't set GID %u\n", gid);
			warn_and_exit(daemonize);
		}
		if (setegid(gid)) {
			ulogd_log(ULOGD_FATAL, "can't set effective GID %u\n",
				  gid);
			warn_and_exit(daemonize);
		}
		if (initgroups(user, gid)) {
			ulogd_log(ULOGD_FATAL, "can't set user secondary GID\n");
			warn_and_exit(daemonize);
		}
		if (setuid(uid)) {
			ulogd_log(ULOGD_FATAL, "can't set UID %u\n", uid);
			warn_and_exit(daemonize);
		}
		if (seteuid(uid)) {
			ulogd_log(ULOGD_FATAL, "can't set effective UID %u\n",
				  uid);
			warn_and_exit(daemonize);
		}
	}

	if (configure_pluginstances()) {
		ulogd_log(ULOGD_FATAL, "configure_pluginstances\n");
		warn_and_exit(daemonize);
	}
	if (ulogd_keysets_bundles_alloc_init(&ulogd_source_pluginstances,
					     ULOGD_N_PERSTACK_DATA)) {
		ulogd_log(ULOGD_FATAL, "ulogd_keysets_bundles_alloc_init\n");
		warn_and_exit(daemonize);
	}
	if (check_last_output()) {
		ulogd_log(ULOGD_FATAL, "check_last_output\n");
		warn_and_exit(daemonize);
	}
	if (start_pluginstances()) {
		ulogd_log(ULOGD_FATAL, "start_pluginstances\n");
		warn_and_exit(daemonize);
	}
	if (ulogd_start_workers(ULOGD_N_INTERP_THREAD) < 0) {
		ulogd_log(ULOGD_FATAL, "ulogd_start_worker\n");
		ulogd_stop_workers();
		stop_pluginstances();
		warn_and_exit(daemonize);
	}

	/*
	struct ulogd_source_pluginstance *spi;
	llist_for_each_entry(spi, &ulogd_source_pluginstances, list) {
		printf_source_pluginstance(stdout, spi);
	}
	fflush(stdout);
	*/

	ulogd_log(ULOGD_INFO,
		  "initialization finished, entering main loop\n");

	ulogd_main_loop();

	/* hackish, but result is the same */
	sigterm_handler(SIGTERM);
	return(0);
}
