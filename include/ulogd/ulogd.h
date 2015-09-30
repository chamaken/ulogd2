#ifndef _ULOGD_H
#define _ULOGD_H
/* ulogd
 *
 * userspace logging daemon for netfilter ULOG target
 * of the linux 2.4/2.6 netfilter subsystem.
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
 * this code is released under the terms of GNU GPL
 *
 */

#include <ulogd/linuxlist.h>
#include <ulogd/conffile.h>
#include <ulogd/ipfix_protocol.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>	/* need this because of extension-sighandler */
#include <sys/types.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <config.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* All types with MSB = 1 make use of value.ptr
 * other types use one of the union's member */

/* types without length */
#define ULOGD_RET_NONE		0x0000

#define ULOGD_RET_INT8		0x0001
#define ULOGD_RET_INT16		0x0002
#define ULOGD_RET_INT32		0x0003
#define ULOGD_RET_INT64		0x0004

#define ULOGD_RET_UINT8		0x0011
#define ULOGD_RET_UINT16	0x0012
#define ULOGD_RET_UINT32	0x0013
#define ULOGD_RET_UINT64	0x0014

#define ULOGD_RET_BOOL		0x0050

#define ULOGD_RET_IPADDR	0x0100
#define ULOGD_RET_IP6ADDR	0x0200

/* types with length field */
#define ULOGD_RET_STRING	0x8020
#define ULOGD_RET_RAW		0x8030
#define ULOGD_RET_RAWSTR	0x8040


/* FLAGS */
#define ULOGD_RETF_NONE		0x0000
#define ULOGD_RETF_VALID	0x0001	/* contains a valid result */
#define ULOGD_RETF_FREE		0x0002	/* ptr needs to be free()d */
#define ULOGD_RETF_NEEDED	0x0004	/* this parameter is actually needed
					 * by some downstream plugin */
#define ULOGD_RETF_DESTRUCT	0x0008	/* call destructor */
#define ULOGD_RETF_EMBED	0x0010	/* length field embedded in keys area */

#define ULOGD_KEYF_OPTIONAL	0x0100	/* this key is optional */
#define ULOGD_KEYF_INACTIVE	0x0200	/* marked as inactive (i.e. totally
					   to be ignored by everyone) */


/* maximum length of ulogd key */
#define ULOGD_MAX_KEYLEN 31
#define ULOGD_MAX_VERLEN 15

#define ULOGD_DEBUG	1	/* debugging information */
#define ULOGD_INFO	3
#define ULOGD_NOTICE	5	/* abnormal/unexpected condition */
#define ULOGD_ERROR	7	/* error condition, requires user action */
#define ULOGD_FATAL	8	/* fatal, program aborted */

/* ulogd data type */
enum ulogd_dtype {
	ULOGD_DTYPE_NULL	= 0x0000,
	ULOGD_DTYPE_RAW		= 0x0002, /* raw packet data */
	ULOGD_DTYPE_PACKET	= 0x0004, /* packet metadata */
	ULOGD_DTYPE_FLOW	= 0x0008, /* flow metadata */
	ULOGD_DTYPE_SUM		= 0x0010, /* sum metadata */
	ULOGD_DTYPE_SINK	= 0x0020, /* sink of data, no output keys */
	ULOGD_DTYPE_WILDCARD	= 0x0040,
};

struct ulogd_pluginstance;
struct ulogd_source_pluginstance;
struct ulogd_keyset;

/*
 * function type definition
 */
typedef void (*key_destructor_t)(void *);

typedef int (*pl_configure_t)(struct ulogd_pluginstance *);
typedef int (*sp_configure_t)(struct ulogd_source_pluginstance *);

/* function to construct a new pluginstance
 * input may be specific to sink plugin which use wildcard */
typedef	int (*pl_start_t)(struct ulogd_pluginstance *, struct ulogd_keyset *);
typedef	int (*sp_start_t)(struct ulogd_source_pluginstance *);

/* function to destruct an existing pluginstance */
typedef int (*pl_stop_t)(struct ulogd_pluginstance *);
typedef int (*sp_stop_t)(struct ulogd_source_pluginstance *);

/* function to receive a signal */
typedef void (*pl_signal_t)(struct ulogd_pluginstance *, uint32_t);
typedef void (*sp_signal_t)(struct ulogd_source_pluginstance *, uint32_t);

/* function to call for each packet */
typedef int (*pl_interp_t)(struct ulogd_pluginstance *, struct ulogd_keyset *, struct ulogd_keyset *);

/* structure describing an input  / output parameter of a plugin */
struct ulogd_key {
	/* length of the returned value (only for lengthed types) */
	uint32_t len;
	/* type of the returned value (ULOGD_DTYPE_...) */
	uint16_t type;
	/* flags (i.e. free, ...) */
	uint16_t flags;
	/* name of this key */
	char name[ULOGD_MAX_KEYLEN + 1];
	/* IETF IPFIX attribute ID */
	struct {
		uint32_t	vendor;
		uint16_t	field_id;
	} ipfix;

	/* Store field name for Common Information Model */
	char cim_name[ULOGD_MAX_KEYLEN + 1];

	/* destructor for this key */
	void (*destruct)(void *u_value_ptr);

	union {
		/* and finally the returned value */
		union {
			uint8_t	b;
			uint8_t	ui8;
			uint16_t	ui16;
			uint32_t	ui32;
			uint64_t	ui64;
			uint32_t	ui128[4];
			int8_t		i8;
			int16_t		i16;
			int32_t		i32;
			int64_t		i64;
			int32_t		i128[4];
			void		*ptr;
		} value;
		struct ulogd_key *source;
	} u;
};

struct ulogd_keyset {
	/* possible input keys of this interpreter */
	struct ulogd_key *keys;
	/* number of input keys */
	uint16_t num_keys;
	/* bitmask of possible types */
	uint16_t type;
};

static inline void okey_set_b(struct ulogd_key *key, uint8_t value)
{
	key->u.value.b = value;
	key->flags |= ULOGD_RETF_VALID;
}

static inline void okey_set_u8(struct ulogd_key *key, uint8_t value)
{
	key->u.value.ui8 = value;
	key->flags |= ULOGD_RETF_VALID;
}

static inline void okey_set_u16(struct ulogd_key *key, uint16_t value)
{
	key->u.value.ui16 = value;
	key->flags |= ULOGD_RETF_VALID;
}

static inline void okey_set_u32(struct ulogd_key *key, uint32_t value)
{
	key->u.value.ui32 = value;
	key->flags |= ULOGD_RETF_VALID;
}

static inline void okey_set_u64(struct ulogd_key *key, uint64_t value)
{
	key->u.value.ui64 = value;
	key->flags |= ULOGD_RETF_VALID;
}

static inline void okey_set_u128(struct ulogd_key *key, const void *value)
{
	memcpy(key->u.value.ui128, value, 16);
	key->flags |= ULOGD_RETF_VALID;
}

static inline void okey_set_ptr(struct ulogd_key *key, void *value)
{
	key->u.value.ptr = value;
	key->flags |= ULOGD_RETF_VALID;
}

static inline void *okey_get_ptr(struct ulogd_key *key)
{
	return key->u.value.ptr;
}

static inline void okey_set_valid(struct ulogd_key *key)
{
	key->flags |= ULOGD_RETF_VALID;
}

static inline uint8_t ikey_get_u8(struct ulogd_key *key)
{
	return key->u.source->u.value.ui8;
}

static inline uint16_t ikey_get_u16(struct ulogd_key *key)
{
	return key->u.source->u.value.ui16;
}

static inline uint32_t ikey_get_u32(struct ulogd_key *key)
{
	return key->u.source->u.value.ui32;
}

static inline uint64_t ikey_get_u64(struct ulogd_key *key)
{
	return key->u.source->u.value.ui64;
}

static inline void *ikey_get_u128(struct ulogd_key *key)
{
	return &key->u.source->u.value.ui128;
}

static inline void *ikey_get_ptr(struct ulogd_key *key)
{
	return key->u.source->u.value.ptr;
}

struct ulogd_plugin_handle {
	/* global list of plugins */
	struct llist_head list;
	void *handle;
};

/*
 * configure, mtsafe, update_self and input in start()
 * may be specific to sink plugin
 */
struct ulogd_plugin {
	/* global list of plugins */
	struct llist_head list;
	/* version */
	char version[ULOGD_MAX_VERLEN + 1];
	/* name of this plugin (predefined by plugin) */
	char name[ULOGD_MAX_KEYLEN + 1];
	/* how many stacks are using this plugin? initially set to zero. */
	unsigned int usage;

	struct ulogd_keyset output;

	/* configuration parameters */
	struct config_keyset *config_kset;

	/* size of instance->priv */
	unsigned int priv_size;

	/*
	 * followings are plugin (not source) specific
	 */
	struct ulogd_keyset input;

	pl_configure_t configure;
	pl_start_t start;
	pl_stop_t stop;
	pl_signal_t signal;
	pl_interp_t interp;

	/* protect interp mutex */
	bool mtsafe;
};

struct ulogd_source_plugin {
	struct llist_head list;
	char *version;
	char name[ULOGD_MAX_KEYLEN + 1];
	unsigned int usage;

	struct ulogd_keyset output;

	struct config_keyset *config_kset;
	unsigned int priv_size;

	/*
	 *  followings are source plugin specific
	 */
	sp_configure_t configure;
	sp_start_t start;
	sp_stop_t stop;
	sp_signal_t signal;
};

#define ULOGD_IRET_ERR		-1
#define ULOGD_IRET_STOP		-2
#define ULOGD_IRET_OK		0

/* an instance of a plugin, element in a stack */
struct ulogd_pluginstance {
	/* global list of pluginstances */
	struct llist_head list;

	/* name / id  of this instance*/
	char id[ULOGD_MAX_KEYLEN + 1];
	/* per-instance config parameters (array) */
	struct config_keyset *config_kset;
	struct ulogd_keyset *output_config;

	/* followings are specific pluginstance */

	/* plugin */
	struct ulogd_plugin *plugin;

	int usage;

	/* syncronize interp by BIG lock */
	pthread_mutex_t interp_mutex;

	/* creating dynamic input/output key in configure() */
	struct ulogd_keyset *input_config;

	 /* for wildcarded (sink) input at start() */
	struct ulogd_keyset *input_template;

	/* private data */
	char private[0];
};

struct ulogd_source_pluginstance {
	/* global list of source pluginstances */
	struct llist_head list;
	/* name / id  of this instance*/
	char id[ULOGD_MAX_KEYLEN + 1];
	/* per-instance config parameters (array) */
	struct config_keyset *config_kset;
	struct ulogd_keyset *output_config;

	/* followings are specific source_pluginstance */

	/* plugin */
	struct ulogd_source_plugin *plugin;

	int usage;

	/* list of keysets_bundles used by stacks
	 * whose head is this pluginstance */
	struct llist_head keysets_bundles;
	pthread_mutex_t keysets_bundles_mutex;
	pthread_cond_t keysets_bundles_condv;

	/* list of stack which source is this source pluginstance */
	struct llist_head stacks;

	/* number of stacks == usage? */
	int nstacks;

	/* private data */
	char private[0];
};

#define UPI_OUTPUT_KEYSET(upi) (upi->output_config != NULL \
	 ? upi->output_config	      \
	 : &upi->plugin->output)
#define UPI_INPUT_KEYSET(upi) (upi->input_config != NULL \
	 ? upi->input_config	      \
	 : &upi->plugin->input)


struct ulogd_stack {
	struct llist_head list;
	/* list of stack_element in this stack */
	struct llist_head elements;
	/* no thought, this stack name? */
	char *name;
	/* source pluginstance which this belongs to */
	struct ulogd_source_pluginstance *spi;
};

/* args for ulogd_pluginstance.interp() */
struct ulogd_stack_element {
	/* list of plugins in this stack */
	struct llist_head list;

	struct ulogd_pluginstance *pi;
	/* index of input keyset in keyset bundle */
	unsigned int iksbi;
	/* index of output keyset in keyset bundle */
	unsigned int oksbi;
};

/***********************************************************************
 * PUBLIC INTERFACE
 ***********************************************************************/

/* thread.c */
int ulogd_propagate_results(struct ulogd_keyset *okeys);
int ulogd_wait_consume(struct ulogd_keyset *okeys);

/* register a new interpreter plugin */
void ulogd_register_plugin(struct ulogd_plugin *me);
/* register a new interpreter source plugin */
void ulogd_register_source_plugin(struct ulogd_source_plugin *me);

/* keysets.c */
struct ulogd_keyset *
ulogd_get_output_keyset(struct ulogd_source_pluginstance *spi);
int ulogd_put_output_keyset(struct ulogd_keyset *okeys);

/* allocate new ulogd_plugin with specified key size, and copy */
struct ulogd_plugin *ulogd_plugin_copy_newkeys(struct ulogd_plugin *src,
					       size_t ikeys_num,
					       size_t okeys_num);

/* write a message to the daemons' logfile */
void __ulogd_log(int level, char *file, int line, const char *message, ...);
/* macro for logging including filename and line number */
#define ulogd_log(level, format, args...) \
	__ulogd_log(level, __FILE__, __LINE__, format, ## args)
/* backwards compatibility */
#define ulogd_error(format, args...) ulogd_log(ULOGD_ERROR, format, ## args)
/* macro for logging including filename for fork()ed process */
#define ulogd_llog(level, line, format, args...)		\
	__ulogd_log(level, __FILE__, line, format, ## args)

#define IS_VALID(x)	((x).flags & ULOGD_RETF_VALID)
#define SET_VALID(x)	(x.flags |= ULOGD_RETF_VALID)
#define IS_NEEDED(x)	(x.flags & ULOGD_RETF_NEEDED)
#define SET_NEEDED(x)	(x.flags |= ULOGD_RETF_NEEDED)

#define GET_FLAGS(res, x)	(res[x].u.source->flags)
#define pp_is_valid(res, x)	\
	(res[x].u.source && (GET_FLAGS(res, x) & ULOGD_RETF_VALID))

int ulogd_key_size(struct ulogd_key *key);

/***********************************************************************
 * file descriptor handling
 ***********************************************************************/

#define ULOGD_FD_READ	0x0001
#define ULOGD_FD_WRITE	0x0002
#define ULOGD_FD_EXCEPT	0x0004

struct ulogd_fd {
	struct llist_head list;
	int fd;				/* file descriptor */
	unsigned int when;
	int (*cb)(int fd, unsigned int what, void *data);
	void *data;			/* void * to pass to callback */
};

int ulogd_init_fd(void);
int ulogd_fini_fd(void);
int ulogd_register_fd(struct ulogd_fd *ufd);
int ulogd_unregister_fd(struct ulogd_fd *ufd);
int ulogd_select_main(void);

/***********************************************************************
 * timer handling
 ***********************************************************************/
#include <ulogd/timer.h>

/***********************************************************************
 * other declarations
 ***********************************************************************/

#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif

#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE 136
#endif

#endif /* _ULOGD_H */
