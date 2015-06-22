#ifndef _KEYSETS_H
#define _KEYSETS_H

#include <ulogd/linuxlist.h>
#include <ulogd/ulogd.h>

struct ulogd_keysets_bundle {
	struct llist_head list;
	struct ulogd_source_pluginstance *spi;
	unsigned int num_keysets;
	int refcnt; /* == source_pluginstance.nstacks */
	size_t length;
	struct ulogd_keyset keysets[0];
};

/* called from thread.c */
int ulogd_put_keysets_bundle(struct ulogd_keysets_bundle *ksb);
int ulogd_clean_results(struct ulogd_keysets_bundle *ksb);

/* called from main */
int ulogd_keysets_bundles_destroy(struct ulogd_source_pluginstance *spi);
int ulogd_keysets_bundles_alloc_init(struct llist_head *source_pluginstances,
				     int ndata);
void printf_source_pluginstance(FILE *out, struct ulogd_source_pluginstance *spi);

#endif
