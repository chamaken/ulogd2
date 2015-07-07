#define _GNU_SOURCE /* _sys_errlist[] */

#include <alloca.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <urcu/uatomic.h>

#include <ulogd/ulogd.h>
#include <ulogd/thread.h>
#include <ulogd/keysets.h>

static int wildcard_num(struct ulogd_source_pluginstance *spi,
			struct ulogd_stack *stack,
			struct ulogd_stack_element *wildpos)
{
	struct ulogd_stack *s;
	struct ulogd_stack_element *e;
	int num_keys = UPI_OUTPUT_KEYSET(spi)->num_keys;

	llist_for_each_entry(s, &spi->stacks, list) {
		if (s != stack)
			continue;
		llist_for_each_entry(e, &s->elements, list) {
			if (e == wildpos)
				return num_keys;
			num_keys += UPI_OUTPUT_KEYSET(e->pi)->num_keys;
		}
	}
	return -1;
}

static int keyset_cmp(struct ulogd_keyset *ks1, struct ulogd_keyset *ks2)
{
	size_t size = sizeof(struct ulogd_key) - offsetof(struct ulogd_key, u);
	unsigned int i;

	if (ks1->num_keys != ks2->num_keys || ks1->type != ks2->type)
		return -1;

	for (i = 0; i < ks1->num_keys; i++)
		if (memcmp(&ks1->keys[i], &ks2->keys[i], size))
			return -1;

	return 0;
}

static struct ulogd_keysets_bundle *
ulogd_keysets_bundle_alloc_init(struct ulogd_source_pluginstance *spi)
{
	struct ulogd_keysets_bundle *ksb;
	struct ulogd_keyset *keysets, *srcout, *input, *output;
	struct ulogd_key *keys;
	struct ulogd_stack *stack;
	struct ulogd_stack_element *element, *e;
	unsigned int ksize, kindex = 0, i;
	unsigned int nkeys;
	void *raw;

	srcout = UPI_OUTPUT_KEYSET(spi);
	nkeys = srcout->num_keys;

	/* calc whole size: 1st */
	ksize = sizeof(struct ulogd_keysets_bundle);
	if (srcout->num_keys > 0) {
		ksize += sizeof(struct ulogd_keyset);
		for (i = 0; i < srcout->num_keys; i++) {
			if (srcout->keys[i].flags & ULOGD_RETF_EMBED)
				ksize += srcout->keys[i].len;
		}
		kindex++;
	}
	llist_for_each_entry(stack, &spi->stacks, list) {
		llist_for_each_entry(element, &stack->elements, list) {
			input = UPI_INPUT_KEYSET(element->pi);
			element->iksbi = kindex++;
			ksize += sizeof(struct ulogd_keyset);
			if (input->type & ULOGD_KEYF_WILDCARD) {
				if (element->list.next != &stack->elements) {
					ulogd_log(ULOGD_ERROR, "wildcard is only"
						  " allowed at the end\n");
					return NULL;
				}
				nkeys += wildcard_num(spi, stack, element);
			} else {
				nkeys += input->num_keys;
			}

			output = UPI_OUTPUT_KEYSET(element->pi);
			element->oksbi = kindex++;
			ksize += sizeof(struct ulogd_keyset);
			for (i = 0; i < output->num_keys; i++) {
				if (output->keys[i].flags & ULOGD_RETF_EMBED)
					ksize += output->keys[i].len;
			}
			nkeys += output->num_keys;
		}
	}
	ksize += nkeys * sizeof(struct ulogd_key);

	ksb = mmap(NULL, ksize, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ksb == MAP_FAILED) {
		ulogd_log(ULOGD_FATAL, "mmap: %s\n", _sys_errlist[errno]);
		return NULL;
	}
	ksb->length = ksize;
	ulogd_log(ULOGD_INFO, "source pluginstance [%s:%s], data size: %d [%p:%p]\n",
		  spi->id, spi->plugin->name, ksize, ksb, (void *)ksb + ksize);

	/* init ulogd_keysets_bundle */
	ksb->spi = spi;
	ksb->num_keysets = kindex;

	/* point each start point */
	keysets = (void *)ksb + sizeof(struct ulogd_keysets_bundle);
	keys = (struct ulogd_key *)(&ksb->keysets[kindex]);
	raw = &keys[nkeys];

	/* init ulogd_keyset for source output */
	if (srcout->num_keys) {
		keysets->num_keys = srcout->num_keys;
		keysets->type = srcout->type;
		keysets->keys = keys;

		ksize = keysets->num_keys * sizeof(struct ulogd_key);
		memcpy(keys, srcout->keys, ksize);
		for (i = 0; i < srcout->num_keys; i++) {
			if (keys[i].flags & ULOGD_RETF_EMBED) {
				keys[i].u.value.ptr = raw;
				raw += keys[i].len;
			}
		}
		keysets++;
		keys = (void *)keys + ksize;
	}

	/* walk through 2nd */
	llist_for_each_entry(stack, &spi->stacks, list) {
		llist_for_each_entry(element, &stack->elements, list) {
			input = UPI_INPUT_KEYSET(element->pi);
			keysets->type = input->type;
			if (input->type & ULOGD_KEYF_WILDCARD) {
				keysets->num_keys = wildcard_num(spi, stack,
								 element);
				/* and type should be ULOGD_KEYF_OPTIONAL ? */
				keysets->keys = keys;

				/* oh my... sorry for deep nest */
				if (srcout->num_keys) {
					memcpy(keys, srcout->keys,
					       srcout->num_keys
					       * sizeof(struct ulogd_key));
					keys += srcout->num_keys;
				}
				llist_for_each_entry(e, &stack->elements, list) {
					if (e == element)
						break;

					struct ulogd_keyset *ok
						= UPI_OUTPUT_KEYSET(e->pi);
					unsigned int n = ok->num_keys;
					ksize = n * sizeof(struct ulogd_key);
					if (n) {
						memcpy(keys, ok->keys, ksize);
						keys += n;
					}
				}
			} else if (input->num_keys) {
				keysets->num_keys = input->num_keys;
				keysets->keys = keys;

				ksize = keysets->num_keys
					* sizeof(struct ulogd_key);
				memcpy(keys, input->keys, ksize);
				keys += keysets->num_keys;
			}
			keysets++;

			output = UPI_OUTPUT_KEYSET(element->pi);
			keysets->type = output->type;
			if (output->num_keys) {
				keysets->num_keys = output->num_keys;

				ksize = keysets->num_keys
					* sizeof(struct ulogd_key);
				memcpy(keys, output->keys, ksize);
				for (i = 0; i < keysets->num_keys; i++) {
					if (keys[i].flags & ULOGD_RETF_EMBED) {
						keys[i].u.value.ptr = raw;
						raw += keys[i].len;
					}
				}
				keysets->keys = keys;
				keys += keysets->num_keys;
			}
			keysets++;

			free(element->pi->input_config);
			element->pi->input_config = NULL;
			free(element->pi->output_config);
			element->pi->output_config = NULL;

			/* NOTE: (re)set input/output template here */
			if (element->pi->input_template != NULL) {
				if (keyset_cmp(element->pi->input_template,
					       &ksb->keysets[element->iksbi])) {
					ulogd_log(ULOGD_ERROR, "instances with"
						  " different input key is not"
						  " supported, sorry\n");
					goto fail_unmap;
				}
			}
			element->pi->input_template
				= &ksb->keysets[element->iksbi];
		}
	}
	return ksb;
fail_unmap:
	munmap(ksb, ksb->length);
	return NULL;
}

/* based on src is just after resolved, all zero but
 * - source
 * - ptr if len > 0
 */
static struct ulogd_keysets_bundle *
ulogd_keysets_bundle_copy(struct ulogd_keysets_bundle *src)
{
	struct ulogd_keysets_bundle *dst;
	struct ulogd_key *dkey, *source;
	struct ulogd_keyset *skeyset = src->keysets, *dkeyset;
	size_t size = sizeof(struct ulogd_keysets_bundle)
		+ sizeof(struct ulogd_keyset) * src->num_keysets;

	unsigned int i, j;
	int offset;

	for (i = 0, skeyset = src->keysets; i < src->num_keysets; i++) {
		for (j = 0; j < skeyset[i].num_keys; j++) {
			size += sizeof(struct ulogd_key);
			if (skeyset[i].keys[j].flags & ULOGD_RETF_EMBED)
				size += skeyset[i].keys[j].len;
		}
	}
	dst = mmap(NULL, size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (dst == NULL)
		return NULL;
	dst->length = size;

	memcpy(dst, src, size);
	offset = (void *)dst - (void *)src;

	for (i = 0, dkeyset = dst->keysets; i < dst->num_keysets; i++) {
		dkeyset[i].keys = (void *)skeyset[i].keys + offset;
		for (j = 0, dkey = dkeyset[i].keys;
		     j < dkeyset[i].num_keys; j++) {
			source = dkey[j].u.source;
			/* source means u.value.ptr too */
			if (source != NULL) {
				dkey[j].u.source = (void *)source + offset;
			}
		}
	}

	return dst;
}

/* find an output key in a given stack */
static struct ulogd_key *
find_okey_in_keysets(char *name,
		     struct ulogd_keysets_bundle *ksb,
		     struct ulogd_stack *stack,
		     struct ulogd_stack_element *elem)
{
	struct ulogd_stack_element *cur;
	struct ulogd_key *okey;
	unsigned int i;

	llist_for_each_entry_reverse(cur, &elem->list, list) {
		if (&cur->list == &stack->elements)
			break; /* not found */
		for (i = 0; i < ksb->keysets[cur->oksbi].num_keys; i++) {
			okey = &ksb->keysets[cur->oksbi].keys[i];
			if (!strcmp(name, okey->name))
				return okey;
		}
	}

	/* try to search source output key */
	for (i = 0; i < ksb->keysets[0].num_keys; i++) {
		okey = &ksb->keysets[0].keys[i];
		if (!strcmp(name, okey->name))
			return okey;
	}

	return NULL;
}

/* resolve only the first element of keysets_bundles */
static int resolve_keysets_bundle(struct ulogd_source_pluginstance *spi)
{
	struct ulogd_stack *stack;
	struct ulogd_stack_element *elem;
	struct ulogd_key *ikey, *okey;
	struct ulogd_keysets_bundle *ksb
		= llist_entry(spi->keysets_bundles.next,
			      struct ulogd_keysets_bundle, list);
	unsigned int i;

	llist_for_each_entry(stack, &spi->stacks, list) {
		llist_for_each_entry_reverse(elem, &stack->elements, list) {
			for (i = 0; i < ksb->keysets[elem->iksbi].num_keys; i++) {
				ikey = &ksb->keysets[elem->iksbi].keys[i];
				/*	skip those marked as 'inactive' by
				 *	pl->configure() */
				if (ikey->flags & ULOGD_KEYF_INACTIVE)
					continue;
				if (ikey->u.source) {
					ulogd_log(ULOGD_ERROR, "input key `%s' "
						  "already has source\n",
						  ikey->name);
					return -EINVAL;
				}
				okey = find_okey_in_keysets(ikey->name, ksb,
							    stack, elem);
				if (!okey) {
					if (ikey->flags & ULOGD_KEYF_OPTIONAL)
						continue;
					ulogd_log(ULOGD_ERROR, "%s:%s cannot "
						  "find key `%s' in stack\n",
						  elem->pi->id,
						  elem->pi->plugin->name,
						  ikey->name);
					return -EINVAL;
				}
				ikey->u.source = okey;
			}
		}
	}
	return 0;
}

/* caller: ulogd.c and self */
int ulogd_keysets_bundles_destroy(struct ulogd_source_pluginstance *spi)
{
	struct ulogd_keysets_bundle *ksb, *tmp;
	int ret;

	ret = pthread_mutex_lock(&spi->keysets_bundles_mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_ERROR, "pthread_mutex_lock: %s\n",
			  _sys_errlist[ret]);
		return -1;
	}
	llist_for_each_entry_safe(ksb, tmp, &spi->keysets_bundles, list) {
		llist_del(&ksb->list);
		munmap(ksb, ksb->length);
		ksb = NULL;
	}
	ret = pthread_mutex_unlock(&spi->keysets_bundles_mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_ERROR, "pthread_mutex_lock: %s\n",
			  _sys_errlist[ret]);
		return -1;
	}

	return 0;
}

/* caller: ulogd.c */
int ulogd_keysets_bundles_alloc_init(struct llist_head *spis, int ndata)
{
	struct ulogd_source_pluginstance *spi;
	struct ulogd_keysets_bundle *ksb;
	int i;

	llist_for_each_entry(spi, spis, list) {
		ksb = ulogd_keysets_bundle_alloc_init(spi);
		if (ksb == NULL)
			goto failure;
		ndata--;

		llist_add(&ksb->list, &spi->keysets_bundles);
		if (resolve_keysets_bundle(spi) != 0)
			goto failure;

		for (i = 0; i < ndata; i++) {
			ksb = ulogd_keysets_bundle_copy(ksb);
			if (ksb == NULL)
				goto failure;
			llist_add(&ksb->list, &spi->keysets_bundles);
		}
	}

	return 0;

failure:
	llist_for_each_entry(spi, spis, list)
		ulogd_keysets_bundles_destroy(spi);
	return -1;
}

/* for debug
 * caller: ulogd.c */
void printf_source_pluginstance(FILE *out, struct ulogd_source_pluginstance *spi)
{
	/* only first ulogd_keysets_bundle */
	struct ulogd_keysets_bundle *ksb
		= llist_entry(spi->keysets_bundles.next,
			      struct ulogd_keysets_bundle, list);
	struct ulogd_stack *stack;
	struct ulogd_stack_element *element;
	struct ulogd_keyset *kset;
	struct ulogd_key *key;
	unsigned int i, j;

	fprintf(out, "source pluginstance: %s:%s (%p)\n",
		spi->id, spi->plugin->name, spi);
	fprintf(out, " 1st keysets bundle: %p\n", ksb);
	fprintf(out, "	number of keysets: %d\n", ksb->num_keysets);
	fprintf(out, "	  keyset start at: %p\n", ksb->keysets);
	for (i = 0; i < ksb->num_keysets; i++) {
		kset = &ksb->keysets[i];
		fprintf(out, "	    keysets[%2d]  : %p\n", i, kset);
		fprintf(out, "	      { .num_keys: %d,", kset->num_keys);
		fprintf(out, "	.type: %d,", kset->num_keys);
		fprintf(out, "	.keys: %p}\n", kset->keys);
		for (j = 0; j < kset->num_keys; j++) {
			key = &kset->keys[j];
			fprintf(out, "		 key[%2d] : %p\n", j, key);
			fprintf(out, "		   { .len: %d,", key->len);
			fprintf(out, " .type: %d,", key->type);
			fprintf(out, " .flags: %d,", key->flags);
			fprintf(out, " .name: %s,", key->name);
			fprintf(out, " .source: %p}\n", key->u.source);
		}
	}

	i = 0;
	fprintf(out, "		  nstacks: %d\n", spi->nstacks);
	llist_for_each_entry(stack, &spi->stacks, list) {
		fprintf(out, "	   stack[%2d] name: %s\n", i++, stack->name);
		llist_for_each_entry(element, &stack->elements, list) {
			fprintf(out, "	      .element { .pi: %s:%s,"
				     " .ikey: %d, .okey: %d }\n",
				element->pi->id, element->pi->plugin->name,
				element->iksbi, element->oksbi);
		}
		fprintf(out, "\n");
	}
}

/* push back keysets bundle */
int ulogd_put_keysets_bundle(struct ulogd_keysets_bundle *ksb)
{
	struct ulogd_source_pluginstance *spi = ksb->spi;
	int ret;

	ret = pthread_mutex_lock(&spi->keysets_bundles_mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_lock: %s\n",
			_sys_errlist[ret]);
		return -1;
	}
	llist_add_tail(&ksb->list, &spi->keysets_bundles);
	ret = pthread_cond_broadcast(&spi->keysets_bundles_condv);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_cond_broadcast: %s\n",
			_sys_errlist[ret]);
		return -1;
	}
	ret = pthread_mutex_unlock(&spi->keysets_bundles_mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_unlock: %s\n",
			_sys_errlist[ret]);
		return -1;
	}

	return 0;
}

/* clean results (set all values to 0 and free pointers)
 * caller: thread.c */
int ulogd_clean_results(struct ulogd_keysets_bundle *ksb)
{
	struct ulogd_keyset *kset;
	struct ulogd_key *key;
	unsigned int i, j;

	for (i = 0; i < ksb->num_keysets; i++) {
		kset = &ksb->keysets[i];
		for (j = 0; j < kset->num_keys; j++) {
			key = &kset->keys[j];
			if (!(key->flags & ULOGD_RETF_VALID))
				continue;

			if (key->flags & ULOGD_RETF_FREE) {
				/* can be a NULL */
				free(key->u.value.ptr);
				key->u.value.ptr = NULL;
			} else if (key->flags & ULOGD_RETF_DESTRUCT
				   && key->destruct != NULL
				   && key->u.value.ptr != NULL) {
				key->destruct(key->u.value.ptr);
			}
			if (key->flags & ULOGD_RETF_EMBED)
				memset(okey_get_ptr(key), 0, key->len);
			else
				memset(&key->u.value, 0, sizeof(key->u.value));
			key->flags &= ~ULOGD_RETF_VALID;
		}
	}

	return 0;
}

/* public interface in ulogd.h
 * get output key for spi */
struct ulogd_keyset *
ulogd_get_output_keyset(struct ulogd_source_pluginstance *spi)
{
	struct ulogd_keysets_bundle *ksb = NULL;
	int ret;

	ret = pthread_mutex_lock(&spi->keysets_bundles_mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_lock: %s\n",
			_sys_errlist[ret]);
		return NULL;
	}
	while (llist_empty(&spi->keysets_bundles)) {
		ret = pthread_cond_wait(&spi->keysets_bundles_condv,
					&spi->keysets_bundles_mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_cond_wait: %s\n",
				  _sys_errlist[ret]);
			return NULL;
		}
	}
	ksb = llist_entry(spi->keysets_bundles.next,
			  struct ulogd_keysets_bundle, list);
	llist_del(spi->keysets_bundles.next);
	ret = pthread_mutex_unlock(&spi->keysets_bundles_mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_unlock: %s\n",
			_sys_errlist[ret]);
		return NULL;
	}

	return ksb->keysets;
}

int ulogd_put_output_keyset(struct ulogd_keyset *okeys)
{
	struct ulogd_keysets_bundle *ksb
		= (void *)okeys - offsetof(struct ulogd_keysets_bundle, keysets);
		/* = container_of(okeys, struct ulogd_keysets_bundle, keysets); */

	ulogd_clean_results(ksb);
	return ulogd_put_keysets_bundle(ksb);
}
