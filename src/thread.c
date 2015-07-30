/* _sys_errlist, PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP, PTHREAD_MUTEX_ERRORCHECK_NP */
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#include <urcu/uatomic.h>

#include <ulogd/ulogd.h>
#include <ulogd/keysets.h>
#include <ulogd/thread.h>

#ifdef THREAD_PER_STACK
#define START_ROUTINE interp_stack
#else
#define START_ROUTINE interp_bundle
#endif

static LLIST_HEAD(ulogd_interp_workers);
static LLIST_HEAD(ulogd_runnable_workers);
static pthread_mutex_t
ulogd_runnable_workers_mutex = ULOGD_MUTEX_INITIALIZER;
static pthread_cond_t ulogd_runnable_workers_condv = PTHREAD_COND_INITIALIZER;
enum runnable_workers_status {
	WORKERS_RUNNABLE,
	WORKERS_SUSPEND,
	WORKERS_STOP
};
static enum runnable_workers_status
ulogd_runnable_workers_status = WORKERS_RUNNABLE;

/* push back worker */
static int put_worker(struct ulogd_interp_thread *worker)
{
	int ret;

	ret = pthread_mutex_lock(&worker->mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_lock: %s\n",
			_sys_errlist[ret]);
		return -1;
	}
	worker->bundle = NULL;
	worker->stack = NULL;
	ret = pthread_mutex_unlock(&worker->mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_unlock: %s\n",
			_sys_errlist[ret]);
		return -1;
	}

	ret = pthread_mutex_lock(&ulogd_runnable_workers_mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_lock: %s\n",
			_sys_errlist[ret]);
		return -1;
	}
	llist_add_tail(&worker->runnable_list, &ulogd_runnable_workers);
	ret = pthread_cond_broadcast(&ulogd_runnable_workers_condv);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_cond_broadcast: %s\n",
			_sys_errlist[ret]);
		pthread_mutex_unlock(&ulogd_runnable_workers_mutex);
		return -1;
	}
	ret = pthread_mutex_unlock(&ulogd_runnable_workers_mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_unlock: %s\n",
			_sys_errlist[ret]);
		return -1;
	}

	return 0;
}

static int exec_stack(struct ulogd_stack *stack,
			    struct ulogd_keyset *keyset)
{
	struct ulogd_stack_element *elem;
	int abort_stack = 0;
	int ret = 0;

	/* XXX: can not stop in this stack loop */
	llist_for_each_entry(elem, &stack->elements, list) {
		if (!elem->pi->plugin->mtsafe) {
			ret = pthread_mutex_lock(&elem->pi->interp_mutex);
			if (ret != 0) {
				ulogd_log(ULOGD_FATAL,
					  "pthread_mutex_lock: %s\n",
					  _sys_errlist[ret]);
				ret = ULOGD_IRET_ERR;
				break;
			}
		}
		ret = elem->pi->plugin->interp(elem->pi,
					       &keyset[elem->iksbi],
					       &keyset[elem->oksbi]);
		if (!elem->pi->plugin->mtsafe) {
			ret = pthread_mutex_unlock(&elem->pi->interp_mutex);
			if (ret != 0) {
				ulogd_log(ULOGD_FATAL,
					  "pthread_mutex_unlock: %s\n",
					  _sys_errlist[ret]);
				ret = ULOGD_IRET_ERR;
				break;
			}
		}
		switch (ret) {
		case ULOGD_IRET_ERR:
			/* fallthrough */
		case ULOGD_IRET_STOP:
			/* we shall abort further iteration of the stack */
			ulogd_log(ULOGD_ERROR,
				  "not OK, interp %s:%s returns: %d\n",
				  elem->pi->id, elem->pi->plugin->name, ret);
			abort_stack = 1;
			break;
		case ULOGD_IRET_OK: /* 0 */
			/* we shall continue travelling down the stack */
			continue;
		default:
			ulogd_log(ULOGD_NOTICE,
				  "unknown return value `%d' from plugin %s\n",
				  ret, elem->pi->plugin->name);
			abort_stack = 1;
			break;
		}
		if (abort_stack)
			break;
	}

	return ret;
}

/* pthread void *(*start_routine)
 * call interp for the whole pluginstances which head is the same
 */
static void *interp_bundle(void *arg)
{
	struct ulogd_interp_thread *th = arg;
	struct ulogd_keysets_bundle *ksb;
	struct ulogd_stack *stack;
	int ret;

	while (th->runnable) {
		/* wait message */
		ret = pthread_mutex_lock(&th->mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_mutex_lock: %s\n",
				_sys_errlist[ret]);
			goto failure;
		}
		while (th->bundle == NULL && th->runnable) {
			ret = pthread_cond_wait(&th->condv, &th->mutex);
			if (ret != 0) {
				ulogd_log(ULOGD_FATAL, "pthread_cond_wait:"
					  " %s\n", _sys_errlist[ret]);
				goto failure_unlock_th;
			}
		}
		ret = pthread_mutex_unlock(&th->mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_mutex_unlock: %s\n",
				  _sys_errlist[ret]);
			goto failure_unlock_th;
		}
		/* break if not runnable */
		if (!th->runnable) {
			if (th->bundle != NULL) {
				ulogd_log(ULOGD_ERROR, "discard keysets: %p"
					  " because of stop\n", th->bundle);
				ulogd_clean_results(th->bundle);
				ulogd_put_keysets_bundle(th->bundle);
				th->retval = ULOGD_IRET_ERR;
				put_worker(th);
			}
			/* is above enough? */
			break;
		}

		ksb = th->bundle;
		/* exec stacks */
		llist_for_each_entry(stack, &ksb->spi->stacks, list) {
			ret = exec_stack(stack, ksb->keysets);
			if (ret) {
				ulogd_log(ULOGD_ERROR, "[T%lu/D%p] stack: %s,"
					  " returned: %d\n",
					  th->tid, ksb, stack->name, ret);
			}
			/* no atomic op is needed since we own entire */
			ksb->refcnt--;
		}
		assert(ksb->refcnt == 0); /* XXX: if and log */

		/* cleanup */
		ret = ulogd_clean_results(ksb);
		if (ret != 0) { /* not fatal rignt now */
			ulogd_log(ULOGD_ERROR, "ulogd_clean_results: %s\n",
				  _sys_errlist[errno]);
		}
		/* put back keysets bundle */
		ret = ulogd_put_keysets_bundle(ksb);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "ulogd_put_output_keyset\n");
			goto failure;
		}

		/* notify to ulogd_wait_consume() */
		ret = pthread_mutex_lock(&ksb->refcnt_mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL,
				  "pthread_mutex_lock: %s\n",
				  _sys_errlist[ret]);
			goto failure;
		}
		ret = pthread_cond_signal(&ksb->refcnt_condv);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL,
				  "pthread_cond_signal: %s\n",
				  _sys_errlist[ret]);
			goto failure_unlock_refcnt;
		}
		ret = pthread_mutex_unlock(&ksb->refcnt_mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL,
				  "pthread_mutex_unlock: %s\n",
				  _sys_errlist[ret]);
			goto failure_unlock_refcnt;
		}

		/* put self back to runnable_workers */
		ret = put_worker(th);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "put_worker\n");
			goto failure;
		}
	}

failure:	/* means no one must own me */
	th->retval = ret;
	return &th->retval;
failure_unlock_th:
	pthread_mutex_unlock(&th->mutex);
	goto failure;
failure_unlock_refcnt:
	pthread_mutex_unlock(&ksb->refcnt_mutex);
	goto failure;
}

/* pthread void *(*start_routine)
 * call interp per stack
 */
__attribute__ ((unused))
static void *interp_stack(void *arg)
{
	struct ulogd_interp_thread *th = arg;
	struct ulogd_keysets_bundle *ksb;
	int ret;

	while (th->runnable) {
		/* wait message */
		ret = pthread_mutex_lock(&th->mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_mutex_lock: %s\n",
				_sys_errlist[ret]);
			goto failure;
		}
		/* only self set .bundle and .stack to NULL
		 * and no one can set these at that time */
		while (th->stack == NULL || th->bundle == NULL) {
			if (!th->runnable)
				break;
			ret = pthread_cond_wait(&th->condv, &th->mutex);
			if (ret != 0) {
				ulogd_log(ULOGD_FATAL, "pthread_cond_wait:"
					  " %s\n", _sys_errlist[ret]);
				goto failure_unlock_th;
			}
		}
		ret = pthread_mutex_unlock(&th->mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_mutex_unlock: %s\n",
				  _sys_errlist[ret]);
			goto failure_unlock_th;
		}
		if (!th->runnable) {
			if (th->bundle != NULL) {
				ulogd_log(ULOGD_ERROR, "discard keysets: %p"
					  " because of stop\n", th->bundle);
				ulogd_clean_results(th->bundle);
				ulogd_put_keysets_bundle(th->bundle);
				th->retval = ULOGD_IRET_ERR;
			}
			put_worker(th);
			/* is above enough? */
			break;
		}

		ksb = th->bundle;
		ret = exec_stack(th->stack, ksb->keysets);
		if (ret) {
			ulogd_log(ULOGD_ERROR, "[T%lu/D%p] stack: %s,"
				  " returned: %d\n",
				  th->tid, th->bundle, th->stack->name, ret);
		}

		if (uatomic_sub_return(&ksb->refcnt, 1) == 0) {
			/* XXX: ?comparison of unsigned expression < 0 is always false [-Wtype-limits] */
			/* cleanup */
			ret = ulogd_clean_results(ksb);
			if (ret != 0) { /* not fatal rignt now */
				ulogd_log(ULOGD_ERROR,
					  "ulogd_clean_results: %s\n",
					  _sys_errlist[errno]);
			}
			/* put back keysets */
			ret = ulogd_put_keysets_bundle(ksb);
			if (ret != 0) {
				ulogd_log(ULOGD_FATAL,
					  "ulogd_put_output_keyset\n");
				goto failure;
			}

			/* notify to ulogd_wait_consume() */
			ret = pthread_mutex_lock(&ksb->refcnt_mutex);
			if (ret != 0) {
				ulogd_log(ULOGD_FATAL,
					  "pthread_mutex_lock: %s\n",
					  _sys_errlist[ret]);
				goto failure;
			}
			ret = pthread_cond_signal(&ksb->refcnt_condv);
			if (ret != 0) {
				ulogd_log(ULOGD_FATAL,
					  "pthread_cond_signal: %s\n",
					  _sys_errlist[ret]);
				goto failure_unlock_refcnt;
			}
			ret = pthread_mutex_unlock(&ksb->refcnt_mutex);
			if (ret != 0) {
				ulogd_log(ULOGD_FATAL,
					  "pthread_mutex_unlock: %s\n",
					  _sys_errlist[ret]);
				goto failure_unlock_refcnt;
			}
		}

		/* put self back to active_workers */
		ret = put_worker(th);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "put_worker\n");
			goto failure;
		}
	}

failure:
	th->retval = ret;
	return &th->retval;
failure_unlock_th:
	pthread_mutex_unlock(&th->mutex);
	goto failure;
failure_unlock_refcnt:
	pthread_mutex_unlock(&ksb->refcnt_mutex);
	goto failure;
}

static struct ulogd_interp_thread *ulogd_get_worker(void)
{
	struct ulogd_interp_thread *worker;
	int ret;

	ret = pthread_mutex_lock(&ulogd_runnable_workers_mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_lock: %s\n",
			_sys_errlist[ret]);
		return NULL;
	}

check_cond:
	switch (ulogd_runnable_workers_status) {
	case WORKERS_STOP:
		pthread_mutex_unlock(&ulogd_runnable_workers_mutex);
		return NULL;
	case WORKERS_RUNNABLE:
		if (!llist_empty(&ulogd_runnable_workers))
			break;
		/* pass through */
	default: /* WORKERS_SUSPEND */
		ret = pthread_cond_wait(&ulogd_runnable_workers_condv,
					&ulogd_runnable_workers_mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_cond_wait:"
				  " %s\n", _sys_errlist[ret]);
			return NULL;
		}
		goto check_cond;
	}

	worker = llist_entry(ulogd_runnable_workers.next,
			     struct ulogd_interp_thread, runnable_list);
	llist_del(ulogd_runnable_workers.next);

	ret = pthread_mutex_unlock(&ulogd_runnable_workers_mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_unlock: %s\n",
			_sys_errlist[ret]);
		return NULL;
	}

	return worker;
}

/* returns number of threads created. caller needs to set sig block mask
 * caller: ulogd.c */
int ulogd_start_workers(int nthreads)
{
	struct ulogd_interp_thread *args, *cur, *tmp;
	int ret, nthr;

	args = calloc(sizeof(struct ulogd_interp_thread), nthreads);
	if (args == NULL) {
		ulogd_log(ULOGD_FATAL, "calloc: %s\n", _sys_errlist[errno]);
		return -1;
	}

	for (nthr = 0; nthr < nthreads; nthr++) {
		pthread_mutexattr_t attr;

		/* XXX: no erro check */
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, ULOGD_MUTEX_ATTR);
		pthread_mutex_init(&args[nthr].mutex, &attr);
		pthread_cond_init(&args[nthr].condv, NULL);
		args[nthr].bundle = NULL;
		args[nthr].stack = NULL;
		args[nthr].runnable = true;
		llist_add(&args[nthr].list, &ulogd_interp_workers);
		/* XXX: any attr? */
		ret = pthread_create(&args[nthr].tid, NULL,
				     START_ROUTINE,
				     &args[nthr]);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_create: %s\n",
				  _sys_errlist[ret]);
			goto failure_cancel;
		}
	}
	/* may not need, but this makes helgrind happy */
	pthread_mutex_lock(&ulogd_runnable_workers_mutex);
	llist_for_each_entry(cur, &ulogd_interp_workers, list)
		llist_add(&cur->runnable_list, &ulogd_runnable_workers);
	pthread_mutex_unlock(&ulogd_runnable_workers_mutex);

	return nthr;

failure_cancel:
	for (--nthr; nthr >= 0; nthr--) {
		/* must be canceled at waiting condv loop */
		ret = pthread_cancel(args[nthr].tid);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_cancel: %s\n",
				  _sys_errlist[ret]);
		}
		ret = pthread_join(args[nthr].tid, NULL);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_join: %s\n",
				  _sys_errlist[ret]);
		}
	}
	llist_for_each_entry_safe(cur, tmp, &ulogd_interp_workers, list) {
		/* XXX: no err check */
		pthread_mutex_destroy(&cur->mutex);
		pthread_cond_destroy(&cur->condv);
		llist_del(&cur->list);
	}
	free(args);

	return -1;
}

/* XXX: use a lot of no async-signal-safe functions
 * caller: ulogd.c */
int ulogd_stop_workers(void)
{
	struct ulogd_interp_thread *cur, *tmp, *head
		= llist_entry(ulogd_interp_workers.next,
			      struct ulogd_interp_thread, list);
	int ret, *retval;

	if (llist_empty(&ulogd_interp_workers))
		return 0;

	llist_for_each_entry(cur, &ulogd_interp_workers, list) {
		ret = pthread_mutex_lock(&cur->mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_mutex_lock: %s\n",
				_sys_errlist[ret]);
			return -1;
		}
		cur->runnable = false;
		ret = pthread_cond_signal(&cur->condv);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_cond_signal: %s\n",
				_sys_errlist[ret]);
			return -1;
		}
		ret = pthread_mutex_unlock(&cur->mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_mutex_unlock: %s\n",
				_sys_errlist[ret]);
			return -1;
		}
	}

	llist_for_each_entry_safe(cur, tmp, &ulogd_interp_workers, list) {
		/* XXX: or sleep and cancel? */
		ret = pthread_join(cur->tid, (void **)&retval);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_join: %s\n",
				  _sys_errlist[ret]);
			return -1;
		}
		if (*retval != 0) {
			ulogd_log(ULOGD_ERROR, "thread [T%lu] returns: %d\n",
				  *retval);
		}
		/* I can't understand why this makes helgrind unhappy */
		ret = pthread_mutex_destroy(&cur->mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_ERROR, "pthread_mutex_destroy: %s\n",
				  _sys_errlist[ret]);
		}
		ret = pthread_cond_destroy(&cur->condv);
		if (ret != 0) {
			ulogd_log(ULOGD_ERROR, "pthread_cond_destroy: %s\n",
				  _sys_errlist[ret]);
		}
		llist_del(&cur->list);
		llist_del(&cur->runnable_list);
		if (cur < head)
			head = cur;
	}
	free(head);

	return 0;
}

int ulogd_suspend_propagation(void)
{
	pthread_mutex_lock(&ulogd_runnable_workers_mutex);
	ulogd_runnable_workers_status = WORKERS_SUSPEND;
	pthread_mutex_unlock(&ulogd_runnable_workers_mutex);
	return 0;
}

int ulogd_resume_propagation(void)
{
	pthread_mutex_lock(&ulogd_runnable_workers_mutex);
	ulogd_runnable_workers_status = WORKERS_RUNNABLE;
	pthread_cond_broadcast(&ulogd_runnable_workers_condv);
	pthread_mutex_unlock(&ulogd_runnable_workers_mutex);
	return 0;
}

int ulogd_stop_propagation(void)
{
	pthread_mutex_lock(&ulogd_runnable_workers_mutex);
	ulogd_runnable_workers_status = WORKERS_RUNNABLE;
	pthread_cond_broadcast(&ulogd_runnable_workers_condv);
	pthread_mutex_unlock(&ulogd_runnable_workers_mutex);
	return 0;
}

static inline int ulogd_propagate_results_bundle(struct ulogd_keyset *okeys)
{
	/* I know here is a dirty hack */
	struct ulogd_keysets_bundle *ksb
		= (void *)okeys - offsetof(struct ulogd_keysets_bundle, keysets);
	/* = container_of(okeys, struct ulogd_keysets_bundle, keysets); */

	struct ulogd_source_pluginstance *spi = ksb->spi;
	struct ulogd_interp_thread *worker = ulogd_get_worker();
	int ret;

	if (worker == NULL || worker->runnable == false) {
		ulogd_log(ULOGD_FATAL, "workers may have stopped\n");
		return ULOGD_IRET_ERR;
	}

	/* would be a trylock? no. */
	ret = pthread_mutex_lock(&worker->mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_lock: %s\n",
			_sys_errlist[ret]);
		goto failure;
	}

	uatomic_set(&ksb->refcnt, spi->nstacks);
	/* let worker run: source pluginstance */
	worker->bundle = ksb;
	ret = pthread_cond_signal(&worker->condv);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_cond_signal: %s\n",
			_sys_errlist[ret]);
		goto failure;
	}
	ret = pthread_mutex_unlock(&worker->mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_unlock: %s\n",
			_sys_errlist[ret]);
		goto failure;
	}

	return ULOGD_IRET_OK;

failure:
	put_worker(worker);
	return ULOGD_IRET_ERR;
}

__attribute__ ((unused))
static inline int ulogd_propagate_results_stack(struct ulogd_keyset *okeys)
{
	struct ulogd_keysets_bundle *ksb
		= (void *)okeys - offsetof(struct ulogd_keysets_bundle, keysets);
	struct ulogd_source_pluginstance *spi = ksb->spi;
	struct ulogd_stack *stack;
	struct ulogd_interp_thread *worker;
	int ret;

	uatomic_set(&ksb->refcnt, spi->nstacks);
	llist_for_each_entry(stack, &spi->stacks, list) {
		worker = ulogd_get_worker();
		if (worker == NULL) {
			ulogd_log(ULOGD_FATAL, "ulogd_get_worker\n");
			return ULOGD_IRET_ERR;
		}

		ret = pthread_mutex_lock(&worker->mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_mutex_lock: %s\n",
				  _sys_errlist[ret]);
			goto failure;
		}

		worker->stack = stack;
		worker->bundle = ksb;
		ret = pthread_cond_signal(&worker->condv);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_cond_signal: %s\n",
				  _sys_errlist[ret]);
			goto failure;
		}
		ret = pthread_mutex_unlock(&worker->mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_mutex_unlock: %s\n",
				  _sys_errlist[ret]);
			goto failure;
		}
	}

	return ULOGD_IRET_OK;

failure:
	put_worker(worker);
	return ULOGD_IRET_ERR;
}

/* public interface in ulogd.h
 * propagate results to all downstream plugins in the stack */
int ulogd_propagate_results(struct ulogd_keyset *okeys)
{
#ifdef THREAD_PER_STACK
	return ulogd_propagate_results_stack(okeys);
#else
	return ulogd_propagate_results_bundle(okeys);
#endif
}

int ulogd_wait_consume(struct ulogd_keyset *okeys)
{
	struct ulogd_keysets_bundle *ksb
		= (void *)okeys - offsetof(struct ulogd_keysets_bundle, keysets);
	int ret;

	ret = pthread_mutex_lock(&ksb->refcnt_mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_lock: %s\n",
			  _sys_errlist[ret]);
		return -1;
	}
	/* was added in ulogd_propagate_result() and deced in interp_bundle() */
	while (uatomic_read(&ksb->refcnt) != 0) {
		ret = pthread_cond_wait(&ksb->refcnt_condv, &ksb->refcnt_mutex);
		if (ret != 0) {
			ulogd_log(ULOGD_FATAL, "pthread_cond_wait: %s\n",
				  _sys_errlist[ret]);
			return -1;
		}
	}
	ret = pthread_mutex_unlock(&ksb->refcnt_mutex);
	if (ret != 0) {
		ulogd_log(ULOGD_FATAL, "pthread_mutex_unlock: %s\n",
			  _sys_errlist[ret]);
		return -1;
	}

	return 0;
}
