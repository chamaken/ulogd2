#ifndef _THREAD_H
#define _THREAD_H

/* PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP, PTHREAD_MUTEX_ERRORCHECK_NP */
#define _GNU_SOURCE

#include <stdbool.h>
#include <pthread.h>
#include <ulogd/linuxlist.h>
#include <ulogd/ulogd.h>
#include <ulogd/keysets.h>

#define DEBUG
#ifdef DEBUG
#define ULOGD_MUTEX_INITIALIZER PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#define ULOGD_MUTEX_ATTR PTHREAD_MUTEX_ERRORCHECK_NP
#else
#define ULOGD_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define ULOGD_MUTEX_ATTR PTHREAD_MUTEX_FAST_NP
#endif

struct ulogd_interp_thread {
	struct llist_head list;
	struct llist_head runnable_list;
	pthread_t tid;
	pthread_mutex_t mutex;	/* stacks, runnable and bundle */
	pthread_cond_t condv;	/* runnable and bundle update */
	bool runnable;
	int retval;	/* errno in thread */

	/* view below to message to this thread */
	struct ulogd_keysets_bundle *bundle;
	/* see: interp_stack(void *arg)
	 *      and must chage propagate function */
	struct ulogd_stack *stack;
};

/* from main */
int ulogd_start_workers(int nthreads);
int ulogd_stop_workers(void);
int ulogd_sync_workers(void);

#endif /* _THREAD_H */
