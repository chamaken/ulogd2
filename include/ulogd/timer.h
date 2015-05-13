#ifndef _TIMER_H_
#define _TIMER_H_

#include <time.h>
#include <ulogd/ulogd.h>

struct ulogd_timer {
	struct ulogd_fd		ufd;
	struct itimerspec	its;
	void			*data;
	void			(*cb)(struct ulogd_timer *a, void *data);
};

int ulogd_init_timer(struct ulogd_timer *t,
		     void *data,
		     void (*cb)(struct ulogd_timer *a, void *data));
int ulogd_fini_timer(struct ulogd_timer *t);
int ulogd_add_timer(struct ulogd_timer *alarm, unsigned long sc);
int ulogd_add_itimer(struct ulogd_timer *alarm,
		     unsigned long ini, unsigned long per);
int ulogd_del_timer(struct ulogd_timer *alarm);
int ulogd_timer_pending(struct ulogd_timer *alarm);

#endif
