/* timer implementation
 *
 * userspace logging daemon for the netfilter subsystem
 *
 * (C) 2015 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
 *
 * based on previous works by:
 *
 * (C) 2006-2008 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * based on previous works by:
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Description:
 *  This is the timer framework for ulogd, it works together with select()
 *  with linux specific timerfd. Each plugin can same things using their own
 *  timerfd. This is a wrapper to ulogd_fd to reuse ulogd modules.
 */

#include <unistd.h>
#include <sys/timerfd.h>

#include <ulogd/ulogd.h>
#include <ulogd/timer.h>

static int fd_timer_cb(int fd, unsigned int what, void *data)
{
        struct ulogd_timer *alarm = data;

	/* unregister first since cb may call add_timer again */
        ulogd_unregister_fd(&alarm->ufd);
        alarm->cb(alarm, alarm->data);
        return 0;
}

static int fd_itimer_cb(int fd, unsigned int what, void *data)
{
        struct ulogd_timer *alarm = data;
        alarm->cb(alarm, alarm->data);
        return 0;
}

int ulogd_init_timer(struct ulogd_timer *t,
                     void *data,
                     void (*cb)(struct ulogd_timer *a, void *data))
{
        t->ufd.fd = timerfd_create(CLOCK_MONOTONIC, 0);
        if (t->ufd.fd == -1)
                return -1; /* XXX: or -errno? */
        t->data = data;
        t->cb = cb;
        t->ufd.when = ULOGD_FD_READ;
        t->ufd.data = t;
        return 0;
}

int ulogd_fini_timer(struct ulogd_timer *t)
{
	t->ufd.cb = NULL;
	t->data = NULL;
	t->cb = NULL;
	t->ufd.when = 0;
	t->ufd.data = NULL;

	return close(t->ufd.fd);
}

int ulogd_add_itimer(struct ulogd_timer *alarm,
                      unsigned long ini, unsigned long per)
{
        /* alarm->its = {{per, 0}, {ini, 0}}; */
        alarm->its.it_interval.tv_sec = per;
        alarm->its.it_interval.tv_nsec = 0;
        alarm->its.it_value.tv_sec = ini;
        alarm->its.it_value.tv_nsec = 0;
        if (timerfd_settime(alarm->ufd.fd, 0, &alarm->its, NULL) == -1)
                return -1;

        alarm->ufd.cb = fd_itimer_cb;
        return ulogd_register_fd(&alarm->ufd);
}

int ulogd_add_timer(struct ulogd_timer *alarm, unsigned long sc)
{
        alarm->its.it_interval.tv_sec = 0;
        alarm->its.it_interval.tv_nsec = 0;
        alarm->its.it_value.tv_sec = sc;
	/* caller want to be called just after now */
        if (sc == 0)
                alarm->its.it_value.tv_nsec = 1;
        else
                alarm->its.it_value.tv_nsec = 0;

        if (timerfd_settime(alarm->ufd.fd, 0, &alarm->its, NULL) == -1)
                return -1;

        alarm->ufd.cb = fd_timer_cb;
        return ulogd_register_fd(&alarm->ufd);
}

int ulogd_del_timer(struct ulogd_timer *alarm)
{
        return timerfd_settime(alarm->ufd.fd, 0, NULL, NULL);
}

int ulogd_timer_pending(struct ulogd_timer *alarm)
{
        struct itimerspec its;

        if (timerfd_gettime(alarm->ufd.fd, &its) == -1)
                return -1; /* XXX: or -errno */

        return its.it_interval.tv_sec > 0
                || its.it_interval.tv_nsec > 0
                || its.it_value.tv_sec > 0
                || its.it_value.tv_nsec > 0;
}
