/* select related functions
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
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

#define _GNU_SOURCE

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <ulogd/ulogd.h>

#define UFD_MAX_EVENTS 16

static int epollfd = -1;

int ulogd_init_fd(void)
{
	epollfd = epoll_create1(0);
	if (epollfd == -1)
		return -1;
	return 0;
}

int ulogd_fini_fd(void)
{
	int ret;

	ret = close(epollfd);
	epollfd = -1;
	return ret;
}

int ulogd_register_fd(struct ulogd_fd *fd)
{
	int flags;
	struct epoll_event ev;

	/* make FD nonblocking */
	flags = fcntl(fd->fd, F_GETFL);
	if (flags < 0)
		return -1;
	flags |= O_NONBLOCK;
	flags = fcntl(fd->fd, F_SETFL, flags);
	if (flags < 0)
		return -1;

	if (fd->when & ULOGD_FD_READ)
		ev.events = EPOLLIN;

	if (fd->when & ULOGD_FD_WRITE)
		ev.events = EPOLLOUT;

	if (fd->when & ULOGD_FD_EXCEPT) {
		/* XXX: intend to be a fd_set *exceptfds, right? */
		ev.events = EPOLLRDHUP | EPOLLPRI | EPOLLERR;
	}

	ev.data.ptr = fd;
	return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd->fd, &ev);
}

int ulogd_unregister_fd(struct ulogd_fd *fd)
{
	struct epoll_event ev;

	if (fd->when & ULOGD_FD_READ)
		ev.events = EPOLLIN;

	if (fd->when & ULOGD_FD_WRITE)
		ev.events = EPOLLOUT;

	if (fd->when & ULOGD_FD_EXCEPT)
		ev.events = EPOLLRDHUP | EPOLLPRI | EPOLLERR;

	ev.data.ptr = fd;
	return epoll_ctl(epollfd, EPOLL_CTL_DEL, fd->fd, &ev);
}

int ulogd_select_main(void)
{
	struct ulogd_fd *ufd;
	struct epoll_event events[UFD_MAX_EVENTS];
	int nfds, i, flags = 0;

	nfds = epoll_wait(epollfd, events, UFD_MAX_EVENTS, -1);
	if (nfds == -1) {
		ulogd_log(ULOGD_ERROR, "epoll_wait: %s\n", _sys_errlist[errno]);
		return -1;
	}

	for (i = 0; i < nfds; i++) {
		ufd = events[i].data.ptr;
		if (events[i].events & EPOLLIN)
			flags |= ULOGD_FD_READ;

		if (events[i].events & EPOLLOUT)
			flags |= ULOGD_FD_WRITE;

		if (events[i].events
		    & (EPOLLRDHUP | EPOLLPRI | EPOLLERR))
			flags |= ULOGD_FD_EXCEPT;

		if (flags)
			ufd->cb(ufd->fd, flags, ufd->data);
	}

	return nfds;
}
