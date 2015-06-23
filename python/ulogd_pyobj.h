#ifndef ULOGD_PY_H
#define ULOGD_PY_H

/* ulogd_pyobj.h
 *
 * python module for ulogd
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <ulogd/linuxlist.h>
#include <ulogd/ulogd.h>

struct py_ulogd_key {
	PyObject_HEAD
	struct llist_head list;
	struct ulogd_key *raw;
};

struct py_ulogd_keylist {
	PyObject_HEAD
	struct llist_head list;
	int max_num_keys;
	struct ulogd_keyset *raw;
};

#define PY_KEYLIST_MAX_NUM \
	((UINT16_MAX - MNL_ATTR_HDRLEN) / sizeof(struct ulogd_key))

struct py_ulogd_keyset {
	PyObject_HEAD
	struct ulogd_keyset *raw;
	long n;
};

struct py_ulogd_pluginstance {
	PyObject_HEAD
	struct ulogd_pluginstance *raw;
};

struct py_ulogd_fd {
	PyObject_HEAD
	int sockfd; /* for parent cb */
	PyObject *file;
	int fd;
	unsigned int when;
	PyObject *cb;
	PyObject *data;
};

struct py_ulogd_timer {
	PyObject_HEAD
	int sockfd; /* for parent cb */
	long sec;
	long nsec;
	PyObject *cb;
	PyObject *data;
};

enum ulogd_py_nlmsg_type {
	ULOGD_PY_IPC_NONE,
	ULOGD_PY_CALL_LOG,
	ULOGD_PY_RETURN_LOG,
	ULOGD_PY_RETURN_CONFIGURE,
	ULOGD_PY_RETURN_CONFIGURE_IKINFO,
	ULOGD_PY_RETURN_CONFIGURE_OKINFO,
	ULOGD_PY_RETURN_CONFIGURE_KEYS,
	ULOGD_PY_CALL_START,
	ULOGD_PY_RETURN_START,
	ULOGD_PY_CALL_INTERP,
	ULOGD_PY_RETURN_INTERP,
	ULOGD_PY_CALL_STOP,
	ULOGD_PY_RETURN_STOP,
	ULOGD_PY_CALL_SIGNAL,
	ULOGD_PY_RETURN_SIGNAL,
	ULOGD_PY_RETURN_KEYSET,
	ULOGD_PY_RETURN_KEY,
	ULOGD_PY_CALL_REGISTER_FD,
	ULOGD_PY_RETURN_REGISTER_FD,
	ULOGD_PY_CALL_UNREGISTER_FD,
	ULOGD_PY_RETURN_UNREGISTER_FD,
	ULOGD_PY_CALL_FD_CALLBACK,
	ULOGD_PY_RETURN_FD_CALLBACK,
	ULOGD_PY_CALL_INIT_TIMER,
	ULOGD_PY_RETURN_INIT_TIMER,
	ULOGD_PY_CALL_ADD_TIMER,
	ULOGD_PY_RETURN_ADD_TIMER,
	ULOGD_PY_CALL_DEL_TIMER,
	ULOGD_PY_RETURN_DEL_TIMER,
	ULOGD_PY_CALL_TIMER_CALLBACK,
	ULOGD_PY_RETURN_TIMER_CALLBACK,
	ULOGD_PY_CALL_PROPAGATE_RESULTS,
	ULOGD_PY_RETURN_PROPAGATE_RESULTS,
	ULOGD_PY_CALL_GET_OUTPUT_KEYSET,
	ULOGD_PY_RETURN_GET_OUTPUT_KEYSET,
};

void py_child_exit(int status, const char *format, ...);
char *py_strerror(char *buf, size_t len);
void __child_log(int level, int line, char *format, ...);
#define child_log(level, format, args...) \
	__child_log(level, __LINE__, format, ## args)
int py_send_vargs(int sockfd, uint16_t type, int cdata,
		  const char *format, va_list ap);
ssize_t py_recv(int fd, void *buf, size_t len, int *cdata);
void py_child_recv(void *buf, size_t len, int *cdata);
void py_child_sendargs(uint16_t type, int cdata, const char *format, ...);

#endif /* ULOGD_PY_H */
