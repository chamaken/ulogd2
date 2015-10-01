/* utils.c
 *
 * utilities for ulogd python module
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
#include <Python.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <libmnl/libmnl.h>

#include <ulogd/ulogd.h>

#include "ulogd_pyobj.h"

int childfd = -1;

char *py_strerror(char *buf, size_t len)
{
	PyObject *type, *value, *trace;
	PyObject *frame, *code;
	PyObject *str = NULL, *line_no, *file_name;
	PyObject *fname_ascii = NULL, *msg_ascii = NULL;
	char *msg, *fname = NULL, *slash;
	long lineno = -1;

	PyErr_Fetch(&type, &value, &trace);
	PyErr_NormalizeException(&type, &value, &trace);

	/* message */
	str = PyObject_Str(value);
	if (str == NULL) {
		snprintf(buf, len, "(could not get message)");
		goto decref;
	}
	if (PyUnicode_Check(str)) {
		msg_ascii = PyUnicode_AsASCIIString(str);
		msg = PyBytes_AsString(msg_ascii);
	} else if (PyBytes_Check(str)) {
		msg = PyBytes_AsString(str);
	} else {
		snprintf(buf, len, "(could not decode message)");
		Py_DECREF(str);
		goto decref;
	}
	Py_DECREF(str);

	if (trace == NULL) {
		snprintf(buf, len, "(no trace) %s", msg);
		goto decref_msg_ascii;
	}

	/* file name */
	frame = PyObject_GetAttrString(trace, "tb_frame");
	if (frame == NULL) {
		snprintf(buf, len, "(could not get frame) %s", msg);
		goto decref_msg_ascii;
	}
	code = PyObject_GetAttrString(frame, "f_code");
	Py_DECREF(frame);
	if (code == NULL) {
		snprintf(buf, len, "(could not get frame code) %s", msg);
		goto decref_msg_ascii;
	}
	file_name = PyObject_GetAttrString(code, "co_filename");
	Py_DECREF(code);
	if (file_name == NULL) {
		snprintf(buf, len, "(could not get filename) %s", msg);
		goto decref_msg_ascii;
	}
	str = PyObject_Str(file_name);
	Py_DECREF(file_name);
	if (str == NULL) {
		snprintf(buf, len, "(could not get filename str) %s", msg);
		goto decref_msg_ascii;
	}
	fname_ascii = PyUnicode_AsASCIIString(str);
	Py_DECREF(str);
	if (fname_ascii == NULL) {
		snprintf(buf, len, "(could not get filename ascii) %s", msg);
		goto decref_msg_ascii;
	}
	fname = PyBytes_AsString(fname_ascii);
	if ((slash = strrchr(fname, '/')) != NULL)
		fname = slash + 1;

	/* line number */
	line_no = PyObject_GetAttrString(trace, "tb_lineno");
	if (line_no == NULL) {
		snprintf(buf, len, "%s: (could not get lineno) %s", fname, msg);
		goto decref_fname_ascii;
	}
	if (!PyLong_Check(line_no)) {
		snprintf(buf, len, "%s: (lineno is not an integer) %s",
			 fname, msg);
		Py_DECREF(line_no);
		goto decref_fname_ascii;;
	}
	lineno = PyLong_AsLong(line_no);
	Py_DECREF(line_no);

	snprintf(buf, len, "%s[%ld]: %s", fname, lineno, msg);

decref_fname_ascii:
	Py_XDECREF(fname_ascii);
decref_msg_ascii:
	Py_XDECREF(msg_ascii);
decref:
	buf[len] = '\0';
	Py_DECREF(type);
	Py_DECREF(value);
	Py_XDECREF(trace); /* may be NULL? */

	return buf;
}

void __child_log(int level, int line, char *format, ...)
{
	va_list ap;
	char buf[MNL_SOCKET_BUFFER_SIZE];

	va_start(ap, format);
	vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	buf[MNL_SOCKET_BUFFER_SIZE - 1] = '\0';

	py_child_sendargs(ULOGD_PY_CALL_LOG,
			  0, "IIz", level, line, buf);
}

/****
 * tx/rx utils
 */
static int get_unaligned_int(const void *s)
{
	int x;
	memcpy(&x, s, sizeof(x));
	return x;
}

static void put_unaligned_int(void *d, int x)
{
	memcpy(d, &x, sizeof(x));
}

/* suppose cdata is a file descriptor */
/* not return sent size, but success: 0 or failure: -1 */
static int py_send_nlmsg(int fd, struct nlmsghdr *nlh, int cdata)
{
	struct msghdr msg = {0};
	struct iovec iov = {0};
	size_t cmsglen = CMSG_SPACE(sizeof(int));
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;

	iov.iov_base = nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (cdata) {
		msg.msg_control = control;
		msg.msg_controllen = cmsglen;
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		put_unaligned_int(CMSG_DATA(cmsg), cdata);
	}

	if (sendmsg(fd, &msg, MSG_NOSIGNAL) != nlh->nlmsg_len)
		return ULOGD_IRET_ERR;

	return ULOGD_IRET_OK;
}

#define _MNL_TYPE_PTR (MNL_TYPE_MAX + 1)
int py_send_vargs(int sockfd, uint16_t type, int cdata,
			 const char *format, va_list ap)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	char *s;
	size_t len;
	void *p;
	int remaind;

	while (format != NULL && *format != '\0') {
		remaind = (void *)&buf[MNL_SOCKET_BUFFER_SIZE - 1]
			- mnl_nlmsg_get_payload_tail(nlh)
			- MNL_ATTR_HDRLEN;
		switch (*format) {
		case 'B':
			if (remaind - (int)MNL_ALIGN(sizeof(uint8_t)) < 0)
				return -E2BIG;
			/* 'uint8_t' is promoted to 'int' when passed ... */
			mnl_attr_put_u8(nlh, MNL_TYPE_U8,
					va_arg(ap, int));
			break;
		case 'H':
			if (remaind - (int)MNL_ALIGN(sizeof(uint16_t)) < 0)
				return -E2BIG;
			/* 'uint16_t' is promoted to 'int' when passed ... */
			mnl_attr_put_u16(nlh, MNL_TYPE_U16,
					 va_arg(ap, int));
			break;
		case 'I':
			if (remaind - (int)MNL_ALIGN(sizeof(uint32_t)) < 0)
				return -E2BIG;
			mnl_attr_put_u32(nlh, MNL_TYPE_U32,
					 va_arg(ap, uint32_t));
			break;
		case 'K':
			if (remaind - (int)MNL_ALIGN(sizeof(uint64_t)) < 0)
				return -E2BIG;
			mnl_attr_put_u64(nlh, MNL_TYPE_U64,
					 va_arg(ap, uint64_t));
			break;
		case 'p':
			if (remaind - (int)MNL_ALIGN(sizeof(uintptr_t)) < 0)
				return -E2BIG;
			p = va_arg(ap, void *);
			mnl_attr_put(nlh, _MNL_TYPE_PTR, sizeof(uintptr_t), &p);
			break;
		case 'z':
			s = va_arg(ap, char *);
			len = strlen(s);
			if (remaind - (int)MNL_ALIGN(len + 1) < 0)
				return -E2BIG;
			mnl_attr_put(nlh, MNL_TYPE_NUL_STRING, len + 1, s);
			break;
		case 'y':
			format++;
			if (*format != '#')
				return -EINVAL;
			p = va_arg(ap, void *);
			len = va_arg(ap, size_t);
			if (remaind - (int)MNL_ALIGN(len) < 0)
				return -E2BIG;
			mnl_attr_put(nlh, MNL_TYPE_BINARY, len, p);
			break;
		default:
			return -EINVAL;
		}
		format++;
	}
	nlh->nlmsg_type = type;
	return py_send_nlmsg(sockfd, nlh, cdata);
}

__attribute__ ((noreturn))
void py_child_exit(int status, const char *format, ...)
{
	va_list ap;

	if (format != NULL) { /* XXX: needed? */
		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
	}
	_exit(status);
	/* NOTREACHED */
}

void py_child_sendargs(uint16_t type, int cdata, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	if (py_send_vargs(childfd, type, cdata, format, ap) != 0)
		py_child_exit(EXIT_FAILURE,
			      "py_send_vargs: %s\n", strerror(errno));
	va_end(ap);
}

ssize_t py_recv(int fd, void *buf, size_t len, int *cdata)
{
	struct msghdr msg = {0};
	struct iovec iov = {0};
	size_t cmsglen = CMSG_SPACE(sizeof(int));
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	ssize_t ret;

	iov.iov_base = buf;
	iov.iov_len = len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (cdata != NULL) {
		msg.msg_control = control;
		msg.msg_controllen = cmsglen;
	}

	ret = recvmsg(fd, &msg, 0);
	if (ret == -1 || cdata == NULL) {
		return ret;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_len != CMSG_LEN(sizeof(int))
	    || cmsg->cmsg_level != SOL_SOCKET
	    || cmsg->cmsg_type != SCM_RIGHTS) {
		*cdata = -1;
	} else {
		*cdata = get_unaligned_int(CMSG_DATA(cmsg));
	}

	return ret;
}

void py_child_recv(void *buf, size_t len, int *cdata)
{
	if (py_recv(childfd, buf, len, cdata) < 0)
		py_child_exit(EXIT_FAILURE,
			      "py_recv: %s\n", strerror(errno));
}

char *_pyulogd_nl_typestr[] = {
	[ULOGD_PY_CALL_LOG]			= "CALL_LOG",
	[ULOGD_PY_RETURN_LOG]			= "RETURN_LOG",
	[ULOGD_PY_RETURN_CONFIGURE]		= "RETURN_CONFIGURE",
	[ULOGD_PY_RETURN_CONFIGURE_IKINFO]	= "RETURN_CONFIGURE_IKINFO",
	[ULOGD_PY_RETURN_CONFIGURE_OKINFO]	= "RETURN_CONFIGURE_OKINFO",
	[ULOGD_PY_RETURN_CONFIGURE_KEYS]	= "RETURN_CONFIGURE_KEYS",
	[ULOGD_PY_CALL_START]			= "CALL_START",
	[ULOGD_PY_RETURN_START]			= "RETURN_START",
	[ULOGD_PY_CALL_INTERP]			= "CALL_INTERP",
	[ULOGD_PY_RETURN_INTERP]		= "RETURN_INTERP",
	[ULOGD_PY_CALL_STOP]			= "CALL_STOP",
	[ULOGD_PY_RETURN_STOP]			= "RETURN_STOP",
	[ULOGD_PY_CALL_SIGNAL]			= "CALL_SIGNAL",
	[ULOGD_PY_RETURN_SIGNAL]		= "RETURN_SIGNAL",
	[ULOGD_PY_RETURN_KEYSET]		= "RETURN_KEYSET",
	[ULOGD_PY_RETURN_KEY]			= "RETURN_KEY",
	[ULOGD_PY_CALL_REGISTER_FD]		= "CALL_REGISTER_FD",
	[ULOGD_PY_RETURN_REGISTER_FD]		= "RETURN_REGISTER_FD",
	[ULOGD_PY_CALL_UNREGISTER_FD]		= "CALL_UNREGISTER_FD",
	[ULOGD_PY_RETURN_UNREGISTER_FD]		= "RETURN_UNREGISTER_FD",
	[ULOGD_PY_CALL_FD_CALLBACK]		= "CALL_FD_CALLBACK",
	[ULOGD_PY_RETURN_FD_CALLBACK]		= "RETURN_FD_CALLBACK",
	[ULOGD_PY_CALL_INIT_TIMER]		= "CALL_INIT_TIMER",
	[ULOGD_PY_RETURN_INIT_TIMER]		= "RETURN_INIT_TIMER",
	[ULOGD_PY_CALL_ADD_TIMER]		= "CALL_ADD_TIMER",
	[ULOGD_PY_RETURN_ADD_TIMER]		= "RETURN_ADD_TIMER",
	[ULOGD_PY_CALL_DEL_TIMER]		= "CALL_DEL_TIMER",
	[ULOGD_PY_RETURN_DEL_TIMER]		= "RETURN_DEL_TIMER",
	[ULOGD_PY_CALL_TIMER_CALLBACK]		= "CALL_TIMER_CALLBACK",
	[ULOGD_PY_RETURN_TIMER_CALLBACK]	= "RETURN_TIMER_CALLBACK",
	[ULOGD_PY_CALL_PROPAGATE_RESULTS]	= "CALL_PROPAGATE_RESULTS",
	[ULOGD_PY_RETURN_PROPAGATE_RESULTS]	= "RETURN_PROPAGATE_RESULTS",
	[ULOGD_PY_CALL_GET_OUTPUT_KEYSET]	= "CALL_GET_OUTPUT_KEYSET",
	[ULOGD_PY_RETURN_GET_OUTPUT_KEYSET]	= "RETURN_GET_OUTPUT_KEYSET",
};
