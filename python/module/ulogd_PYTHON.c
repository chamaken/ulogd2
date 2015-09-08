/* ulogd_PYTHON.c
 *
 * ulogd PYTHON plugin
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
#include <memoryobject.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <libmnl/libmnl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/timer.h>

#include "ulogd_pyobj.h"

#define ERRBUF_SIZE		1024

struct py_priv {
	int sockfd;
	pid_t childpid;
};

enum ulogd_pluginstance_type {
	ULOGD_PLUGINSTANCE_SOURCE,
	ULOGD_PLUGINSTANCE_FILTER,
	ULOGD_PLUGINSTANCE_SINK,
};

/* no need to put in priv since these are process specific */
static PyObject *user_mod;
static struct py_ulogd_keyset *ikeyset, *okeyset;
static struct py_ulogd_keylist *ikeylist, *okeylist;
static PyObject *configure_func, *start_func, *interp_func,
	*signal_func, *stop_func;
/* flag to check this is a source or not in child */
static struct py_ulogd_source_pluginstance *source_pluginstance;
extern int childfd;
extern char *_pyulogd_nl_typestr[];

struct py_ulogd_cbdata {
	struct llist_head list;
	union {
		struct ulogd_fd ufd;
		struct ulogd_timer timer;
	};
	struct py_priv *priv;
	uintptr_t pydata;
};
static LLIST_HEAD(py_ulogd_cbdatas);

enum py_conf {
	PY_CONF_MODNAME = 0,
	PY_CONF_PATH_APPEND,
	PY_CONF_MAX,
};

static struct config_keyset py_kset = {
	.num_ces = PY_CONF_MAX,
	.ces = {
		[PY_CONF_MODNAME] = {
			.key = "module",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		[PY_CONF_PATH_APPEND] = {
			.key = "path_append",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
	},
};

#define modname_ce(x)		(((x)->ces[PY_CONF_MODNAME]).u.string)
#define path_append_ce(x)	(((x)->ces[PY_CONF_PATH_APPEND]).u.string)

static int py_parent_session(struct py_priv *priv, uint16_t fin_type);

static int py_parent_waitpid(struct py_priv *priv, int option)
{
	int status;

	switch (waitpid(priv->childpid, &status, option)) {
	case -1:
		ulogd_log(ULOGD_ERROR, "waitpid: %s\n",
			  strerror(errno));
		break;
	case 0:
		/* WNOHANG was specified and the child exist
		 * but have not yet changed state */
		ulogd_log(ULOGD_INFO, "child have not yet changed state\n");
		return ULOGD_IRET_ERR;
		break;
	default:
		ulogd_log(ULOGD_INFO, "child: %d has exited: %d\n",
			  priv->childpid, WEXITSTATUS(status));
		priv->childpid = 0;
	}

	return ULOGD_IRET_OK;
}

static int py_parent_sendargs(struct py_priv *priv, uint16_t type, int cdata,
			      const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = py_send_vargs(priv->sockfd, type, cdata, format, ap);
	va_end(ap);
	if (ret != 0) {
		ulogd_log(ULOGD_ERROR, "py_send_vargs: %s\n",
			  strerror(errno));
		py_parent_waitpid(priv, WNOHANG);
	}

	return ret;
}

static ssize_t py_parent_recv(struct py_priv *priv,
			      void *buf, size_t len, int *cdata)
{
	ssize_t nrecv = py_recv(priv->sockfd, buf, len, cdata);

	if (nrecv == 0) { /* child closed sockfd? */
		/* wait for child core dumping for 1s ;-) */
		sleep(1);
		py_parent_waitpid(priv, WNOHANG);

		return -1;
	} else if (nrecv < 0) {
		ulogd_log(ULOGD_ERROR, "parent py_recv: %s\n",
			  strerror(errno));
		return -1;
	}
	return nrecv;
}

/****
 * logging
 */
static int py_parent_log(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	int32_t level, line;

	level = mnl_attr_get_u32(nla);
	nla = mnl_attr_next(nla);
	line = mnl_attr_get_u32(nla);
	nla = mnl_attr_next(nla);
	ulogd_llog(level, line, mnl_attr_get_payload(nla));

	return ULOGD_IRET_OK;
}

static PyObject *load_module(char *modname)
{
	PyObject *name, *module;

	name = PyUnicode_FromString(modname);
	if (name == NULL) {
		return NULL;
	}

	module = PyImport_Import(name);
	Py_DECREF(name);
	if (module == NULL) {
		return NULL;
	}

	return module;
}

static int prepare_pyobj(char *modname, int pitype)
{
	PyObject *ulogd_mod, *xcfunc, *value;
	PyObject *keylist, *keyset;
	PyObject *spiclass;
	char ebuf[ERRBUF_SIZE + 1];
	int ret = ULOGD_IRET_ERR;

	/* load ulogd module */
	ulogd_mod = load_module("ulogd");
	if (ulogd_mod == NULL) {
		child_log(ULOGD_ERROR, "could not load module ulogd: %s\n",
			  py_strerror(ebuf, ERRBUF_SIZE));
		return ULOGD_IRET_ERR;
	}
	/* create keylists for configure() */
	keylist = PyObject_GetAttrString(ulogd_mod, "Keylist");
	if (keylist == NULL) {
		child_log(ULOGD_ERROR, "could not get ulogd.Keylist: %s\n",
			  py_strerror(ebuf, ERRBUF_SIZE));
		return ULOGD_IRET_ERR;
	}
	if (pitype != ULOGD_PLUGINSTANCE_SOURCE) {
		ikeylist = (struct py_ulogd_keylist *)
			PyObject_CallObject(keylist, NULL);
		if (ikeylist == NULL) {
			child_log(ULOGD_ERROR, "call Keylist.init: %s\n",
				  py_strerror(ebuf, ERRBUF_SIZE));
			goto dec_keylist;
		}
	}
	okeylist = (struct py_ulogd_keylist *)
		PyObject_CallObject(keylist, NULL);
	if (okeylist == NULL) {
		child_log(ULOGD_ERROR, "call Keylist.init: %s\n",
			  py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_ikeylist;
	}

	/* create keysets for start() and interp() */
	if (pitype != ULOGD_PLUGINSTANCE_SOURCE) {
		keyset = PyObject_GetAttrString(ulogd_mod, "IKeyset");
		if (keyset == NULL) {
			child_log(ULOGD_ERROR, "could not get ulogd.IKeyset: %s\n",
				  py_strerror(ebuf, ERRBUF_SIZE));
			goto dec_okeylist;
		}
		ikeyset = (struct py_ulogd_keyset *)PyObject_CallObject(keyset, NULL);
		Py_DECREF(keyset);
		if (ikeyset == NULL) {
			child_log(ULOGD_ERROR, "call Keylist.init: %s\n",
				  py_strerror(ebuf, ERRBUF_SIZE));
			goto dec_okeylist;
		}
	}
	keyset = PyObject_GetAttrString(ulogd_mod, "OKeyset");
	if (keyset == NULL) {
		child_log(ULOGD_ERROR, "could not get ulogd.OKeyset: %s\n",
			  py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_ikeyset;
	}
	okeyset = (struct py_ulogd_keyset *)PyObject_CallObject(keyset, NULL);
	Py_DECREF(keyset);
	if (okeyset == NULL) {
		child_log(ULOGD_ERROR, "call Keylist.init: %s\n",
			  py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_ikeyset;
	}

	if (pitype == ULOGD_PLUGINSTANCE_SOURCE) {
		/* create source pluginstance holder */
		spiclass = PyObject_GetAttrString(ulogd_mod,
						  "SourcePluginstance");
		if (spiclass == NULL) {
			child_log(ULOGD_ERROR, "could not get"
				  "ulogd.SourcePluginstance:  %s\n",
				  py_strerror(ebuf, ERRBUF_SIZE));
			goto dec_okeyset;
		}
		source_pluginstance = (struct py_ulogd_source_pluginstance *)
			PyObject_CallObject(spiclass, NULL);
		Py_DECREF(spiclass);
		if (source_pluginstance == NULL) {
			child_log(ULOGD_ERROR, "call SourcePluginstance.init: %s\n",
				  py_strerror(ebuf, ERRBUF_SIZE));
			goto dec_okeyset;
		}
	}
	/* load user module */
	user_mod = load_module(modname);
	if (user_mod == NULL) {
		child_log(ULOGD_ERROR, "could not load module %s: %s\n",
			  modname, py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_source_pluginstance;
	}

	/* get functions */
	configure_func = PyObject_GetAttrString(user_mod, "configure");
	if (configure_func == NULL || !PyCallable_Check(configure_func)) {
		child_log(ULOGD_ERROR, "can not call %s.configure: %s\n",
			  modname, py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_configure_func;
	}
	start_func = PyObject_GetAttrString(user_mod, "start");
	if (start_func == NULL || !PyCallable_Check(start_func)) {
		child_log(ULOGD_ERROR, "can not call %s.start: %s\n",
			  modname, py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_start_func;
	}
	if (pitype != ULOGD_PLUGINSTANCE_SOURCE) {
		interp_func = PyObject_GetAttrString(user_mod, "interp");
		if (interp_func == NULL || !PyCallable_Check(interp_func)) {
			child_log(ULOGD_ERROR, "can not call %s.interp: %s\n",
				  modname, py_strerror(ebuf, ERRBUF_SIZE));
			goto dec_interp_func;
		}
	}
	signal_func = PyObject_GetAttrString(user_mod, "signal");
	if (signal_func == NULL || !PyCallable_Check(signal_func)) {
		child_log(ULOGD_ERROR, "can not call %s.signal: %s\n",
			  modname, py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_signal_func;
	}
	stop_func = PyObject_GetAttrString(user_mod, "stop");
	if (stop_func == NULL || !PyCallable_Check(stop_func)) {
		child_log(ULOGD_ERROR, "can not call %s.stop: %s\n",
			  modname, py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_stop_func;
	}

	/* a hacky way? exchange between python module */
	xcfunc = PyObject_GetAttrString(ulogd_mod, "_setsockfd");
	value = PyObject_CallFunction(xcfunc, "i", childfd);
	Py_DECREF(xcfunc);
	if (value == NULL || PyErr_Occurred())
		goto dec_value;
	Py_DECREF(value);

	return ULOGD_IRET_OK;

dec_value:
	Py_XDECREF(value);
dec_stop_func:
	Py_XDECREF(stop_func);
dec_signal_func:
	Py_XDECREF(signal_func);
dec_interp_func:
	Py_XDECREF(interp_func);
dec_start_func:
	Py_XDECREF(start_func);
dec_configure_func:
	Py_XDECREF(configure_func);
dec_source_pluginstance:
	Py_XDECREF(source_pluginstance);
dec_okeyset:
	Py_DECREF(okeyset);
dec_ikeyset:
	Py_XDECREF(ikeyset);
dec_okeylist:
	Py_DECREF(okeylist);
dec_ikeylist:
	Py_XDECREF(ikeylist);
dec_keylist:
	Py_DECREF(keylist);

	return ret;
}

static void py_child_undef_handler(int signum)
{
	child_log(ULOGD_ERROR, "receive unusal signal: %d\n", signum);
	/* seems to be required to SOCK_SEQPACKET to invalidate sockfd */
	shutdown(childfd, SHUT_RDWR);
	signal(signum, SIG_DFL);
	kill(getpid(), signum);
}

static void py_child_set_sighandler(void)
{
	signal(SIGBUS, py_child_undef_handler);
	signal(SIGFPE, py_child_undef_handler);
	signal(SIGILL, py_child_undef_handler);
	signal(SIGSEGV, py_child_undef_handler);
	signal(SIGABRT, py_child_undef_handler);
}

static int py_child_call_fd_callback(struct nlmsghdr *nlh, int *rc)
{
	struct py_ulogd_fd *ufd;
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	PyObject *what, *value;
	char ebuf[ERRBUF_SIZE + 1];

	*rc = ULOGD_IRET_ERR;
	what = Py_BuildValue("I", (unsigned int)mnl_attr_get_u32(nla));
	nla = mnl_attr_next(nla);
	ufd = (struct py_ulogd_fd *)*(void **)mnl_attr_get_payload(nla);
	value = PyObject_CallFunctionObjArgs(ufd->cb, ufd->file, what, ufd->data, NULL);
	Py_DECREF(what);
	if (PyErr_Occurred() || value == NULL) {
		child_log(ULOGD_ERROR, "fd callback returns: %p: %s\n",
			  value, py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_value;
	}
	if (!PyLong_Check(value)) {
		child_log(ULOGD_ERROR, "requires fd callback returning"
			  " an integer value\n");
		goto dec_value;
	}
	if (PyLong_AsLong(value) != 0)
		goto dec_value;
	Py_DECREF(value);
	*rc = ULOGD_IRET_OK;
	return ULOGD_IRET_OK;

dec_value:
	Py_XDECREF(value);
	return ULOGD_IRET_ERR;
}

static int py_child_call_timer_callback(struct nlmsghdr *nlh, int *rc)
{
	struct py_ulogd_timer *timer;
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	PyObject *value;
	char ebuf[ERRBUF_SIZE + 1];

	*rc = ULOGD_IRET_ERR;
	timer = (struct py_ulogd_timer *)*(void **)mnl_attr_get_payload(nla);
	value = PyObject_CallFunctionObjArgs(timer->cb, timer,
					     timer->data, NULL);
	if (PyErr_Occurred() || value == NULL) {
		child_log(ULOGD_ERROR, "timer callback returns: %p: %s\n",
			  value, py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_value;
	}
	if (!PyLong_Check(value)) {
		child_log(ULOGD_ERROR, "requires timer callback returning"
			  " an integer value\n");
		goto dec_value;
	}
	if (PyLong_AsLong(value) != 0)
		goto dec_value;
	Py_DECREF(value);
	*rc = ULOGD_IRET_OK;
	return ULOGD_IRET_OK;

dec_value:
	Py_XDECREF(value);
	return ULOGD_IRET_ERR;
}

/* send struct ulogd_key from child */
static int send_keylist(uint16_t msgtype, struct py_ulogd_keylist *klist)
{
	struct py_ulogd_key *pkey;
	char *databuf, *p;
	size_t datalen;

	if (klist->raw->num_keys == 0 && klist->raw->type == 0)
		return ULOGD_IRET_OK;

	if (klist->raw->num_keys > PY_KEYLIST_MAX_NUM) {
		child_log(ULOGD_ERROR, "exceeds max num keys: %d\n",
			  klist->raw->num_keys);
		return ULOGD_IRET_ERR;
	}

	/* alloc buf for sending keys */
	datalen = sizeof(struct ulogd_key) * klist->raw->num_keys;
	databuf = alloca(datalen);
	if (databuf == NULL) {
		child_log(ULOGD_ERROR, "allocate keys: %s\n", strerror(errno));
		return ULOGD_IRET_ERR;
	}

	/* send keyset.type and num_keys */
	py_child_sendargs(msgtype, 0, "II",
			  klist->raw->type, klist->raw->num_keys);

	/* send keys */
	if (klist->raw->num_keys == 0)
		return ULOGD_IRET_OK;

	p = databuf;
	llist_for_each_entry(pkey, &klist->list, list) {
		memcpy(p, pkey->raw, sizeof(struct ulogd_key));
		p += sizeof(struct ulogd_key);
	}
	py_child_sendargs(ULOGD_PY_RETURN_CONFIGURE_KEYS,
			  0, "y#", databuf, datalen);

	return ULOGD_IRET_OK;
}

/* child call - def configure(input, output) */
static int py_child_call_configure(int pitype)
{
	PyObject *value;
	char ebuf[ERRBUF_SIZE + 1];
	int ret = ULOGD_IRET_ERR;

	if (pitype == ULOGD_PLUGINSTANCE_SOURCE ) {
		value = PyObject_CallFunctionObjArgs(configure_func,
						     okeylist, NULL);
	} else {
		value = PyObject_CallFunctionObjArgs(configure_func,
						     ikeylist, okeylist, NULL);
	}
	if (PyErr_Occurred() || value == NULL) {
		child_log(ULOGD_ERROR, "configure() returns: %p: %s\n",
			  value, py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_value;
	}
	if (!PyLong_Check(value)) {
		child_log(ULOGD_ERROR, "requires python configure() returning"
			  " an integer value\n");
		goto dec_value;
	}
	if (PyLong_AsLong(value) != 0)
		goto dec_value;

	if (pitype != ULOGD_PLUGINSTANCE_SOURCE) {
		if (send_keylist(ULOGD_PY_RETURN_CONFIGURE_IKINFO,
				 ikeylist) != 0)
			goto dec_value;
	}
	if (send_keylist(ULOGD_PY_RETURN_CONFIGURE_OKINFO, okeylist) != 0)
		goto dec_value;
	ret = ULOGD_IRET_OK;

dec_value:
	Py_XDECREF(value);
	return ret;
}

/* child call - def start(input) */
static int py_child_call_start(struct ulogd_source_pluginstance *spi,
			       struct ulogd_keyset *input, int pitype)
{
	PyObject *value;
	char ebuf[ERRBUF_SIZE + 1];
	int ret = ULOGD_IRET_ERR;

	if (pitype == ULOGD_PLUGINSTANCE_SOURCE) {
		source_pluginstance->raw = spi;
		value = PyObject_CallFunctionObjArgs(start_func,
						     source_pluginstance, NULL);
	} else {
		ikeyset->raw = input;
		value = PyObject_CallFunctionObjArgs(start_func, ikeyset, NULL);
	}
	if (PyErr_Occurred() || value == NULL) {
		child_log(ULOGD_ERROR, "start() returns %p: %s\n",
			  value, py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_value;
	}
	if (!PyLong_Check(value)) {
		child_log(ULOGD_ERROR, "requires python start() returning"
			  " an integer value\n");
		goto dec_value;
	}
	if (PyLong_AsLong(value) == 0)
		ret = ULOGD_IRET_OK;

dec_value:
	Py_XDECREF(value);
	return ret;
}

/* child call - def interp(input, output) */
static int py_child_call_interp(struct nlmsghdr *nlh, int *rc)
{
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	struct ulogd_keyset *input, *output;
	PyObject *value;
	char ebuf[ERRBUF_SIZE + 1];
	int ret = ULOGD_IRET_ERR;

	*rc = ULOGD_IRET_ERR;
	/* set args */
	input = (struct ulogd_keyset *)*(void **)mnl_attr_get_payload(nla);
	ikeyset->raw = input;
	nla = mnl_attr_next(nla);
	output = (struct ulogd_keyset *)*(void **)mnl_attr_get_payload(nla);
	okeyset->raw = output;
	/* call - def interp(ikeyset, okeyset) */
	value = PyObject_CallFunctionObjArgs(interp_func,
					     ikeyset, okeyset, NULL);
	if (PyErr_Occurred() || value == NULL) {
		child_log(ULOGD_ERROR, "interp() returns %p: %s\n",
			  value, py_strerror(ebuf, ERRBUF_SIZE));
		goto dec_value;
	}
	if (!PyLong_Check(value)) {
		child_log(ULOGD_ERROR, "requires python interp() returning"
			  " an integer value\n");
		goto dec_value;
	}
	if (PyLong_AsLong(value) == 0)
		*rc = ULOGD_IRET_OK;
	ret = ULOGD_IRET_OK;

dec_value:
	Py_XDECREF(value);
	return ret;
}

/* child call - def stop()
 * it is a little bit tricky to adjust child_fn typedef */
__attribute__ ((noreturn))
static int py_child_call_stop(struct nlmsghdr *nlh, int *rc)
{
	PyObject *value;
	char ebuf[ERRBUF_SIZE + 1];
	int ret = ULOGD_IRET_ERR;

	*rc = ULOGD_IRET_ERR;
	value = PyObject_CallFunctionObjArgs(stop_func, NULL);
	if (PyErr_Occurred() || value == NULL) {
		child_log(ULOGD_ERROR, "stop() returns %p: %s\n",
			  value, py_strerror(ebuf, ERRBUF_SIZE));
		goto failure;
	}
	if (!PyLong_Check(value)) {
		child_log(ULOGD_ERROR, "requires python stop() returning"
			  " an integer value\n");
		goto failure;
	}
	if (PyLong_AsLong(value) == 0)
		ret = ULOGD_IRET_OK;

	py_child_sendargs(ULOGD_PY_RETURN_STOP, 0, "I", ret);
	py_child_exit(ret == ULOGD_IRET_OK ? EXIT_SUCCESS: EXIT_FAILURE, NULL);
	/* NOTREACHED */

failure:
	py_child_sendargs(ULOGD_PY_RETURN_STOP, 0, "I", ret);
	py_child_exit(EXIT_FAILURE, NULL);
	/* NOTREACHED */
}

/* child call - def signal(signo) */
static int py_child_call_signal(struct nlmsghdr *nlh, int *rc)
{
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	PyObject *signo, *value;
	char ebuf[ERRBUF_SIZE + 1];

	*rc = ULOGD_IRET_ERR;
	signo = Py_BuildValue("i", (int)mnl_attr_get_u32(nla));
	value = PyObject_CallFunctionObjArgs(signal_func, signo, NULL);
	if (PyErr_Occurred() || value == NULL) {
		child_log(ULOGD_ERROR, "error at signal(): %s\n",
			  py_strerror(ebuf, ERRBUF_SIZE));
		Py_XDECREF(value);
		return ULOGD_IRET_ERR;
	}
	Py_DECREF(value);
	*rc = ULOGD_IRET_OK;
	return ULOGD_IRET_OK;
}

static int py_child_append_path(char *apath)
{
	PyObject *sys_path, *str;
	char ebuf[ERRBUF_SIZE + 1];
	char *tok;

	sys_path = PySys_GetObject("path");
	if (sys_path == NULL) {
		child_log(ULOGD_ERROR, "could not get sys.path\n");
		return -1;
	}
	if (!PyList_Check(sys_path)) {
		child_log(ULOGD_ERROR, "sys.path is not a list\n");
		return -1;
	}

	while ((tok = strtok(apath, ":")) != NULL) {
		str = PyUnicode_FromString(tok);
		if (str == NULL) {
			child_log(ULOGD_ERROR, "%s\n",
				  py_strerror(ebuf, ERRBUF_SIZE));
			return -1;
		}
		if (PyList_Append(sys_path, str) < 0) {
			child_log(ULOGD_ERROR, "%s\n",
				  py_strerror(ebuf, ERRBUF_SIZE));
			Py_DECREF(str);
			return -1;
		}
		Py_DECREF(str);
		apath = NULL;
	}

	return 0;
}

/* child call python configure() and exit */
__attribute__ ((noreturn))
static void py_child_configure(int sockfd, char *id,
			       char *modname, char *apath, int pitype)
{
	childfd = sockfd;
	Py_Initialize();

	if (apath != NULL && py_child_append_path(apath) < 0) {
		child_log(ULOGD_ERROR, "%s could not append sys.path: %s\n",
			  id, apath);
		py_child_sendargs(ULOGD_PY_RETURN_CONFIGURE,
				  0, "I", ULOGD_IRET_ERR);
		py_child_exit(EXIT_FAILURE, NULL);
		/* NOTREACHED */
	}

	if (prepare_pyobj(modname, pitype) != 0) {
		child_log(ULOGD_ERROR, "failed to %s.prepare_pyobj()\n", id);
		py_child_sendargs(ULOGD_PY_RETURN_CONFIGURE,
				   0, "I", ULOGD_IRET_ERR);
		py_child_exit(EXIT_FAILURE, NULL);
		/* NOTREACHED */
	}
	if (py_child_call_configure(pitype) != 0) {
		child_log(ULOGD_ERROR, "failed to child"
			  " %s:%s.configure()\n", id, modname);
		py_child_sendargs(ULOGD_PY_RETURN_CONFIGURE,
				  0, "I", ULOGD_IRET_ERR);
		py_child_exit(EXIT_FAILURE, NULL);
		/* NOTREACHED */
	}
	py_child_sendargs(ULOGD_PY_RETURN_CONFIGURE, 0, "I", ULOGD_IRET_OK);
	py_child_exit(EXIT_SUCCESS, NULL);
	/* NOTREACHED */
}

typedef int (*child_fn)(struct nlmsghdr *, int *rc);
static struct child_func {
	child_fn fn;
	int ret_type;
} child_start_ftbl[] = {
	[ULOGD_PY_CALL_INTERP]		= { py_child_call_interp,
					    ULOGD_PY_RETURN_INTERP },
	[ULOGD_PY_CALL_STOP]		= { py_child_call_stop,
					    ULOGD_PY_RETURN_STOP },
	[ULOGD_PY_CALL_SIGNAL]		= { py_child_call_signal,
					    ULOGD_PY_RETURN_SIGNAL},
	[ULOGD_PY_CALL_FD_CALLBACK]	= { py_child_call_fd_callback,
					    ULOGD_PY_RETURN_FD_CALLBACK },
	[ULOGD_PY_CALL_TIMER_CALLBACK]	= { py_child_call_timer_callback,
					    ULOGD_PY_RETURN_TIMER_CALLBACK },
};

/* child call python start() and wait message until receiving STOP */
__attribute__ ((noreturn))
static void py_child_start(char *id, struct ulogd_keyset *input,
			   int sockfd, char *modname, char *apath,
			   int pitype, struct ulogd_source_pluginstance *spi)
{
	int ret = ULOGD_IRET_ERR, rc = ULOGD_IRET_ERR;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct child_func cfn;

	childfd = sockfd;
	Py_Initialize();

	if (apath != NULL && py_child_append_path(apath) < 0) {
		child_log(ULOGD_ERROR, "%s could not append sys.path: %s\n",
			  id, apath);
		py_child_sendargs(ULOGD_PY_RETURN_START,
				  0, "I", ULOGD_IRET_ERR);
		py_child_exit(EXIT_FAILURE, NULL);
		/* NOTREACHED */
	}

	if (prepare_pyobj(modname, pitype) != 0) {
		child_log(ULOGD_ERROR, "failed to %s.prepare_pyobj()\n", id);
		py_child_sendargs(ULOGD_PY_RETURN_START,
				   0, "I", ULOGD_IRET_ERR);
		py_child_exit(EXIT_FAILURE, NULL);
		/* NOTREACHED */
	}
	ret = py_child_call_start(spi, input, pitype);
	if (ret != 0) {
		child_log(ULOGD_ERROR, "failed to child %s:%s.start()\n",
			  id, modname);
		py_child_sendargs(ULOGD_PY_RETURN_START,
				  0, "I", ULOGD_IRET_ERR);
		py_child_exit(EXIT_FAILURE, NULL);
		/* NOTREACHED */
	}
	py_child_sendargs(ULOGD_PY_RETURN_START, 0, "I", ULOGD_IRET_OK);

	while (1) {
		py_child_recv(buf, sizeof(buf), NULL);
		if (nlh->nlmsg_type > ULOGD_PY_CALL_TIMER_CALLBACK) {
			child_log(ULOGD_ERROR, "child receive unknown msgtype:"
				  " %d\n", nlh->nlmsg_type);
			continue;
		}
		cfn = child_start_ftbl[nlh->nlmsg_type];
		if (cfn.fn == NULL) {
			child_log(ULOGD_ERROR, "child receive unknown msgtype:"
				  " %d\n", nlh->nlmsg_type);
			continue;
		}
		if (cfn.fn(nlh, &rc) != 0)
			child_log(ULOGD_ERROR, "child %s returns error\n",
				  _pyulogd_nl_typestr[nlh->nlmsg_type]);
		py_child_sendargs(cfn.ret_type, 0, "I", rc);
	}
}

static int py_parent_fd_callback(int fd, unsigned int what, void *data)
{
	struct py_ulogd_cbdata *cbdata = data;
	struct py_priv *priv = cbdata->priv;

	if (py_parent_sendargs(priv, ULOGD_PY_CALL_FD_CALLBACK,
			       0, "Ip", what, cbdata->pydata) != 0) {
		ulogd_log(ULOGD_ERROR, "parent_fd_callback sendmsg\n");
		return ULOGD_IRET_ERR;
	}

	return py_parent_session(priv, ULOGD_PY_RETURN_FD_CALLBACK);
}

static int py_parent_register_fd(struct py_priv *priv, struct nlmsghdr *nlh,
				 int fd)
{
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	struct py_ulogd_cbdata *cbdata;
	int ret;

	cbdata = calloc(1, sizeof(struct py_ulogd_cbdata));
	if (cbdata == NULL) {
		ulogd_log(ULOGD_ERROR, "could not alloc: %s\n",
			  strerror(errno));
		return ULOGD_IRET_ERR;
	}
	cbdata->ufd.when = (unsigned int)mnl_attr_get_u32(nla);
	cbdata->ufd.fd = fd;
	cbdata->ufd.cb = py_parent_fd_callback;

	nla = mnl_attr_next(nla);
	cbdata->pydata = (uintptr_t)*(void **)mnl_attr_get_payload(nla);
	cbdata->priv = priv;
	cbdata->ufd.data = cbdata;

	ret = ulogd_register_fd(&cbdata->ufd);
	if (py_parent_sendargs(priv, ULOGD_PY_RETURN_REGISTER_FD,
			       0, "I", ret) != 0) {
		ulogd_log(ULOGD_ERROR, "parent_register_fd sendmsg\n");
		return ULOGD_IRET_ERR;
	}

	if (ret == 0)
		llist_add(&cbdata->list, &py_ulogd_cbdatas);
	return ret;
}

static int py_parent_unregister_fd(struct py_priv *priv,
				   struct nlmsghdr *nlh, int fd)
{
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	struct py_ulogd_cbdata *cbdata, *tmp;
	uintptr_t data;
	int ret = ULOGD_IRET_ERR;

	data = (uintptr_t)*(void **)mnl_attr_get_payload(nla);
	llist_for_each_entry_safe(cbdata, tmp, &py_ulogd_cbdatas, list) {
		if (data == cbdata->pydata) {
			ulogd_unregister_fd(&cbdata->ufd);
			llist_del(&cbdata->list);
			free(cbdata);
			ret = ULOGD_IRET_OK;
			break;
		}
	}

	if (ret != ULOGD_IRET_OK)
		ulogd_log(ULOGD_ERROR, "could not found ulogd_fd\n");
	if (py_parent_sendargs(priv, ULOGD_PY_RETURN_UNREGISTER_FD,
			       0, "I", ret) != 0) {
		ulogd_log(ULOGD_ERROR, "parent_unregister_fd sendmsg\n");
		return ULOGD_IRET_ERR;
	}

	return ret;
}

static void py_parent_timer_callback(struct ulogd_timer *a, void *data)
{
	struct py_ulogd_cbdata *cbdata = data;
	struct py_priv *priv = cbdata->priv;

	if (py_parent_sendargs(priv, ULOGD_PY_CALL_TIMER_CALLBACK,
			       0, "p", cbdata->pydata) != 0) {
		ulogd_log(ULOGD_ERROR, "parent_timer_callback sendmsg\n");
		return;
	}

	py_parent_session(priv, ULOGD_PY_RETURN_TIMER_CALLBACK);
}

static int py_parent_init_timer(struct py_priv *priv,
				struct nlmsghdr *nlh, int fd)
{
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	struct py_ulogd_cbdata *cbdata;

	cbdata = calloc(1, sizeof(struct py_ulogd_cbdata));
	if (cbdata == NULL) {
		ulogd_log(ULOGD_ERROR, "could not alloc: %s\n",
			  strerror(errno));
		return ULOGD_IRET_ERR;
	}
	cbdata->pydata = (uintptr_t)*(void **)mnl_attr_get_payload(nla);
	cbdata->priv = priv;
	ulogd_init_timer(&cbdata->timer, cbdata, py_parent_timer_callback);

	if (py_parent_sendargs(priv, ULOGD_PY_RETURN_INIT_TIMER,
			       0, "I", ULOGD_IRET_OK) != 0) {
		ulogd_log(ULOGD_ERROR, "py_parent_init_timer sendmsg\n");
		return ULOGD_IRET_ERR;
	}
	llist_add(&cbdata->list, &py_ulogd_cbdatas);

	return ULOGD_IRET_OK;
}

static struct ulogd_timer *find_timer(struct py_priv *priv, uintptr_t cookie)
{
	struct py_ulogd_cbdata *cbdata;

	llist_for_each_entry(cbdata, &py_ulogd_cbdatas, list) {
		if (cbdata->priv == priv && cbdata->pydata == cookie)
			return &cbdata->timer;
	}
	return NULL;
}

static int py_parent_add_timer(struct py_priv *priv,
			       struct nlmsghdr *nlh, int fd)
{
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	struct ulogd_timer *timer = NULL;
	unsigned long sc;
	uintptr_t pydata;
	int ret = ULOGD_IRET_ERR;

	sc = (unsigned long)mnl_attr_get_u32(nla);
	nla = mnl_attr_next(nla);
	pydata = (uintptr_t)*(void **)mnl_attr_get_payload(nla);
	timer = find_timer(priv, pydata);
	if (timer != NULL) {
		ulogd_add_timer(timer, sc);
		ret = ULOGD_IRET_OK;
	} else {
		ulogd_log(ULOGD_ERROR, "could not found timer: %p\n", pydata);
	}
	if (py_parent_sendargs(priv, ULOGD_PY_RETURN_ADD_TIMER,
			       0, "I", ret) != 0) {
		ulogd_log(ULOGD_ERROR, "py_parent_add_timer sendmsg\n");
		ret = ULOGD_IRET_ERR;
	}

	return ret;
}

static int py_parent_del_timer(struct py_priv *priv,
			       struct nlmsghdr *nlh, int fd)
{
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	struct ulogd_timer *timer = NULL;
	uintptr_t pydata;
	int ret = ULOGD_IRET_ERR;

	pydata = (uintptr_t)*(void **)mnl_attr_get_payload(nla);
	timer = find_timer(priv, pydata);
	if (timer != NULL) {
		ulogd_del_timer(timer);
		ret = ULOGD_IRET_OK;
	}

	if (py_parent_sendargs(priv, ULOGD_PY_RETURN_DEL_TIMER,
			       0, "I", ret) != 0) {
		ulogd_log(ULOGD_ERROR, "py_parent_del_timer sendmsg\n");
		ret = ULOGD_IRET_ERR;
	}

	return ret;
}

static int py_parent_propagate_results(struct py_priv *priv,
				       struct nlmsghdr *nlh, int fd)
{
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	struct ulogd_keyset *okeyset;
	int ret;

	okeyset = (struct ulogd_keyset *)*(void **)mnl_attr_get_payload(nla);
	ret = ulogd_propagate_results(okeyset);
	if (py_parent_sendargs(priv, ULOGD_PY_RETURN_PROPAGATE_RESULTS,
			       0, "I", ret) != 0) {
		ulogd_log(ULOGD_ERROR, "parent_propagate_results sendmsg\n");
		return ULOGD_IRET_ERR;
	}

	return ULOGD_IRET_OK;
}

static int py_parent_get_output_keyset(struct py_priv *priv,
				       struct nlmsghdr *nlh, int fd)
{
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	struct ulogd_source_pluginstance *spi;
	struct ulogd_keyset *output;

	spi = (struct ulogd_source_pluginstance *)
		*(void **)mnl_attr_get_payload(nla);
	output = ulogd_get_output_keyset(spi);
	if (py_parent_sendargs(priv, ULOGD_PY_RETURN_GET_OUTPUT_KEYSET,
			       0, "p", output) != 0) {
		ulogd_log(ULOGD_ERROR, "parent_get_output_keyset sendmsg\n");
		return ULOGD_IRET_ERR;
	}

	return ULOGD_IRET_OK;
}

typedef int (*parent_fn)(struct py_priv *, struct nlmsghdr *, int);
static parent_fn parent_session_ftbl[] = {
	[ULOGD_PY_CALL_LOG]			= py_parent_log,
	[ULOGD_PY_CALL_REGISTER_FD]		= py_parent_register_fd,
	[ULOGD_PY_CALL_UNREGISTER_FD]		= py_parent_unregister_fd,
	[ULOGD_PY_CALL_INIT_TIMER]		= py_parent_init_timer,
	[ULOGD_PY_CALL_ADD_TIMER]		= py_parent_add_timer,
	[ULOGD_PY_CALL_DEL_TIMER]		= py_parent_del_timer,
	[ULOGD_PY_CALL_PROPAGATE_RESULTS]	= py_parent_propagate_results,
	[ULOGD_PY_CALL_GET_OUTPUT_KEYSET]	= py_parent_get_output_keyset,
};

/* handle message until receiving specified by fin_type */
static int py_parent_session(struct py_priv *priv, uint16_t fin_type)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct nlattr *nla;
	parent_fn fn;
	int fd;

	while (1) {
		if (py_parent_recv(priv, buf, sizeof(buf), &fd) < 0)
			return ULOGD_IRET_ERR;

		if (nlh->nlmsg_type == fin_type) {
			nla = mnl_nlmsg_get_payload(nlh);
			if (mnl_attr_get_u32(nla) == 0)
				return ULOGD_IRET_OK;
			ulogd_log(ULOGD_ERROR, "%s returns error\n",
				  _pyulogd_nl_typestr[nlh->nlmsg_type]);
			return ULOGD_IRET_ERR;
		}
		if (nlh->nlmsg_type > ULOGD_PY_CALL_GET_OUTPUT_KEYSET
		    || (fn = parent_session_ftbl[nlh->nlmsg_type]) == NULL) {
			ulogd_log(ULOGD_ERROR,
				  "parent receive unknown msgtype: %d\n",
				  nlh->nlmsg_type);
			return ULOGD_IRET_ERR;
		}
		/* XXX: non-source pluginstance can call...?
		 * if (source_pluginstance == NULL
		 *     && nlh->nlmsg_type > ULOGD_PY_CALL_DEL_TIMER) */
		if (fn(priv, nlh, fd) != 0) {
			ulogd_log(ULOGD_ERROR, "parent %s returns error\n",
				  _pyulogd_nl_typestr[nlh->nlmsg_type]);
			return ULOGD_IRET_ERR;
		}
	}
	return ULOGD_IRET_ERR;
}

/* parent receiption of struct ulogd_key, counterpart of send_keylist() */
static int recv_keylist(struct nlmsghdr *nlh, struct ulogd_keyset *dst)
{
	struct nlattr *nla;

	if (dst->num_keys == 0)
		return ULOGD_IRET_OK;

	dst->keys = calloc(dst->num_keys, sizeof(struct ulogd_key));
	if (dst->keys == NULL)
		return ULOGD_IRET_ERR;

	nla = mnl_nlmsg_get_payload(nlh);
	if (mnl_attr_get_payload_len(nla)
	    != sizeof(struct ulogd_key) * dst->num_keys) {
		ulogd_log(ULOGD_ERROR, "expected nla_len: %d but got: %d\n",
			  sizeof(struct ulogd_key) * dst->num_keys,
			  mnl_attr_get_payload_len(nla));
		goto free_keys;
	}
	memcpy(dst->keys, mnl_attr_get_payload(nla),
	       mnl_attr_get_payload_len(nla));

	return ULOGD_IRET_OK;

free_keys:
	free(dst->keys);
	dst->keys = NULL;
	return ULOGD_IRET_ERR;
}

static struct ulogd_keyset *alloc_keyset(struct ulogd_keyset **keyset)
{
	if (*keyset != NULL)
		free(keyset);
	*keyset = calloc(1, sizeof(struct ulogd_keyset));
	return *keyset;
}

static int py_parent_configure(struct py_priv *priv,
			       struct ulogd_keyset **input_config,
			       struct ulogd_keyset **output_config)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct nlattr *nla;
	struct ulogd_keyset *rcvkset = NULL;

	/* XXX: not free input/output config on error */
	while (1) {
		if (py_parent_recv(priv, buf, sizeof(buf), NULL) < 0)
			return ULOGD_IRET_ERR;

		nla = mnl_nlmsg_get_payload(nlh);
		switch (nlh->nlmsg_type) {
		case ULOGD_PY_CALL_LOG:
			py_parent_log(priv, nlh, 0);
			break;
		case ULOGD_PY_RETURN_CONFIGURE:
			if (mnl_attr_get_u32(nla) != 0) {
				py_parent_waitpid(priv, 0);
				return ULOGD_IRET_ERR;
			}
			return py_parent_waitpid(priv, 0);
		case ULOGD_PY_RETURN_CONFIGURE_IKINFO:
			if (input_config == NULL) {
				/* source pluginstance */
				ulogd_log(ULOGD_ERROR, "source pluginstance"
					  "has no input keyset\n");
				return ULOGD_IRET_ERR;
			}
			rcvkset = alloc_keyset(input_config);
			if (rcvkset == NULL)
				return ULOGD_IRET_ERR;
			rcvkset->type = (unsigned int)mnl_attr_get_u32(nla);
			nla = mnl_attr_next(nla);
			rcvkset->num_keys = (unsigned int)mnl_attr_get_u32(nla);
			break;
		case ULOGD_PY_RETURN_CONFIGURE_OKINFO:
			rcvkset = alloc_keyset(output_config);
			if (rcvkset == NULL)
				return ULOGD_IRET_ERR;
			rcvkset->type = (unsigned int)mnl_attr_get_u32(nla);
			nla = mnl_attr_next(nla);
			rcvkset->num_keys = (unsigned int)mnl_attr_get_u32(nla);
			break;
		case ULOGD_PY_RETURN_CONFIGURE_KEYS:
			if (rcvkset == NULL) {
				ulogd_log(ULOGD_ERROR,
					  "unexpected msg type: %d\n",
					  nlh->nlmsg_type);
				return ULOGD_IRET_ERR;
			}
			if (recv_keylist(nlh, rcvkset) != 0) {
				return ULOGD_IRET_ERR;
			}
			rcvkset = NULL;
			break;
		default:
			ulogd_log(ULOGD_ERROR, "unknown config message: %d\n",
				  nlh->nlmsg_type);
			return ULOGD_IRET_ERR;
		}
	}
	return ULOGD_IRET_ERR;
}

static int py_configure(struct py_priv *priv, char *id, int pitype,
			struct config_keyset *config_kset,
			struct ulogd_keyset **input_config,
			struct ulogd_keyset **output_config)
{
	char *modname;
	int sv[2], ret = ULOGD_IRET_ERR;

	if (config_parse_file(id, config_kset) < 0)
		return ret;
	modname = modname_ce(config_kset);
	if (modname == NULL) {
		ulogd_log(ULOGD_ERROR, "no py_module specified\n");
		return ret;
	}

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == -1) {
		ulogd_log(ULOGD_ERROR, "socketpair: %s\n", strerror(errno));
		return ret;
	}

	priv->sockfd = sv[0];
	priv->childpid = fork();
	switch (priv->childpid) {
	case -1:
		ulogd_log(ULOGD_ERROR, "fork: %s\n", strerror(errno));
		return ret;
	case 0:
		py_child_set_sighandler();
		py_child_configure(sv[1], id, modname,
				   path_append_ce(config_kset), pitype);
		/* NOTREACHED */
		break;
	default:
		ret = py_parent_configure(priv,
					  input_config, output_config);
		break;
	}

	return ret;
}

static int py_source_configure(struct ulogd_source_pluginstance *spi)
{
	struct py_priv *priv = (struct py_priv *)&spi->private;

	return py_configure(priv, spi->id, ULOGD_PLUGINSTANCE_SOURCE,
			    spi->config_kset, NULL, &spi->output_config);
}

static int py_flow_configure(struct ulogd_pluginstance *upi)
{
	struct py_priv *priv = (struct py_priv *)&upi->private;

	return py_configure(priv, upi->id, ULOGD_PLUGINSTANCE_FILTER,
			    upi->config_kset,
			    &upi->input_config, &upi->output_config);
}

static int py_start(struct py_priv *priv, char *id, struct ulogd_keyset *input,
		    struct config_keyset *config_kset, int pitype,
		    struct ulogd_source_pluginstance *spi)
{
	char *modname;
	int sv[2], ret = ULOGD_IRET_ERR;

	modname = modname_ce(config_kset);
	if (modname == NULL) {
		ulogd_log(ULOGD_ERROR, "no py_module specified\n");
		return ret;
	}

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == -1) {
		ulogd_log(ULOGD_ERROR, "socketpair: %s\n", strerror(errno));
		return ret;
	}

	priv->sockfd = sv[0];
	priv->childpid = fork();
	switch (priv->childpid) {
	case -1:
		ulogd_log(ULOGD_ERROR, "fork: %s\n", strerror(errno));
		return ret;
	case 0:
		py_child_set_sighandler();
		py_child_start(id, input, sv[1], modname,
			       path_append_ce(config_kset), pitype, spi);
		/* NOTREACHED */
		break;
	default:
		if (py_parent_session(priv, ULOGD_PY_RETURN_START) != 0) {
			py_parent_waitpid(priv, 0);
		} else {
			ulogd_log(ULOGD_INFO, "%s(%s) started pid: %d\n",
				  id, modname, priv->childpid);
			ret = ULOGD_IRET_OK;
		}
		break;
	}
	return ret;
}

static int py_flow_start(struct ulogd_pluginstance *pi,
			 struct ulogd_keyset *input)
{
	struct py_priv *priv = (struct py_priv *)&pi->private;

	return py_start(priv, pi->id, input, pi->config_kset,
			ULOGD_PLUGINSTANCE_FILTER, NULL);
}

static int py_source_start(struct ulogd_source_pluginstance *spi)
{
	struct py_priv *priv = (struct py_priv *)&spi->private;

	return py_start(priv, spi->id, NULL, spi->config_kset,
			ULOGD_PLUGINSTANCE_SOURCE, spi);
}


static int py_stop(char *id, struct py_priv *priv)
{
	int ret;

	if (priv->childpid == 0) {
		ulogd_log(ULOGD_ERROR, "%s no child running\n", id);
		return ULOGD_IRET_ERR;
	}

	if (py_parent_sendargs(priv, ULOGD_PY_CALL_STOP, 0, NULL) != 0) {
		ulogd_log(ULOGD_ERROR, "py_stop sendmsg\n");
		return ULOGD_IRET_ERR;
	}

	ret = py_parent_session(priv, ULOGD_PY_RETURN_STOP);
	ret |= py_parent_waitpid(priv, 0);
	return ret;
}

static int py_flow_stop(struct ulogd_pluginstance *upi)
{
	struct py_priv *priv = (struct py_priv *)&upi->private;
	return py_stop(upi->id, priv);
}

static int py_source_stop(struct ulogd_source_pluginstance *spi)
{
	struct py_priv *priv = (struct py_priv *)&spi->private;
	return py_stop(spi->id, priv);
}


static int py_flow_interp(struct ulogd_pluginstance *upi,
			  struct ulogd_keyset *input,
			  struct ulogd_keyset *output)
{
	struct py_priv *priv = (struct py_priv *)&upi->private;

	if (priv->childpid == 0) {
		ulogd_log(ULOGD_ERROR, "%s no child running\n", upi->id);
		return ULOGD_IRET_ERR;
	}

	if (py_parent_sendargs(priv, ULOGD_PY_CALL_INTERP,
			       0, "pp", input, output) != 0) {
		ulogd_log(ULOGD_ERROR, "py_interp sendmsg\n");
		return ULOGD_IRET_ERR;
	}

	return py_parent_session(priv, ULOGD_PY_RETURN_INTERP);
}

static void py_signal(struct py_priv *priv, char *id, int signal)
{
	if (priv->childpid == 0) {
		ulogd_log(ULOGD_ERROR, "%s no child running\n", id);
	}

	if (py_parent_sendargs(priv, ULOGD_PY_CALL_SIGNAL,
			       0, "I", signal) != 0) {
		ulogd_log(ULOGD_ERROR, "py_signal sendmsg\n");
		return;
	}

	py_parent_session(priv, ULOGD_PY_RETURN_SIGNAL);
}

static void py_flow_signal(struct ulogd_pluginstance *upi, int signal)
{
	struct py_priv *priv = (struct py_priv *)&upi->private;
	return py_signal(priv, upi->id, signal);
}

static void py_source_signal(struct ulogd_source_pluginstance *spi, int signal)
{
	struct py_priv *priv = (struct py_priv *)&spi->private;
	return py_signal(priv, spi->id, signal);
}


static struct ulogd_plugin py_plugin = {
	.name = "PYTHON",
	/* .input and .output should be specified by configure() */
	.configure	= &py_flow_configure,
	.interp		= &py_flow_interp,
	.start		= &py_flow_start,
	.stop		= &py_flow_stop,
	.signal		= &py_flow_signal,
	.config_kset	= &py_kset,
	.priv_size	= sizeof(struct py_priv),
	.version	= VERSION,
};

static struct ulogd_source_plugin py_source_plugin = {
	.name = "PYTHON",
	/* .input and .output should be specified by configure() */
	.configure	= &py_source_configure,
	.start		= &py_source_start,
	.stop		= &py_source_stop,
	.signal		= &py_source_signal,
	.config_kset	= &py_kset,
	.priv_size	= sizeof(struct py_priv),
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&py_plugin);
	ulogd_register_source_plugin(&py_source_plugin);
}
