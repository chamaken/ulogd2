/* ulogd_pyobj.c
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
#include <Python.h>
#include "structmember.h"

#include <stdint.h>
#include <libmnl/libmnl.h>

#include <ulogd/ulogd.h>
#include <ulogd/linuxlist.h>

#include "ulogd_pyobj.h"

extern int childfd;
extern char *_pyulogd_nl_typestr[];

static PyObject *py_ulogd_set_childfd(PyObject *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, "i", &childfd))
		return NULL;
	Py_RETURN_NONE;
}

static PyMethodDef py_ulogd_methods[] = {
	{"_setsockfd", py_ulogd_set_childfd, METH_VARARGS,
	 "set sockfd to communicate with parent"},
	{NULL, NULL, 0, NULL},
};

/****
 * struct ulogd_key
 */
static PyObject *
py_ulogd_keyinfo_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct py_ulogd_key *self;

	self = (struct py_ulogd_key *)type->tp_alloc(type, 0);
	if (self == NULL)
		return NULL;
	self->raw = calloc(1, sizeof(struct ulogd_key));
	if (self->raw == NULL) {
		free(self);
		return NULL;
	}

	return (PyObject *)self;
}
static void py_ulogd_keyinfo_dealloc(struct py_ulogd_key *self)
{
	free(self->raw);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int py_ulogd_keyinfo_init(struct py_ulogd_key *self,
				 PyObject *args, PyObject *kwds)
{
	long len = 0, type = 0, flags = 0,
		ipfix_vendor = 0, ipfix_field_id = 0;
	char *name = NULL, *cim_name = NULL;
	struct ulogd_key *key = self->raw;
	static char *kwlist[] = {"name", "len", "type", "flags", "ipfix_vendor",
				 "ipfix_field_id", "cim_name", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|llllls", kwlist,
					 &name, &len, &type, &flags,
					 &ipfix_vendor, &ipfix_field_id,
					 &cim_name))
		return -1;

	if (name != NULL) {
		strncpy(self->raw->name, name, ULOGD_MAX_KEYLEN);
		self->raw->name[ULOGD_MAX_KEYLEN] = '\0';
	}
	if (len < 0 || len > UINT32_MAX) {
		PyErr_SetString(PyExc_AttributeError, "uint32_t len");
		return -1;
	}
	key->len = len;
	if (type < 0 || type > UINT16_MAX) {
		PyErr_SetString(PyExc_AttributeError, "uint16_t type");
		return -1;
	}
	key->type = type;
	if (flags < 0 || flags > UINT16_MAX) {
		PyErr_SetString(PyExc_AttributeError, "uint16_t flags");
		return -1;
	}
	key->flags = flags;
	if (ipfix_vendor < 0 || ipfix_vendor > UINT32_MAX) {
		PyErr_SetString(PyExc_AttributeError, "uint32_t ipfix.vendor");
		return -1;
	}
	key->ipfix.vendor = ipfix_vendor;
	if (ipfix_field_id < 0 || ipfix_field_id > UINT32_MAX) {
		PyErr_SetString(PyExc_AttributeError, "uint32_t ipfix.field_id");
		return -1;
	}
	key->ipfix.field_id = ipfix_field_id;
	if (cim_name != NULL) {
		strncpy(self->raw->cim_name, cim_name, ULOGD_MAX_KEYLEN);
		self->raw->cim_name[ULOGD_MAX_KEYLEN] = '\0';
	}

	return 0;
}

#define UINT_KEY_GETSET(_objtype, _name, _type, _max)	\
static PyObject * \
_objtype ## _get ## _name(struct _objtype *self, void *closure)\
{\
	return Py_BuildValue("I", self->raw->_name);\
}\
static int \
_objtype ## _set ## _name(struct _objtype *self, PyObject *value, void *closure)\
{\
	long _name;\
	if (value == NULL) {\
		PyErr_SetString(PyExc_TypeError, "cannot delete the " #_name "	attribute");\
		return -1;\
	}\
	if (!PyLong_Check(value)) {\
		PyErr_SetString(PyExc_TypeError, #_type " " #_name);\
		return -1;\
	}\
	_name = PyLong_AsLong(value);\
	if (_name < 0 || _name > _max) {\
		PyErr_SetString(PyExc_TypeError, #_type " " #_name);\
		return -1;\
	}\
	self->raw->_name = (_type)_name;\
	return 0;\
}
UINT_KEY_GETSET(py_ulogd_key, len, uint32_t, UINT32_MAX)
UINT_KEY_GETSET(py_ulogd_key, type, uint16_t, UINT16_MAX)
UINT_KEY_GETSET(py_ulogd_key, flags, uint16_t, UINT16_MAX)

#define STRING_KEY_GETSET(_name, _maxlen) \
static PyObject * \
py_ulogd_key_get##_name(struct py_ulogd_key *self, void *closure)\
{\
	return Py_BuildValue("s", self->raw->_name);\
}\
static int \
py_ulogd_key_set##_name(struct py_ulogd_key *self, PyObject *value, void *closure)\
{\
	char * _name;\
	PyObject *tmp; \
	if (value == NULL) {\
		PyErr_SetString(PyExc_TypeError,\
				"cannot delete the " #_name "	attribute"); \
		return -1;\
	}\
	if (!PyUnicode_Check(value)) {\
		PyErr_SetString(PyExc_TypeError, #_name " must be a string");\
		return -1;\
	}\
	/* tmp = PyUnicode_AsUTF8AndSize(value, &size); */	\
	tmp = PyUnicode_AsASCIIString(value);\
	_name = PyBytes_AsString(tmp);\
	if (strlen(_name) > _maxlen) {				\
		PyErr_Format(PyExc_TypeError,\
			     "length of " #_name " must be less than: %d", _maxlen); \
		return -1;\
	}\
	strncpy(self->raw->_name, _name, _maxlen); \
	self->raw->_name[_maxlen] = '\0'; \
	return 0;\
}
STRING_KEY_GETSET(name, ULOGD_MAX_KEYLEN)
STRING_KEY_GETSET(cim_name, ULOGD_MAX_KEYLEN)

static PyObject *
py_ulogd_key_getipfix_vendor(struct py_ulogd_key *self, void *closure)
{
	return Py_BuildValue("I", self->raw->ipfix.vendor);
}
static int
py_ulogd_key_setipfix_vendor(struct py_ulogd_key *self,
				 PyObject *value, void *closure)
{
	long ipfix_vendor;
	if (value == NULL) {
		PyErr_SetString(PyExc_TypeError,
				"cannot delete the ipfix_vendor attribute");
		return -1;
	}
	if (!PyLong_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "uint32_t ipfix_vendor");
		return -1;
	}
	ipfix_vendor = PyLong_AsLong(value);
	if (ipfix_vendor < 0 || ipfix_vendor > UINT32_MAX) {
		PyErr_SetString(PyExc_TypeError, "uint32_t ipfix_vendor");
		return -1;
	}
	self->raw->ipfix.vendor = (uint32_t)ipfix_vendor;
	return 0;
}
static PyObject *
py_ulogd_key_getipfix_field_id(struct py_ulogd_key *self, void *closure)
{
	return Py_BuildValue("I", self->raw->ipfix.field_id);
}
static int
py_ulogd_key_setipfix_field_id(struct py_ulogd_key *self,
				   PyObject *value, void *closure)
{
	long ipfix_field_id;
	if (value == NULL) {
		PyErr_SetString(PyExc_TypeError,
				"cannot delete the ipfix_field_id attribute");
		return -1;
	}
	if (!PyLong_Check(value)) {
		PyErr_SetString(PyExc_TypeError, "uint16_t ipfix_field_id");
		return -1;
	}
	ipfix_field_id= PyLong_AsLong(value);
	if (ipfix_field_id < 0 || ipfix_field_id > UINT16_MAX) {
		PyErr_SetString(PyExc_TypeError, "uint16_t ipfix_field_id");
		return -1;
	}
	self->raw->ipfix.field_id = (uint16_t)ipfix_field_id;
	return 0;
}

static PyGetSetDef py_ulogd_keyinfo_getseters[] = {
	{
		"len",
		(getter)py_ulogd_key_getlen,
		(setter)py_ulogd_key_setlen,
		"struct ulogd_key. uint32_t len",
		NULL
	},
	{
		"type",
		(getter)py_ulogd_key_gettype,
		(setter)py_ulogd_key_settype,
		"struct ulogd_key. uint16_t type",
		NULL
	},
	{
		"flags",
		(getter)py_ulogd_key_getflags,
		(setter)py_ulogd_key_setflags,
		"struct ulogd_key. uint16_t flags",
		NULL
	},
	{
		"name",
		(getter)py_ulogd_key_getname,
		(setter)py_ulogd_key_setname,
		"struct ulogd_key. char name[ULOGD_MAX_KEYLEN+1]",
		NULL
	},
	{
		"cim_name",
		(getter)py_ulogd_key_getcim_name,
		(setter)py_ulogd_key_setcim_name,
		"struct ulogd_key. char cim_name[ULOGD_MAX_KEYLEN+1]",
		NULL
	},
	{
		"ipfix_vendor",
		(getter)py_ulogd_key_getipfix_vendor,
		(setter)py_ulogd_key_setipfix_vendor,
		"struct ulogd_key. uint32_t ipfix.vendor",
		NULL
	},
	{
		"ipfix_field_id",
		(getter)py_ulogd_key_getipfix_field_id,
		(setter)py_ulogd_key_setipfix_field_id,
		"struct ulogd_key. uint16_t ipfix.field_id",
		NULL
	},
	{NULL},
};

static PyTypeObject py_ulogd_keyinfo_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "ulogd.Keyinfo",
	.tp_basicsize	= sizeof(struct py_ulogd_key),
	.tp_new		= py_ulogd_keyinfo_new,
	.tp_dealloc	= (destructor)py_ulogd_keyinfo_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct ulogd_key meta info",
	.tp_getset	= py_ulogd_keyinfo_getseters,
	.tp_init	= (initproc)py_ulogd_keyinfo_init,
};

static void py_ulogd_key_dealloc(struct py_ulogd_key *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
py_ulogd_key_getvalue(struct py_ulogd_key *self, PyObject *args)
{
	struct ulogd_key *key = self->raw;

	if (!key->u.source || !(key->u.source->flags & ULOGD_RETF_VALID))
		Py_RETURN_NONE;

	switch (key->type) {
	case ULOGD_RET_BOOL:
		if (ikey_get_u8(key)) {
			Py_RETURN_TRUE;
		}
		Py_RETURN_FALSE;
	case ULOGD_RET_UINT8:
		return Py_BuildValue("B", ikey_get_u8(key));
	case ULOGD_RET_UINT16:
		return Py_BuildValue("H", ikey_get_u16(key));
	case ULOGD_RET_UINT32:
	case ULOGD_RET_IPADDR:
		return Py_BuildValue("I", ikey_get_u32(key));
	case ULOGD_RET_UINT64:
		return Py_BuildValue("K", ikey_get_u64(key));
	case ULOGD_RET_IP6ADDR:
		return Py_BuildValue("y#", ikey_get_u128(key), 16);
	case ULOGD_RET_RAW:
		return Py_BuildValue("L", ikey_get_u64(key));
	case ULOGD_RET_STRING:
	case ULOGD_RET_RAWSTR:
		return Py_BuildValue("s", ikey_get_ptr(key));
	default:
		PyErr_Format(PyExc_AttributeError,
			     "unsupported type: %d", key->type);
		return NULL;
	}
	return NULL;
}

static PyObject *py_ulogd_inkey_is_valid(struct py_ulogd_key *self,
					 PyObject *args)
{
	struct ulogd_key *key = self->raw;

	if (key->u.source && key->u.source->flags & ULOGD_RETF_VALID)
		Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyMethodDef py_ulogd_inkey_methods[] = {
	{"is_valid", (PyCFunction)py_ulogd_inkey_is_valid, METH_NOARGS,
	 "check input key validity"
	},
	{NULL},
};

static PyGetSetDef py_ulogd_inkey_getseters[] = {
	{
		"len",
		(getter)py_ulogd_key_getlen,
		NULL,
		"struct ulogd_key. uint32_t len",
		NULL
	},
	{
		"type",
		(getter)py_ulogd_key_gettype,
		NULL,
		"struct ulogd_key. uint16_t type",
		NULL
	},
	{
		"flags",
		(getter)py_ulogd_key_getflags,
		NULL,
		"struct ulogd_key. uint16_t flags",
		NULL
	},
	{
		"name",
		(getter)py_ulogd_key_getname,
		NULL,
		"struct ulogd_key. char name[ULOGD_MAX_KEYLEN+1]",
		NULL
	},
	{
		"cim_name",
		(getter)py_ulogd_key_getcim_name,
		NULL,
		"struct ulogd_key. char cim_name[ULOGD_MAX_KEYLEN+1]",
		NULL
	},
	{
		"ipfix_vendor",
		(getter)py_ulogd_key_getipfix_vendor,
		NULL,
		"struct ulogd_key. uint32_t ipfix.vendor",
		NULL
	},
	{
		"ipfix_field_id",
		(getter)py_ulogd_key_getipfix_field_id,
		NULL,
		"struct ulogd_key. uint16_t ipfix.field_id",
		NULL
	},
	{
		"value",
		(getter)py_ulogd_key_getvalue,
		NULL,
		"struct ulogd_key. input value",
		NULL
	},
	{NULL},
};

static PyTypeObject py_ulogd_inkey_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "ulogd.Inkey",
	.tp_basicsize	= sizeof(struct py_ulogd_key),
	.tp_new		= PyType_GenericNew,
	.tp_dealloc	= (destructor)py_ulogd_key_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct ulogd_key for input",
	.tp_methods	= py_ulogd_inkey_methods,
	.tp_getset	= py_ulogd_inkey_getseters,
};

static int
py_ulogd_key_setvalue(struct py_ulogd_key *self,
		      PyObject *value, void *closure)
{
	struct ulogd_key *key = self->raw;
	Py_buffer view;

	switch (key->type) {
	case ULOGD_RET_BOOL:
		if (!PyBool_Check(value))
			return -1;
		if (value == Py_True) {
			okey_set_b(key, 1);
		} else {
			okey_set_b(key, 0);
		}
		return 0;
	case ULOGD_RET_UINT8:
		if (!PyLong_Check(value))
			return -1;
		okey_set_u8(key, (uint8_t)PyLong_AsLong(value));
		return 0;
	case ULOGD_RET_UINT16:
		if (!PyLong_Check(value))
			return -1;
		okey_set_u16(key, (uint16_t)PyLong_AsLong(value));
		return 0;
	case ULOGD_RET_UINT32:
	case ULOGD_RET_IPADDR:
		if (!PyLong_Check(value))
			return -1;
		okey_set_u32(key, (uint32_t)PyLong_AsLong(value));
		return 0;
	case ULOGD_RET_UINT64:
		if (!PyLong_Check(value))
			return -1;
		/* XXX: assume long long as u64 */
		okey_set_u64(key, (uint32_t)PyLong_AsLongLong(value));
		return 0;
	case ULOGD_RET_IP6ADDR:
		if (!PyObject_CheckBuffer(value))
			return -1;
		if (!PyObject_GetBuffer(value, &view, PyBUF_SIMPLE))
			return -1;
		okey_set_u128(key, view.buf);
		return 0;
	default:
		PyErr_Format(PyExc_AttributeError,
			     "unsupported type: %d", key->type);
		return -1;
	}
	return -1;
}

static PyGetSetDef py_ulogd_outkey_getseters[] = {
	{
		"len",
		(getter)py_ulogd_key_getlen,
		NULL,
		"struct ulogd_key. uint32_t len",
		NULL
	},
	{
		"type",
		(getter)py_ulogd_key_gettype,
		NULL,
		"struct ulogd_key. uint16_t type",
		NULL
	},
	{
		"flags",
		(getter)py_ulogd_key_getflags,
		NULL,
		"struct ulogd_key. uint16_t flags",
		NULL
	},
	{
		"name",
		(getter)py_ulogd_key_getname,
		NULL,
		"struct ulogd_key. char name[ULOGD_MAX_KEYLEN+1]",
		NULL
	},
	{
		"cim_name",
		(getter)py_ulogd_key_getcim_name,
		NULL,
		"struct ulogd_key. char cim_name[ULOGD_MAX_KEYLEN+1]",
		NULL
	},
	{
		"ipfix_vendor",
		(getter)py_ulogd_key_getipfix_vendor,
		NULL,
		"struct ulogd_key. uint32_t ipfix.vendor",
		NULL
	},
	{
		"ipfix_field_id",
		(getter)py_ulogd_key_getipfix_field_id,
		NULL,
		"struct ulogd_key. uint16_t ipfix.field_id",
		NULL
	},
	{
		"value",
		NULL,
		(setter)py_ulogd_key_setvalue,
		"struct ulogd_key. output value",
		NULL
	},
	{NULL},
};

static PyTypeObject py_ulogd_outkey_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "ulogd.Outkey",
	.tp_basicsize	= sizeof(struct py_ulogd_key),
	.tp_new		= PyType_GenericNew,
	.tp_dealloc	= (destructor)py_ulogd_key_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct ulogd_key for output",
	.tp_getset	= py_ulogd_outkey_getseters,
};

/****
 * struct ulogd_key holder for input/output key creation in configure()
 */
static PyObject *
py_ulogd_keylist_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	struct py_ulogd_keylist *self;

	self = (struct py_ulogd_keylist *)type->tp_alloc(type, 0);
	if (self == NULL)
		return NULL;
	self->raw = calloc(1, sizeof(struct ulogd_keyset));
	if (self->raw == NULL) {
		free(self);
		return NULL;
	}
	INIT_LLIST_HEAD(&self->list);
	return (PyObject *)self;
}

static void py_ulogd_keylist_dealloc(struct py_ulogd_keylist *self)
{
	struct py_ulogd_key *k, *tmp;

	llist_for_each_entry_safe(k, tmp, &self->list, list) {
		Py_DECREF(k);
		llist_del(&k->list);
	}
	free(self->raw);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

UINT_KEY_GETSET(py_ulogd_keylist, type, uint16_t, UINT16_MAX)

static PyGetSetDef py_ulogd_keylist_getseters[] = {
	{
		"type",
		(getter)py_ulogd_keylist_gettype,
		(setter)py_ulogd_keylist_settype,
		"struct ulogd_keyset. uint16_t type",
		NULL
	},
	{NULL},
};

static PyObject *
py_ulogd_keylist_add(struct py_ulogd_keylist *self, PyObject *args)
{
	struct py_ulogd_key *key, *k;

	if (!PyArg_ParseTuple(args, "O", &key))
		return NULL;
	if (!PyObject_TypeCheck(key, &py_ulogd_keyinfo_type)) {
		PyErr_SetString(PyExc_TypeError, "not a ulogd.Key");
		return NULL;
	}

	if (key->raw->type == ULOGD_RET_NONE) {
		PyErr_SetString(PyExc_AttributeError, "no type");
		return NULL;
	}
	if (key->raw->name == NULL
	    || strlen(key->raw->name) == 0) {
		PyErr_SetString(PyExc_AttributeError, "no name");
		return NULL;
	}
	llist_for_each_entry(k, &self->list, list) {
		if (!strcmp(k->raw->name, key->raw->name)) {
			PyErr_Format(PyExc_AttributeError, "dup name: %s",
				     key->raw->name);
			return NULL;
		}
	}
	if (self->raw->num_keys >= PY_KEYLIST_MAX_NUM) {
		PyErr_Format(PyExc_NotImplementedError,
			     "exceeds max num keys: %d", PY_KEYLIST_MAX_NUM);
		return NULL;
	}
	Py_INCREF(key);
	llist_add_tail(&key->list, &self->list);
	self->raw->num_keys++;

	Py_RETURN_NONE;
}

static PyObject *
py_ulogd_keylist_del(struct py_ulogd_keylist *self, PyObject *args)
{
	struct py_ulogd_key *key, *tmp;
	char *name;

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	llist_for_each_entry_safe(key, tmp, &self->list, list) {
		if (!strcmp(name, key->raw->name)) {
			llist_del(&key->list);
			Py_DECREF(key);
			self->raw->num_keys--;
			Py_RETURN_NONE;
		}
	}

	PyErr_Format(PyExc_KeyError, "could not find a key: %s", name);
	return NULL;
}

static PyMethodDef py_ulogd_keylist_methods[] = {
	{"add", (PyCFunction)py_ulogd_keylist_add, METH_VARARGS,
	 "add ulogd.Keyinfo"
	},
	{"delete", (PyCFunction)py_ulogd_keylist_del, METH_VARARGS,
	 "del ulogd.Keyinfo"
	},
	{NULL},
};

static PyTypeObject py_ulogd_keylist_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "ulogd.Keylist",
	.tp_basicsize	= sizeof(struct py_ulogd_keylist),
	.tp_new		= py_ulogd_keylist_new,
	.tp_dealloc	= (destructor)py_ulogd_keylist_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct ulogd_key holder",
	.tp_getset	= py_ulogd_keylist_getseters,
	.tp_methods	= py_ulogd_keylist_methods,
};

/****
 * struct ulogd_keyset
 */
struct ulogd_key *find_key_by_name(struct ulogd_keyset *kset, char *name)
{
	unsigned int i;

	for (i = 0; i < kset->num_keys; i++)
		if (!strcmp(name, kset->keys[i].name))
			return &kset->keys[i];

	return NULL;
}

static void py_ulogd_keyset_dealloc(struct py_ulogd_keyset *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static Py_ssize_t py_ulogd_keyset_len(struct py_ulogd_keyset *self)
{
	return self->raw->num_keys;
}

static PyObject *
py_ulogd_keyset_getitem(struct py_ulogd_keyset *self,
			PyTypeObject *type, PyObject *args)
{
	struct ulogd_key *key = NULL;
	long index;
	char *name;
	PyObject *keyobj;

	if (PyLong_Check(args)) {
		index = PyLong_AsLong(args);
		if (index < 0 || index > self->raw->num_keys) {
			PyErr_Format(PyExc_KeyError, "not exist: %d", index);
			return NULL;
		}
		key = &self->raw->keys[index];
	} else if (PyArg_Parse(args, "s", &name)) {
		key = find_key_by_name(self->raw, name);
		if (key == NULL) {
			PyErr_Format(PyExc_KeyError, "not exist: %s", name);
			return NULL;
		}
	} else {
		PyErr_SetString(PyExc_TypeError, "invalid arg type");
		return NULL;
	}

	keyobj = PyObject_CallObject((PyObject *)type, NULL);
	if (keyobj == NULL)
		return NULL;

	((struct py_ulogd_key *)keyobj)->raw = key;
	return (PyObject *)keyobj;
}

static PyObject *
py_ulogd_ikeyset_getitem(struct py_ulogd_keyset *self, PyObject *args)
{
	return py_ulogd_keyset_getitem(self, &py_ulogd_inkey_type, args);
}

static PyObject *
py_ulogd_okeyset_getitem(struct py_ulogd_keyset *self, PyObject *args)
{
	return py_ulogd_keyset_getitem(self, &py_ulogd_outkey_type, args);
}

static PyMappingMethods py_ulogd_ikeyset_as_mapping = {
	(lenfunc)py_ulogd_keyset_len,
	(binaryfunc)py_ulogd_ikeyset_getitem,
	NULL,
};

static PyMappingMethods py_ulogd_okeyset_as_mapping = {
	(lenfunc)py_ulogd_keyset_len,
	(binaryfunc)py_ulogd_okeyset_getitem,
	NULL,
};

static PyObject *py_ulogd_keyset_iternext(PyObject *self, PyTypeObject *type)
{
	struct py_ulogd_keyset *kset = (struct py_ulogd_keyset *)self;
	PyObject *next;

	if (kset->n >= kset->raw->num_keys) {
		PyErr_SetNone(PyExc_StopIteration);
		return NULL;
	}
	next = PyObject_CallObject((PyObject *)type, NULL);
	if (next == NULL)
		return NULL;

	((struct py_ulogd_key *)next)->raw = &kset->raw->keys[kset->n];
	kset->n++;
	return next;
}

static PyObject *py_ulogd_ikeyset_iternext(PyObject *self)
{
	return py_ulogd_keyset_iternext(self, &py_ulogd_inkey_type);
}

static PyObject *py_ulogd_okeyset_iternext(PyObject *self)
{
	return py_ulogd_keyset_iternext(self, &py_ulogd_outkey_type);
}

static PyTypeObject py_ulogd_input_keyset_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "ulogd.IKeyset",
	.tp_basicsize	= sizeof(struct py_ulogd_keyset),
	.tp_dealloc	= (destructor)py_ulogd_keyset_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct ulogd_keyset for input",
	.tp_new		= PyType_GenericNew,
	.tp_as_mapping	= &py_ulogd_ikeyset_as_mapping,
	.tp_iter	= PyObject_SelfIter,
	.tp_iternext	= py_ulogd_ikeyset_iternext,
};

static int py_child_session(uint16_t fin_type)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);

	py_child_recv(buf, sizeof(buf), NULL);
	if (nlh->nlmsg_type != fin_type) {
		child_log(ULOGD_INFO,
			  "child expecting: %s, but got: %d\n",
			  _pyulogd_nl_typestr[fin_type],
			  nlh->nlmsg_type);
		return ULOGD_IRET_ERR;
	}
	if (mnl_attr_get_u32(nla) == 0)
		return ULOGD_IRET_OK;
	return ULOGD_IRET_ERR;
}

static PyTypeObject py_ulogd_output_keyset_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "ulogd.OKeyset",
	.tp_basicsize	= sizeof(struct py_ulogd_keyset),
	.tp_dealloc	= (destructor)py_ulogd_keyset_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct ulogd_keyset for output",
	.tp_new		= PyType_GenericNew,
	.tp_as_mapping	= &py_ulogd_okeyset_as_mapping,
	.tp_iter	= PyObject_SelfIter,
	.tp_iternext	= py_ulogd_okeyset_iternext,
};

static PyObject *
py_ulogd_source_okeyset_propagate_results(struct py_ulogd_key *self,
					  PyObject *args)
{
	struct py_ulogd_keyset *okset = (struct py_ulogd_keyset *)self;

	py_child_sendargs(ULOGD_PY_CALL_PROPAGATE_RESULTS, 0, "p", okset->raw);
	if (py_child_session(ULOGD_PY_RETURN_PROPAGATE_RESULTS) != 0) {
		PyErr_SetString(PyExc_RuntimeError, "child session error");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyMethodDef py_ulogd_source_okeyset_methods[] = {
	{"propagate_results", (PyCFunction)
	 py_ulogd_source_okeyset_propagate_results,
	 METH_NOARGS, "call ulogd_propagate_results()"
	},
	{NULL},
};

static PyTypeObject py_ulogd_source_output_keyset_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "ulogd.SourceOKeyset",
	.tp_basicsize	= sizeof(struct py_ulogd_keyset),
	.tp_dealloc	= (destructor)py_ulogd_keyset_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct ulogd_keyset for source output",
	.tp_new		= PyType_GenericNew,
	.tp_methods	= py_ulogd_source_okeyset_methods,
	.tp_as_mapping	= &py_ulogd_okeyset_as_mapping,
	.tp_iter	= PyObject_SelfIter,
	.tp_iternext	= py_ulogd_okeyset_iternext,
};

/****
 * struct ulogd_source_pluginstance
 */
static void
py_ulogd_source_pluginstance_dealloc(struct py_ulogd_source_pluginstance *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
py_ulogd_source_pluginstance_get_okeyset(PyObject *self, PyObject *args)
{
	struct py_ulogd_source_pluginstance *upi
		= (struct py_ulogd_source_pluginstance *)self;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct nlattr *nla = mnl_nlmsg_get_payload(nlh);
	struct ulogd_keyset *raw;
	struct py_ulogd_keyset *output;

	py_child_sendargs(ULOGD_PY_CALL_GET_OUTPUT_KEYSET, 0, "p", upi->raw);
	py_child_recv(buf, sizeof(buf), NULL);
	if (nlh->nlmsg_type != ULOGD_PY_RETURN_GET_OUTPUT_KEYSET) {
		child_log(ULOGD_INFO,
			  "child expecting: RETURN_GET_OUTPUT_KEYSET,"
			  "but got: %d\n", nlh->nlmsg_type);
		return NULL;
	}
	raw = (struct ulogd_keyset *)*(void **)mnl_attr_get_payload(nla);
	output = (struct py_ulogd_keyset *)
		PyObject_CallObject((PyObject *)
				    &py_ulogd_source_output_keyset_type,
				    NULL);
	output->raw = raw;

	return (PyObject *)output;
}

static PyMethodDef py_ulogd_source_pluginstance_methods[] = {
	{"get_output_keyset", py_ulogd_source_pluginstance_get_okeyset,
	 METH_NOARGS, "get output keyset for propagation"},
	{NULL, NULL, 0, NULL},
};

static PyTypeObject py_ulogd_source_pluginstance_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "ulogd.SourcePluginstance",
	.tp_basicsize	= sizeof(struct py_ulogd_source_pluginstance),
	.tp_dealloc	= (destructor)py_ulogd_source_pluginstance_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct ulogd_source_pluginstance",
	.tp_new		= PyType_GenericNew,
	.tp_methods	= py_ulogd_source_pluginstance_methods,
};

/****
 * struct ulogd_fd
 */
static void py_ulogd_fd_dealloc(struct py_ulogd_fd *self)
{
	Py_DECREF(self->file);
	Py_DECREF(self->cb);
	Py_DECREF(self->data);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int py_ulogd_fd_init(PyObject *self, PyObject *args, PyObject *kwds)
{
	PyObject *file, *data, *fileno, *cb, *value;
	unsigned int when;
	struct py_ulogd_fd *ufd = (struct py_ulogd_fd *)self;
	static char *kwlist[] = {"file", "when", "cb", "data", NULL};


	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OIOO", kwlist,
					 &file, &when, &cb, &data))
		return -1;
	if (!PyCallable_Check(cb)) {
		PyErr_SetString(PyExc_TypeError, "cb is not a callable");
		return -1;
	}
	fileno = PyObject_GetAttrString(file, "fileno");
	if (fileno == NULL || !PyCallable_Check(fileno)) {
		PyErr_SetString(PyExc_TypeError, "first arg has no fileno()");
		return -1;
	}
	value = PyObject_CallFunctionObjArgs(fileno, NULL);
	if (PyErr_Occurred())
		return -1;
	if (!PyLong_Check(value)) {
		PyErr_SetString(PyExc_AttributeError,
				"fileno() must return an integer");
		return -1;
	}

	ufd->fd = (int)PyLong_AsLong(value);
	ufd->file = file;
	ufd->when = when;
	ufd->cb = cb;
	ufd->data = data;
	Py_INCREF(ufd->file);
	Py_INCREF(ufd->cb);
	Py_INCREF(ufd->data);

	return 0;
}

static PyObject *py_ulogd_fd_register(PyObject *self, PyObject *args)
{
	struct py_ulogd_fd *ufd = (struct py_ulogd_fd *)self;

	py_child_sendargs(ULOGD_PY_CALL_REGISTER_FD,
			  ufd->fd, "Ip", ufd->when, ufd);
	if (py_child_session(ULOGD_PY_RETURN_REGISTER_FD) != 0) {
		PyErr_SetString(PyExc_RuntimeError, "child session error");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_ulogd_fd_unregister(PyObject *self, PyObject *args)
{
	struct py_ulogd_fd *ufd = (struct py_ulogd_fd *)self;

	py_child_sendargs(ULOGD_PY_CALL_UNREGISTER_FD, 0, "p", ufd);
	if (py_child_session(ULOGD_PY_RETURN_UNREGISTER_FD) != 0) {
		PyErr_SetString(PyExc_RuntimeError, "child session error");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyMethodDef py_ulogd_fd_methods[] = {
	{"register", (PyCFunction)py_ulogd_fd_register, METH_NOARGS,
	 "ulogd_register_fd()"},
	{"unregister", (PyCFunction)py_ulogd_fd_unregister, METH_NOARGS,
	 "ulogd_unregister_fd()"},
	{NULL},
};

static PyTypeObject py_ulogd_fd_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "ulogd.Fd",
	.tp_basicsize	= sizeof(struct py_ulogd_fd),
	.tp_new		= PyType_GenericNew,
	.tp_dealloc	= (destructor)py_ulogd_fd_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct ulogd_fd",
	.tp_init	= (initproc)py_ulogd_fd_init,
	.tp_methods	= py_ulogd_fd_methods,
};

/****
 * struct ulogd_timer
 */
static void py_ulogd_timer_dealloc(struct py_ulogd_timer *self)
{
	Py_INCREF(self->cb);
	Py_INCREF(self->data);
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int py_ulogd_timer_init(PyObject *self, PyObject *args, PyObject *kwds)
{
	struct py_ulogd_timer *timer = (struct py_ulogd_timer *)self;
	static char *kwlist[] = {"cb", "data", NULL};

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
					 &timer->cb, &timer->data))
		return -1;

	if (!PyCallable_Check(timer->cb)) {
		PyErr_SetString(PyExc_TypeError, "cb is not a callable");
		return -1;
	}

	py_child_sendargs(ULOGD_PY_CALL_INIT_TIMER, 0, "p", timer);
	if (py_child_session(ULOGD_PY_RETURN_INIT_TIMER) != 0) {
		PyErr_SetString(PyExc_RuntimeError, "child session error");
		return -1;
	}

	Py_INCREF(timer->cb);
	Py_INCREF(timer->data);

	return 0;
}

static PyObject *py_ulogd_timer_add(PyObject *self, PyObject *args)
{
	struct py_ulogd_timer *timer = (struct py_ulogd_timer *)self;
	unsigned long sc;

	if (!PyArg_ParseTuple(args, "L", &sc))
		return NULL;

	py_child_sendargs(ULOGD_PY_CALL_ADD_TIMER, 0, "Ip", sc, timer);
	if (py_child_session(ULOGD_PY_RETURN_ADD_TIMER) != 0) {
		PyErr_SetString(PyExc_RuntimeError, "child session error");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *py_ulogd_timer_del(PyObject *self, PyObject *args)
{
	struct py_ulogd_timer *timer = (struct py_ulogd_timer *)self;

	py_child_sendargs(ULOGD_PY_CALL_DEL_TIMER, 0, "p", timer);
	if (py_child_session(ULOGD_PY_RETURN_DEL_TIMER) != 0) {
		PyErr_SetString(PyExc_RuntimeError, "child session error");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyMethodDef py_ulogd_timer_methods[] = {
	{"add", (PyCFunction)py_ulogd_timer_add, METH_VARARGS,
	 "ulogd_add_timer()"},
	{"delete", (PyCFunction)py_ulogd_timer_del, METH_NOARGS,
	 "ulogd_del_timer()"},
	{NULL},
};

static PyTypeObject py_ulogd_timer_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "ulogd.Timer",
	.tp_basicsize	= sizeof(struct py_ulogd_timer),
	.tp_new		= PyType_GenericNew,
	.tp_dealloc	= (destructor)py_ulogd_timer_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct ulogd_timer",
	.tp_init	= (initproc)py_ulogd_timer_init,
	.tp_methods	= py_ulogd_timer_methods,
};

static PyModuleDef ulogd_module = {
	PyModuleDef_HEAD_INIT,
	"ulogd",
	"python module for netfilter ulogd",
	-1,
	NULL, NULL, NULL, NULL, NULL,
};

PyMODINIT_FUNC
PyInit_ulogd(void)
{
	PyObject *m;

	if (PyType_Ready(&py_ulogd_keyinfo_type) < 0)
		return NULL;
	if (PyType_Ready(&py_ulogd_inkey_type) < 0)
		return NULL;
	if (PyType_Ready(&py_ulogd_outkey_type) < 0)
		return NULL;
	if (PyType_Ready(&py_ulogd_keylist_type) < 0)
		return NULL;
	if (PyType_Ready(&py_ulogd_input_keyset_type) < 0)
		return NULL;
	if (PyType_Ready(&py_ulogd_output_keyset_type) < 0)
		return NULL;
	if (PyType_Ready(&py_ulogd_source_output_keyset_type) < 0)
		return NULL;
	if (PyType_Ready(&py_ulogd_source_pluginstance_type) < 0)
		return NULL;
	if (PyType_Ready(&py_ulogd_fd_type) < 0)
		return NULL;
	if (PyType_Ready(&py_ulogd_timer_type) < 0)
		return NULL;

	ulogd_module.m_methods = py_ulogd_methods;
	m = PyModule_Create(&ulogd_module);
	if (m == NULL)
		return NULL;

	Py_INCREF(&py_ulogd_keyinfo_type);
	PyModule_AddObject(m, "Keyinfo",
			   (PyObject *)&py_ulogd_keyinfo_type);
	Py_INCREF(&py_ulogd_inkey_type);
	PyModule_AddObject(m, "Inkey",
			   (PyObject *)&py_ulogd_inkey_type);
	Py_INCREF(&py_ulogd_outkey_type);
	PyModule_AddObject(m, "Outkey",
			   (PyObject *)&py_ulogd_outkey_type);
	Py_INCREF(&py_ulogd_keylist_type);
	PyModule_AddObject(m, "Keylist",
			   (PyObject *)&py_ulogd_keylist_type);
	Py_INCREF(&py_ulogd_input_keyset_type);
	PyModule_AddObject(m, "IKeyset",
			   (PyObject *)&py_ulogd_input_keyset_type);
	Py_INCREF(&py_ulogd_output_keyset_type);
	PyModule_AddObject(m, "OKeyset",
			   (PyObject *)&py_ulogd_output_keyset_type);
	Py_INCREF(&py_ulogd_source_output_keyset_type);
	PyModule_AddObject(m, "SourceOKeyset",
			   (PyObject *)&py_ulogd_source_output_keyset_type);
	Py_INCREF(&py_ulogd_source_pluginstance_type);
	PyModule_AddObject(m, "SourcePluginstance",
			   (PyObject *)&py_ulogd_source_pluginstance_type);
	Py_INCREF(&py_ulogd_fd_type);
	PyModule_AddObject(m, "Fd",
			   (PyObject *)&py_ulogd_fd_type);
	Py_INCREF(&py_ulogd_timer_type);
	PyModule_AddObject(m, "Timer",
			   (PyObject *)&py_ulogd_timer_type);

	PyModule_AddIntMacro(m, ULOGD_RET_NONE);
	PyModule_AddIntMacro(m, ULOGD_RET_UINT8);
	PyModule_AddIntMacro(m, ULOGD_RET_UINT16);
	PyModule_AddIntMacro(m, ULOGD_RET_UINT32);
	PyModule_AddIntMacro(m, ULOGD_RET_UINT64);
	PyModule_AddIntMacro(m, ULOGD_RET_BOOL);
	PyModule_AddIntMacro(m, ULOGD_RET_IPADDR);
	PyModule_AddIntMacro(m, ULOGD_RET_IP6ADDR);
	/* no key_(set|get)_ function */
	PyModule_AddIntMacro(m, ULOGD_RET_INT8);
	PyModule_AddIntMacro(m, ULOGD_RET_INT16);
	PyModule_AddIntMacro(m, ULOGD_RET_INT32);
	PyModule_AddIntMacro(m, ULOGD_RET_INT64);
	PyModule_AddIntMacro(m, ULOGD_RET_STRING);
	PyModule_AddIntMacro(m, ULOGD_RET_RAW);
	PyModule_AddIntMacro(m, ULOGD_RET_RAWSTR);

	PyModule_AddIntMacro(m, ULOGD_RETF_NONE);
	PyModule_AddIntMacro(m, ULOGD_RETF_VALID);
	PyModule_AddIntMacro(m, ULOGD_RETF_FREE);
	PyModule_AddIntMacro(m, ULOGD_RETF_NEEDED);
	PyModule_AddIntMacro(m, ULOGD_RETF_EMBED);

	PyModule_AddIntMacro(m, ULOGD_KEYF_OPTIONAL);
	PyModule_AddIntMacro(m, ULOGD_KEYF_INACTIVE);
	PyModule_AddIntMacro(m, ULOGD_KEYF_WILDCARD);

	PyModule_AddIntMacro(m, ULOGD_DTYPE_NULL);
	PyModule_AddIntMacro(m, ULOGD_DTYPE_RAW);
	PyModule_AddIntMacro(m, ULOGD_DTYPE_PACKET);
	PyModule_AddIntMacro(m, ULOGD_DTYPE_FLOW);
	PyModule_AddIntMacro(m, ULOGD_DTYPE_SUM);
	PyModule_AddIntMacro(m, ULOGD_DTYPE_SINK);

	PyModule_AddIntMacro(m, ULOGD_IRET_ERR);
	PyModule_AddIntMacro(m, ULOGD_IRET_STOP);
	PyModule_AddIntMacro(m, ULOGD_IRET_OK);

	PyModule_AddIntMacro(m, ULOGD_FD_READ);
	PyModule_AddIntMacro(m, ULOGD_FD_WRITE);
	PyModule_AddIntMacro(m, ULOGD_FD_EXCEPT);

	return m;
}
