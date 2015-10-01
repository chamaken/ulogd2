AM_CPPFLAGS = -I$(top_srcdir)/include ${LIBPYTHON_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES	= ulogd_PYTHON.la
pyexec_LTLIBRARIES	= ulogd.la

ulogd_PYTHON_la_SOURCES	= ulogd_PYTHON.c utils.c ulogd_pyobj.h
ulogd_PYTHON_la_LDFLAGS	= -avoid-version -module
ulogd_PYTHON_la_LIBADD	= ${LIBPYTHON_LIBS} -lmnl

ulogd_la_SOURCES	= ulogd_pyobj.c utils.c ulogd_pyobj.h
ulogd_la_CPPFLAGS	= -I$(top_srcdir)/include ${python_CFLAGS}
ulogd_la_LDFLAGS	= -module -avoid-version ${python_LDFLAGS}
ulogd_la_LIBADD	= -lmnl
