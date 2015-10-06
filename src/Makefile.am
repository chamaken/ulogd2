
AM_CPPFLAGS = -I$(top_srcdir)/include \
	      -DULOGD_CONFIGFILE="\"$(sysconfdir)/ulogd.conf\"" \
	      -DULOGD_LOGFILE_DEFAULT="\"$(localstatedir)/log/ulogd.log\""
AM_CFLAGS = ${regular_CFLAGS}

sbin_PROGRAMS = ulogd

ulogd_SOURCES = ulogd.c select.c timer.c conffile.c hash.c thread.c keysets.c json.c
ulogd_LDADD   = ${libdl_LIBS} ${libpthread_LIBS} ${LIBPYTHON_LIBS} ${JANSSON_LIBS}
ulogd_LDFLAGS = -export-dynamic
# ulogd_LDFLAGS = -export-symbols-regex '^ulogd_.*'

noinst_LTLIBRARIES	= libulog.la
libulog_la_SOURCES	= ${ulogd_SOURCES}
# libulog_la_CFLAGS	= ${AM_CPPFLAGS} ${AM_CFLAGS} # Objects-created-both-with-libtool-and-without
libulog_la_CFLAGS	= -DULOGD_TEST_LIB=1
