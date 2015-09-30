AM_CPPFLAGS = -I$(top_srcdir)/include ${LIBNETFILTER_ACCT_CFLAGS} \
              ${LIBNETFILTER_CONNTRACK_CFLAGS} ${LIBNETFILTER_LOG_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS}

SUBDIRS= sqlite3

pkglib_LTLIBRARIES = ulogd_output_LOGEMU.la ulogd_output_SYSLOG.la \
			 ulogd_output_GPRINT.la ulogd_output_XML2.la

if HAVE_JANSSON
pkglib_LTLIBRARIES += ulogd_output_JSON.la
endif

if BUILD_NFCT
pkglib_LTLIBRARIES += ulogd_output_NFLOW9.la
pkglib_LTLIBRARIES += ulogd_output_IPFIX.la
endif

ulogd_output_GPRINT_la_SOURCES = ulogd_output_GPRINT.c
ulogd_output_GPRINT_la_LDFLAGS = -avoid-version -module

ulogd_output_LOGEMU_la_SOURCES = ulogd_output_LOGEMU.c
ulogd_output_LOGEMU_la_LDFLAGS = -avoid-version -module

ulogd_output_SYSLOG_la_SOURCES = ulogd_output_SYSLOG.c
ulogd_output_SYSLOG_la_LDFLAGS = -avoid-version -module

if HAVE_JANSSON
ulogd_output_JSON_la_SOURCES = ulogd_output_JSON.c
ulogd_output_JSON_la_LIBADD  = ${libjansson_LIBS}
ulogd_output_JSON_la_LDFLAGS = -avoid-version -module
endif

if BUILD_NFCT
ulogd_output_NFLOW9_la_SOURCES = ulogd_output_NFLOW9.c
ulogd_output_NFLOW9_la_LDFLAGS = -avoid-version -module
ulogd_output_NFLOW9_la_LIBADD = ${LIBNETFILTER_CONNTRACK_LIBS} $(top_srcdir)/util/libutil.la
ulogd_output_IPFIX_la_SOURCES = ulogd_output_IPFIX.c 
ulogd_output_IPFIX_la_LDFLAGS = -avoid-version -module
ulogd_output_IPFIX_la_LIBADD = ${LIBNETFILTER_CONNTRACK_LIBS} $(top_srcdir)/util/libutil.la
endif

ulogd_output_XML2_la_SOURCES = ulogd_output_XML2.c
ulogd_output_XML2_la_LIBADD  = ${LIBNETFILTER_LOG_LIBS} \
			       ${LIBNETFILTER_CONNTRACK_LIBS} \
			       ${LIBNETFILTER_ACCT_LIBS} \
			       ${LIBNFTNL_LIBS}
ulogd_output_XML2_la_LDFLAGS = -avoid-version -module
