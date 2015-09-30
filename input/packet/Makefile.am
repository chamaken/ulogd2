
AM_CPPFLAGS = -I$(top_srcdir)/include ${LIBNETFILTER_LOG_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS}

if BUILD_NFLOG
pkglib_LTLIBRARIES = ulogd_inppkt_NFLOG.la
if BUILD_NFLOG2
pkglib_LTLIBRARIES += ulogd_inppkt_NFLOG2.la
endif
endif

ulogd_inppkt_NFLOG_la_SOURCES = ulogd_inppkt_NFLOG.c
ulogd_inppkt_NFLOG_la_LDFLAGS = -avoid-version -module $(LIBNETFILTER_LOG_LIBS)

ulogd_inppkt_NFLOG2_la_SOURCES = ulogd_inppkt_NFLOG2.c
ulogd_inppkt_NFLOG2_la_LDFLAGS = -avoid-version -module $(LIBMNL_LIBS) $(LIBNETFILTER_LOG_LIBS) $(top_srcdir)/util/libutil.la
