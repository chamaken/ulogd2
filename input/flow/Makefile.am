
AM_CPPFLAGS = -I$(top_srcdir)/include ${LIBMNL_CFLAGS} ${LIBNETFILTER_CONNTRACK_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS}

if BUILD_NFCT
pkglib_LTLIBRARIES = ulogd_inpflow_NFCT.la ulogd_inpflow_NFCT2.la # ulogd_inpflow_IPFIX.la

ulogd_inpflow_NFCT_la_SOURCES = ulogd_inpflow_NFCT.c
ulogd_inpflow_NFCT_la_LDFLAGS = -avoid-version -module $(LIBNETFILTER_CONNTRACK_LIBS)

ulogd_inpflow_NFCT2_la_SOURCES = ulogd_inpflow_NFCT2.c ../../util/ring.c
ulogd_inpflow_NFCT2_la_LDFLAGS = -avoid-version -module $(LIBMNL_LIBS) $(LIBNETFILTER_CONNTRACK_LIBS)
endif

#ulogd_inpflow_IPFIX_la_SOURCES = ulogd_inpflow_IPFIX.c
#ulogd_inpflow_IPFIX_la_LDFLAGS = -avoid-version -module
