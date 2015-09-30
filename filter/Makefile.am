AM_CPPFLAGS = -I$(top_srcdir)/include ${LIBNFNETLINK_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS}

pkglib_LTLIBRARIES = ulogd_filter_IFINDEX.la ulogd_filter_TIMECONV.la \
			 ulogd_filter_PACKICMP.la ulogd_filter_MARKIF.la

ulogd_filter_IFINDEX_la_SOURCES = ulogd_filter_IFINDEX.c
ulogd_filter_IFINDEX_la_LDFLAGS = -avoid-version -module
ulogd_filter_IFINDEX_la_LIBADD  = ${LIBNFNETLINK_LIBS}

ulogd_filter_TIMECONV_la_SOURCES = ulogd_filter_TIMECONV.c
ulogd_filter_TIMECONV_la_LDFLAGS = -avoid-version -module

ulogd_filter_PACKICMP_la_SOURCES = ulogd_filter_PACKICMP.c
ulogd_filter_PACKICMP_la_LDFLAGS = -avoid-version -module

ulogd_filter_MARKIF_la_SOURCES = ulogd_filter_MARKIF.c
ulogd_filter_MARKIF_la_LDFLAGS = -avoid-version -module
