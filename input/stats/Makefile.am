
AM_CPPFLAGS = -I$(top_srcdir)/include ${LIBMNL_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS}

if BUILD_NFCTST
pkglib_LTLIBRARIES = ulogd_inpstats_NFCTST.la

ulogd_inpstats_NFCTST_la_SOURCES = ulogd_inpstats_NFCTST.c
ulogd_inpstats_NFCTST_la_LDFLAGS = -avoid-version -module $(LIBMNL_LIBS)
endif
