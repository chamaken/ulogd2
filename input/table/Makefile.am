
AM_CPPFLAGS = -I$(top_srcdir)/include ${LIBMNL_CFLAGS} ${LIBNFTNL_CFLAGS}
AM_CFLAGS = ${regular_CFLAGS}

if BUILD_NFT
pkglib_LTLIBRARIES = ulogd_inptable_NFT.la

ulogd_inptable_NFT_la_SOURCES = ulogd_inptable_NFT.c
ulogd_inptable_NFT_la_LDFLAGS = -avoid-version -module $(LIBMNL_LIBS) $(LIBNFTNL_LIBS)
endif
