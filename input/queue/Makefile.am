AM_CPPFLAGS = -I$(top_srcdir)/include $(LIBNETFILTER_QUEUE_CFLAGS) $(LIBMNL_CFLAGS)
AM_CFLAGS = ${regular_CFLAGS}

if BUILD_NFQ
pkglib_LTLIBRARIES		= ulogd_input_NFQ.la ulogd_input_MTNFQ.la

ulogd_input_NFQ_la_SOURCES	= ulogd_input_NFQ.c
ulogd_input_NFQ_la_LDFLAGS	= -avoid-version -module
ulogd_input_NFQ_la_LIBADD	= $(LIBNETFILTER_QUEUE_LIBS) $(LIBMNL_LIBS) $(top_srcdir)/util/libutil.la

ulogd_input_MTNFQ_la_SOURCES	= ulogd_input_MTNFQ.c
ulogd_input_MTNFQ_la_LDFLAGS	= -avoid-version -module
ulogd_input_MTNFQ_la_LIBADD	= $(LIBNETFILTER_QUEUE_LIBS) $(LIBMNL_LIBS) $(top_srcdir)/util/libutil.la
endif
