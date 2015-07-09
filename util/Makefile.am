AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}

noinst_LTLIBRARIES	= libutil.la
libutil_la_SOURCES	= db.c ipfix.c printflow.c printpkt.c

if HAVE_NLMMAP
libutil_la_SOURCES	+= ring.c
endif
