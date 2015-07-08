AM_CPPFLAGS = -I$(top_srcdir)/include $(MYSQL_INC)
AM_CFLAGS = ${regular_CFLAGS}

if HAVE_MYSQL

pkglib_LTLIBRARIES = ulogd_output_MYSQL.la

ulogd_output_MYSQL_la_SOURCES = ulogd_output_MYSQL.c
ulogd_output_MYSQL_la_LIBADD  = ${MYSQL_LIB} $(top_srcdir)/util/libutil.la
ulogd_output_MYSQL_la_LDFLAGS = -avoid-version -module

endif
