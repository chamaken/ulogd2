AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = ${regular_CFLAGS}
AM_YFLAGS = -d
#AM_LFLAGS = --header-file=scanner.h

if BUILD_SPRINT

pkglib_LTLIBRARIES = ulogd_output_SPRINT.la

ulogd_output_SPRINT_la_SOURCES = ulogd_output_SPRINT.c ulogd_output_SPRINT-scanner.l ulogd_output_SPRINT-parser.y
ulogd_output_SPRINT_la_LDFLAGS = -avoid-version -module
# ulogd_output_SPRINT_la_LFLAGS =  --header-file=scanner.h

BUILT_SOURCES = ulogd_output_SPRINT-parser.h ulogd_output_SPRINT-parser.c \
		ulogd_output_SPRINT-scanner.h ulogd_output_SPRINT-scanner.c
CLEANFILES = $(BUILT_SOURCES)

ulogd_output_SPRINT-scanner.h: ulogd_output_SPRINT-scanner.l
	$(LEX) -o /dev/null --header-file=$@ $<

endif
