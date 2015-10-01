dnl Process this file with autoconf to produce a configure script.
AC_INIT([ulogd], [2.0.5])
AC_PREREQ([2.50])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall foreign tar-pax no-dist-gzip dist-bzip2 1.10b])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl Checks for programs.
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

dnl Checks for libraries.
AC_SEARCH_LIBS([dlopen], [dl], [libdl_LIBS="$LIBS"; LIBS=""])
AC_SUBST([libdl_LIBS])

dnl Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM
AC_SYS_LARGEFILE

dnl Checks for library functions.
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(socket strerror)

regular_CFLAGS="-Wall -Wextra -Wundef -Waggregate-return \
	-Wno-unused-parameter -Wmissing-declarations \
	-Wstrict-prototypes -Wmissing-prototypes \
	-Wshadow -Wcast-align -Wcast-qual -Wformat=2 -pipe"
# "-Wpointer-arith -Wconversion"
# regular_CFLAGS="-Wall -Wextra -Wno-unused-parameter -fno-omit-frame-pointer -fstack-protector-all -fsanitize=address"
AC_SUBST([regular_CFLAGS])

AC_SEARCH_LIBS([pthread_create], [pthread], [libpthread_LIBS="$LIBS"; LIBS=""])
AC_SUBST([libpthread_LIBS])

dnl Check for timerfd header.
AC_CHECK_HEADER(sys/timerfd.h,[],[AC_MSG_ERROR(unable to find timerfd header)])

dnl Check for signalfd header.
AC_CHECK_HEADER(sys/signalfd.h,[],[AC_MSG_ERROR(unable to find signalfd header)])

dnl Check for epoll header.
AC_CHECK_HEADER(sys/epoll.h,[],[AC_MSG_ERROR(unable to find epoll header)])

AC_MSG_CHECKING([for enable mmaped netlink])
AC_CACHE_VAL(ac_cv_mmaped_netlink,
AC_TRY_COMPILE(
    [ #include <linux/netlink.h>],
    [ int i = NETLINK_RX_RING; ],
    ac_cv_mmaped_netlink=yes,
    ac_cv_mmaped_netlink=no))
AC_MSG_RESULT($ac_cv_mmaped_netlink)
AM_CONDITIONAL([HAVE_NLMMAP], [test "x$ac_cv_mmaped_netlink" = "xyes"])

dnl Check for the right nfnetlink version
PKG_CHECK_MODULES([LIBNFNETLINK], [libnfnetlink >= 1.0.1])

dnl Check for the right libmnl version
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])

dnl Check for the right jansson version
PKG_CHECK_MODULES([JANSSON], [jansson >= 2.6])

AC_ARG_ENABLE(nflog,
       AS_HELP_STRING([--enable-nflog], [Enable nflog module [default=yes]]),[enable_nflog=$enableval],[enable_nflog=yes])
AS_IF([test "x$enable_nflog" = "xyes"], [
    PKG_CHECK_MODULES([LIBNETFILTER_LOG], [libnetfilter_log >= 1.0.0],
                      AC_DEFINE([BUILD_NFLOG], [1], [Building nflog module]),
                      enable_nflog="no")
])
AM_CONDITIONAL([BUILD_NFLOG], [test "x$enable_nflog" = "xyes"])

AC_ARG_ENABLE(nflog2,
       AS_HELP_STRING([--enable-nflog2], [Enable nflog2 module [default=yes]]),[enable_nflog2=$enableval],[enable_nflog2=yes])
AS_IF([test "x$enable_nflog2" = "xyes"], [
    AC_MSG_CHECKING([does libnetfilter_log have nflog_nlmsg_parse])
    AC_CACHE_VAL(ac_cv_nflog_nlmsg_parse,
        SAVE_LIBS=$LIBS
        LIBS="$LIBS -lnetfilter_log -lmnl"
        AC_TRY_LINK(
	    [ #include <stddef.h>
	      #include <libnetfilter_log/libnetfilter_log.h> ],	    
            [ return nflog_nlmsg_parse(NULL, NULL); ],
            ac_cv_nflog_nlmsg_parse=yes,
            ac_cv_nflog_nlmsg_parse=no)
	LIBS=$SAVE_LIBS)
    AC_MSG_RESULT($ac_cv_nflog_nlmsg_parse)
    AS_IF([test "x$ac_cv_mmaped_netlink" = "xyes" -a "x$ac_cv_nflog_nlmsg_parse" = "xyes" -a "x$enable_nflog2" = "xyes"],
        AC_DEFINE([BUILD_NFLOG2], [1], [Building nflog2 module]),
	enable_nflog2="no")
])
AM_CONDITIONAL([BUILD_NFLOG2], [test "x$enable_nflog2" = "xyes"])

AC_ARG_ENABLE(nfct,
       AS_HELP_STRING([--enable-nfct], [Enable nfct module [default=yes]]),[enable_nfct=$enableval],[enable_nfct=yes])
AS_IF([test "x$enable_nfct" = "xyes"], [
    PKG_CHECK_MODULES([LIBNETFILTER_CONNTRACK], [libnetfilter_conntrack >= 1.0.5],
		      AC_DEFINE([BUILD_NFCT], [1], [Building nfct module]),
                      enable_nfct="no")
])
AM_CONDITIONAL([BUILD_NFCT], [test "x$enable_nfct" = "xyes"])

AC_ARG_ENABLE(nfct2,
       AS_HELP_STRING([--enable-nfct2], [Enable nfct2 module [default=yes]]),[enable_nfct2=$enableval],[enable_nfct2=yes])
AS_IF([test "x$enable_nfct2" = "xyes" -a "x$enable_nfct" = "xyes" -a "x$ac_cv_mmaped_netlink" = "xyes"],
      AC_DEFINE([BUILD_NFCT2], [1], [Building nfct2 module]),
      enable_nfct2="no")
AM_CONDITIONAL([BUILD_NFCT2], [test "x$enable_nfct2" = "xyes"])

AC_ARG_ENABLE(nfacct,
       AS_HELP_STRING([--enable-nfacct], [Enable nfacct module [default=yes]]),[enable_nfacct=$enableval],[enable_nfacct=yes])
AS_IF([test "x$enable_nfacct" = "xyes"], [
    PKG_CHECK_MODULES([LIBNETFILTER_ACCT], [libnetfilter_acct >= 1.0.1],
                      AC_DEFINE([BUILD_NFACCT], [1], [Building nfacct module]),
                      enable_nfacct="no")
])
AM_CONDITIONAL([BUILD_NFACCT], [test "x$enable_nfacct" = "xyes"])

AC_ARG_ENABLE(nfq,
	AS_HELP_STRING([--enable-nfq], [Enable nfq module [default=yes]]),[enable_nfq=$enableval],[enable_nfq=yes])
AS_IF([test "x$enable_nfq" = "xyes"], [
    PKG_CHECK_MODULES([LIBNETFILTER_QUEUE], [libnetfilter_queue >= 1.0.2],
                      AC_DEFINE([BUILD_NFQ], [1], [Building nfq module]),
		      enable_nfq="no")
])
AM_CONDITIONAL([BUILD_NFQ], [test "x$enable_nfq" = "xyes"])

AC_ARG_ENABLE(nfctst,
       AS_HELP_STRING([--enable-nfctst], [Enable nfct stat module [default=yes]]),[enable_nfctst=$enableval],[enable_nfctst=yes])
AM_CONDITIONAL([BUILD_NFCTST], [test "x$enable_nfctst" = "xyes"])

AC_ARG_ENABLE(nft,
       AS_HELP_STRING([--enable-nft], [Enable nft module [default=yes]]),[enable_nft=$enableval],[enable_nft=yes])
AS_IF([test "x$enable_nft" = "xyes"], [
    PKG_CHECK_MODULES([LIBNFTNL], [libnftnl >= 1.0.0],
                      AC_DEFINE([BUILD_NFT], [1], [Building nft module]),
		      enable_nft="no")
])
AM_CONDITIONAL([BUILD_NFT], [test "x$enable_nft" = "xyes"])

AC_ARG_WITH([sqlite], AS_HELP_STRING([--without-sqlite], [Build without SQLITE3 output plugin [default=test]]))
AS_IF([test "x$with_sqlite" != "xno"], [
    PKG_CHECK_MODULES([libsqlite3], [sqlite3], [], [:])
])
AM_CONDITIONAL([HAVE_SQLITE3], [test -n "$libsqlite3_LIBS"])
if test "x$libsqlite3_LIBS" != "x"; then
	enable_sqlite3="yes"
else
	enable_sqlite3="no"
fi

dnl Check for urcu lib (uatomic only now)
AC_CHECK_HEADER(urcu/uatomic.h,[],[AC_MSG_ERROR(requires urcu).])

AC_ARG_ENABLE(python,
       AS_HELP_STRING([--enable-python], [Enable python module [default=yes]]),[enable_python=$enableval],[enable_python=yes])
AS_IF([test "x$enable_python" = "xyes"], [
    AM_PATH_PYTHON([3.2], [
        PKG_CHECK_MODULES([LIBPYTHON], [python-$PYTHON_VERSION], [
	    AC_PATH_PROG(PYTHON_CONFIG, python$PYTHON_VERSION-config, no)
	    AS_IF([test "$PYTHON_CONFIG" = no],
	        [AC_MSG_ERROR([cannot find python-config for $PYTHON])
	         enable_python="no"],
	        [AC_MSG_CHECKING([python cflags])
	         python_CFLAGS=`$PYTHON_CONFIG --cflags`
	         AC_SUBST([python_CFLAGS])
	         AC_MSG_RESULT([$python_CFLAGS])
	         AC_MSG_CHECKING([python ldflags])
	         python_LDFLAGS=`$PYTHON_CONFIG --ldflags`
	         AC_SUBST([python_LDFLAGS])
	         AC_MSG_RESULT([$python_LDFLAGS])
	        ])
            ], enable_python="no")
    ], enable_python="no")
])
AM_CONDITIONAL([HAVE_PYTHON], [test "x$enable_python" = "xyes"])

dnl Checks for PR-SCTP
AC_ARG_WITH([sctp], AC_HELP_STRING([--with-sctp], [Build with SCTP support [default=test]]))
AS_IF([test "x$with_sctp" != "xno"], [
    AC_CHECK_HEADERS(netinet/sctp.h)
    AC_MSG_CHECKING([for SCTP_PR_SCTP_TTL])
    AC_CACHE_VAL(ac_cv_pr_strp,
        AC_TRY_COMPILE(
            [ #include <netinet/sctp.h> ],
            [ struct sctp_prinfo p = { .policy = SCTP_PR_SCTP_TTL }; ],
            ac_cv_pr_sctp=yes,
            ac_cv_pr_sctp=no))
    AC_MSG_RESULT($ac_cv_pr_sctp)
])
AS_IF([test "x$ac_cv_pr_sctp" = "xyes"],
      [AC_DEFINE([HAVE_PR_SCTP], [1], [may handle PR-SCTP but not implemented yet])
])
AM_CONDITIONAL([HAVE_PR_SCTP], [test "x$ac_cv_pr_sctp" = "xyes"])

AC_CONFIG_FILES(include/Makefile include/ulogd/Makefile \
 	  include/linux/Makefile include/linux/netfilter/Makefile \
	  include/linux/netfilter_ipv4/Makefile util/Makefile \
	  input/Makefile input/packet/Makefile input/flow/Makefile \
	  input/sum/Makefile input/queue/Makefile input/stats/Makefile input/table/Makefile \
	  filter/Makefile output/Makefile output/sqlite3/Makefile \
	  bindings/Makefile bindings/python/Makefile src/Makefile Makefile Rules.make)
AC_OUTPUT

echo "
Ulogd configuration:
  Input plugins:
    NFLOG plugin:			${enable_nflog}
    NFLOG2 plugin:			${enable_nflog2}
    NFCT plugin:			${enable_nfct}
    NFCT2 plugin:			${enable_nfct2}
    NFACCT plugin:			${enable_nfacct}
    NFQ plugin:				${enable_nfq}
    NFCTST plugin:			${enable_nfctst}
    NFT plugin:				${enable_nft}
  Output plugins:
    SQLITE3 plugin:			${enable_sqlite3}
    NetFlow v9 plugin:			${enable_nfct}
    IPFIX plugin:			${enable_nfct}
  PYTHON plugin:			${enable_python}
"
echo "You can now run 'make' and 'make install'"
