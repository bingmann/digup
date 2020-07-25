# -*- mode: autoconf -*-

AC_PREREQ(2.60)
AC_INIT(digup, 0.6.57)
AC_CONFIG_SRCDIR(src/digup.c)
AC_CONFIG_AUX_DIR(acscripts)

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

# Check for mingw system and set compilation flag.

AC_CANONICAL_HOST

AC_MSG_CHECKING(building on win32)
case "$host_os" in
    *cygwin* | *mingw32*)
        ON_WIN32=1
	AC_DEFINE(ON_WIN32, 1, "")
	AC_DEFINE(__MSVCRT_VERSION__, 0x0601, "") # needed for _stat64
        AC_MSG_RESULT(yes)
        ;;
    *)
        ON_WIN32=0
	AC_DEFINE(ON_WIN32, 0, "")
        AC_MSG_RESULT(no)
        ;;
esac

# enable full optimization by configure switch

AC_ARG_ENABLE(optimize,
	AS_HELP_STRING([--enable-optimize],
		       [Build with full optimization @<:@default=no@:>@]),
        [ case "${enableval}" in
          yes)
                CFLAGS="$CFLAGS -O3 -DNDEBUG -fomit-frame-pointer";
          ;;
          no) ;;
          *) AC_MSG_ERROR(bad value ${enableval} for --enable-optimize) ;;
          esac ])

# enable rbtree invariant testing by configure switch

AC_ARG_ENABLE(rbtree-verify,
	AS_HELP_STRING([--enable-rbtree-verify],
		       [Build digup with full red-black tree testing @<:@default=no@:>@]),
        [ case "${enableval}" in
          yes)
                CFLAGS="$CFLAGS -DRBTREE_VERIFY";
          ;;
          no) ;;
          *) AC_MSG_ERROR(bad value ${enableval} for --enable-rbtree-verify) ;;
          esac ])

# possibly disable building of test programs by configure switch

AC_ARG_ENABLE(tests,
    AS_HELP_STRING([--disable-tests],
                   [Disable building of test program suite @<:@default=no@:>@]),
	[ case "${enableval}" in
          yes) buildtests=true ;;
          no)  buildtests=false ;;
          *)   AC_MSG_ERROR([bad value ${enableval} for --disable-tests]) ;;
          esac ],
        [ buildtests=true ])

AM_CONDITIONAL(BUILDTESTS, test x"$buildtests" = "xtrue")

# check whether to enable gcov coverage flags and macros

AC_ARG_ENABLE(gcov,
    AS_HELP_STRING([--enable-gcov],
                   [enable test coverage with gcov @<:@default=no@:>@]),
	[case "${enableval}" in
         yes) gcov=true ;;
         no)  gcov=false ;;
         *)   AC_MSG_ERROR([bad value ${enableval} for --enable-gcov]) ;;
         esac],
        [ gcov=false ])

AM_CONDITIONAL(GCOV, test x"$gcov" = "xtrue")

if test x"$gcov" = "xtrue"; then
    CFLAGS="$CFLAGS -fprofile-arcs -ftest-coverage"
fi

# set debug info flag if no optimization flags are set.

if test "$CFLAGS" == ""; then
    CFLAGS="-g"
fi

# enable GNU and large file extensions.

AC_DEFINE(_GNU_SOURCE)

AC_SYS_LARGEFILE

# checks for programs.

AC_PROG_CC

# check for missing library functions.

AC_CHECK_FUNCS([strndup asprintf getline lstat readlink])

# check for include files

AC_CHECK_HEADER(endian.h, [AC_DEFINE(HAVE_ENDIAN_H, 1, "")], [AC_DEFINE(HAVE_ENDIAN_H, 0, "")])
AC_CHECK_HEADER(sys/param.h, [AC_DEFINE(HAVE_SYS_PARAM_H, 1, "")], [AC_DEFINE(HAVE_SYS_PARAM_H, 0, "")])

# Output transformed files.

AC_CONFIG_FILES([Makefile
		 src/Makefile
		 digup.spec])
AC_OUTPUT
