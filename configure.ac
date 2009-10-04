# $Id$ -*- Autoconf -*-

AC_PREREQ(2.60)
AC_INIT(digup, 0.6)
AC_CONFIG_SRCDIR(src/digup.c)
AC_CONFIG_AUX_DIR(acscripts)

AM_INIT_AUTOMAKE(foreign)
# AM_MAINTAINER_MODE

# enable full optimization by configure switch

AC_ARG_ENABLE(optimize,
	AS_HELP_STRING([--enable-optimize],
		       [Build with full optimization @<:@default=no@:>@]),
        [ case "${enableval}" in
          yes)
                CFLAGS="$CFLAGS -O3 -fomit-frame-pointer";
          ;;
          no) ;;
          *) AC_MSG_ERROR(bad value ${enableval} for --enable-optimize) ;;
          esac ],
        [ optimize=false ])

# check whether to enable gcov coverage flags and macros

AC_ARG_ENABLE(gcov,
    AS_HELP_STRING([--enable-gcov],
                   [enable test coverage with gcov @<:@default=no@:>@]),
	[case "${enableval}" in
         yes) gcov=true ;;
         no)  gcov=false ;;
         *)   AC_MSG_ERROR([bad value ${enableval} for --enable-gcov]) ;;
         esac],
        [gcov=false])

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

# Output transformed files.

AC_CONFIG_FILES([Makefile
		 src/Makefile])
AC_OUTPUT
