#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Copyright (c) 2009-2016, The Trusted Domain Project.  All rights reserved.
# 

#
# Setup
#
AC_PREREQ(2.61)

#
# Package version
#
m4_define([VERSION_RELEASE], 0)
m4_define([VERSION_MAJOR_REV], 1)
m4_define([VERSION_MINOR_REV], 0)
m4_define([VERSION_PATCH], 0)

#
# Library version
# 	- bump "current" and reset "revision" with API changes
# 	- bump "revision" with internal source code changes
#
m4_define([LIBVERSION_CURRENT], 0)
m4_define([LIBVERSION_REVISION], 0)
m4_define([LIBVERSION_AGE], 0)

#
# Autotools setup
#
AC_INIT([OpenARC],
        [VERSION_RELEASE.VERSION_MAJOR_REV.VERSION_MINOR_REV],
        [bugs@trusteddomain.org])

AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE(
  1.11.1
  dnl Automake version before 1.13 (when the serial-tests option was
  dnl still the default) still defined the badly obsolete macro
  dnl 'AM_PROG_INSTALL'.
  m4_ifndef([AM_PROG_INSTALL], [serial-tests])
)
AC_CONFIG_HEADERS([build-config.h])

AC_CONFIG_MACRO_DIR([m4])

#
# Hexadecimal version, for use in generating dkim.h
# 
HEX_VERSION=$(printf %08x $(( ((VERSION_RELEASE << 8 | VERSION_MAJOR_REV) << 8 | VERSION_MINOR_REV) << 8| VERSION_PATCH )))
AC_SUBST([HEX_VERSION])

#
# library version, passed to libtool
# 
LIBOPENARC_VERSION_INFO=$(printf %d:%d:%d LIBVERSION_CURRENT LIBVERSION_REVISION LIBVERSION_AGE)
AC_SUBST([LIBOPENARC_VERSION_INFO])

#
# Checks for programs
#
AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

PKG_PROG_PKG_CONFIG

#
# Check for how to compile threaded stuff
#
AX_PTHREAD

#
# save outer values
#
outer_CFLAGS="$CFLAGS"
outer_CPPFLAGS="$CPPFLAGS"
outer_LDFLAGS="$LDFLAGS"
outer_LIBS="$LIBS"

#
# Checks for libraries
#
saved_LIBS="$LIBS"
LIBS=""
AC_SEARCH_LIBS(inet_addr, nsl)
LIBNSL_LIBS="$LIBS"
LIBS="$saved_LIBS"
AC_SUBST([LIBNSL_LIBS])

saved_LIBS="$LIBS"
LIBS=""
AC_SEARCH_LIBS(dlopen, dl)
LIBDL_LIBS="$LIBS"
LIBS="$saved_LIBS"
AC_SUBST([LIBDL_LIBS])

AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(inet_aton, resolv)
AC_SEARCH_LIBS(inet_pton, resolv,
               AC_DEFINE(HAVE_INET_PTON, 1,
                         [Define to 1 if you have the `inet_pton()' function.]))
AC_SEARCH_LIBS(inet_ntop, resolv nsl,
               AC_DEFINE(HAVE_INET_NTOP, 1,
                        [Define to 1 if you have the `inet_ntop()' function.]))
AC_SEARCH_LIBS(getaddrinfo, resolv,
               AC_DEFINE(HAVE_GETADDRINFO, 1,
                         [Define to 1 if you have the `getaddrinfo()' function.]))
AC_SEARCH_LIBS(res_ninit, resolv,
               AC_DEFINE(HAVE_RES_NINIT, 1,
                         [Define to 1 if you have the `res_ninit()' function.]))
AC_SEARCH_LIBS(res_sertservers, resolv bind,
               AC_DEFINE(HAVE_RES_SETSERVERS, 1,
                         [Define to 1 if you have the `res_setservers()' function.]))
AC_SEARCH_LIBS(getopt_long, iberty,
               AC_DEFINE(HAVE_GETOPT_LONG, 1,
                         [Define to 1 if you have the `getopt_long()' function.]))

AC_HEADER_RESOLV

#
# Check for types
#

AC_CHECK_TYPES([useconds_t])

#
# See if libopenarc will need -lresolv
#
dnscheck='
#include "confdefs.h" 
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h> 
int main() {
res_mkquery (0, 0, 0, 0, 0, 0, 0, 0, 0);
dn_expand (0, 0, 0, 0, 0);
dn_skipname (0, 0);
dn_comp (0, 0, 0, 0, 0);
return 0;
}'
AC_MSG_CHECKING([whether the resolver works without -lresolv])
LIBRESOLV=
AC_LINK_IFELSE([AC_LANG_SOURCE([
$dnscheck
])] , [
	AC_MSG_RESULT(yes)
] , [
	AC_MSG_RESULT(no)
	AC_MSG_CHECKING([whether the resolver works with -lresolv])
	saved_LIBS="$LIBS"
	LIBS="$outer_LIBS -lresolv"
	AC_LINK_IFELSE([AC_LANG_SOURCE([
$dnscheck
	])] , [
		AC_MSG_RESULT(yes)
		LIBRESOLV=-lresolv
	] , [
		AC_MSG_RESULT(no)
		AC_MSG_ERROR([need workable resolver library])
	])
	LIBS="$saved_LIBS"
])
AC_SUBST([LIBRESOLV])
 
#
# Checks for header files
#
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h iso/limits_iso.h netdb.h netinet/in.h paths.h stdlib.h string.h sys/file.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h stdint.h])

#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

#
# Checks for library functions.
#
AC_FUNC_FORK
AC_FUNC_GETGROUPS
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC

AC_CHECK_FUNCS([dup2 endpwent getcwd gethostname gethostbyname getaddrinfo gethostbyname2 gettimeofday isascii memchr memmove memset regcomp select socket strcasecmp strchr strdup strerror strncasecmp strrchr strstr strtol strtoul strtoull realpath strsep])

bsdstrl_h_found="no"
strl_found="no"
libstrl_found="no"
strl_h_found="no"

AC_CHECK_HEADERS([bsd/string.h], [bsdstrl_h_found="yes"])

AC_CHECK_FUNCS([strlcat strlcpy], [strl_found="yes"],
               [
		saved_LIBS="$LIBS"
		LIBS="$outer_LIBS"
		AC_SEARCH_LIBS([strlcat],
		               [bsd strl],
		               [libstrl_found="yes"],
		               [strl_found="no"])
		AC_SEARCH_LIBS([strlcpy],
		               [bsd strl],
		               [libstrl_found="yes"],
		               [strl_found="no"])
		STRL_LIBS="$LIBS"
		LIBS="$saved_LIBS"
               ])

if test x"$libstrl_found" = x"yes"
then
	LIBS="$LIBS $STRL_LIBS"
fi

# we need something above to have worked
if test x"$strl_found" != x"yes" -a x"$libstrl_found" != x"yes"
then
	AC_MSG_ERROR(no strlcpy/strlcat found)
fi

AC_CHECK_HEADERS([strl.h], [strl_h_found="yes"])
if test x"$strl_h_found" != x"yes"
then
	strldirs="/usr/local/include /usr/include"

	for d in $strldirs
	do
		AC_MSG_CHECKING([for strl.h in $d/strl])
		if test -f $d/strl/strl.h
		then
			unset ac_cv_header_strl_h
			saved_CPPFLAGS="$CPPFLAGS"
			CPPFLAGS="$CPPFLAGS -I$d/strl"
			AC_CHECK_HEADERS([strl.h], [strl_h_found="yes"])
			CPPFLAGS="$saved_CPPFLAGS"
		fi

		if test x"$strl_h_found" = x"yes"
		then
			CPPFLAGS="$CPPFLAGS -I$d/strl"
			break
		fi
	done
fi

# we need to include <strl.h> if an installed strl.h was found and no
# bsd/string.h was found
if test x"$strl_h_found" = x"yes" -a x"$bsdstrl_h_found" = x"no"
then
	AC_DEFINE([USE_STRL_H], 1,
	          [Define to 1 if you need to include <strl.h> to get the `strlcat()' and `strlcpy()' functions.])
fi

if test x"$bsdstrl_h_found" = x"yes"
then
	AC_DEFINE([USE_BSD_H], 1,
	          [Define to 1 if you need to include <bsd/string.h> to get the `strlcat()' and `strlcpy()' functions.])
fi

#
# Checks for structure members
#
AC_CHECK_MEMBER([struct sockaddr_un.sun_len],
                AC_DEFINE([HAVE_SUN_LEN],
                          [1],
                          [Define if sockaddr_un has a sun_len member]),
                [],
                [[#include <sys/un.h>]])

AC_CHECK_MEMBER([struct sockaddr_in.sin_len],
                AC_DEFINE([HAVE_SIN_LEN],
                          [1],
                          [Define if sockaddr_in has a sin_len member]),
                [],
                [[#include <netinet/in.h>]])

AC_CHECK_MEMBER([struct sockaddr_in6.sin6_len],
                AC_DEFINE([HAVE_SIN6_LEN],
                          [1],
                          [Define if sockaddr_in6 has a sin6_len member]),
                [],
                [[#include <netinet/in.h>]])

#
# Library feature string and macros
#
LIBOPENARC_FEATURE_STRING="libopenarc $PACKAGE_VERSION:"

AC_DEFUN([TR_UP], [m4_translit([AS_TR_SH([$1])], [a-z], [A-Z])])

AC_DEFUN([FEATURE],
         [notincluded="(Not enabled for this installation.)"
          AC_ARG_ENABLE($1, AS_HELP_STRING(--enable-$1, $2),
                        AS_IF([test "x$enable_]$1[" = "xyes"],
                              [
				AC_SUBST(TR_UP($1)[_MANNOTICE], "")
				AC_DEFINE(TR_UP($1), 1, [enable $1 feature])
			      ],
			      [
				AC_SUBST(TR_UP($1)[_MANNOTICE], $notincluded)
			      ]),
                        AC_SUBST(TR_UP($1)[_MANNOTICE], $notincluded))
         ])

AC_DEFUN([LIB_FEATURE],
         [FEATURE($1, $2)
          AS_IF([test "x$enable_]$1[" = "xyes"],
	        [
			LIBOPENARC_FEATURE_STRING="$LIBOPENARC_FEATURE_STRING $1"
		])
         ])

AC_DEFUN([FFR_FEATURE],
         [experimentalnotincluded="(Experimental feature not enabled for this installation.)"
          AC_ARG_ENABLE($1, AS_HELP_STRING(--enable-$1, $2),
                        AS_IF([test "x$enable_]$1[" = "xyes"],
                              [
				AC_DEFINE([_FFR_]TR_UP($1), 1,
				          [enable $1 feature])
				AC_SUBST(TR_UP($1)[_MANNOTICE],
				         "(Note: Feature is experimental.)")
                              ],
                              [
				AC_SUBST(TR_UP($1)[_MANNOTICE],
				         $experimentalnotincluded)
                              ]),
                        AC_SUBST(TR_UP($1)[_MANNOTICE],
                                 $experimentalnotincluded))
         ])

AC_DEFUN([LIB_FFR_FEATURE],
         [FFR_FEATURE($1, $2)
          AS_IF([test "x$enable_]$1[" = "xyes"],
                [
			LIBOPENARC_FEATURE_STRING="$LIBOPENARC_FEATURE_STRING $1"
		])
         ])

#
# openarc
#

FEATURE([poll], [use poll() instead of select()])

# sendmail command

AC_PATH_PROG([SENDMAIL_PATH], [sendmail], [/usr/sbin/sendmail],
             [/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/lib:$PATH])
AC_DEFINE_UNQUOTED([SENDMAIL_PATH], "$ac_cv_path_SENDMAIL_PATH",
                   [The path the the sendmail executable for report sending])
AC_SUBST([SENDMAIL_PATH])

#
# use rpath at load time?
#

AC_ARG_ENABLE(
	[rpath],
	AS_HELP_STRING([--enable-rpath],
	               [include library load paths in binaries]),
	,
	enable_rpath="yes")
AM_CONDITIONAL([RPATH], [test x"$enable_rpath" = x"yes"])
if test x"$enable_rpath" != x"yes"
then
	AC_MSG_RESULT([Suppressing -rpath use by libtool])
	hardcode_libdir_flag_spec=" -D__LIBTOOL_NO_RPATH__ "
	chmod 0755 libtool
fi

#
# test coverage/profiling stuff
# 
AC_ARG_ENABLE([codecoverage],
	AS_HELP_STRING([--enable-codecoverage],
	               [include code coverage/profiling code]))
if test x"$enable_codecoverage" = x"yes"
then
	# gcc can do all of them; Solaris cc can only do gprof
	AC_CHECK_PROG([hasgcc], [gcc], [yes])
	AC_CHECK_PROG([hascc], [cc], [yes])
	if test x"$hasgcc" != x"yes" -a x"$hascc" = x"yes"
	then
		if test x`cc -V 2>&1 | grep -c "Sun C"` = x"1"
		then
			hassuncc="yes"
		fi
	fi

	# figure out which profiling system to use
	AC_CHECK_PROG([hasgprof], [gprof], [yes])
	AC_ARG_WITH(gprof,
		AS_HELP_STRING(--with-gprof, profiling with gprof),
		hasgprof="$withval")
	if test x"$hasgcc" = x"yes"
	then
		AC_CHECK_PROG([hasgcov], [gcov], [yes])
		AC_ARG_WITH(gcov,
			AS_HELP_STRING(--with-gcov, profiling with gcov),
			hasgcov="$withval")
		AC_CHECK_PROG([haslcov], [lcov], [yes])
		AC_ARG_WITH(lcov,
			AS_HELP_STRING(--with-lcov, profiling with lcov),
			haslcov="$withval")
	fi

	# bail if none
	if test x"$hasgprof" != x"yes" -a \
		x"$hasgcov" != x"yes" -a \
		x"$haslcov" != x"yes"
	then
		AC_MSG_ERROR([no supported test coverage packages found])
	fi

	# see if there's a libgcov (OpenBSD doesn't have one)
	if test x"$hasgcov" = x"yes" -a x"$haslcov" != x"yes"
	then
		saved_LIBS="$LIBS"
		LIBS="$outer_LIBS"
		AC_SEARCH_LIBS([__gcov_init], [gcov])
		GCOV_LIBS="$LIBS"
		LIBS="$saved_LIBS"
	fi

	COV_CFLAGS=""
	COV_LDFLAGS=""
	COV_LIBADD=""

	# sun profiling
	if test x"$hasgprof" = x"yes" -a \
	        x"$hasgcov" != x"yes" -a \
	        x"$hassuncc" = x"yes"
	then
		COV_CFLAGS="-g -xpg"
		COV_LDFLAGS="-g -xpg"
	# non-sun profiling
	elif test x"$hasgprof" = x"yes" -a \
		x"$hasgcov" != x"yes" -a \
		x"$hassuncc" != x"yes"
	then
		COV_CFLAGS="-g -pg"
		COV_LDFLAGS="-g -pg"
	# gcov profiling
	elif test x"$hasgcov" = x"yes"
	then
		COV_CFLAGS="-g -fprofile-arcs -ftest-coverage"
		COV_LIBADD="$GCOV_LIBS"
	fi

	AC_SUBST(COV_CFLAGS)
	AC_SUBST(COV_LDFLAGS)
	AC_SUBST(COV_LIBADD)
fi

# see if profiling-enabled binaries generate profile output with the
# standard name "gmon.out" or "<file>.gmon"

gprof_gmon_out="unknown"
if test x"$hasgprof" = x"yes"
then
	gprofcheck='
int main() {
	long x;

	x = random();
}'
	AC_MSG_CHECKING([names of profiling output files])

	saved_CFLAGS="$CFLAGS"
	saved_LDFLAGS="$LDFLAGS"

	CFLAGS="$CFLAGS $COV_CFLAGS"
	LDFLAGS="$LDFLAGS $COV_LDFLAGS"

	AC_RUN_IFELSE([AC_LANG_SOURCE([$gprofcheck])],
	              [	if test -f "gmon.out"
			then
				gprof_gmon_out="yes"
				rm -f gmon.out
				AC_MSG_RESULT(gmon.out)
			else
				gprof_gmon_out="no"
				rm -f *.gmon
				AC_MSG_RESULT([<binary>.gmon])
			fi
	              ],
	              [AC_MSG_RESULT(unknown)])

	CFLAGS="$saved_CFLAGS"
	LDFLAGS="$saved_LDFLAGS"
fi

AM_CONDITIONAL(LCOV, test x"$haslcov" = x"yes" -a x"$hasgcov" = x"yes")
AM_CONDITIONAL(GCOV, test x"$hasgcov" = x"yes")
AM_CONDITIONAL(GCOV_ONLY, test x"$hasgcov" = x"yes" -a x"$haslcov" != x"yes")
AM_CONDITIONAL(GPROF, test x"$hasgprof" = x"yes" -a x"$hasgcov" != x"yes")
AM_CONDITIONAL(GPROF_FILENAMES, test x"$gprof_gmon_out" = x"no")

#
# openarc
# 
AC_ARG_ENABLE([filter],
              AS_HELP_STRING([--disable-filter],
                             [do not compile the openarc filter]),
              [enable_filter=$enableval],
              [enable_filter=yes])
AM_CONDITIONAL([BUILD_FILTER], [test x"$enable_filter" != x"no"])

#
# Conditional stuff
#
AC_ARG_ENABLE([allsymbols],
              AS_HELP_STRING([--enable-allsymbols],
                             [export internal-use symbols for better test coverage]))
AM_CONDITIONAL(ALL_SYMBOLS, [test x"$enable_allsymbols" = x"yes"])

# the AM_CONDITIONAL and AC_DEFINE for USE_ARLIB are farther below,
# after the Darwin checks

AC_ARG_ENABLE([debug],
              AS_HELP_STRING([--enable-debug],
	                     [produce debugging binaries and libraries]),
              AS_IF([test "x$enable_debug" = x"yes"],
		[
			LIBOPENARC_FEATURE_STRING="$LIBOPENARC_FEATURE_STRING debug"
			[[CFLAGS=`echo $CFLAGS | sed 's/ -O[1-9s]*//g'`]]
		])
)

AM_CONDITIONAL([DEBUG], [test x"$enable_debug" = x"yes"])

#
# OpenSSL
#

AC_ARG_WITH([openssl],
            AS_HELP_STRING([--with-openssl],
                           [location of OpenSSL includes and library]),
                           [sslpath="$withval"], [sslpath="auto"])

openssl_found="no"

if test \( "$sslpath" = "auto" -o x"$sslpath" = x"yes" \) -a x"$PKG_CONFIG" != x""
then
	PKG_CHECK_MODULES([LIBCRYPTO], [openssl >= 0.9.7],
	                  [openssl_found="yes"],
	                  [openssl_found="no"
	                   AC_MSG_WARN([pkg-config for openssl not found, trying manual search...])
	                  ])
elif test "$sslpath" != "auto" -a x"$sslpath" != x"yes"
then
	AC_MSG_CHECKING([for OpenSSL includes])
	if test -f $sslpath/include/openssl/opensslv.h
	then
		LIBCRYPTO_CPPFLAGS="-I$sslpath/include"
		LIBCRYPTO_CFLAGS=""
		LIBCRYPTO_LIBDIRS="-L$sslpath/lib"
		LIBCRYPTO_LIBS="-lssl -lcrypto"
		openssl_found=yes
		AC_MSG_RESULT([$sslpath])
	else
		AC_MSG_RESULT([no])
	fi
fi

if test x"$openssl_found" = x"no"
then
	AC_MSG_CHECKING([for OpenSSL library and includes])
	ssldirs="/usr/local/ssl /usr/local /usr/sfw /opt/local /usr"
	if test "$sslpath" = "auto" -o "$sslpath" = "yes"
	then
		for d in $ssldirs
		do
			if test -f $d/include/openssl/opensslv.h
			then
				sslpath=$d
				openssl_found=yes
				break
			fi
		done
	fi
	case "$sslpath" in
		no)
			AC_MSG_ERROR([OpenSSL is required])
			;;
		auto)
			AC_MSG_ERROR([OpenSSL not found])
			;;
		*/*)
			AC_MSG_RESULT([$sslpath])
			;;
		*)
			AC_MSG_ERROR([OpenSSL not found])
			;;
	esac
        LIBCRYPTO_CPPFLAGS="-I$sslpath/include"
        LIBCRYPTO_CFLAGS=""
        LIBCRYPTO_LIBDIRS="-L$sslpath/lib"
        LIBCRYPTO_LIBS="-lssl -lcrypto"
fi

if test x"$openssl_found" = x"yes"
then
	saved_CFLAGS="$CFLAGS"
	saved_CPPFLAGS="$CPPFLAGS"
	saved_LDFLAGS="$LDFLAGS"
	saved_LIBS="$LIBS"

	LIBS="$outer_LIBS $LIBCRYPTO_LIBS $saved_LIBS"
	CPPFLAGS="$LIBCRYPTO_CPPFLAGS $saved_CPPFLAGS"
	CFLAGS="$LIBCRYPTO_CFLAGS $saved_CFLAGS"
	LDFLAGS="$outer_LDFLAGS $LIBCRYPTO_LIBDIRS $saved_LDFLAGS"

	AC_CHECK_HEADERS([openssl/bio.h openssl/conf.h openssl/crypto.h openssl/err.h openssl/evp.h openssl/md5.h openssl/opensslv.h openssl/pem.h openssl/rsa.h openssl/sha.h openssl/ssl.h], ,
                 	AC_MSG_ERROR([required OpenSSL header not found]))

	# -ldl is needed to assist with compilation of static openssl libraries.
	# It appears to need dl for opening engine plugins. It fails at load
	# time It also fails to build on FreeBSD if enabled by default.
	AC_SEARCH_LIBS([ERR_peek_error], [crypto], ,
	               AC_MSG_ERROR([libcrypto not found]))

	AC_SEARCH_LIBS([SSL_library_init], [ssl], ,
		[
			if test x"$enable_shared" = x"yes"
			then
				AC_MSG_ERROR([Cannot build shared openarc
				              against static openssl libraries.
				              Configure with --disable-shared
				              to get this working or obtain a
				              shared libssl library for
				              openarc to use.])
			fi

			# avoid caching issue - last result of SSL_library_init
			# shouldn't be cached for this next check
			unset ac_cv_search_SSL_library_init
			LIBCRYPTO_LIBS="$LIBCRYPTO_LIBS -ldl"
			AC_SEARCH_LIBS([SSL_library_init], [ssl], ,
			               AC_MSG_ERROR([libssl not found]), [-ldl])
		]
	)

	AC_CHECK_DECL([SHA256_DIGEST_LENGTH],
                      AC_DEFINE([HAVE_SHA256], 1,
 	                        [Define to 1 if your crypto library has SHA256 support]),
	              AC_MSG_WARN([SHA256 is required for DKIM but is not
	                           supported with your version of OpenSSL]),
	              [
#include <sys/types.h>
#include <openssl/sha.h>])

	CFLAGS="$saved_CFLAGS"
	CPPFLAGS="$saved_CPPFLAGS"
	LDFLAGS="$saved_LDFLAGS"
	LIBS="$saved_LIBS"
fi

AC_SUBST(LIBCRYPTO_CFLAGS)
AC_SUBST(LIBCRYPTO_CPPFLAGS)
AC_SUBST(LIBCRYPTO_LIBDIRS)
AC_SUBST(LIBCRYPTO_LIBS)

#
# libmilter
#
AC_MSG_CHECKING([for milter library and includes])
AC_ARG_WITH([milter],
            AS_HELP_STRING([--with-milter],
                           [location of milter includes and library]),
            [milterpath="$withval"], [milterpath="auto"])

if test x"$enable_filter" = x"no"
then
	milterpath="no"
fi

if test "$milterpath" = "auto" -o "$milterpath" = "yes"
then
	milterdirs="/usr/local /opt/local /usr"
	for d in $milterdirs
	do
		if test -f $d/include/libmilter/mfapi.h
		then
			milterpath=$d
			break
		fi
	done
fi
case "$milterpath" in
	no)
		if test x"$enable_filter" = x"yes"
		then
			AC_MSG_ERROR([milter is required])
		fi
		AC_MSG_RESULT(disabled)
		;;
	auto)
		AC_MSG_ERROR([milter not found])
		;;
	*/*)
		if ! test -f $milterpath/include/libmilter/mfapi.h
		then
			AC_MSG_ERROR([milter includes not found at $milterpath])
		fi
		AC_MSG_RESULT([$milterpath])
		;;
	*)
		AC_MSG_ERROR([milter not found])
		;;
esac

LIBMILTER_INCDIRS=""
LIBMILTER_LIBDIRS=""
LIBMILTER_LIBS=""

if test x"$milterpath" != x"no"
then
	LIBMILTER_INCDIRS="-I$milterpath/include"

	saved_CC="$CC"
	saved_CFLAGS="$CFLAGS"
	saved_CPPFLAGS="$CPPFLAGS"
	saved_LDFLAGS="$LDFLAGS"
	saved_LIBS="$LIBS"

	CC="$PTHREAD_CC"
	LIBS="$outer_LIBS $PTHREAD_LIBS $saved_LIBS"
	CPPFLAGS="$LIBMILTER_INCDIRS $saved_CPPFLAGS"
	CFLAGS="$PTHREAD_CFLAGS $saved_CFLAGS"
	LDFLAGS="$outer_LDFLAGS $PTHREAD_CFLAGS $saved_LDFLAGS"

	breakloop="no"
	for d in lib lib64 lib/libmilter
	do
		unset ac_cv_search_smfi_register
		LDFLAGS="$outer_LDFLAGS $PTHREAD_CFLAGS -L$milterpath/$d $saved_LDFLAGS"
		AC_SEARCH_LIBS([smfi_register], [milter],
		               [
		               	LIBMILTER_LIBDIRS="-L$milterpath/$d"
		               	LIBMILTER_LIBS="-lmilter"
		               	breakloop="yes"
		               ])

		AC_CHECK_FUNC([smfi_insheader],
			      AC_DEFINE([HAVE_SMFI_INSHEADER], 1,
					[Define if libmilter has smfi_insheader()]))

		AC_CHECK_FUNC([smfi_opensocket],
			      AC_DEFINE([HAVE_SMFI_OPENSOCKET], 1,
					[Define if libmilter has smfi_opensocket()]))

		AC_CHECK_FUNC([smfi_progress],
			      AC_DEFINE([HAVE_SMFI_PROGRESS], 1,
					[Define if libmilter has smfi_progress()]))

		AC_CHECK_FUNC([smfi_setsymlist],
			      AC_DEFINE([HAVE_SMFI_SETSYMLIST], 1,
					[Define if libmilter has smfi_setsymlist()]))

		AC_CHECK_FUNC([smfi_version],
			      AC_DEFINE([HAVE_SMFI_VERSION], 1,
					[Define if libmilter has smfi_version()]))

		if test x"$breakloop" = x"yes"
		then
			break
		fi
	done
	if test x"$LIBMILTER_LIBDIRS" = x""
	then
		AC_MSG_ERROR([libmilter not found])
	fi

	CC="$saved_CC"
	CPPFLAGS="$saved_CPPFLAGS"
	CFLAGS="$saved_CFLAGS"
	LDFLAGS="$saved_LDFLAGS"
	LIBS="$saved_LIBS"
fi

AC_SUBST(LIBMILTER_INCDIRS)
AC_SUBST(LIBMILTER_LIBDIRS)
AC_SUBST(LIBMILTER_LIBS)

# This (below) is just for the pkg-config file openarc.pc.in
LIBOPENARC_LIBS_PKG="$LIBOPENARC_LIBS"
LIBOPENARC_INC="$LIBCRYPTO_CPPFLAGS $LIBCRYPTO_CFLAGS $LIBTRE_CPPFLAGS"

if test x"$USE_DB_LIBOPENARC_TRUE" = x""
then
	LIBOPENARC_INC="$LIBOPENARC_INC $LIBDB_INCDIRS"
	LIBOPENARC_LIBS_PKG="$LIBOPENARC_LIBS_PKG $LIBDB_LIBS"
	LIBOPENARC_LIBS="$LIBOPENARC_LIBS $LIBDB_LIBS"
fi

AC_SUBST(LIBOPENARC_LIBS)
AC_SUBST(LIBOPENARC_LIBS_PKG)
AC_SUBST(LIBOPENARC_INC)

AC_DEFINE_UNQUOTED([LIBOPENARC_FEATURE_STRING], "$LIBOPENARC_FEATURE_STRING",
                   [Feature string for printing])

#
# setup for testing
# 

AC_ARG_ENABLE([live-testing],
              AS_HELP_STRING([--disable-live-testing],
                             [disable tests that require Internet access]),
              [live_tests="$enable_live_testing"], [live_tests="yes"])
AM_CONDITIONAL(LIVE_TESTS, test x"$live_tests" = x"yes")

#
# specify test socket
# 

AC_ARG_WITH([test-socket],
            AS_HELP_STRING([--with-test-socket],
                           [specify socket to use for all tests]),
            [testsocket="$withval"], [testsocket=""])
AM_CONDITIONAL(TEST_SOCKET, test x"$testsocket" != x"")
if test x"$testsocket" != x""
then
	TESTSOCKET=$testsocket
	AC_SUBST(TESTSOCKET)
fi

#
# Platform Specific Configuration
#
AC_CANONICAL_HOST
case "$host" in
	*-darwin*)
		CPPFLAGS="$CPPFLAGS -DBIND_8_COMPAT -DDARWIN"
		if test x"$unboundpath" = x"no"
		then
			AC_MSG_ERROR("unbound required on Darwin")
		fi
		;;
esac

#
# Determine domainname for sample configs
#
AC_ARG_WITH([domain],
            AS_HELP_STRING([--with-domain],
                           [name of the domain for signing - sets this in sample configuration files]),
            [
                 DOMAIN="$withval"
	    ],[
                 AC_PATH_PROG(domainname, domainname)
	         AS_IF([test x"$domainname" != x""],
	         	[DOMAIN=`$domainname`],
		 )
		 AS_IF([test x"$DOMAIN" = x"" -o x"$DOMAIN" = x"(none)" ],
	         		[DOMAIN=example.com]
		 )
	    ]
	    )

AC_SUBST([DOMAIN])

#
# final command line tweaks
#

CPPFLAGS="$CPPFLAGS -DCONFIG_BASE=\\\"$sysconfdir\\\""

test "x$prefix" = xNONE && prefix=$ac_default_prefix 
SYSCONFDIR=`eval echo "$sysconfdir"`
AC_SUBST([SYSCONFDIR])

#
# for contrib/spec/openarc.spec.in
#

installbin="no"
specconfig=""
specrequires=""
specbuildrequires=""

SPECBINDIR=""
if test x"$installbin" = x"yes"
then
	SPECBINDIR="%{_bindir}/*"
fi

SPECCONFIGURE="$specconfig"

if test x"$specrequires" = x""
then
	SPECREQUIRES=""
else
	SPECREQUIRES="Requires:$specrequires"
fi

if test x"$specbuildrequires" = x""
then
	SPECBUILDREQUIRES=""
else
	SPECBUILDREQUIRES="BuildRequires:$specbuildrequires"
fi

AC_SUBST(SPECBINDIR)
AC_SUBST(SPECCONFIGURE)
AC_SUBST(SPECREQUIRES)
AC_SUBST(SPECBUILDREQUIRES)

#
# Finish up
#

AC_OUTPUT([	Makefile
		docs/Makefile
		contrib/Makefile
			contrib/docs/Makefile
			contrib/init/Makefile
			contrib/init/generic/Makefile
			contrib/init/redhat/Makefile
			contrib/init/redhat/openarc
			contrib/init/solaris/Makefile
			contrib/spec/Makefile
			contrib/spec/openarc.spec
			contrib/systemd/Makefile
			contrib/systemd/openarc.service
		libopenarc/openarc.pc libopenarc/Makefile
		libopenarc/docs/Makefile
		openarc/Makefile openarc/openarc.8 openarc/openarc.conf.5
			openarc/openarc.conf.simple
])
		#libopenarc/tests/Makefile
		#openarc/tests/Makefile
