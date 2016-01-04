#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT(gameserv, 1.0.00, duoyi@example.com)

AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([serv/main.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for libraries.
AC_PROG_RANLIB
AC_PROG_LIBTOOL


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_gettime gethostbyname gettimeofday inet_ntoa memset socket strerror])

AC_CHECK_LIB(pthread, pthread_create) 

GLOBAL_CFLAGS=-DVDEBUG

AC_SUBST(GLOBAL_CFLAGS)

AC_CONFIG_FILES([Makefile
				 client/Makefile
				 common/Makefile
				 include/Makefile include/common/Makefile 
				 serv/Makefile ])


AC_OUTPUT
