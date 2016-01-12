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

# Checks for libraries.
AC_PROG_RANLIB
AC_PROG_LIBTOOL


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

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
#AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero clock_gettime gethostbyname gettimeofday inet_ntoa memset mkfifo socket strerror])

AC_CHECK_LIB(pthread, pthread_create) 

# enable debug or not                                                          
AC_ARG_ENABLE(debug,
              AS_HELP_STRING([--enable-debug], [enable DEBUG mode(default=no)]), [],
              [enable_debug=no])
AS_IF([test "${enable_debug}" = "yes"], [
       CFLAGS="-g2 -O0 -DDEBUG -Wall"
       CXXFLAGS="-g2 -O0 -DDEBUG -Wall"
       ], 
	  [test "${enable_debug}" = "no"], [
       CFLAGS="-O2 -Wall"
       CXXFLAGS="-O2 -Wall"
       ], [])     

AC_ARG_ENABLE(verbose, 
              AS_HELP_STRING([--enable-verbose], [enable printf verbose log (default=no)]), [],
              [enable_verbose=no]) 
AS_IF([test "${enable_verbose}" != "no"], [
       CFLAGS="${CFLAGS} -DVDEBUG"
       CXXFLAGS="${CXXFLAGS} -DVDEBUG"
       ])


LIBPTHREAD=""
AC_SEARCH_LIBS(pthread_rwlock_init, pthread pthreads c_r, [
  AS_IF([test "$ac_cv_search_pthread_rwlock_init" != "none required"], [
    LIBPTHREAD="$ac_cv_search_pthread_rwlock_init"
  ])
])
AC_SUBST(LIBPTHREAD)

#LIBRT=""
#AC_CHECK_LIB(rt, clock_gettime, [LIBRT="-lrt"])
#AC_SUBST(LIBRT)

AC_CHECK_LIB(rt, clock_gettime, [SERV_ADD_LIBS([servcore],[-lrt])])

GLOBAL_CFLAGS=
AC_SUBST(GLOBAL_CFLAGS)

AC_CONFIG_FILES([Makefile
				 client/Makefile
				 common/Makefile
				 include/Makefile include/common/Makefile 
				 serv/Makefile ])


AC_OUTPUT
