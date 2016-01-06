
AM_CFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libclient.la
libclient_la_SOURCES = client.c
libclient_la_LIBADD = $(top_srcdir)/common/libcommon.a -lrt

clientincludedir=$(includedir)
clientinclude_HEADERS=client.h

