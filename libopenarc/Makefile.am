# Copyright (c) 2016, 2017, The Trusted Domain Project.  All rights reserved.

#SUBDIRS=tests docs
SUBDIRS=docs

if DEBUG
AM_CFLAGS = -g
endif
LDADD = ./libopenarc.la

lib_LTLIBRARIES = libopenarc.la
libopenarc_la_SOURCES = base64.c base64.h arc.c arc.h arc-canon.c arc-canon.h arc-dns.c arc-dns.h arc-internal.h arc-keys.c arc-keys.h arc-tables.c arc-tables.h arc-types.h arc-util.c arc-util.h
libopenarc_la_CPPFLAGS = $(LIBCRYPTO_CPPFLAGS)
libopenarc_la_CFLAGS = $(LIBCRYPTO_INCDIRS) $(LIBOPENARC_INC)
libopenarc_la_LDFLAGS = -no-undefined  $(LIBCRYPTO_LIBDIRS) -version-info $(LIBOPENARC_VERSION_INFO)
libopenarc_la_LIBADD = $(LIBOPENARC_LIBS) $(LIBCRYPTO_LDADD)
if !ALL_SYMBOLS
libopenarc_la_DEPENDENCIES = symbols.map
libopenarc_la_LDFLAGS += -export-symbols symbols.map
endif
if RPATH
libopenarc_la_LDFLAGS += -rpath $(libdir)
endif
libopenarc_includedir = $(includedir)/openarc
libopenarc_include_HEADERS = arc.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = openarc.pc

DISTCLEANFILES=symbols.map *.gcno *.gcda

symbols.map: $(libopenarc_include_HEADERS)
	grep '^extern' $? | \
		awk '{ for (c = 1; c <= NF; c++) if ($$c ~ /arc_/) { print $$c; break; } }' | \
		sed -e s/\[\*\;\]//g -e s/\[\\\[\\\]\]//g -e s/\(.*// | \
		sort -u -o $@

MOSTLYCLEANFILES=symbols.map *.gcno *.gcda
