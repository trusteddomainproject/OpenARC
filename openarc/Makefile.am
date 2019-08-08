# Copyright (c) 2010-2014, 2016, 2017, The Trusted Domain Project.
# All rights reserved.

if DEBUG
AM_CFLAGS = -g
endif

if BUILD_FILTER
dist_doc_DATA = openarc.conf.sample openarc.conf.simple

man_MANS = openarc.conf.5 openarc.8

sbin_PROGRAMS = openarc
openarc_SOURCES = config.c config.h openarc.c openarc.h openarc-ar.c openarc-ar.h openarc-config.h openarc-crypto.c openarc-crypto.h openarc-test.c openarc-test.h util.c util.h
openarc_CC = $(PTHREAD_CC)
openarc_CFLAGS = $(PTHREAD_CFLAGS) $(LIBCRYPTO_CFLAGS)
openarc_CPPFLAGS = -I$(srcdir)/../libopenarc $(LIBCRYPTO_CPPFLAGS) $(LIBMILTER_INCDIRS) $(LIBJANSSON_CPPFLAGS)
openarc_LDFLAGS = $(LIBCRYPTO_LIBDIRS) $(LIBMILTER_LIBDIRS) $(PTHREAD_CFLAGS) $(LIBJANSSON_LDFLAGS)
openarc_LDADD = ../libopenarc/libopenarc.la $(LIBMILTER_LIBS) $(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) $(LIBJANSSON_LIBS) $(LIBRESOLV)
endif
