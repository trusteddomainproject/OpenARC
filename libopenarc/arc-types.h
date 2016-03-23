/*
**  Copyright (c) 2016, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _ARC_TYPES_H_
#define _ARC_TYPES_H_

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <regex.h>

/* OpenSSL includes */
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>

/* libopenarc includes */
#include "arc.h"
#include "arc-internal.h"

/* struct arc_dstring -- a dynamically-sized string */
struct arc_dstring
{
	int			ds_alloc;
	int			ds_max;
	int			ds_len;
	unsigned char *		ds_buf;
	ARC_MESSAGE *		ds_msg;
};

/* struct arc_msghandle -- a complete ARC transaction context */
struct arc_msghandle
{
	u_char *		arc_domain;
	u_char *		arc_selector;
	u_char *		arc_key;
	u_char *		arc_error;
	u_int			arc_state;
	u_int			arc_hdrcnt;
	size_t			arc_keylen;
	size_t			arc_errorlen;
	struct arc_hdrfield *	arc_hhead;
	struct arc_hdrfield *	arc_htail;
	ARC_LIB *		arc_library;
};

/* struct arc_lib -- a ARC library context */
struct arc_lib
{
	uint32_t		arcl_flags;
	struct arc_dstring *	arcl_sslerrbuf;
	u_char			arcl_tmpdir[MAXPATHLEN + 1];
};

/* struct arc_hdrfield -- a header field */
struct arc_hdrfield
{
	uint32_t		hdr_flags;
	size_t			hdr_namelen;
	size_t			hdr_textlen;
	u_char *		hdr_colon;
	u_char *		hdr_text;
	struct arc_hdrfield *	hdr_next;
};

#endif /* _ARC_TYPES_H_ */
