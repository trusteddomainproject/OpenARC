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

/* struct arc_sha1 -- stuff needed to do a sha1 hash */
struct arc_sha1
{
	int			sha1_tmpfd;
	BIO *			sha1_tmpbio;
	SHA_CTX			sha1_ctx;
	u_char			sha1_out[SHA_DIGEST_LENGTH];
};

#ifdef HAVE_SHA256
/* struct arc_sha256 -- stuff needed to do a sha256 hash */
struct arc_sha256
{
	int			sha256_tmpfd;
	BIO *			sha256_tmpbio;
	SHA256_CTX		sha256_ctx;
	u_char			sha256_out[SHA256_DIGEST_LENGTH];
};
#endif /* HAVE_SHA256 */

/* struct arc_dstring -- a dynamically-sized string */
struct arc_dstring
{
	int			ds_alloc;
	int			ds_max;
	int			ds_len;
	unsigned char *		ds_buf;
	ARC_MESSAGE *		ds_msg;
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

/* hdr_flags bits */
#define	ARC_HDR_SIGNED		0x01

/* struct arc_plist -- a parameter/value pair */
struct arc_plist
{
	u_char *		plist_param;
	u_char *		plist_value;
	struct arc_plist *	plist_next;
};

/* struct arc_set -- a set of parameter/value pairs */
struct arc_kvset
{
	_Bool			set_bad;
	arc_kvsettype_t		set_type;
	u_char *		set_data;
	struct arc_plist *	set_plist[NPRINTABLE];
	struct arc_kvset *	set_next;
};

/* struct arc_canon -- a canonicalization status handle */
struct arc_canon
{
	_Bool			canon_done;
	_Bool			canon_hdr;
	_Bool			canon_blankline;
	int			canon_lastchar;
	int			canon_bodystate;
	u_int			canon_hashtype;
	u_int			canon_blanks;
	size_t			canon_hashbuflen;
	size_t			canon_hashbufsize;
	ssize_t			canon_remain;
	ssize_t			canon_wrote;
	ssize_t			canon_length;
	u_char *		canon_hashbuf;
	u_char *		canon_hdrlist;
	void *			canon_hash;
	struct arc_dstring *	canon_buf;
	struct arc_hdrfield *	canon_sigheader;
	struct arc_canon *	canon_next;
};

/* struct arc_msghandle -- a complete ARC transaction context */
struct arc_msghandle
{
	u_char *		arc_key;
	u_char *		arc_error;
	u_char *		arc_hdrlist;
	u_char *		arc_domain;
	u_char *		arc_selector;
	int			arc_dnssec_key;
	u_int			arc_nsets;
	u_int			arc_state;
	u_int			arc_hdrcnt;
	u_int			arc_timeout;
	arc_query_t		arc_query;
	size_t			arc_keylen;
	size_t			arc_errorlen;
	ssize_t			arc_bodylen;
	ARC_CHAIN		arc_cstate;
	ARC_SIGERROR		arc_sigerror;
	struct arc_dstring *	arc_canonbuf;
	struct arc_dstring *	arc_hdrbuf;
	struct arc_canon *	arc_hdrcanon;
	struct arc_canon *	arc_bodycanon;
	struct arc_canon *	arc_canonhead;
	struct arc_canon *	arc_canontail;
	struct arc_hdrfield *	arc_hhead;
	struct arc_hdrfield *	arc_htail;
	struct arc_kvset *	arc_kvsethead;
	struct arc_kvset *	arc_kvsettail;
	ARC_LIB *		arc_library;
	const void *		arc_user_context;
};

/* struct arc_lib -- a ARC library context */
struct arc_lib
{
	u_int			arcl_flsize;
	uint32_t		arcl_flags;
	u_int *			arcl_flist;
	struct arc_dstring *	arcl_sslerrbuf;
	u_int			arcl_callback_int;
	void			(*arcl_dns_callback) (const void *context);
	void			*arcl_dns_service;
	int			(*arcl_dns_init) (void **srv);
	void			(*arcl_dns_close) (void *srv);
	int			(*arcl_dns_start) (void *srv, int type,
				                   unsigned char *query,
				                   unsigned char *buf,
				                   size_t buflen,
				                   void **qh);
	int			(*arcl_dns_cancel) (void *srv, void *qh);
	int			(*arcl_dns_waitreply) (void *srv,
				                       void *qh,
				                       struct timeval *to,
				                       size_t *bytes,
				                       int *error,
				                       int *dnssec);
	u_char			arcl_tmpdir[MAXPATHLEN + 1];
	u_char			arcl_queryinfo[MAXPATHLEN + 1];
};

#endif /* _ARC_TYPES_H_ */
