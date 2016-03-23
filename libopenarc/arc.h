/*
**  Copyright (c) 2016, The Trusted Domain Project.  All rights reserved.
*/

#ifndef _ARC_H_
#define _ARC_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <inttypes.h>
#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif /* HAVE_LIMITS_H */

/*
**  version -- 0xrrMMmmpp
**  
**  	rr == release number
**  	MM == major revision number
**  	mm == minor revision number
**  	pp == patch number
*/

#define	OPENARC_LIB_VERSION	0x00010000

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

/* definitions */
#define ARC_HDRMARGIN		75	/* "standard" header margin */
#define ARC_MAXHEADER		4096	/* buffer for caching one header */
#define	ARC_MAXHOSTNAMELEN	256	/* max. FQDN we support */

#define	ARC_AR_HDRNAME		"ARC-Authentication-Results"
#define	ARC_MSGSIG_HDRNAME	"ARC-Message-Signature"
#define	ARC_SEAL_HDRNAME	"ARC-Seal"

/* special DNS tokens */
#define	ARC_DNSKEYNAME		"_domainkey"

/*
**  ARC_STAT -- status code type
*/

typedef int ARC_STAT;

#define	ARC_STAT_OK		0	/* function completed successfully */
#define	ARC_STAT_BADSIG		1	/* signature available but failed */
#define	ARC_STAT_NOSIG		2	/* no signature available */
#define	ARC_STAT_NOKEY		3	/* public key not found */
#define	ARC_STAT_CANTVRFY	4	/* can't get domain key to verify */
#define	ARC_STAT_SYNTAX		5	/* message is not valid syntax */
#define	ARC_STAT_NORESOURCE	6	/* resource unavailable */
#define	ARC_STAT_INTERNAL	7	/* internal error */
#define	ARC_STAT_REVOKED	8	/* key found, but revoked */
#define	ARC_STAT_INVALID	9	/* invalid function parameter */
#define	ARC_STAT_NOTIMPLEMENT	10	/* function not implemented */
#define	ARC_STAT_KEYFAIL	11	/* key retrieval failed */
#define	ARC_STAT_MULTIDNSREPLY	12	/* multiple DNS replies */
#define	ARC_STAT_SIGGEN		13	/* seal generation failed */

/*
**  ARC_SIGN -- signing method
*/

typedef int arc_alg_t;

#define ARC_SIGN_UNKNOWN	(-2)	/* unknown method */
#define ARC_SIGN_DEFAULT	(-1)	/* use internal default */
#define ARC_SIGN_RSASHA1	0	/* an RSA-signed SHA1 digest */
#define ARC_SIGN_RSASHA256	1	/* an RSA-signed SHA256 digest */

/*
**  ARC_PARAM -- known signature parameters
*/

typedef int arc_param_t;

#define ARC_PARAM_UNKNOWN	(-1)	/* unknown */
#define ARC_PARAM_SIGNATURE	0	/* b */
#define ARC_PARAM_SIGNALG	1	/* a */
#define ARC_PARAM_DOMAIN	2	/* d */
#define ARC_PARAM_SELECTOR	5	/* s */
#define ARC_PARAM_VERSION	7	/* v */
#define ARC_PARAM_INSTANCE	8	/* i */
#define ARC_PARAM_TIMESTAMP	9	/* t */
#define ARC_PARAM_CHAINSTATUS	10	/* cv */
#define ARC_PARAM_KEYPATH	11	/* k */

/*
**  ARC_OPTS -- library-specific options
*/

typedef int arc_opt_t;

/* what operations can be done */
#define ARC_OP_GETOPT		0
#define	ARC_OP_SETOPT		1

typedef int arc_opts_t;

/* what options can be set */
#define	ARC_OPTS_FLAGS		0
#define	ARC_OPTS_TMPDIR		1

/* flags */
#define	ARC_LIBFLAGS_NONE		0x00000000
#define	ARC_LIBFLAGS_FIXCRLF		0x00000001

/* default */
#define	ARC_LIBFLAGS_DEFAULT		ARC_LIBFLAGS_NONE

/*
**  ARC_LIB -- library handle
*/

struct arc_lib;
typedef struct arc_lib ARC_LIB;

/*
**  ARC_MESSAGE -- ARC message context
*/

struct arc_msghandle;
typedef struct arc_msghandle ARC_MESSAGE;

/*
**  ARC_HDRFIELD -- a header field
*/

struct arc_hdrfield;
typedef struct arc_hdrfield ARC_HDRFIELD;

/*
**  PROTOTYPES
*/

/*
**  ARC_ERROR -- log an error message to an ARC message context
**
**  Parameters:
**  	msg -- ARC message context
**  	fmt -- format
**  	... -- arguments
**
**  Return value:
**  	None.
*/

void arc_error __P((ARC_MESSAGE *, const char *, ...));

/*
**  ARC_INIT -- create a library instance
**
**  Parameters:
**  	None.
**
**  Return value:
**  	A new library instance.
*/

ARC_LIB *arc_init(void);

/*
**  ARC_CLOSE -- terminate a library instance
**
**  Parameters:
**  	lib -- library instance to terminate
**
**  Return value:
**  	None.
*/

void arc_close(ARC_LIB *);

/*
** 
**  ARC_OPTIONS -- get/set library options
**
**  Parameters:
**  	lib -- library instance of interest
**  	opt -- ARC_OP_GETOPT or ARC_OP_SETOPT
**  	arg -- ARC_OPTS_* constant
**  	val -- pointer to the new new value (or NULL)
**  	valsz -- size of the thing at val
**
**  Return value:
**  	An ARC_STAT_* constant.
**  	argument.
*/

ARC_STAT arc_options(ARC_LIB *, int, int, void *, size_t);

/*
**  ARC_GETSSLBUF -- retrieve SSL error buffer
**
**  Parameters:
**  	lib -- library handle
**
**  Return value:
**  	Pointer to the SSL buffer in the library handle.
*/

const char *arc_getsslbuf(ARC_LIB *);

/*
**  ARC_MESSAGE -- create a new message handle
**
**  Parameters:
**  	lib -- containing library instance
**  	err -- error string (returned)
**
**  Return value:
**  	A new message instance, or NULL on failure (and "err" is updated).
*/

ARC_MESSAGE *arc_message(ARC_LIB *, const u_char **);

/*
**  ARC_FREE -- deallocate a message object
**
**  Parameters:
**  	msg -- message object to be destroyed
**
**  Return value:
**  	None.
*/

void arc_free(ARC_MESSAGE *);

/*
**  ARC_HEADER_FIELD -- consume a header field
**
**  Parameters:
**  	msg -- message handle
**  	hname -- name of the header field
**  	hlen -- bytes to use at hname
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT arc_header_field(ARC_MESSAGE *, u_char *, size_t);

/*
**  ARC_EOH -- declare no more headers are coming
**
**  Parameters:
**  	msg -- message handle
**
**  Return value:
**  	An ARC_STAT_* constant.
**
**  Notes:
**  	This can probably be merged with arc_eom().
*/

ARC_STAT arc_eoh(ARC_MESSAGE *);

/*
**  ARC_EOM -- declare end of message
**
**  Parameters:
**  	msg -- message handle
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT arc_eom(ARC_MESSAGE *);

/*
**  ARC_GETSEAL -- get the "seal" to apply to this message
**
**  Parameters:
**  	msg -- ARC_MESSAGE object
**  	seal -- seal to apply (returned)
**  	selector -- selector name
**  	domain -- domain name
**  	key -- secret key, printable
**  	keylen -- key length
**
**  Return value:
**  	An ARC_STAT_* constant.
**
**  Notes:
**  	The "seal" is a sequence of prepared header fields that should be
**  	prepended to the message in the presented order.
*/

ARC_STAT arc_getseal(ARC_MESSAGE *, ARC_HDRFIELD **, char *, char *,
                     u_char *, size_t);

/*
**  ARC_HDR_NAME -- extract name from an ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
** 	len -- length of the header field name (returned)
**
**  Return value:
**  	Header field name stored in the object.
*/

u_char *arc_hdr_name(ARC_HDRFIELD *, size_t *);

/*
**  ARC_HDR_VALUE -- extract value from an ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
**
**  Return value:
**  	Header field value stored in the object.
*/

u_char *arc_hdr_value(ARC_HDRFIELD *);

/*
**  ARC_HDR_NEXT -- return pointer to next ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
**
**  Return value:
**  	Pointer to the next ARC_HDRFIELD in the sequence.
*/

ARC_HDRFIELD *arc_hdr_next(ARC_HDRFIELD *hdr);

/*
**  ARC_SSL_VERSION -- report the version of the crypto library against which
**  	the library was compiled, so the caller can ensure it matches
**
**  Parameters:
**  	None.
**
**  Return value:
**  	SSL library version, expressed as a uint64_t.
*/

uint64_t arc_ssl_version(void);

#endif /* _ARC_H_ */
