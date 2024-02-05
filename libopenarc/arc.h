/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.  All rights reserved.
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
#define	ARC_DEFAULT_MINKEYSIZE	1024
#define	ARC_MSGSIG_HDRNAME	"ARC-Message-Signature"
#define	ARC_MSGSIG_HDRNAMELEN	sizeof(ARC_MSGSIG_HDRNAME) - 1
#define	ARC_SEAL_HDRNAME	"ARC-Seal"
#define	ARC_SEAL_HDRNAMELEN	sizeof(ARC_SEAL_HDRNAME) - 1

#define	ARC_EXT_AR_HDRNAME	"Authentication-Results"

/* special DNS tokens */
#define	ARC_DNSKEYNAME		"_domainkey"

#define	DKIM_VERSION_KEY	"DKIM1"

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
#define	ARC_STAT_BADALG		14	/* unknown or invalid algorithm */

/*
**  ARC_CHAIN -- chain state
*/

typedef int ARC_CHAIN;

#define	ARC_CHAIN_UNKNOWN	(-1)	/* unknown */
#define	ARC_CHAIN_NONE		0	/* none */
#define	ARC_CHAIN_FAIL		1	/* fail */
#define	ARC_CHAIN_PASS		2	/* pass */

/*
** ARC_CANON_T -- a canoncalization mode
*/

typedef int arc_canon_t;

#define	ARC_CANON_UNKNOWN	(-1)
#define	ARC_CANON_SIMPLE	0
#define	ARC_CANON_RELAXED	1

/*
**  ARC_SIGERROR -- signature errors
*/

typedef int ARC_SIGERROR;

#define ARC_SIGERROR_UNKNOWN		(-1)	/* unknown error */
#define ARC_SIGERROR_OK			0	/* no error */
#define ARC_SIGERROR_VERSION		1	/* unsupported version */
#define ARC_SIGERROR_DOMAIN		2	/* invalid domain (d=/i=) */
#define ARC_SIGERROR_EXPIRED		3	/* signature expired */
#define ARC_SIGERROR_FUTURE		4	/* signature in the future */
#define ARC_SIGERROR_TIMESTAMPS		5	/* x= < t= */
#define ARC_SIGERROR_UNUSED		6	/* OBSOLETE */
#define ARC_SIGERROR_INVALID_HC		7	/* c= invalid (header) */
#define ARC_SIGERROR_INVALID_BC		8	/* c= invalid (body) */
#define ARC_SIGERROR_MISSING_A		9	/* a= missing */
#define ARC_SIGERROR_INVALID_A		10	/* a= invalid */
#define ARC_SIGERROR_MISSING_H		11	/* h= missing */
#define ARC_SIGERROR_INVALID_L		12	/* l= invalid */
#define ARC_SIGERROR_INVALID_Q		13	/* q= invalid */
#define ARC_SIGERROR_INVALID_QO		14	/* q= option invalid */
#define ARC_SIGERROR_MISSING_D		15	/* d= missing */
#define ARC_SIGERROR_EMPTY_D		16	/* d= empty */
#define ARC_SIGERROR_MISSING_S		17	/* s= missing */
#define ARC_SIGERROR_EMPTY_S		18	/* s= empty */
#define ARC_SIGERROR_MISSING_B		19	/* b= missing */
#define ARC_SIGERROR_EMPTY_B		20	/* b= empty */
#define ARC_SIGERROR_CORRUPT_B		21	/* b= corrupt */
#define ARC_SIGERROR_NOKEY		22	/* no key found in DNS */
#define ARC_SIGERROR_DNSSYNTAX		23	/* DNS reply corrupt */
#define ARC_SIGERROR_KEYFAIL		24	/* DNS query failed */
#define ARC_SIGERROR_MISSING_BH		25	/* bh= missing */
#define ARC_SIGERROR_EMPTY_BH		26	/* bh= empty */
#define ARC_SIGERROR_CORRUPT_BH		27	/* bh= corrupt */
#define ARC_SIGERROR_BADSIG		28	/* signature mismatch */
#define ARC_SIGERROR_SUBDOMAIN		29	/* unauthorized subdomain */
#define ARC_SIGERROR_MULTIREPLY		30	/* multiple records returned */
#define ARC_SIGERROR_EMPTY_H		31	/* h= empty */
#define ARC_SIGERROR_INVALID_H		32	/* h= missing req'd entries */
#define ARC_SIGERROR_TOOLARGE_L		33	/* l= value exceeds body size */
#define ARC_SIGERROR_MBSFAILED		34	/* "must be signed" failure */
#define	ARC_SIGERROR_KEYVERSION		35	/* unknown key version */
#define	ARC_SIGERROR_KEYUNKNOWNHASH	36	/* unknown key hash */
#define	ARC_SIGERROR_KEYHASHMISMATCH	37	/* sig-key hash mismatch */
#define	ARC_SIGERROR_NOTEMAILKEY	38	/* not an e-mail key */
#define	ARC_SIGERROR_UNUSED2		39	/* OBSOLETE */
#define	ARC_SIGERROR_KEYTYPEMISSING	40	/* key type missing */
#define	ARC_SIGERROR_KEYTYPEUNKNOWN	41	/* key type unknown */
#define	ARC_SIGERROR_KEYREVOKED		42	/* key revoked */
#define	ARC_SIGERROR_KEYDECODE		43	/* key couldn't be decoded */
#define	ARC_SIGERROR_MISSING_V		44	/* v= tag missing */
#define	ARC_SIGERROR_EMPTY_V		45	/* v= tag empty */
#define	ARC_SIGERROR_KEYTOOSMALL	46	/* too few key bits */
#define	ARC_SIGERROR_DUPINSTANCE	47	/* duplicate instance */

/* generic DNS error codes */
#define	ARC_DNS_ERROR		(-1)		/* error in transit */
#define	ARC_DNS_SUCCESS		0		/* reply available */
#define	ARC_DNS_NOREPLY		1		/* reply not available (yet) */
#define	ARC_DNS_EXPIRED		2		/* no reply, query expired */
#define	ARC_DNS_INVALID		3		/* invalid request */

/*
**  ARC_SIGN -- signing method
*/

typedef int arc_alg_t;

#define ARC_SIGN_UNKNOWN	(-2)	/* unknown method */
#define ARC_SIGN_DEFAULT	(-1)	/* use internal default */
#define ARC_SIGN_RSASHA1	0	/* an RSA-signed SHA1 digest */
#define ARC_SIGN_RSASHA256	1	/* an RSA-signed SHA256 digest */

/*
**  ARC_QUERY -- key query method
*/

typedef int arc_query_t;

#define ARC_QUERY_UNKNOWN	(-1)	/* unknown method */
#define ARC_QUERY_DNS		0	/* DNS query method (per the draft) */
#define ARC_QUERY_FILE		1	/* text file method (for testing) */

#define ARC_QUERY_DEFAULT	ARC_QUERY_DNS

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
#define	ARC_OPTS_FIXEDTIME	2
#define	ARC_OPTS_SIGNHDRS	3
#define	ARC_OPTS_OVERSIGNHDRS	4
#define	ARC_OPTS_MINKEYSIZE	5

/* flags */
#define	ARC_LIBFLAGS_NONE		0x00000000
#define	ARC_LIBFLAGS_FIXCRLF		0x00000001
#define	ARC_LIBFLAGS_KEEPFILES		0x00000002

/* default */
#define	ARC_LIBFLAGS_DEFAULT		ARC_LIBFLAGS_NONE

/*
**  ARC_DNSSEC -- results of DNSSEC queries
*/

#define ARC_DNSSEC_UNKNOWN	(-1)
#define ARC_DNSSEC_BOGUS	0
#define ARC_DNSSEC_INSECURE	1
#define ARC_DNSSEC_SECURE	2

/*
**  ARC_KEYFLAG -- key flags
*/

#define ARC_KEYFLAG_TESTKEY	0x01
#define ARC_KEYFLAG_NOSUBDOMAIN	0x02

/*
**  ARC_MODE -- operating modes
*/

typedef u_int arc_mode_t;

#define	ARC_MODE_SIGN		0x01
#define	ARC_MODE_VERIFY		0x02

/*
**  ARC_LIB -- library handle
*/

struct arc_lib;
typedef struct arc_lib ARC_LIB;

/* LIBRARY FEATURES */
#define	ARC_FEATURE_SHA256	1

#define	ARC_FEATURE_MAX		1

extern _Bool arc_libfeature __P((ARC_LIB *lib, u_int fc));

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

extern void arc_error __P((ARC_MESSAGE *, const char *, ...));

/*
**  ARC_INIT -- create a library instance
**
**  Parameters:
**  	None.
**
**  Return value:
**  	A new library instance.
*/

extern ARC_LIB *arc_init __P((void));

/*
**  ARC_CLOSE -- terminate a library instance
**
**  Parameters:
**  	lib -- library instance to terminate
**
**  Return value:
**  	None.
*/

extern void arc_close __P((ARC_LIB *));

/*
**  ARC_GETERROR -- return any stored error string from within the DKIM
**                  context handle
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle from which to retrieve an error string
**
**  Return value:
**  	A pointer to the stored string, or NULL if none was stored.
*/

extern const char *arc_geterror __P((ARC_MESSAGE *));

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
*/

extern ARC_STAT arc_options __P((ARC_LIB *, int, int, void *, size_t));

/*
**  ARC_GETSSLBUF -- retrieve SSL error buffer
**
**  Parameters:
**  	lib -- library handle
**
**  Return value:
**  	Pointer to the SSL buffer in the library handle.
*/

extern const char *arc_getsslbuf __P((ARC_LIB *));

/*
**  ARC_MESSAGE -- create a new message handle
**
**  Parameters:
**  	lib -- containing library instance
**  	canonhdr -- canonicalization to use for the header
**  	canonbody -- canonicalization to use for the body
**  	signalg -- signing algorithm
**  	mode -- mask of mode bits
**  	err -- error string (returned)
**
**  Return value:
**  	A new message instance, or NULL on failure (and "err" is updated).
*/

extern ARC_MESSAGE *arc_message __P((ARC_LIB *, arc_canon_t, arc_canon_t,
				     arc_alg_t, arc_mode_t, const u_char **));

/*
**  ARC_FREE -- deallocate a message object
**
**  Parameters:
**  	msg -- message object to be destroyed
**
**  Return value:
**  	None.
*/

extern void arc_free __P((ARC_MESSAGE *));

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

extern ARC_STAT arc_header_field __P((ARC_MESSAGE *, u_char *, size_t));

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

extern ARC_STAT arc_eoh __P((ARC_MESSAGE *));

/*
**  ARC_BODY -- process a body chunk
**
**  Parameters:
**  	msg -- an ARC message handle
**  	buf -- the body chunk to be processed, in canonical format
**  	len -- number of bytes to process starting at "buf"
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

extern ARC_STAT arc_body __P((ARC_MESSAGE *msg, u_char *buf, size_t len));

/*
**  ARC_EOM -- declare end of message
**
**  Parameters:
**  	msg -- message handle
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

extern ARC_STAT arc_eom __P((ARC_MESSAGE *));

/*
**  ARC_SET_CV -- force the chain state
**
**  Parameters:
**      msg -- ARC_MESSAGE object
**      cv -- chain state
**
**  Return value:
**  	None.
*/

extern void arc_set_cv __P((ARC_MESSAGE *, ARC_CHAIN));

/*
**  ARC_GETSEAL -- get the "seal" to apply to this message
**
**  Parameters:
**  	msg -- ARC_MESSAGE object
**  	seal -- seal to apply (returned)
**  	authservid -- authservid to use when generating A-R fields
**  	selector -- selector name
**  	domain -- domain name
**  	key -- secret key
**  	keylen -- key length
**  	ar -- Authentication-Results to be enshrined
**
**  Return value:
**  	An ARC_STAT_* constant.
**
**  Notes:
**  	The "seal" is a sequence of prepared header fields that should be
**  	prepended to the message in the presented order.
*/

extern ARC_STAT arc_getseal __P((ARC_MESSAGE *, ARC_HDRFIELD **, char *,
                                 char *, char *, u_char *, size_t, u_char *));

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

extern u_char *arc_hdr_name __P((ARC_HDRFIELD *, size_t *));

/*
**  ARC_HDR_VALUE -- extract value from an ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
**
**  Return value:
**  	Header field value stored in the object.
*/

extern u_char *arc_hdr_value __P((ARC_HDRFIELD *));

/*
**  ARC_HDR_NEXT -- return pointer to next ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
**
**  Return value:
**  	Pointer to the next ARC_HDRFIELD in the sequence.
*/

extern ARC_HDRFIELD *arc_hdr_next __P((ARC_HDRFIELD *hdr));

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

extern uint64_t arc_ssl_version __P((void));

/*
**  ARC_GET_DOMAIN -- retrieve stored domain for this message
**
**  Parameters:
**      msg -- ARC_MESSAGE object
**
**  Return value:
**      Pointer to string containing the domain stored for this message
*/

extern char *arc_get_domain __P((ARC_MESSAGE *msg));

/*
**  ARC_CHAIN_STATUS_STR -- retrieve chain status, as a string
**
**  Parameters:
**      msg -- ARC_MESSAGE object
**
**  Return value:
**      Pointer to string containing the current chain status.
*/

extern const char *arc_chain_status_str __P((ARC_MESSAGE *msg));

/*
**  ARC_CHAIN_CUSTODY_STR -- retrieve domain chain, as a string
**
**  Parameters:
**	msg -- ARC_MESSAGE object
**	buf -- where to write
**	buflen -- bytes at "buf"
**
**  Return value:
**	Number of bytes written. If value is greater than or equal to buflen
**	argument, then buffer was too small and output was truncated.
*/

extern int arc_chain_custody_str __P((ARC_MESSAGE *msg, u_char *buf,
                                      size_t buflen));

/*
**  ARC_MAIL_PARSE -- extract the local-part and domain-name from a structured
**                    header field
**
**  Parameters:
**  	addr -- the header to parse; see RFC2822 for format
**  	user -- local-part of the parsed header (returned)
**  	domain -- domain part of the parsed header (returned)
**
**  Return value:
**  	0 on success; other on error (see source)
*/

extern int arc_mail_parse __P((u_char *addr, u_char **user, u_char **domain));

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _ARC_H_ */
