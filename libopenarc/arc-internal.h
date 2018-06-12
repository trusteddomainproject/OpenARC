/*
**  Copyright (c) 2016, The Trusted Domain Project.
**  	All rights reserved.
*/

#ifndef _ARC_INTERNAL_H_
#define _ARC_INTERNAL_H_

/* libopenarc includes */
#include "arc.h"

/* the basics */
#ifndef NULL
# define NULL	0
#endif /* ! NULL */
#ifndef FALSE
# define FALSE	0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE	1
#endif /* ! TRUE */
#ifndef MAXPATHLEN
# define MAXPATHLEN		256
#endif /* ! MAXPATHLEN */

#ifndef ULONG_MAX
# define ULONG_MAX		0xffffffffL
#endif /* ! ULONG_MAX */
#ifndef ULLONG_MAX
# define ULLONG_MAX		0xffffffffffffffffLL
#endif /* ! ULLONG_MAX */

#ifndef MIN
# define MIN(x,y)		((x) < (y) ? (x) : (y))
#endif /* ! MIN */
#ifndef MAX
# define MAX(x,y)		((x) > (y) ? (x) : (y))
#endif /* ! MAX */

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

/* limits, macros, etc. */
#define	BUFRSZ			1024	/* base temp buffer size */
#define	BASE64SIZE(x)		(((x + 2) / 3) * 4)
					/* base64 encoding growth ratio */
#define MAXADDRESS		256	/* biggest user@host we accept */
#define	MAXBUFRSZ		65536	/* max temp buffer size */
#define MAXCNAMEDEPTH		3	/* max. CNAME recursion we allow */
#define MAXHEADERS		32768	/* buffer for caching headers */
#define MAXLABELS		16	/* max. labels we allow */
#define MAXTAGNAME		8	/* biggest tag name */

#define	NPRINTABLE		95	/* number of printable characters */

#define ARC_MAXHEADER		4096	/* buffer for caching one header */
#define	ARC_MAXHOSTNAMELEN	256	/* max. FQDN we support */

/* defaults */
#define	DEFTMPDIR		"/tmp"	/* default temporary directory */

/*
**  ARC_KVSETTYPE -- types of key-value sets
*/

typedef int arc_kvsettype_t;

#define	ARC_KVSETTYPE_ANY	(-1)
#define	ARC_KVSETTYPE_SIGNATURE	0
#define	ARC_KVSETTYPE_KEY	1
#define ARC_KVSETTYPE_SEAL	2
#define ARC_KVSETTYPE_AR	3
#define ARC_KVSETTYPE_MAX	3	/* sentinel value */

/*
**  ARC_HASHTYPE -- types of hashes
*/

#define ARC_HASHTYPE_UNKNOWN	(-1)
#define ARC_HASHTYPE_SHA1	0
#define ARC_HASHTYPE_SHA256	1

/*
**  ARC_KEYTYPE -- types of keys
*/

#define	ARC_KEYTYPE_UNKNOWN	(-1)
#define	ARC_KEYTYPE_RSA		0

/*
**  ARC_QUERY -- types of queries
*/

#define	ARC_QUERY_UNKNOWN	(-1)
#define	ARC_QUERY_DNS		0

/*
** ARC_KVSET -- a set of parameters and values
*/

struct arc_kvset;
typedef struct arc_kvset ARC_KVSET;

/*
**  ARC_PLIST -- a parameter/value pair, as a linked list
*/

struct arc_plist;
typedef struct arc_plist ARC_PLIST;

/*
**  ARC_CANON -- canonicalization
*/

struct arc_canon;
typedef struct arc_canon ARC_CANON;

/*
**  memory allocation wrappers
*/

#include <openssl/crypto.h>
#define ARC_FREE	OPENSSL_free
#define ARC_MALLOC	OPENSSL_malloc
#define ARC_REALLOC	OPENSSL_realloc
#ifdef OPENSSL_strdup
# define ARC_STRDUP	OPENSSL_strdup
#else /* OPENSSL_strdup */
# define ARC_STRDUP	arc_strdup
#endif /* OPENSSL_strdup */

#endif /* ! _ARC_INTERNAL_H_ */
