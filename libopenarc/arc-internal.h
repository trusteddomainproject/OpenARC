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

#endif /* ! _ARC_INTERNAL_H_ */
