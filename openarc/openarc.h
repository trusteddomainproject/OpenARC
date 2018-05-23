/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2014, 2016, The Trusted Domain Project.
**  	All rights reserved.
*/

#ifndef _OPENARC_H_
#define _OPENARC_H_

#define	ARCF_PRODUCT	"OpenARC Filter"
#define	ARCF_PRODUCTNS	"OpenARC-Filter"

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

/* libmilter */
#ifdef ARCF_MILTER_PROTOTYPES
# include <libmilter/mfapi.h>
#endif /* ARCF_MILTER_PROTOTYPES */

/* libopenarc */
#include "arc.h"

/* make sure we have TRUE and FALSE */
#ifndef FALSE
# define FALSE		0
#endif /* !FALSE */
#ifndef TRUE
# define TRUE		1
#endif /* !TRUE */

/* defaults, limits, etc. */
#define	BUFRSZ		1024
#define CONFIGOPTS	"Ac:flnp:P:rt:u:vV"
#define	DEFCONFFILE	CONFIG_BASE "/openarc.conf"
#define	DEFINTERNAL	"csl:127.0.0.1,::1"
#define	DEFMAXHDRSZ	65536
#define	HOSTUNKNOWN	"unknown-host"
#define	JOBIDUNKNOWN	"(unknown-jobid)"
#define	LOCALHOST	"127.0.0.1"
#define	LOCALHOST6	"::1"
#define	MAXADDRESS	256
#define	MAXARGV		65536
#define	MAXBUFRSZ	65536
#define	MAXHDRCNT	64
#define	MAXHDRLEN	78
#define	MAXSIGNATURE	1024
#define	MTAMARGIN	78
#define	NULLDOMAIN	"(invalid)"
#define	UNKNOWN		"unknown"

#define AUTHRESULTSHDR	"Authentication-Results"
#define	SWHEADERNAME	"ARC-Filter"

/*
**  HEADER -- a handle referring to a header
*/

typedef struct Header * Header;
struct Header
{
	char *		hdr_hdr;
	char *		hdr_val;
	struct Header *	hdr_next;
	struct Header *	hdr_prev;
};

/* externs */
extern _Bool dolog;
extern char *progname;

/* prototypes, exported for test.c */
extern ARC_MESSAGE *arcf_getarc __P((void *));

#ifdef ARCF_MILTER_PROTOTYPES
extern sfsistat mlfi_connect __P((SMFICTX *, char *, _SOCK_ADDR *));
extern sfsistat mlfi_envfrom __P((SMFICTX *, char **));
extern sfsistat mlfi_envrcpt __P((SMFICTX *, char **));
extern sfsistat mlfi_header __P((SMFICTX *, char *, char *));
extern sfsistat mlfi_eoh __P((SMFICTX *));
extern sfsistat mlfi_body __P((SMFICTX *, u_char *, size_t));
extern sfsistat mlfi_eom __P((SMFICTX *));
extern sfsistat mlfi_abort __P((SMFICTX *));
extern sfsistat mlfi_close __P((SMFICTX *));
#endif /* ARCF_MILTER_PROTOTYPES */

#endif /* _OPENARC_H_ */
