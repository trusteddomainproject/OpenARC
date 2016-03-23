/*
**  Copyright (c) 2009-2016, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* for Solaris */
#ifndef _REENTRANT
# define _REENTRANT
#endif /* ! REENTRANT */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <netdb.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <pthread.h>
#include <resolv.h>

#ifdef __STDC__
# include <stdarg.h>
#else /* __STDC__ */
# include <varargs.h>
#endif /* _STDC_ */

/* OpenSSL includes */
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>

/* libopenarc includes */
#include "arc-internal.h"
#include "arc-types.h"
#include "arc-util.h"
#include "arc.h"
#include "base64.h"

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* prototypes */
void arc_error __P((ARC_MESSAGE *, const char *, ...));

/* macros */
#define	ARC_STATE_INIT		0
#define	ARC_STATE_HEADER	1
#define	ARC_STATE_EOH		2
#define	ARC_STATE_EOM		3
#define	ARC_STATE_UNUSABLE	99

#define	CRLF			"\r\n"

#define	BUFRSZ			1024
#define	DEFERRLEN		128
#define	DEFTIMEOUT		10

/* local definitions needed for DNS queries */
#define MAXPACKET		8192
#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T		char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T		unsigned char *
#endif /* __RES && __RES >= 19940415 */

#ifndef T_AAAA
# define T_AAAA			28
#endif /* ! T_AAAA */

/* macros */
#define ARC_ISLWSP(x)  ((x) == 011 || (x) == 013 || (x) == 014 || (x) == 040)

/*
**  ARC_ERROR -- log an error into a DKIM handle
**
**  Parameters:
**  	msg -- ARC message context in which this is performed
**  	format -- format to apply
**  	... -- arguments
**
**  Return value:
**  	None.
*/

void
arc_error(ARC_MESSAGE *msg, const char *format, ...)
{
	int flen;
	int saverr;
	u_char *new;
	va_list va;

	assert(msg != NULL);
	assert(format != NULL);

	saverr = errno;

	if (msg->arc_error == NULL)
	{
		msg->arc_error = malloc(DEFERRLEN);
		if (msg->arc_error == NULL)
		{
			errno = saverr;
			return;
		}
		msg->arc_errorlen = DEFERRLEN;
	}

	for (;;)
	{
		va_start(va, format);
		flen = vsnprintf((char *) msg->arc_error, msg->arc_errorlen,
		                 format, va);
		va_end(va);

		/* compensate for broken vsnprintf() implementations */
		if (flen == -1)
			flen = msg->arc_errorlen * 2;

		if (flen >= msg->arc_errorlen)
		{
			new = malloc(flen + 1);
			if (new == NULL)
			{
				errno = saverr;
				return;
			}

			free(msg->arc_error);
			msg->arc_error = new;
			msg->arc_errorlen = flen + 1;
		}
		else
		{
			break;
		}
	}

	errno = saverr;
}

/*
**  ARC_INIT -- create a library instance
**
**  Parameters:
**  	None.
**
**  Return value:
**  	A new library instance.
*/

ARC_LIB *
arc_init(void)
{
	ARC_LIB *lib;

	lib = (ARC_LIB *) malloc(sizeof *lib);
	if (lib != NULL)
	{
		memset(lib, '\0', sizeof *lib);
		lib->arcl_flags = ARC_LIBFLAGS_DEFAULT;
	}

	return lib;
}

/*
**  ARC_CLOSE -- terminate a library instance
**
**  Parameters:
**  	lib -- library instance to terminate
**
**  Return value:
**  	None.
*/

void
arc_close(ARC_LIB *lib)
{
	free(lib);
}

/*
** 
**  ARC_OPTIONS -- get/set library options
**
**  Parameters:
**  	lib -- library instance of interest
**  	opt -- ARC_OP_GETOPT or ARC_OP_SETOPT
**  	arg -- ARC_OPTS_* constant
**  	val -- pointer to the new value (or NULL)
**  	valsz -- size of the thing at val
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_options(ARC_LIB *lib, int op, int arg, void *val, size_t valsz)
{
	assert(lib != NULL);
	assert(op == ARC_OP_GETOPT || op == ARC_OP_SETOPT);

	switch (arg)
	{
	  case ARC_OPTS_FLAGS:
		if (val == NULL)
			return ARC_STAT_INVALID;

		if (valsz != sizeof lib->arcl_flags)
			return ARC_STAT_INVALID;

		if (op == ARC_OP_GETOPT)
			memcpy(val, &lib->arcl_flags, valsz);
		else
			memcpy(&lib->arcl_flags, val, valsz);

		return ARC_STAT_OK;

	  case ARC_OPTS_TMPDIR:
		if (op == ARC_OP_GETOPT)
		{
			strlcpy((char *) val, (char *) lib->arcl_tmpdir,
			        valsz);
		}
		else if (val == NULL)
		{
			strlcpy((char *) lib->arcl_tmpdir, DEFTMPDIR,
			        sizeof lib->arcl_tmpdir);
		}
		else
		{
			strlcpy((char *) lib->arcl_tmpdir, (char *) val,
			        sizeof lib->arcl_tmpdir);
		}
		return ARC_STAT_OK;

	  default:
		assert(0);
	}
}

/*
**  ARC_GETSSLBUF -- retrieve SSL error buffer
**
**  Parameters:
**  	lib -- library handle
**
**  Return value:
**  	Pointer to the SSL buffer in the library handle.
*/

const char *
arc_getsslbuf(ARC_LIB *lib)
{
	return (const char *) arc_dstring_get(lib->arcl_sslerrbuf);
}

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

ARC_MESSAGE *
arc_message(ARC_LIB *lib, const u_char **err)
{
	ARC_MESSAGE *msg;

	msg = (ARC_MESSAGE *) malloc(sizeof *msg);
	if (msg == NULL)
	{
		*err = strerror(errno);
	}
	else
	{
		memset(msg, '\0', sizeof *msg);

		msg->arc_library = lib;
	}

	return msg;
}

/*
**  ARC_FREE -- deallocate a message object
**
**  Parameters:
**  	msg -- message object to be destroyed
**
**  Return value:
**  	None.
*/

void
arc_free(ARC_MESSAGE *msg)
{
	struct arc_hdrfield *h;
	struct arc_hdrfield *tmp;

	h = msg->arc_hhead;
	while (h != NULL)
	{
		tmp = h->hdr_next;
		free(h->hdr_text);
		free(h);
		h = tmp;
	}

	free(msg);
}

/*
**  ARC_HDRFIELD -- consume a header field
**
**  Parameters:
**  	msg -- message handle
**  	hdr -- full text of the header field
**  	hlen -- bytes to use at hname
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_header_field(ARC_MESSAGE *msg, u_char *hdr, size_t hlen)
{
	u_char *colon;
	u_char *semicolon;
	u_char *end = NULL;
	size_t c;
	struct arc_hdrfield *h;

	assert(msg != NULL);
	assert(hdr != NULL);
	assert(hlen != 0);

	if (msg->arc_state > ARC_STATE_HEADER)
		return ARC_STAT_INVALID;
	msg->arc_state = ARC_STATE_HEADER;

	/* enforce RFC 5322, Section 2.2 */
	colon = NULL;
	for (c = 0; c < hlen; c++)
	{
		if (colon == NULL)
		{
			/*
			**  Field names are printable ASCII; also tolerate
			**  plain whitespace.
			*/

			if (hdr[c] < 32 || hdr[c] > 126)
				return ARC_STAT_SYNTAX;

			/* the colon is special */
			if (hdr[c] == ':')
				colon = &hdr[c];
		}
		else
		{
			/* field bodies are printable ASCII, SP, HT, CR, LF */
			if (!(hdr[c] != 9 ||  /* HT */
			      hdr[c] != 10 || /* LF */
			      hdr[c] != 13 || /* CR */
			      (hdr[c] >= 32 && hdr[c] <= 126) /* SP, print */ ))
				return ARC_STAT_SYNTAX;
		}
	}

	if (colon == NULL)
		return ARC_STAT_SYNTAX;

	end = colon;

	while (end > hdr && isascii(*(end - 1)) && isspace(*(end - 1)))
		end--;

	/* don't allow a field name containing a semicolon */
	semicolon = memchr(hdr, ';', hlen);
	if (semicolon != NULL && colon != NULL && semicolon < colon)
		return ARC_STAT_SYNTAX;

	h = malloc(sizeof *h);
	if (h == NULL)
	{
		arc_error(msg, "unable to allocate %d byte(s)", sizeof *h);
		return ARC_STAT_NORESOURCE;
	}

	if ((msg->arc_library->arcl_flags & ARC_LIBFLAGS_FIXCRLF) != 0)
	{
		u_char prev = '\0';
		u_char *p;
		u_char *q;
		struct arc_dstring *tmphdr;

		tmphdr = arc_dstring_new(msg, BUFRSZ, MAXBUFRSZ);
		if (tmphdr == NULL)
		{
			free(h);
			return ARC_STAT_NORESOURCE;
		}

		q = hdr + hlen;

		for (p = hdr; p < q && *p != '\0'; p++)
		{
			if (*p == '\n' && prev != '\r')		/* bare LF */
			{
				arc_dstring_catn(tmphdr, CRLF, 2);
			}
			else if (prev == '\r' && *p != '\n')	/* bare CR */
			{
				arc_dstring_cat1(tmphdr, '\n');
				arc_dstring_cat1(tmphdr, *p);
			}
			else					/* other */
			{
				arc_dstring_cat1(tmphdr, *p);
			}

			prev = *p;
		}

		if (prev == '\r')				/* end CR */
			arc_dstring_cat1(tmphdr, '\n');

		h->hdr_text = arc_strndup(arc_dstring_get(tmphdr),
		                          arc_dstring_len(tmphdr));

		arc_dstring_free(tmphdr);
	}
	else
	{
		h->hdr_text = arc_strndup(hdr, hlen);
	}

	if (h->hdr_text == NULL)
	{
		free(h);
		return ARC_STAT_NORESOURCE;
	}

	h->hdr_namelen = end != NULL ? end - hdr : hlen;
	h->hdr_textlen = hlen;
	if (colon == NULL)
		h->hdr_colon = NULL;
	else
		h->hdr_colon = h->hdr_text + (colon - hdr);
	h->hdr_flags = 0;
	h->hdr_next = NULL;

	if (msg->arc_hhead == NULL)
	{
		msg->arc_hhead = h;
		msg->arc_htail = h;
	}
	else
	{
		msg->arc_htail->hdr_next = h;
		msg->arc_htail = h;
	}

	msg->arc_hdrcnt++;

	return ARC_STAT_OK;
}

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

ARC_STAT
arc_eoh(ARC_MESSAGE *msg)
{
	return ARC_STAT_OK;
}

/*
**  ARC_EOM -- declare end of message
**
**  Parameters:
**  	msg -- message handle
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_eom(ARC_MESSAGE *msg)
{
	return ARC_STAT_OK;
}

/*
**  ARC_GETSEAL -- get the "seal" to apply to this message
**
**  Parameters:
**  	msg -- ARC_MESSAGE object
**  	seal -- seal to apply (returned)
**      selector -- selector name
**      domain -- domain name
**      key -- secret key, printable
**      keylen -- key length
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_getseal(ARC_MESSAGE *msg, ARC_HDRFIELD **seal, char *selector,
            char *domain, u_char *key, size_t keylen)
{
	return ARC_STAT_OK;
}

/*
**  ARC_HDR_NAME -- extract name from an ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
**
**  Return value:
**  	Header field name stored in the object.
*/

u_char *
arc_hdr_name(ARC_HDRFIELD *hdr, size_t *len)
{
	if (len != NULL)
		*len = hdr->hdr_namelen;
	return hdr->hdr_text;
}

/*
**  ARC_HDR_VALUE -- extract value from an ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
**
**  Return value:
**  	Header field value stored in the object.
*/

u_char *
arc_hdr_value(ARC_HDRFIELD *hdr)
{
	return hdr->hdr_colon + 1;
}

/*
**  ARC_HDR_NEXT -- return pointer to next ARC_HDRFIELD
**
**  Parameters:
**  	hdr -- ARC_HDRFIELD object
**
**  Return value:
**  	Pointer to the next ARC_HDRFIELD in the sequence.
*/

ARC_HDRFIELD *
arc_hdr_next(ARC_HDRFIELD *hdr)
{
	return hdr->hdr_next;
}

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

uint64_t
arc_ssl_version(void)
{
	return 0;
}
