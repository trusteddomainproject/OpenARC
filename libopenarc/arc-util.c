/*
**  Copyright (c) 2016, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <resolv.h>
#include <ctype.h>

/* libopenarc includes */
#include "arc-internal.h"
#include "arc-types.h"
#include "arc-util.h"

#if defined(__RES) && (__RES >= 19940415)
# define RES_UNC_T		char *
#else /* __RES && __RES >= 19940415 */
# define RES_UNC_T		unsigned char *
#endif /* __RES && __RES >= 19940415 */

/* prototypes */
extern void arc_error __P((ARC_MESSAGE *, const char *, ...));

/*
**  ARC_DSTRING_RESIZE -- resize a dynamic string (dstring)
**
**  Parameters:
**  	dstr -- ARC_DSTRING handle
**  	len -- number of bytes desired
**
**  Return value:
**  	TRUE iff the resize worked (or wasn't needed)
**
**  Notes:
**  	This will actually ensure that there are "len" bytes available.
**  	The caller must account for the NULL byte when requesting a
**  	specific size.
*/

static _Bool
arc_dstring_resize(struct arc_dstring *dstr, int len)
{
	int newsz;
	unsigned char *new;

	assert(dstr != NULL);
	assert(len > 0);

	if (dstr->ds_alloc >= len)
		return TRUE;

	/* must resize */
	for (newsz = dstr->ds_alloc * 2;
	     newsz < len;
	     newsz *= 2)
	{
		/* impose ds_max limit, if specified */
		if (dstr->ds_max > 0 && newsz > dstr->ds_max)
		{
			if (len <= dstr->ds_max)
			{
				newsz = len;
				break;
			}

			arc_error(dstr->ds_msg, "maximum string size exceeded");
			return FALSE;
		}

		/* check for overflow */
		if (newsz > INT_MAX / 2)
		{
			/* next iteration will overflow "newsz" */
			arc_error(dstr->ds_msg,
			          "internal string limit reached");
			return FALSE;
		}
	}

	new = malloc(newsz);
	if (new == NULL)
	{
		arc_error(dstr->ds_msg, "unable to allocate %d byte(s)",
                          newsz);
		return FALSE;
	}

	memcpy(new, dstr->ds_buf, dstr->ds_alloc);
	free(dstr->ds_buf);
	dstr->ds_alloc = newsz;
	dstr->ds_buf = new;

	return TRUE;
}

/*
**  ARC_DSTRING_NEW -- make a new dstring
**
**  Parameters:
**  	msg -- associated ARC message context
**  	len -- initial number of bytes
**  	maxlen -- maximum allowed length, including the NULL byte
**  	          (0 == unbounded)
**
**  Return value:
**  	A ARC_DSTRING handle, or NULL on failure.
*/

struct arc_dstring *
arc_dstring_new(ARC_MESSAGE *msg, int len, int maxlen)
{
	struct arc_dstring *new;

	assert(msg != NULL);

	/* fail on invalid parameters */
	if ((maxlen > 0 && len > maxlen) || len < 0)
		return NULL;

	if (len < BUFRSZ)
		len = BUFRSZ;

	new = (struct arc_dstring *) malloc(sizeof *new);
	if (new == NULL)
	{
		arc_error(msg, "unable to allocate %d byte(s)",
		          sizeof(struct arc_dstring));
		return NULL;
	}

	new->ds_msg = msg;
	new->ds_buf = malloc(len);
	if (new->ds_buf == NULL)
	{
		arc_error(msg, "unable to allocate %d byte(s)",
		          sizeof(struct arc_dstring));
		free(new);
		return NULL;
	}

	memset(new->ds_buf, '\0', len);
	new->ds_alloc = len;
	new->ds_len = 0;
	new->ds_max = maxlen;
	new->ds_msg = msg;

	return new;
}

/*
**  ARC_DSTRING_FREE -- destroy an existing dstring
**
**  Parameters:
**  	dstr -- ARC_DSTRING handle to be destroyed
**
**  Return value:
**  	None.
*/

void
arc_dstring_free(struct arc_dstring *dstr)
{
	assert(dstr != NULL);

	free(dstr->ds_buf);
	free(dstr);
}

/*
**  ARC_DSTRING_COPY -- copy data into a dstring
**
**  Parameters:
**  	dstr -- ARC_DSTRING handle to update
**  	str -- input string
**
**  Return value:
**  	TRUE iff the copy succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
arc_dstring_copy(struct arc_dstring *dstr, unsigned char *str)
{
	int len;

	assert(dstr != NULL);
	assert(str != NULL);

	len = strlen((char *) str);

	/* too big? */
	if (dstr->ds_max > 0 && len >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= len)
	{
		/* nope; try to resize */
		if (!arc_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* copy */
	memcpy(dstr->ds_buf, str, len + 1);
	dstr->ds_len = len;

	return TRUE;
}

/*
**  ARC_DSTRING_CAT -- append data onto a dstring
**
**  Parameters:
**  	dstr -- ARC_DSTRING handle to update
**  	str -- input string
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
arc_dstring_cat(struct arc_dstring *dstr, unsigned char *str)
{
	size_t len;
	size_t needed;

	assert(dstr != NULL);
	assert(str != NULL);

	len = strlen((char *) str);
	needed = dstr->ds_len + len;

	/* too big? */
	if (dstr->ds_max > 0 && needed >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= needed)
	{
		/* nope; try to resize */
		if (!arc_dstring_resize(dstr, needed + 1))
			return FALSE;
	}

	/* append */
	memcpy(dstr->ds_buf + dstr->ds_len, str, len + 1);
	dstr->ds_len += len;

	return TRUE;
}

/*
**  ARC_DSTRING_CAT1 -- append one byte onto a dstring
**
**  Parameters:
**  	dstr -- ARC_DSTRING handle to update
**  	c -- input character
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
arc_dstring_cat1(struct arc_dstring *dstr, int c)
{
	int len;

	assert(dstr != NULL);

	len = dstr->ds_len + 1;

	/* too big? */
	if (dstr->ds_max > 0 && len >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= len)
	{
		/* nope; try to resize */
		if (!arc_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* append */
	dstr->ds_buf[dstr->ds_len++] = c;
	dstr->ds_buf[dstr->ds_len] = '\0';

	return TRUE;
}

/*
**  ARC_DSTRING_CATN -- append 'n' bytes onto a dstring
**
**  Parameters:
**  	dstr -- ARC_DSTRING handle to update
**  	str -- input string
**  	nbytes -- number of bytes to append
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
arc_dstring_catn(struct arc_dstring *dstr, unsigned char *str, size_t nbytes)
{
	size_t needed;

	assert(dstr != NULL);
	assert(str != NULL);

	needed = dstr->ds_len + nbytes;

	/* too big? */
	if (dstr->ds_max > 0 && needed >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= needed)
	{
		/* nope; try to resize */
		if (!arc_dstring_resize(dstr, needed + 1))
			return FALSE;
	}

	/* append */
	memcpy(dstr->ds_buf + dstr->ds_len, str, nbytes);
	dstr->ds_len += nbytes;
	dstr->ds_buf[dstr->ds_len] = '\0';

	return TRUE;
}

/*
**  ARC_DSTRING_GET -- retrieve data in a dstring
**
**  Parameters:
**  	dstr -- ARC_STRING handle whose string should be retrieved
**
**  Return value:
**  	Pointer to the NULL-terminated contents of "dstr".
*/

unsigned char *
arc_dstring_get(struct arc_dstring *dstr)
{
	assert(dstr != NULL);

	return dstr->ds_buf;
}

/*
**  ARC_DSTRING_LEN -- retrieve length of data in a dstring
**
**  Parameters:
**  	dstr -- ARC_STRING handle whose string should be retrieved
**
**  Return value:
**  	Number of bytes in a dstring.
*/

int
arc_dstring_len(struct arc_dstring *dstr)
{
	assert(dstr != NULL);

	return dstr->ds_len;
}

/*
**  ARC_DSTRING_BLANK -- clear out the contents of a dstring
**
**  Parameters:
**  	dstr -- ARC_STRING handle whose string should be cleared
**
**  Return value:
**  	None.
*/

void
arc_dstring_blank(struct arc_dstring *dstr)
{
	assert(dstr != NULL);

	dstr->ds_len = 0;
	dstr->ds_buf[0] = '\0';
}

/*
**  ARC_DSTRING_PRINTF -- write variable length formatted output to a dstring
**
**  Parameters:
**  	dstr -- ARC_STRING handle to be updated
**  	fmt -- format
**  	... -- variable arguments
**
**  Return value:
**  	New size, or -1 on error.
*/

size_t
arc_dstring_printf(struct arc_dstring *dstr, char *fmt, ...)
{
	size_t len;
	size_t rem;
	va_list ap;
	va_list ap2;

	assert(dstr != NULL);
	assert(fmt != NULL);

	va_start(ap, fmt);
	va_copy(ap2, ap);
	rem = dstr->ds_alloc - dstr->ds_len;
	len = vsnprintf((char *) dstr->ds_buf + dstr->ds_len, rem, fmt, ap);
	va_end(ap);

	if (len > rem)
	{
		if (!arc_dstring_resize(dstr, dstr->ds_len + len + 1))
		{
			va_end(ap2);
			return (size_t) -1;
		}

		rem = dstr->ds_alloc - dstr->ds_len;
		len = vsnprintf((char *) dstr->ds_buf + dstr->ds_len, rem,
		                fmt, ap2);
	}

	va_end(ap2);

	dstr->ds_len += len;

	return dstr->ds_len;
}

/*
**  ARC_STRNDUP -- clone the first n bytes of a string
**
**  Parameters:
**  	src -- source string
**  	len -- bytes to copy
**
**  Return value:
**  	Pointer to the copy.  The caller owns it.
*/

u_char *
arc_strndup(u_char *src, size_t len)
{
	u_char *ret;

	ret = malloc(len + 1);
	if (ret != NULL)
	{
		memset(ret, '\0', len + 1);
		strncpy(ret, src, len);
	}

	return ret;
}

/*
**  ARC_COLLAPSE -- remove spaces from a string
**
**  Parameters:
**  	str -- string to process
**
**  Return value:
**  	None.
*/

void
arc_collapse(u_char *str)
{
	u_char *q;
	u_char *r;

	assert(str != NULL);

	for (q = str, r = str; *q != '\0'; q++)
	{
		if (!isspace(*q))
		{
			if (q != r)
				*r = *q;
			r++;
		}
	}

	*r = '\0';
}

/*
**  ARC_HDRLIST -- build up a header list for use in a regexp
**
**  Parameters:
**  	buf -- where to write
**  	buflen -- bytes at "buf"
**  	hdrlist -- array of header names
**  	first -- first call
**
**  Return value:
**  	TRUE iff everything fit.
*/

_Bool
arc_hdrlist(u_char *buf, size_t buflen, u_char **hdrlist, _Bool first)
{
	_Bool escape = FALSE;
	int c;
	int len;
	u_char *p;
	u_char *q;
	u_char *end;

	assert(buf != NULL);
	assert(hdrlist != NULL);

	for (c = 0; ; c++)
	{
		if (hdrlist[c] == NULL)
			break;

		if (!first)
		{
			len = strlcat((char *) buf, "|", buflen);
			if (len >= buflen)
				return FALSE;
		}
		else
		{
			len = strlen((char *) buf);
		}

		first = FALSE;

		q = &buf[len];
		end = &buf[buflen - 1];

		for (p = hdrlist[c]; *p != '\0'; p++)
		{
			if (q >= end)
				return FALSE;

			if (escape)
			{
				*q = *p;
				q++;
				escape = FALSE;
			}

			switch (*p)
			{
			  case '*':
				*q = '.';
				q++;
				if (q >= end)
					return FALSE;
				*q = '*';
				q++;
				break;

			  case '.':
				*q = '\\';
				q++;
				if (q >= end)
					return FALSE;
				*q = '.';
				q++;
				break;

			  case '\\':
				escape = TRUE;
				break;

			  default:
				*q = *p;
				q++;
				break;
			}
		}
	}

	return TRUE;
}

/*
**  ARC_LOWERHDR -- convert a string (presumably a header) to all lowercase,
**                  but only up to a colon
**
**  Parameters:
**  	str -- string to modify
**
**  Return value:
**  	None.
*/

void
arc_lowerhdr(unsigned char *str)
{
	unsigned char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		if (*p == ':')
			return;

		if (isascii(*p) && isupper(*p))
			*p = tolower(*p);
	}
}

/*
**  ARC_TMPFILE -- open a temporary file
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle
**  	fp -- descriptor (returned)
**  	keep -- if FALSE, unlink() the file once created
**
**  Return value:
**  	An ARC_STAT_* constant.
*/

ARC_STAT
arc_tmpfile(ARC_MESSAGE *msg, int *fp, _Bool keep)
{
	int fd;
	char *p;
	char path[MAXPATHLEN + 1];

	assert(msg != NULL);
	assert(fp != NULL);

	snprintf(path, MAXPATHLEN, "%s/arc.XXXXXX",
	         msg->arc_library->arcl_tmpdir);

	for (p = path + strlen((char *) msg->arc_library->arcl_tmpdir) + 1;
	     *p != '\0';
	     p++)
	{
		if (*p == '/')
			*p = '.';
	}

	fd = mkstemp(path);
	if (fd == -1)
	{
		arc_error(msg, "can't create temporary file at %s: %s",
		          path, strerror(errno));
		return ARC_STAT_NORESOURCE;
	}

	*fp = fd;

	if (!keep)
		(void) unlink(path);

	return ARC_STAT_OK;
}

/*
**  ARC_MIN_TIMEVAL -- determine the timeout to apply before reaching
**                     one of two timevals
**
**  Parameters:
**  	t1 -- first timeout (absolute)
**  	t2 -- second timeout (absolute) (may be NULL)
**  	t -- final timeout (relative)
**  	which -- which of t1 and t2 hit first
**
**  Return value:
**  	None.
*/

void
arc_min_timeval(struct timeval *t1, struct timeval *t2, struct timeval *t,
                struct timeval **which)
{
	struct timeval *next;
	struct timeval now;

	assert(t1 != NULL);
	assert(t != NULL);

	if (t2 == NULL ||
	    t2->tv_sec > t1->tv_sec ||
	    (t2->tv_sec == t1->tv_sec && t2->tv_usec > t1->tv_usec))
		next = t1;
	else
		next = t2;

	(void) gettimeofday(&now, NULL);

	if (next->tv_sec < now.tv_sec ||
	    (next->tv_sec == now.tv_sec && next->tv_usec < now.tv_usec))
	{
		t->tv_sec = 0;
		t->tv_usec = 0;
	}
	else
	{
		t->tv_sec = next->tv_sec - now.tv_sec;
		if (next->tv_usec < now.tv_usec)
		{
			t->tv_sec--;
			t->tv_usec = next->tv_usec - now.tv_usec + 1000000;
		}
		else
		{
			t->tv_usec = next->tv_usec - now.tv_usec;
		}
	}

	if (which != NULL)
		*which = next;
}

/*
**  ARC_CHECK_DNS_REPLY -- see if a DNS reply is truncated or corrupt
**
**  Parameters:
**  	ansbuf -- answer buffer
**  	anslen -- number of bytes returned
**  	xclass -- expected class
**  	xtype -- expected type
**
**  Return value:
**  	2 -- reply not usable
**  	1 -- reply truncated but usable
**  	0 -- reply intact (but may not be what you want)
**  	-1 -- other error
*/

int
arc_check_dns_reply(unsigned char *ansbuf, size_t anslen,
                    int xclass, int xtype)
{
	_Bool trunc = FALSE;
	int qdcount;
	int ancount;
	int n;
	uint16_t type = (uint16_t) -1;
	uint16_t class = (uint16_t) -1;
	unsigned char *cp;
	unsigned char *eom;
	HEADER hdr;
	unsigned char name[ARC_MAXHOSTNAMELEN + 1];

	assert(ansbuf != NULL);

	/* set up pointers */
	memcpy(&hdr, ansbuf, sizeof hdr);
	cp = ansbuf + HFIXEDSZ;
	eom = ansbuf + anslen;

	/* skip over the name at the front of the answer */
	for (qdcount = ntohs((unsigned short) hdr.qdcount);
	     qdcount > 0;
	     qdcount--)
	{
		/* copy it first */
		(void) dn_expand((unsigned char *) ansbuf, eom, cp,
		                 (RES_UNC_T) name, sizeof name);

		if ((n = dn_skipname(cp, eom)) < 0)
			return 2;

		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ > eom)
			return 2;

		GETSHORT(type, cp);
		GETSHORT(class, cp);
	}

	if (type != xtype || class != xclass)
		return 0;

	/* if NXDOMAIN, return DKIM_STAT_NOKEY */
	if (hdr.rcode == NXDOMAIN)
		return 0;

	/* if truncated, we can't do it */
	if (hdr.tc)
		trunc = TRUE;

	/* get the answer count */
	ancount = ntohs((unsigned short) hdr.ancount);
	if (ancount == 0)
		return (trunc ? 2 : 0);

	/*
	**  Extract the data from the first TXT answer.
	*/

	while (--ancount >= 0 && cp < eom)
	{
		/* grab the label, even though we know what we asked... */
		if ((n = dn_expand((unsigned char *) ansbuf, eom, cp,
		                   (RES_UNC_T) name, sizeof name)) < 0)
			return 2;

		/* ...and move past it */
		cp += n;

		/* extract the type and class */
		if (cp + INT16SZ + INT16SZ + INT32SZ > eom)
			return 2;

		GETSHORT(type, cp);
		cp += INT16SZ; /* class */
		cp += INT32SZ; /* ttl */

		/* skip CNAME if found; assume it was resolved */
		if (type == T_CNAME)
		{
			if ((n = dn_expand((u_char *) ansbuf, eom, cp,
			                   (RES_UNC_T) name, sizeof name)) < 0)
				return 2;

			cp += n;
			continue;
		}
		else if (type != xtype)
		{
			return (trunc ? 1 : 0);
		}

		/* found a record we can use; break */
		break;
	}

	/* if ancount went below 0, there were no good records */
	if (ancount < 0)
		return (trunc ? 1 : 0);

	/* get payload length */
	if (cp + INT16SZ > eom)
		return 2;

	GETSHORT(n, cp);

	/*
	**  XXX -- maybe deal with a partial reply rather than require
	**  	   it all
	*/

	if (cp + n > eom)
		return 2;

	return (trunc ? 1 : 0);
}

/*
**  ARC_COPY_ARRAY -- copy an array of char pointers
**
**  Parameters:
**  	in -- input array, must be NULL-terminated
**
**  Return value:
**  	A copy of "in" and its elements, or NULL on failure.
*/

const char **
arc_copy_array(char **in)
{
	unsigned int c;
	unsigned int n;
	char **out;

	assert(in != NULL);

	for (n = 0; in[n] != NULL; n++)
		continue;

	out = malloc(sizeof(char *) * (n + 1));
	if (out == NULL)
		return NULL;
	
	for (c = 0; c < n; c++)
	{
		out[c] = strdup(in[c]);
		if (out[c] == NULL)
		{
			for (n = 0; n < c; n++)
				free(out[n]);
			free(out);
			return NULL;
		}
	}

	out[c] = NULL;

	return (const char **) out;
}

/*
**  ARC_CLOBBER_ARRAY -- clobber a cloned array of char pointers
**
**  Parameters:
**  	in -- input array, must be NULL-terminated
**
**  Return value:
**  	None.
*/

void
arc_clobber_array(char **in)
{
	unsigned int n;

	assert(in != NULL);

	for (n = 0; in[n] != NULL; n++)
		free(in[n]);

	free(in);
}
