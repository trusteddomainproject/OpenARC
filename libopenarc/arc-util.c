/*
**  Copyright (c) 2016, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
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
#include <ctype.h>

/* libopenarc includes */
#include "arc-internal.h"
#include "arc-types.h"
#include "arc-util.h"

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

	snprintf(path, MAXPATHLEN, "%s/dkim.XXXXXX",
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
