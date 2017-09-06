/*
**  Copyright (c) 2016, 2017, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <assert.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif /* HAVE_PATHS_H */
#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL		"/dev/null"
#endif /* ! _PATH_DEVNULL */

#ifdef SOLARIS
# if SOLARIS <= 20600
#  define socklen_t size_t
# endif /* SOLARIS <= 20600 */
#endif /* SOLARIS */

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* openarc includes */
#include "openarc.h"
#include "util.h"

/* missing definitions */
#ifndef INADDR_NONE
# define INADDR_NONE	((uint32_t) -1)
#endif /* ! INADDR_NONE */

/* globals */
static char *optlist[] =
{
#if DEBUG
	"DEBUG",
#endif /* DEBUG */

#if POLL
	"POLL",
#endif /* POLL */

	NULL
};

/* struct arcf_dstring -- a dynamically-sized string */
struct arcf_dstring
{
	int			ds_alloc;
	int			ds_max;
	int			ds_len;
	u_char *		ds_buf;
};

/* base64 alphabet */
static unsigned char alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
**  ARCF_OPTLIST -- print active FFRs
**
**  Parameters:
**  	where -- where to write the list
**
**  Return value:
**   	None.
*/

void
arcf_optlist(FILE *where)
{
	_Bool first = TRUE;
	int c;

	assert(where != NULL);

	for (c = 0; optlist[c] != NULL; c++)
	{
		if (first)
		{
			fprintf(where, "\tActive code options:\n");
			first = FALSE;
		}

		fprintf(where, "\t\t%s\n", optlist[c]);
	}
        fprintf(where, "\t%s\n", LIBOPENARC_FEATURE_STRING);
}

/*
**  ARCF_SETMAXFD -- increase the file descriptor limit as much as possible
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

void
arcf_setmaxfd(void)
{
	struct rlimit rlp;

	if (getrlimit(RLIMIT_NOFILE, &rlp) != 0)
	{
		syslog(LOG_WARNING, "getrlimit(): %s", strerror(errno));
	}
	else
	{
		rlp.rlim_cur = rlp.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rlp) != 0)
		{
			syslog(LOG_WARNING, "setrlimit(): %s",
			       strerror(errno));
		}
	}
}

/*
**  ARCF_HOSTLIST -- see if a hostname is in a pattern of hosts/domains
**
**  Parameters:
**  	host -- hostname to compare
**   	list -- NULL-terminated char * array to search
**
**  Return value:
**  	TRUE iff either "host" was in the list or it match a domain pattern
**  	found in the list.
*/

_Bool
arcf_hostlist(char *host, char **list)
{
	int c;
	char *p;

	assert(host != NULL);
	assert(list != NULL);

	/* walk the entire list */
	for (c = 0; list[c] != NULL; c++)
	{
		/* first try a full hostname match */
		if (strcasecmp(host, list[c]) == 0)
			return TRUE;

		/* try each domain */
		for (p = strchr(host, '.'); p != NULL; p = strchr(p + 1, '.'))
		{
			if (strcasecmp(p, list[c]) == 0)
				return TRUE;
		}
	}

	/* not found */
	return FALSE;
}

/*
**  ARCF_DSTRING_RESIZE -- resize a dynamic string (dstring)
**
**  Parameters:
**  	dstr -- ARCF_DSTRING handle
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
arcf_dstring_resize(struct arcf_dstring *dstr, int len)
{
	int newsz;
	u_char *new;

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

			return FALSE;
		}

		/* check for overflow */
		if (newsz > INT_MAX / 2)
		{
			/* next iteration will overflow "newsz" */
			return FALSE;
		}
	}

	new = malloc(newsz);
	if (new == NULL)
		return FALSE;

	memcpy(new, dstr->ds_buf, dstr->ds_alloc);

	free(dstr->ds_buf);

	dstr->ds_alloc = newsz;
	dstr->ds_buf = new;

	return TRUE;
}

/*
**  ARCF_DSTRING_NEW -- make a new dstring
**
**  Parameters:
**  	arc -- DKIM handle
**  	len -- initial number of bytes
**  	maxlen -- maximum allowed length (0 == unbounded)
**
**  Return value:
**  	A ARCF_DSTRING handle, or NULL on failure.
*/

struct arcf_dstring *
arcf_dstring_new(int len, int maxlen)
{
	struct arcf_dstring *new;

	/* fail on invalid parameters */
	if ((maxlen > 0 && len > maxlen) || len == 0)
		return NULL;

	if (len < BUFRSZ)
		len = BUFRSZ;

	new = malloc(sizeof(struct arcf_dstring));
	if (new == NULL)
		return NULL;

	new->ds_buf = malloc(len);
	if (new->ds_buf == NULL)
	{
		free(new);
		return NULL;
	}

	memset(new->ds_buf, '\0', len);
	new->ds_alloc = len;
	new->ds_len = 0;
	new->ds_max = maxlen;

	return new;
}

/*
**  ARCF_DSTRING_FREE -- destroy an existing dstring
**
**  Parameters:
**  	dstr -- ARCF_DSTRING handle to be destroyed
**
**  Return value:
**  	None.
*/

void
arcf_dstring_free(struct arcf_dstring *dstr)
{
	assert(dstr != NULL);

	free(dstr->ds_buf);
	free(dstr);
}

/*
**  ARCF_DSTRING_COPY -- copy data into a dstring
**
**  Parameters:
**  	dstr -- ARCF_DSTRING handle to update
**  	str -- input string
**
**  Return value:
**  	TRUE iff the copy succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
arcf_dstring_copy(struct arcf_dstring *dstr, u_char *str)
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
		if (!arcf_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* copy */
	dstr->ds_len = strlcpy((char *) dstr->ds_buf, (char *) str,
	                       dstr->ds_alloc);

	return TRUE;
}

/*
**  ARCF_DSTRING_CAT -- append data onto a dstring
**
**  Parameters:
**  	dstr -- ARCF_DSTRING handle to update
**  	str -- input string
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
arcf_dstring_cat(struct arcf_dstring *dstr, u_char *str)
{
	int len;

	assert(dstr != NULL);
	assert(str != NULL);

	len = strlen((char *) str) + dstr->ds_len;

	/* too big? */
	if (dstr->ds_max > 0 && len >= dstr->ds_max)
		return FALSE;

	/* fits now? */
	if (dstr->ds_alloc <= len)
	{
		/* nope; try to resize */
		if (!arcf_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* append */
	dstr->ds_len = strlcat((char *) dstr->ds_buf, (char *) str,
	                       dstr->ds_alloc);

	return TRUE;
}

/*
**  ARCF_DSTRING_CAT1 -- append one byte onto a dstring
**
**  Parameters:
**  	dstr -- ARCF_DSTRING handle to update
**  	c -- input character
**
**  Return value:
**  	TRUE iff the update succeeded.
**
**  Side effects:
**  	The dstring may be resized.
*/

_Bool
arcf_dstring_cat1(struct arcf_dstring *dstr, int c)
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
		if (!arcf_dstring_resize(dstr, len + 1))
			return FALSE;
	}

	/* append */
	dstr->ds_buf[dstr->ds_len++] = c;
	dstr->ds_buf[dstr->ds_len] = '\0';

	return TRUE;
}

/*
**  ARCF_DSTRING_CATN -- append 'n' bytes onto a dstring
**
**  Parameters:
**  	dstr -- ARCF_DSTRING handle to update
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
arcf_dstring_catn(struct arcf_dstring *dstr, unsigned char *str,
                   size_t nbytes)
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
		if (!arcf_dstring_resize(dstr, needed + 1))
			return FALSE;
	}

	/* append */
	memcpy(dstr->ds_buf + dstr->ds_len, str, nbytes);
	dstr->ds_len += nbytes;
	dstr->ds_buf[dstr->ds_len] = '\0';

	return TRUE;
}

/*
**  ARCF_DSTRING_GET -- retrieve data in a dstring
**
**  Parameters:
**  	dstr -- ARCF_DSTRING handle whose string should be retrieved
**
**  Return value:
**  	Pointer to the NULL-terminated contents of "dstr".
*/

u_char *
arcf_dstring_get(struct arcf_dstring *dstr)
{
	assert(dstr != NULL);

	return dstr->ds_buf;
}

/*
**  ARCF_DSTRING_LEN -- retrieve length of data in a dstring
**
**  Parameters:
**  	dstr -- ARCF_DSTRING handle whose string should be retrieved
**
**  Return value:
**  	Number of bytes in a dstring.
*/

int
arcf_dstring_len(struct arcf_dstring *dstr)
{
	assert(dstr != NULL);

	return dstr->ds_len;
}

/*
**  ARCF_DSTRING_BLANK -- clear out the contents of a dstring
**
**  Parameters:
**  	dstr -- ARCF_DSTRING handle whose string should be cleared
**
**  Return value:
**  	None.
*/

void
arcf_dstring_blank(struct arcf_dstring *dstr)
{
	assert(dstr != NULL);

	dstr->ds_len = 0;
	dstr->ds_buf[0] = '\0';
}

/*
**  ARCF_DSTRING_CHOP -- truncate contents of a dstring
**
**  Parameters:
**  	dstr -- ARCF_DSTRING handle whose string should be cleared
**  	len -- length after which to clobber
**
**  Return value:
**  	None.
*/

void
arcf_dstring_chop(struct arcf_dstring *dstr, int len)
{
	assert(dstr != NULL);

	if (len < dstr->ds_len)
	{
		dstr->ds_len = len;
		dstr->ds_buf[len] = '\0';
	}
}

/*
**  ARCF_DSTRING_PRINTF -- write variable length formatted output to a dstring
**
**  Parameters:
**  	dstr -- ARCF_STRING handle to be updated
**  	fmt -- format
**  	... -- variable arguments
**
**  Return value:
**  	New size, or -1 on error.
*/

size_t
arcf_dstring_printf(struct arcf_dstring *dstr, char *fmt, ...)
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
		if (!arcf_dstring_resize(dstr, dstr->ds_len + len + 1))
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
**  ARCF_SOCKET_CLEANUP -- try to clean up the socket
**
**  Parameters:
**  	sockspec -- socket specification
**
**  Return value:
**  	0 -- nothing to cleanup or cleanup successful
**  	other -- an error code (a la errno)
*/

int
arcf_socket_cleanup(char *sockspec)
{
	int s;
	char *colon;
	struct sockaddr_un sock;

	assert(sockspec != NULL);

	/* we only care about "local" or "unix" sockets */
	colon = strchr(sockspec, ':');
	if (colon != NULL)
	{
		if (strncasecmp(sockspec, "local:", 6) != 0 &&
		    strncasecmp(sockspec, "unix:", 5) != 0)
			return 0;
	}

	/* find the filename */
	if (colon == NULL)
	{
		colon = sockspec;
	}
	else
	{
		if (*(colon + 1) == '\0')
			return EINVAL;
	}

	/* get a socket */
	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s == -1)
		return errno;

	/* set up a connection */
	memset(&sock, '\0', sizeof sock);
#ifdef BSD
	sock.sun_len = sizeof sock;
#endif /* BSD */
	sock.sun_family = PF_UNIX;
	strlcpy(sock.sun_path, colon + 1, sizeof sock.sun_path);

	/* try to connect */
	if (connect(s, (struct sockaddr *) &sock, (socklen_t) sizeof sock) != 0)
	{
		/* if ECONNREFUSED, try to unlink */
		if (errno == ECONNREFUSED)
		{
			close(s);

			if (unlink(sock.sun_path) == 0)
				return 0;
			else
				return errno;
		}

		/* if ENOENT, the socket's not there */
		else if (errno == ENOENT)
		{
			close(s);

			return 0;
		}

		/* something else happened */
		else
		{
			int saveerr;

			saveerr = errno;

			close(s);

			return saveerr;
		}
	}

	/* connection apparently succeeded */
	close(s);
	return EADDRINUSE;
}

/*
**  ARCF_BASE64_ENCODE_FILE -- base64-encode a file
**
**  Parameters:
**  	infd -- input file descriptor
**  	out -- output stream
**  	lm -- left margin
** 	rm -- right margin
**  	initial -- space consumed on the initial line
**
**  Return value:
**  	None (yet).
*/

void
arcf_base64_encode_file(infd, out, lm, rm, initial)
	int infd;
	FILE *out;
	int lm;
	int rm;
	int initial;
{
	int len;
	int bits;
	int c;
	int d;
	int char_count;
	ssize_t rlen;
	char buf[MAXBUFRSZ];

	assert(infd >= 0);
	assert(out != NULL);
	assert(lm >= 0);
	assert(rm >= 0);
	assert(initial >= 0);

	bits = 0;
	char_count = 0;
	len = initial;

	(void) lseek(infd, 0, SEEK_SET);

	for (;;)
	{
		rlen = read(infd, buf, sizeof buf);
		if (rlen == -1)
			break;

		for (c = 0; c < rlen; c++)
		{
			bits += buf[c];
			char_count++;
			if (char_count == 3)
			{
				fputc(alphabet[bits >> 18], out);
				fputc(alphabet[(bits >> 12) & 0x3f], out);
				fputc(alphabet[(bits >> 6) & 0x3f], out);
				fputc(alphabet[bits & 0x3f], out);
				len += 4;
				if (rm > 0 && lm > 0 && len >= rm - 4)
				{
					fputc('\n', out);
					for (d = 0; d < lm; d++)
						fputc(' ', out);
					len = lm;
				}
				bits = 0;
				char_count = 0;
			}
			else
			{
				bits <<= 8;
			}
		}

		if (rlen < (ssize_t) sizeof buf)
			break;
	}

	if (char_count != 0)
	{
		if (rm > 0 && lm > 0 && len >= rm - 4)
		{
			fputc('\n', out);
			for (d = 0; d < lm; d++)
				fputc(' ', out);
		}
		bits <<= 16 - (8 * char_count);
		fputc(alphabet[bits >> 18], out);
		fputc(alphabet[(bits >> 12) & 0x3f], out);
		if (char_count == 1)
			fputc('=', out);
		else
			fputc(alphabet[(bits >> 6) & 0x3f], out);
		fputc('=', out);
	}
}

/*
**  ARCF_LOWERCASE -- lowercase-ize a string
**
**  Parameters:
**  	str -- string to convert
**
**  Return value:
**  	None.
*/

void
arcf_lowercase(u_char *str)
{
	u_char *p;

	assert(str != NULL);

	for (p = str; *p != '\0'; p++)
	{
		if (isascii(*p) && isupper(*p))
			*p = tolower(*p);
	}
}

/*
**  ARCF_INET_NTOA -- thread-safe inet_ntoa()
**
**  Parameters:
**  	a -- (struct in_addr) to be converted
**  	buf -- destination buffer
**  	buflen -- number of bytes at buf
**
**  Return value:
**  	Size of the resultant string.  If the result is greater than buflen,
**  	then buf does not contain the complete result.
*/

size_t
arcf_inet_ntoa(struct in_addr a, char *buf, size_t buflen)
{
	in_addr_t addr;

	assert(buf != NULL);

	addr = ntohl(a.s_addr);

	return snprintf(buf, buflen, "%d.%d.%d.%d",
	                (addr >> 24), (addr >> 16) & 0xff,
	                (addr >> 8) & 0xff, addr & 0xff);
}

/*
**  ARCF_MKARRAY -- turn a comma-separated list into an array
**
**  Parameters:
**  	in -- input string
**
**  Return value:
**  	A NULL-terminated array.
**
**  Side effects:
** 	"in" is modified.
*/

const char **
arcf_mkarray(char *in)
{
	int c = 0;
	int n = 1;
	char *p;
	char *ctx;
	char **out = NULL;

	assert(in != NULL);

	for (p = in; *p != '\0'; p++)
	{
		if (*p == ',')
			n++;
	}

	out = (char **) malloc((n + 1) * sizeof(char *));
	if (out == NULL)
		return (const char **) NULL;

	for (p = strtok_r(in, ",", &ctx); p != NULL; p = strtok_r(NULL, ",", &ctx))
		out[c++] = p;
	out[n] = NULL;

	return (const char **) out;
}
