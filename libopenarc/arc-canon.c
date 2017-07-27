/*
**  Copyright (c) 2007-2009 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009-2016, The Trusted Domain Project.  All rights reserved.
*/

#include "build-config.h"

/* for Solaris */
#ifndef _REENTRANT
# define _REENTRANT
#endif /* _REENTRANT */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <regex.h>

/* libopenarc includes */
#include "arc-internal.h"
#include "arc-types.h"
#include "arc-canon.h"
#include "arc-util.h"
#include "arc-tables.h"

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* definitions */
#define	CRLF	(u_char *) "\r\n"
#define	SP	(u_char *) " "

/* macros */
#define	ARC_ISWSP(x)	((x) == 011 || (x) == 040)
#define	ARC_ISLWSP(x)	((x) == 011 || (x) == 012 || (x) == 015 || (x) == 040)

/* prototypes */
extern void arc_error __P((ARC_MESSAGE *, const char *, ...));

/* ========================= PRIVATE SECTION ========================= */

/*
**  ARC_CANON_FREE -- destroy a canonicalization
**
**  Parameters:
**  	msg -- ARC message handle
**  	canon -- canonicalization to destroy
**
**  Return value:
**  	None.
*/

static void
arc_canon_free(ARC_MESSAGE *msg, ARC_CANON *canon)
{
	assert(msg != NULL);
	assert(canon != NULL);

	if (canon->canon_hash != NULL)
	{
		switch (canon->canon_hashtype)
		{
		  case ARC_HASHTYPE_SHA1:
		  {
			struct arc_sha1 *sha1;

			sha1 = (struct arc_sha1 *) canon->canon_hash;

			if (sha1->sha1_tmpbio != NULL)
			{
				BIO_free(sha1->sha1_tmpbio);
				sha1->sha1_tmpfd = -1;
				sha1->sha1_tmpbio = NULL;
			}

			break;
		  }

#ifdef HAVE_SHA256
		  case ARC_HASHTYPE_SHA256:
		  {
			struct arc_sha256 *sha256;

			sha256 = (struct arc_sha256 *) canon->canon_hash;

			if (sha256->sha256_tmpbio != NULL)
			{
				BIO_free(sha256->sha256_tmpbio);
				sha256->sha256_tmpfd = -1;
				sha256->sha256_tmpbio = NULL;
			}

			break;
		  }
#endif /* HAVE_SHA256 */

		  default:
			assert(0);
			/* NOTREACHED */
		}

		free(canon->canon_hash);
	}

	if (canon->canon_hashbuf != NULL)
		free(canon->canon_hashbuf);

	if (canon->canon_buf != NULL)
		arc_dstring_free(canon->canon_buf);

	free(canon);
}

/*
**  ARC_CANON_WRITE -- write data to canonicalization stream(s)
**
**  Parameters:
**  	canon -- ARC_CANON handle
**  	buf -- buffer containing canonicalized data
**  	buflen -- number of bytes to consume
**
**  Return value:
**  	None.
*/

static void
arc_canon_write(ARC_CANON *canon, u_char *buf, size_t buflen)
{
	assert(canon != NULL);

	if (canon->canon_remain != (ssize_t) -1)
		buflen = MIN(buflen, canon->canon_remain);

	canon->canon_wrote += buflen;

	if (buf == NULL || buflen == 0)
		return;

	assert(canon->canon_hash != NULL);

	switch (canon->canon_hashtype)
	{
	  case ARC_HASHTYPE_SHA1:
	  {
		struct arc_sha1 *sha1;

		sha1 = (struct arc_sha1 *) canon->canon_hash;
		SHA1_Update(&sha1->sha1_ctx, buf, buflen);

		if (sha1->sha1_tmpbio != NULL)
			BIO_write(sha1->sha1_tmpbio, buf, buflen);

		break;
	  }

#ifdef HAVE_SHA256
	  case ARC_HASHTYPE_SHA256:
	  {
		struct arc_sha256 *sha256;

		sha256 = (struct arc_sha256 *) canon->canon_hash;
		SHA256_Update(&sha256->sha256_ctx, buf, buflen);

		if (sha256->sha256_tmpbio != NULL)
			BIO_write(sha256->sha256_tmpbio, buf, buflen);

		break;
	  }
#endif /* HAVE_SHA256 */
	}

	if (canon->canon_remain != (ssize_t) -1)
		canon->canon_remain -= buflen;
}

/*
**  ARC_CANON_BUFFER -- buffer for arc_canon_write()
**
**  Parameters:
**  	canon -- ARC_CANON handle
**  	buf -- buffer containing canonicalized data
**  	buflen -- number of bytes to consume
**
**  Return value:
**  	None.
*/

static void
arc_canon_buffer(ARC_CANON *canon, u_char *buf, size_t buflen)
{
	assert(canon != NULL);

	/* NULL buffer or 0 length means flush */
	if (buf == NULL || buflen == 0)
	{
		if (canon->canon_hashbuflen > 0)
		{
			arc_canon_write(canon, canon->canon_hashbuf,
			                canon->canon_hashbuflen);
			canon->canon_hashbuflen = 0;
		}
		return;
	}

	/* not enough buffer space; write the buffer out */
	if (canon->canon_hashbuflen + buflen > canon->canon_hashbufsize)
	{
		arc_canon_write(canon, canon->canon_hashbuf,
		                canon->canon_hashbuflen);
		canon->canon_hashbuflen = 0;
	}

	/*
	**  Now, if the input is bigger than the buffer, write it too;
	**  otherwise cache it.
	*/

	if (buflen >= canon->canon_hashbufsize)
	{
		arc_canon_write(canon, buf, buflen);
	}
	else
	{
		memcpy(&canon->canon_hashbuf[canon->canon_hashbuflen],
		       buf, buflen);
		canon->canon_hashbuflen += buflen;
	}
}

/*
**  ARC_CANON_HEADER_STRING -- canonicalize a header field
**
**  Parameters:
**  	dstr -- arc_dstring to use for output
**  	canon -- arc_canon_t
**  	hdr -- header field input
**  	hdrlen -- bytes to process at "hdr"
**  	crlf -- write a CRLF at the end?
**
**  Return value:
**  	A ARC_STAT constant.
*/

ARC_STAT
arc_canon_header_string(struct arc_dstring *dstr, arc_canon_t canon,
                        unsigned char *hdr, size_t hdrlen, _Bool crlf)
{
	_Bool space;
	u_char *p;
	u_char *tmp;
	u_char *end;
	u_char tmpbuf[BUFRSZ];
	assert(dstr != NULL);
	assert(hdr != NULL);

	tmp = tmpbuf;
	end = tmpbuf + sizeof tmpbuf - 1;

	switch (canon)
	{
	  case ARC_CANON_SIMPLE:
		if (!arc_dstring_catn(dstr, hdr, hdrlen) ||
		    (crlf && !arc_dstring_catn(dstr, CRLF, 2)))
			return ARC_STAT_NORESOURCE;
		break;

	  case ARC_CANON_RELAXED:
		/* process header field name (before colon) first */
		for (p = hdr; p < hdr + hdrlen; p++)
		{
			/*
			**  Discard spaces before the colon or before the end
			**  of the first word.
			*/

			if (isascii(*p))
			{
				/* discard spaces */
				if (ARC_ISLWSP(*p))
					continue;

				/* convert to lowercase */
				if (isupper(*p))
					*tmp++ = tolower(*p);
				else
					*tmp++ = *p;
			}
			else
			{
				*tmp++ = *p;
			}

			/* reaching the end of the cache buffer, flush it */
			if (tmp == end)
			{
				*tmp = '\0';

				if (!arc_dstring_catn(dstr,
				                       tmpbuf, tmp - tmpbuf))
					return ARC_STAT_NORESOURCE;

				tmp = tmpbuf;
			}

			if (*p == ':')
			{
				p++;
				break;
			}
		}

		/* skip all spaces before first word */
		while (*p != '\0' && ARC_ISLWSP(*p))
			p++;

		space = FALSE;				/* just saw a space */

		for ( ; *p != '\0'; p++)
		{
			if (isascii(*p) && isspace(*p))
			{
				/* mark that there was a space and continue */
				space = TRUE;

				continue;
			}

			/*
			**  Any non-space marks the beginning of a word.
			**  If there's a stored space, use it up.
			*/

			if (space)
			{
				*tmp++ = ' ';

				/* flush buffer? */
				if (tmp == end)
				{
					*tmp = '\0';

					if (!arc_dstring_catn(dstr,
					                      tmpbuf,
					                      tmp - tmpbuf))
						return ARC_STAT_NORESOURCE;

					tmp = tmpbuf;
				}

				space = FALSE;
			}

			/* copy the byte */
			*tmp++ = *p;

			/* flush buffer? */
			if (tmp == end)
			{
				*tmp = '\0';

				if (!arc_dstring_catn(dstr,
				                      tmpbuf, tmp - tmpbuf))
					return ARC_STAT_NORESOURCE;

				tmp = tmpbuf;
			}
		}

		/* flush any cached data */
		if (tmp != tmpbuf)
		{
			*tmp = '\0';

			if (!arc_dstring_catn(dstr,
			                       tmpbuf, tmp - tmpbuf))
				return ARC_STAT_NORESOURCE;
		}

		if (crlf && !arc_dstring_catn(dstr, CRLF, 2))
			return ARC_STAT_NORESOURCE;

		break;
	}

	return ARC_STAT_OK;
}

/*
**  ARC_CANON_HEADER -- canonicalize a header and write it
**
**  Parameters:
**  	msg -- ARC message handle
**  	canon -- ARC_CANON handle
**  	hdr -- header handle
**  	crlf -- write a CRLF at the end?
**
**  Return value:
**  	A ARC_STAT constant.
*/

static ARC_STAT
arc_canon_header(ARC_MESSAGE *msg, ARC_CANON *canon, struct arc_hdrfield *hdr,
                 _Bool crlf)
{
	ARC_STAT status;

	assert(msg != NULL);
	assert(canon != NULL);
	assert(hdr != NULL);

	if (msg->arc_canonbuf == NULL)
	{
		msg->arc_canonbuf = arc_dstring_new(msg, hdr->hdr_textlen, 0);
		if (msg->arc_canonbuf == NULL)
			return ARC_STAT_NORESOURCE;
	}
	else
	{
		arc_dstring_blank(msg->arc_canonbuf);
	}

	arc_canon_buffer(canon, NULL, 0);

	status = arc_canon_header_string(msg->arc_canonbuf, canon->canon_canon,
	                                 hdr->hdr_text, hdr->hdr_textlen,
	                                 crlf);

	if (status != ARC_STAT_OK)
		return status;

	arc_canon_buffer(canon, arc_dstring_get(msg->arc_canonbuf),
	                 arc_dstring_len(msg->arc_canonbuf));

	return ARC_STAT_OK;
}

/*
**  ARC_CANON_FLUSHBLANKS -- use accumulated blank lines in canonicalization
**
**  Parameters:
**  	canon -- ARC_CANON handle
**
**  Return value:
**  	None.
*/

static void
arc_canon_flushblanks(ARC_CANON *canon)
{
	int c;

	assert(canon != NULL);

	for (c = 0; c < canon->canon_blanks; c++)
		arc_canon_buffer(canon, CRLF, 2);
	canon->canon_blanks = 0;
}

/*
**  ARC_CANON_FIXCRLF -- rebuffer a body chunk, fixing "naked" CRs and LFs
**
**  Parameters:
**  	msg -- ARC message handle
**  	canon -- canonicalization being handled
**  	buf -- buffer to be fixed
**  	buflen -- number of bytes at "buf"
**
**  Return value:
**  	A ARC_STAT_* constant.
**
**  Side effects:
**  	msg->arc_canonbuf will be initialized and used.
*/

static ARC_STAT
arc_canon_fixcrlf(ARC_MESSAGE *msg, ARC_CANON *canon,
                  u_char *buf, size_t buflen)
{
	u_char prev;
	u_char *p;
	u_char *eob;

	assert(msg != NULL);
	assert(canon != NULL);
	assert(buf != NULL);

	if (msg->arc_canonbuf == NULL)
	{
		msg->arc_canonbuf = arc_dstring_new(msg, buflen, 0);
		if (msg->arc_canonbuf == NULL)
			return ARC_STAT_NORESOURCE;
	}
	else
	{
		arc_dstring_blank(msg->arc_canonbuf);
	}

	eob = buf + buflen - 1;

	prev = canon->canon_lastchar;

	for (p = buf; p <= eob; p++)
	{
		if (*p == '\n' && prev != '\r')
		{
			/* fix a solitary LF */
			arc_dstring_catn(msg->arc_canonbuf, CRLF, 2);
		}
		else if (*p == '\r')
		{
			if (p < eob && *(p + 1) != '\n')
				/* fix a solitary CR */
				arc_dstring_catn(msg->arc_canonbuf, CRLF, 2);
			else
				/* CR at EOL, or CR followed by a LF */
				arc_dstring_cat1(msg->arc_canonbuf, *p);
		}
		else
		{
			/* something else */
			arc_dstring_cat1(msg->arc_canonbuf, *p);
		}

		prev = *p;
	}

	return ARC_STAT_OK;
}

/* ========================= PUBLIC SECTION ========================= */

/*
**  ARC_CANON_INIT -- initialize all canonicalizations
**
**  Parameters:
**  	msg -- ARC message handle
**  	tmp -- make temp files?
**  	keep -- keep temp files?
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

ARC_STAT
arc_canon_init(ARC_MESSAGE *msg, _Bool tmp, _Bool keep)
{
	int fd;
	ARC_STAT status;
	ARC_CANON *cur;

	assert(msg != NULL);

	for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
	{
		cur->canon_hashbuf = malloc(ARC_HASHBUFSIZE);
		if (cur->canon_hashbuf == NULL)
		{
			arc_error(msg, "unable to allocate %d byte(s)",
			          ARC_HASHBUFSIZE);
			return ARC_STAT_NORESOURCE;
		}
		cur->canon_hashbufsize = ARC_HASHBUFSIZE;
		cur->canon_hashbuflen = 0;
		cur->canon_buf = arc_dstring_new(msg, BUFRSZ, BUFRSZ);
		if (cur->canon_buf == NULL)
			return ARC_STAT_NORESOURCE;

		switch (cur->canon_hashtype)
		{
		  case ARC_HASHTYPE_SHA1:
		  {
			struct arc_sha1 *sha1;

			sha1 = (struct arc_sha1 *) malloc(sizeof(struct arc_sha1));
			if (sha1 == NULL)
			{
				arc_error(msg,
				          "unable to allocate %d byte(s)",
				          sizeof(struct arc_sha1));
				return ARC_STAT_NORESOURCE;
			}

			memset(sha1, '\0', sizeof(struct arc_sha1));
			SHA1_Init(&sha1->sha1_ctx);

			if (tmp)
			{
				status = arc_tmpfile(msg, &fd, keep);
				if (status != ARC_STAT_OK)
				{
					free(sha1);
					return status;
				}

				sha1->sha1_tmpfd = fd;
				sha1->sha1_tmpbio = BIO_new_fd(fd, 1);
			}

			cur->canon_hash = sha1;

		  	break;
		  }

#ifdef HAVE_SHA256
		  case ARC_HASHTYPE_SHA256:
		  {
			struct arc_sha256 *sha256;

			sha256 = (struct arc_sha256 *) malloc(sizeof(struct arc_sha256));
			if (sha256 == NULL)
			{
				arc_error(msg,
				          "unable to allocate %d byte(s)",
				          sizeof(struct arc_sha256));
				return ARC_STAT_NORESOURCE;
			}

			memset(sha256, '\0', sizeof(struct arc_sha256));
			SHA256_Init(&sha256->sha256_ctx);

			if (tmp)
			{
				status = arc_tmpfile(msg, &fd, keep);
				if (status != ARC_STAT_OK)
				{
					free(sha256);
					return status;
				}

				sha256->sha256_tmpfd = fd;
				sha256->sha256_tmpbio = BIO_new_fd(fd, 1);
			}

			cur->canon_hash = sha256;

		  	break;
		  }
#endif /* HAVE_SHA256 */

		  default:
			assert(0);
		}
	}

	return ARC_STAT_OK;
}

/*
**  ARC_CANON_CLEANUP -- discard canonicalizations
**
**  Parameters:
**  	msg -- ARC message handle
**
**  Return value:
**  	None.
*/

void
arc_canon_cleanup(ARC_MESSAGE *msg)
{
	ARC_CANON *cur;
	ARC_CANON *next;

	assert(msg != NULL);

	cur = msg->arc_canonhead;
	while (cur != NULL)
	{
		next = cur->canon_next;

		arc_canon_free(msg, cur);

		cur = next;
	}

	msg->arc_canonhead = NULL;
}

/*
**  ARC_ADD_CANON -- add a new canonicalization handle if needed
**
**  Parameters:
**  	msg -- verification handle
**  	type -- an ARC_CANONTYPE_* constant
**  	canon -- arc_canon_t
**  	hashtype -- hash type
**  	hdrlist -- for header canonicalization, the header list
**  	sighdr -- pointer to header being verified (NULL for signing)
**  	length -- for body canonicalization, the length limit (-1 == all)
**  	cout -- ARC_CANON handle (returned)
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

ARC_STAT
arc_add_canon(ARC_MESSAGE *msg, int type, arc_canon_t canon, int hashtype,
               u_char *hdrlist, struct arc_hdrfield *sighdr,
               ssize_t length, ARC_CANON **cout)
{
	ARC_CANON *cur;
	ARC_CANON *new;

	assert(msg != NULL);
	assert(canon == ARC_CANON_SIMPLE || canon == ARC_CANON_RELAXED);

	if (arc_libfeature(msg->arc_library, ARC_FEATURE_SHA256))
	{
		assert(hashtype == ARC_HASHTYPE_SHA1 ||
		       hashtype == ARC_HASHTYPE_SHA256);
	}
	else
	{
		assert(hashtype == ARC_HASHTYPE_SHA1);
	}

	if (type == ARC_CANONTYPE_HEADER)
	{
		for (cur = msg->arc_canonhead;
		     cur != NULL;
		     cur = cur->canon_next)
		{
			if (cur->canon_type == ARC_CANONTYPE_HEADER ||
			    cur->canon_hashtype != hashtype)
				continue;

			if (length != cur->canon_length)
				continue;

			if (cout != NULL)
				*cout = cur;

			return ARC_STAT_OK;
		}
	}

	new = (ARC_CANON *) malloc(sizeof *new);
	if (new == NULL)
	{
		arc_error(msg, "unable to allocate %d byte(s)", sizeof *new);
		return ARC_STAT_NORESOURCE;
	}

	new->canon_done = FALSE;
	new->canon_type = type;
	new->canon_hashtype = hashtype;
	new->canon_hash = NULL;
	new->canon_wrote = 0;
	new->canon_canon = canon;
	if (type != ARC_CANONTYPE_BODY)
	{
		new->canon_length = (ssize_t) -1;
		new->canon_remain = (ssize_t) -1;
	}
	else
	{
		new->canon_length = length;
		new->canon_remain = length;
	}
	new->canon_sigheader = sighdr;
	new->canon_hdrlist = hdrlist;
	new->canon_buf = NULL;
	new->canon_next = NULL;
	new->canon_blankline = TRUE;
	new->canon_blanks = 0;
	new->canon_bodystate = 0;
	new->canon_hashbuflen = 0;
	new->canon_hashbufsize = 0;
	new->canon_hashbuf = NULL;
	new->canon_lastchar = '\0';

	if (msg->arc_canonhead == NULL)
	{
		msg->arc_canontail = new;
		msg->arc_canonhead = new;
	}
	else
	{
		msg->arc_canontail->canon_next = new;
		msg->arc_canontail = new;
	}

	if (cout != NULL)
		*cout = new;

	return ARC_STAT_OK;
}

/*
**  ARC_CANON_SELECTHDRS -- choose headers to be included in canonicalization
**
**  Parameters:
**  	msg -- ARC message context in which this is performed
**  	hdrlist -- string containing headers that should be marked, separated
**  	           by the ":" character
**  	ptrs -- array of header pointers (modified)
**  	nptr -- number of pointers available at "ptrs"
**
**  Return value:
**  	Count of headers added to "ptrs", or -1 on error.
**
**  Notes:
**  	Selects header fields to be passed to canonicalization and the order in
**  	which this is done.  "ptrs" is populated by pointers to header fields
**  	in the order in which they should be fed to canonicalization.
**
**  	If any of the returned pointers is NULL, then a header field named by
**  	"hdrlist" was not found.
*/

int
arc_canon_selecthdrs(ARC_MESSAGE *msg, u_char *hdrlist,
                     struct arc_hdrfield **ptrs, int nptrs)
{
	int c;
	int n;
	int m;
	int shcnt;
	size_t len;
	char *bar;
	char *ctx;
	u_char *colon;
	struct arc_hdrfield *hdr;
	struct arc_hdrfield **lhdrs;
	u_char **hdrs;

	assert(msg != NULL);
	assert(ptrs != NULL);
	assert(nptrs != 0);

	/* if there are no header fields named, use them all */
	if (hdrlist == NULL)
	{
		n = 0;

		for (hdr = msg->arc_hhead; hdr != NULL; hdr = hdr->hdr_next)
		{
			if (n >= nptrs)
			{
				arc_error(msg,
				          "too many header fields (max %d)",
				          nptrs);
				return -1;
			}
			ptrs[n] = hdr;
			n++;
		}

		return n;
	}

	if (msg->arc_hdrlist == NULL)
	{
		msg->arc_hdrlist = malloc(ARC_MAXHEADER);
		if (msg->arc_hdrlist == NULL)
		{
			arc_error(msg, "unable to allocate %d bytes(s)",
			          ARC_MAXHEADER);
			return -1;
		}
	}

	strlcpy((char *) msg->arc_hdrlist, (char *) hdrlist, ARC_MAXHEADER);

	/* mark all headers as not used */
	for (hdr = msg->arc_hhead; hdr != NULL; hdr = hdr->hdr_next)
		hdr->hdr_flags &= ~ARC_HDR_SIGNED;

	n = msg->arc_hdrcnt * sizeof(struct arc_hdrfield *);
	lhdrs = malloc(n);
	if (lhdrs == NULL)
		return -1;
	memset(lhdrs, '\0', n);

	shcnt = 1;
	for (colon = msg->arc_hdrlist; *colon != '\0'; colon++)
	{
		if (*colon == ':')
			shcnt++;
	}
	n = sizeof(u_char *) * shcnt;
	hdrs = malloc(n);
	if (hdrs == NULL)
	{
		free(lhdrs);
		return -1;
	}
	memset(hdrs, '\0', n);

	n = 0;

	/* make a split-out copy of hdrlist */
	for (bar = strtok_r((char *) msg->arc_hdrlist, ":", &ctx);
	     bar != NULL;
	     bar = strtok_r(NULL, ":", &ctx))
	{
		hdrs[n] = (u_char *) bar;
		n++;
	}

	/* for each named header, find the last unused one and use it up */
	shcnt = 0;
	for (c = 0; c < n; c++)
	{
		lhdrs[shcnt] = NULL;

		len = MIN(ARC_MAXHEADER, strlen((char *) hdrs[c]));
		while (len > 0 &&
		       ARC_ISWSP(hdrs[c][len - 1]))
			len--;

		for (hdr = msg->arc_hhead; hdr != NULL; hdr = hdr->hdr_next)
		{
			if (hdr->hdr_flags & ARC_HDR_SIGNED)
				continue;

			if (len == hdr->hdr_namelen &&
			    strncasecmp((char *) hdr->hdr_text,
			                (char *) hdrs[c], len) == 0)
				lhdrs[shcnt] = hdr;
		}

		if (lhdrs[shcnt] != NULL)
		{
			lhdrs[shcnt]->hdr_flags |= ARC_HDR_SIGNED;
			shcnt++;
		}
	}

	/* bounds check */
	if (shcnt > nptrs)
	{
		arc_error(msg, "too many headers (found %d, max %d)", shcnt,
		          nptrs);

		free(lhdrs);
		free(hdrs);

		return -1;
	}

	/* copy to the caller's buffers */
	m = 0;
	for (c = 0; c < shcnt; c++)
	{
		if (lhdrs[c] != NULL)
		{
			ptrs[m] = lhdrs[c];
			m++;
		}
	}

	free(lhdrs);
	free(hdrs);

	return m;
}

/*
**  ARC_CANON_STRIP_B -- strip "b=" value from a header field
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle
**  	text -- string containing header field to strip
**
**  Return value:
**  	An ARC_STAT_* constant.
**
**  Side effects:
**  	The stripped header field is left in msg->arc_hdrbuf.
*/

static ARC_STAT
arc_canon_strip_b(ARC_MESSAGE *msg, u_char *text)
{
	int n;
	u_char in;
	u_char last;
	u_char *p;
	u_char *tmp;
	u_char *end;
	u_char tmpbuf[BUFRSZ];

	assert(msg != NULL);
	assert(text != NULL);

	arc_dstring_blank(msg->arc_hdrbuf);

	tmp = tmpbuf;
	end = tmpbuf + sizeof tmpbuf;

	n = 0;
	in = '\0';
	for (p = text; *p != '\0'; p++)
	{
		if (*p == ';')
			in = '\0';

		if (in == 'b')
		{
			last = *p;
			continue;
		}

		if (in == '\0' && *p == '=')
			in = last;

		*tmp++ = *p;

		/* flush buffer? */
		if (tmp == end)
		{
			*tmp = '\0';

			if (!arc_dstring_catn(msg->arc_hdrbuf,
			                      tmpbuf, tmp - tmpbuf))
				return ARC_STAT_NORESOURCE;

			tmp = tmpbuf;
		}

		last = *p;
	}

	/* flush anything cached */
	if (tmp != tmpbuf)
	{
		*tmp = '\0';

		if (!arc_dstring_catn(msg->arc_hdrbuf,
		                      tmpbuf, tmp - tmpbuf))
			return ARC_STAT_NORESOURCE;
	}

	return ARC_STAT_OK;
}

/*
**  ARC_CANON_FINALIZE -- finalize a canonicalization
**
**  Parameters:
**  	canon -- canonicalization to finalize
**
**  Return value:
**  	None.
*/

static void
arc_canon_finalize(ARC_CANON *canon)
{
	assert(canon != NULL);

	switch (canon->canon_hashtype)
	{
	  case ARC_HASHTYPE_SHA1:
	  {
		struct arc_sha1 *sha1;

		sha1 = (struct arc_sha1 *) canon->canon_hash;
		SHA1_Final(sha1->sha1_out, &sha1->sha1_ctx);

		if (sha1->sha1_tmpbio != NULL)
			(void) BIO_flush(sha1->sha1_tmpbio);

		break;
	  }

#ifdef HAVE_SHA256
	  case ARC_HASHTYPE_SHA256:
	  {
		struct arc_sha256 *sha256;

		sha256 = (struct arc_sha256 *) canon->canon_hash;
		SHA256_Final(sha256->sha256_out, &sha256->sha256_ctx);

		if (sha256->sha256_tmpbio != NULL)
			(void) BIO_flush(sha256->sha256_tmpbio);

		break;
	  }
#endif /* HAVE_SHA256 */

	  default:
		assert(0);
		/* NOTREACHED */
	}
}

/*
**  ARC_CANON_RUNHEADERS_SEAL -- run the ARC-specific header fields through
**                               seal canonicalization(s)
**
**  Parameters:
**  	msg -- ARC_MESSAGE handle
**
**  Return value:
**  	An ARC_STAT_* constant.
**
**  For each ARC set number N, apply it to seal canonicalization handles 0
**  through N-1.  That way the first one is only set 1, the second one is
**  sets 1 and 2, etc.  For the final one in each set, strip "b=".  Then
**  also do one more complete one so that can be used for re-sealing.
*/

ARC_STAT
arc_canon_runheaders_seal(ARC_MESSAGE *msg)
{
	ARC_STAT status;
	u_int m;
	u_int n;
	ARC_CANON *cur;

	assert(msg != NULL);

	for (n = 0; n < msg->arc_nsets; n++)
	{
		cur = msg->arc_sealcanons[n];

		if (cur->canon_done)
			continue;

		/* build up the canonicalized seals for verification */
		for (m = 0; m <= n; m++)
		{
			status = arc_canon_header(msg, cur,
			                          msg->arc_sets[m].arcset_aar,
			                          TRUE);
			if (status != ARC_STAT_OK)
				return status;

			status = arc_canon_header(msg, cur,
			                          msg->arc_sets[m].arcset_ams,
			                          TRUE);
			if (status != ARC_STAT_OK)
				return status;

			if (m != n)
			{
				status = arc_canon_header(msg, cur,
				                          msg->arc_sets[m].arcset_as,
				                          TRUE);
			}
			else
			{
				struct arc_hdrfield tmphdr;
				arc_canon_strip_b(msg,
				                  msg->arc_sets[m].arcset_as->hdr_text);

				tmphdr.hdr_text = arc_dstring_get(msg->arc_hdrbuf);
				tmphdr.hdr_namelen = cur->canon_sigheader->hdr_namelen;
				tmphdr.hdr_colon = tmphdr.hdr_text + (cur->canon_sigheader->hdr_colon - cur->canon_sigheader->hdr_text);
				tmphdr.hdr_textlen = arc_dstring_len(msg->arc_hdrbuf);
				tmphdr.hdr_flags = 0;
				tmphdr.hdr_next = NULL;

				arc_lowerhdr(tmphdr.hdr_text);
				/* XXX -- void? */
				(void) arc_canon_header(msg, cur, &tmphdr,
				                        FALSE);
				arc_canon_buffer(cur, NULL, 0);
			}

			if (status != ARC_STAT_OK)
				return status;
		}

		arc_canon_finalize(cur);
		cur->canon_done = TRUE;

		cur = msg->arc_sealcanon;

		if (cur->canon_done)
			continue;

		/* write all the ARC sets once more for re-sealing */
		status = arc_canon_header(msg, cur,
		                          msg->arc_sets[n].arcset_aar,
		                          TRUE);
		if (status != ARC_STAT_OK)
			return status;

		status = arc_canon_header(msg, cur,
		                          msg->arc_sets[n].arcset_ams,
		                          TRUE);
		if (status != ARC_STAT_OK)
			return status;

		status = arc_canon_header(msg, cur,
		                          msg->arc_sets[n].arcset_as,
		                          TRUE);
		if (status != ARC_STAT_OK)
			return status;
	}

	return ARC_STAT_OK;
}

/*
**  ARC_CANON_RUNHEADERS -- run the headers through all header and seal
**                          canonicalizations
**
**  Parameters:
**  	msg -- ARC message handle
**
**  Return value:
**  	A ARC_STAT_* constant.
**
**  Note:
**  	Header canonicalizations are finalized by this function when
**  	verifying.  In signing mode, header canonicalizations are finalized
**  	by a subsequent call to arc_canon_signature().
*/

ARC_STAT
arc_canon_runheaders(ARC_MESSAGE *msg)
{
	_Bool signing;
	u_char savechar;
	int c;
	int n;
	int in;
	int nhdrs = 0;
	int last = '\0';
	ARC_STAT status;
	u_char *tmp;
	u_char *end;
	ARC_CANON *cur;
	u_char *p;
	struct arc_hdrfield *hdr;
	struct arc_hdrfield **hdrset;
	struct arc_hdrfield tmphdr;
	u_char tmpbuf[BUFRSZ];

	assert(msg != NULL);

	tmp = tmpbuf;
	end = tmpbuf + sizeof tmpbuf - 1;

	n = msg->arc_hdrcnt * sizeof(struct arc_hdrfield *);
	hdrset = malloc(n);
	if (hdrset == NULL)
		return ARC_STAT_NORESOURCE;

	if (msg->arc_hdrbuf == NULL)
	{
		msg->arc_hdrbuf = arc_dstring_new(msg, BUFRSZ, MAXBUFRSZ);
		if (msg->arc_hdrbuf == NULL)
		{
			free(hdrset);
			return ARC_STAT_NORESOURCE;
		}
	}
	else
	{
		arc_dstring_blank(msg->arc_hdrbuf);
	}

	for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
	{
		arc_dstring_blank(msg->arc_hdrbuf);

		/* skip done hashes and those which are of the wrong type */
		if (cur->canon_done || cur->canon_type != ARC_CANONTYPE_HEADER)
			continue;

		signing = (cur->canon_sigheader == NULL);

		/* clear header selection flags if verifying */
		if (!signing)
		{
			if (cur->canon_hdrlist == NULL)
			{
				for (hdr = msg->arc_hhead;
				     hdr != NULL;
				     hdr = hdr->hdr_next)
					hdr->hdr_flags |= ARC_HDR_SIGNED;
			}
			else
			{
				for (hdr = msg->arc_hhead;
				     hdr != NULL;
				     hdr = hdr->hdr_next)
					hdr->hdr_flags &= ~ARC_HDR_SIGNED;

				memset(hdrset, '\0', n);

				/* do header selection */
				nhdrs = arc_canon_selecthdrs(msg,
				                             cur->canon_hdrlist,
				                             hdrset,
				                             msg->arc_hdrcnt);

				if (nhdrs == -1)
				{
					arc_error(msg,
					          "arc_canon_selecthdrs() failed during canonicalization");
					free(hdrset);
					return ARC_STAT_INTERNAL;
				}
			}
		}
		else
		{
			ARC_LIB *lib;
			regex_t *hdrtest;

			lib = msg->arc_library;
			hdrtest = &lib->arcl_hdrre;

			memset(hdrset, '\0', sizeof *hdrset);
			nhdrs = 0;

			/* tag all header fields to be signed */
			for (hdr = msg->arc_hhead;
			     hdr != NULL;
			     hdr = hdr->hdr_next)
			{
				if (!lib->arcl_signre)
				{
					if (strncasecmp(ARC_AR_HDRNAME,
					                hdr->hdr_text,
					                hdr->hdr_namelen) == 0 ||
					    strncasecmp(ARC_MSGSIG_HDRNAME,
					                hdr->hdr_text,
					                hdr->hdr_namelen) == 0 ||
					    strncasecmp(ARC_SEAL_HDRNAME,
					                hdr->hdr_text,
					                hdr->hdr_namelen) == 0)
						continue;

					tmp = arc_dstring_get(msg->arc_hdrbuf);

					if (tmp[0] != '\0')
						arc_dstring_cat1(msg->arc_hdrbuf, ':');

					arc_dstring_catn(msg->arc_hdrbuf,
					                  hdr->hdr_text,
					                  hdr->hdr_namelen);
					continue;
				}

				/* could be space, could be colon ... */
				savechar = hdr->hdr_text[hdr->hdr_namelen];

				/* terminate the header field name and test */
				hdr->hdr_text[hdr->hdr_namelen] = '\0';
				status = regexec(hdrtest,
				                 (char *) hdr->hdr_text,
				                 0, NULL, 0);

				/* restore the character */
				hdr->hdr_text[hdr->hdr_namelen] = savechar;

				if (status == 0)
				{
					tmp = arc_dstring_get(msg->arc_hdrbuf);

					if (tmp[0] != '\0')
					{
						arc_dstring_cat1(msg->arc_hdrbuf, ':');
					}
					arc_dstring_catn(msg->arc_hdrbuf, hdr->hdr_text, hdr->hdr_namelen);
				}
				else
				{
					assert(status == REG_NOMATCH);
				}
			}


			memset(hdrset, '\0', n);

			/* do header selection */
			nhdrs = arc_canon_selecthdrs(msg,
			                             arc_dstring_get(msg->arc_hdrbuf),
			                             hdrset,
			                             msg->arc_hdrcnt);

			if (nhdrs == -1)
			{
				arc_error(msg,
				          "arc_canon_selecthdrs() failed during canonicalization");
				free(hdrset);
				return ARC_STAT_INTERNAL;
			}
		}

		/* canonicalize each marked header */
		for (c = 0; c < nhdrs; c++)
		{
			if (hdrset[c] != NULL &&
			    (hdrset[c]->hdr_flags & ARC_HDR_SIGNED) != 0)
			{
				status = arc_canon_header(msg, cur,
				                          hdrset[c], TRUE);
				if (status != ARC_STAT_OK)
				{
					free(hdrset);
					return status;
				}
			}
		}

		/* if signing, we can't do the rest of this yet */
		if (cur->canon_sigheader == NULL)
			continue;

		/*
		**  We need to copy the ARC-Message-Signature: field being
		**  verified, minus the contents of the "b=" part, and include
		**  it in the canonicalization.  However, skip this if no
		**  hashing was done.
		*/

		status = arc_canon_strip_b(msg, cur->canon_sigheader->hdr_text);
		if (status != ARC_STAT_OK)
		{
			free(hdrset);
			return status;
		}

		/* canonicalize */
		tmphdr.hdr_text = arc_dstring_get(msg->arc_hdrbuf);
		tmphdr.hdr_namelen = cur->canon_sigheader->hdr_namelen;
		tmphdr.hdr_colon = tmphdr.hdr_text + (cur->canon_sigheader->hdr_colon - cur->canon_sigheader->hdr_text);
		tmphdr.hdr_textlen = arc_dstring_len(msg->arc_hdrbuf);
		tmphdr.hdr_flags = 0;
		tmphdr.hdr_next = NULL;

		(void) arc_canon_header(msg, cur, &tmphdr, FALSE);
		arc_canon_buffer(cur, NULL, 0);

		/* finalize */
		arc_canon_finalize(cur);

		cur->canon_done = TRUE;
	}

	free(hdrset);

	return ARC_STAT_OK;
}

/*
**  ARC_CANON_SIGNATURE -- append a signature header when signing
**
**  Parameters:
**  	msg -- ARC message handle
**  	hdr -- header
**  	seal -- TRUE iff this is for an ARC-Seal
**
**  Return value:
**  	A ARC_STAT_* constant.
**
**  Notes:
**  	Header canonicalizations are finalized by this function.
*/

ARC_STAT
arc_canon_signature(ARC_MESSAGE *msg, struct arc_hdrfield *hdr, _Bool seal)
{
	ARC_STAT status;
	ARC_CANON *cur;
	struct arc_hdrfield tmphdr;

	assert(msg != NULL);
	assert(hdr != NULL);

	if (msg->arc_hdrbuf == NULL)
	{
		msg->arc_hdrbuf = arc_dstring_new(msg, ARC_MAXHEADER, 0);
		if (msg->arc_hdrbuf == NULL)
			return ARC_STAT_NORESOURCE;
	}
	else
	{
		arc_dstring_blank(msg->arc_hdrbuf);
	}

	for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
	{
		/* skip done hashes and those which are of the wrong type */
		if (cur->canon_done)
			continue;
		if (!seal && cur->canon_type != ARC_CANONTYPE_HEADER)
			continue;
		if (seal && cur->canon_type != ARC_CANONTYPE_SEAL)
			continue;

		/* prepare the data */
		arc_dstring_copy(msg->arc_hdrbuf, hdr->hdr_text);
		tmphdr.hdr_text = arc_dstring_get(msg->arc_hdrbuf);
		tmphdr.hdr_namelen = hdr->hdr_namelen;
		tmphdr.hdr_colon = tmphdr.hdr_text + (hdr->hdr_colon - hdr->hdr_text);
		tmphdr.hdr_textlen = arc_dstring_len(msg->arc_hdrbuf);
		tmphdr.hdr_flags = 0;
		tmphdr.hdr_next = NULL;
		arc_lowerhdr(tmphdr.hdr_text);

		/* canonicalize the signature */
		status = arc_canon_header(msg, cur, &tmphdr, FALSE);
		if (status != ARC_STAT_OK)
			return status;
		arc_canon_buffer(cur, NULL, 0);

		/* now close it */
		arc_canon_finalize(cur);

		cur->canon_done = TRUE;
	}

	return ARC_STAT_OK;
}

/*
**  ARC_CANON_MINBODY -- return number of bytes required to satisfy all
**                       canonicalizations
**
**  Parameters:
**  	msg -- ARC message handle
**
**  Return value:
**  	0 -- all canonicalizations satisfied
**  	ULONG_MAX -- at least one canonicalization wants the whole message
**  	other -- bytes required to satisfy all canonicalizations
*/

u_long
arc_canon_minbody(ARC_MESSAGE *msg)
{
	u_long minbody = 0;
	ARC_CANON *cur;

	assert(msg != NULL);

	for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
	{
		/* skip done hashes and those which are of the wrong type */
		if (cur->canon_done || cur->canon_type != ARC_CANONTYPE_BODY)
			continue;

		/* if this one wants the whole message, short-circuit */
		if (cur->canon_remain == (ssize_t) -1)
			return ULONG_MAX;

		/* compare to current minimum */
		minbody = MAX(minbody, (u_long) cur->canon_remain);
	}

	return minbody;
}

/*
**  ARC_CANON_BODYCHUNK -- run a body chunk through all body
**                          canonicalizations
**
**  Parameters:
**  	msg -- ARC message handle
**  	buf -- pointer to bytes to canonicalize
**  	buflen -- number of bytes to canonicalize
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

ARC_STAT
arc_canon_bodychunk(ARC_MESSAGE *msg, u_char *buf, size_t buflen)
{
	_Bool fixcrlf;
	ARC_STAT status;
	u_int wlen;
	ARC_CANON *cur;
	size_t plen;
	u_char *p;
	u_char *wrote;
	u_char *eob;
	u_char *start;

	assert(msg != NULL);

	msg->arc_bodylen += buflen;

	fixcrlf = (msg->arc_library->arcl_flags & ARC_LIBFLAGS_FIXCRLF);

	for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
	{
		/* skip done hashes and those which are of the wrong type */
		if (cur->canon_done || cur->canon_type != ARC_CANONTYPE_BODY)
			continue;

		start = buf;
		plen = buflen;

		if (fixcrlf)
		{
			status = arc_canon_fixcrlf(msg, cur, buf, buflen);
			if (status != ARC_STAT_OK)
				return status;

			start = arc_dstring_get(msg->arc_canonbuf);
			plen = arc_dstring_len(msg->arc_canonbuf);
		}

		eob = start + plen - 1;
		wrote = start;
		wlen = 0;

		switch (cur->canon_canon)
		{
		  case ARC_CANON_SIMPLE:
			for (p = start; p <= eob; p++)
			{
				if (*p == '\n')
				{
					if (cur->canon_lastchar == '\r')
					{
						if (cur->canon_blankline)
						{
							cur->canon_blanks++;
						}
						else if (wlen == 1 ||
						         p == start)
						{
							arc_canon_buffer(cur,
							                 CRLF,
							                 2);
						}
						else
						{
							arc_canon_buffer(cur,
							                 wrote,
							                 wlen + 1);
						}

						wrote = p + 1;
						wlen = 0;
						cur->canon_blankline = TRUE;
					}
				}
				else
				{
					if (p == start &&
					    cur->canon_lastchar == '\r')
					{
						if (fixcrlf)
						{
							arc_canon_buffer(cur,
							                 CRLF,
							                 2);
							cur->canon_lastchar = '\n';
							cur->canon_blankline = TRUE;
						}
						else
						{
							arc_canon_buffer(cur,
							                 (u_char *) "\r",
							                 1);
						}
					}

					if (*p != '\r')
					{
						if (cur->canon_blanks > 0)
							arc_canon_flushblanks(cur);
						cur->canon_blankline = FALSE;
					}

					wlen++;
				}

				cur->canon_lastchar = *p;
			}

			if (wlen > 0 && wrote[wlen - 1] == '\r')
				wlen--;

			arc_canon_buffer(cur, wrote, wlen);

			break;

		  case ARC_CANON_RELAXED:
			for (p = start; p <= eob; p++)
			{
				switch (cur->canon_bodystate)
				{
				  case 0:
					if (ARC_ISWSP(*p))
					{
						cur->canon_bodystate = 1;
					}
					else if (*p == '\r')
					{
						cur->canon_bodystate = 2;
					}
					else
					{
						cur->canon_blankline = FALSE;
						arc_dstring_cat1(cur->canon_buf,
						                 *p);
						cur->canon_bodystate = 3;
					}
					break;

				  case 1:
					if (ARC_ISWSP(*p))
					{
						break;
					}
					else if (*p == '\r')
					{
						cur->canon_bodystate = 2;
					}
					else
					{
						arc_canon_flushblanks(cur);
						arc_canon_buffer(cur, SP, 1);
						cur->canon_blankline = FALSE;
						arc_dstring_cat1(cur->canon_buf,
						                 *p);
						cur->canon_bodystate = 3;
					}
					break;

				  case 2:
					if (fixcrlf || *p == '\n')
					{
						if (cur->canon_blankline)
						{
							cur->canon_blanks++;
							cur->canon_bodystate = 0;
						}
						else
						{
							arc_canon_flushblanks(cur);
							arc_canon_buffer(cur,
							                 arc_dstring_get(cur->canon_buf),
							                 arc_dstring_len(cur->canon_buf));
							arc_canon_buffer(cur,
							                 CRLF,
							                 2);
							arc_dstring_blank(cur->canon_buf);

							if (*p == '\n')
							{
								cur->canon_blankline = TRUE;
								cur->canon_bodystate = 0;
							}
							else if (*p == '\r')
							{
								cur->canon_blankline = TRUE;
							}
							else
							{
								if (ARC_ISWSP(*p))
								{
									cur->canon_bodystate = 1;
								}
								else
								{
									arc_dstring_cat1(cur->canon_buf,
									                 *p);
									cur->canon_bodystate = 3;
								}
							}
						}
					}
					else if (*p == '\r')
					{
						cur->canon_blankline = FALSE;
						arc_dstring_cat1(cur->canon_buf,
						                 *p);
					}
					else if (ARC_ISWSP(*p))
					{
						arc_canon_flushblanks(cur);
						arc_canon_buffer(cur,
						                 arc_dstring_get(cur->canon_buf),
						                 arc_dstring_len(cur->canon_buf));
						arc_dstring_blank(cur->canon_buf);
						cur->canon_bodystate = 1;
					}
					else
					{
						cur->canon_blankline = FALSE;
						arc_dstring_cat1(cur->canon_buf,
						                 *p);
						cur->canon_bodystate = 3;
					}
					break;

				  case 3:
					if (ARC_ISWSP(*p))
					{
						arc_canon_flushblanks(cur);
						arc_canon_buffer(cur,
						                 arc_dstring_get(cur->canon_buf),
						                 arc_dstring_len(cur->canon_buf));
						arc_dstring_blank(cur->canon_buf);
						cur->canon_bodystate = 1;
					}
					else if (*p == '\r')
					{
						cur->canon_bodystate = 2;
					}
					else
					{
						arc_dstring_cat1(cur->canon_buf,
						                 *p);
					}
					break;
				}

				cur->canon_lastchar = *p;
			}

			arc_canon_buffer(cur, NULL, 0);

			break;

		  default:
			assert(0);
			/* NOTREACHED */
		}

		arc_canon_buffer(cur, NULL, 0);
	}

	return ARC_STAT_OK;
}

/*
**  ARC_CANON_CLOSEBODY -- close all body canonicalizations
**
**  Parameters:
**  	msg -- ARC message handle
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

ARC_STAT
arc_canon_closebody(ARC_MESSAGE *msg)
{
	ARC_CANON *cur;

	assert(msg != NULL);

	for (cur = msg->arc_canonhead; cur != NULL; cur = cur->canon_next)
	{
		/* skip done hashes or header canonicalizations */
		if (cur->canon_done || cur->canon_type != ARC_CANONTYPE_BODY)
			continue;

		/* handle unprocessed content */
		if (arc_dstring_len(cur->canon_buf) > 0)
		{
			if ((msg->arc_library->arcl_flags & ARC_LIBFLAGS_FIXCRLF) != 0)
			{
				arc_canon_buffer(cur,
				                 arc_dstring_get(cur->canon_buf),
				                 arc_dstring_len(cur->canon_buf));
				arc_canon_buffer(cur, CRLF, 2);
			}
			else
			{
				arc_error(msg, "CRLF at end of body missing");
				return ARC_STAT_SYNTAX;
			}
		}

		arc_canon_buffer(cur, NULL, 0);

		/* finalize */
		switch (cur->canon_hashtype)
		{
		  case ARC_HASHTYPE_SHA1:
		  {
			struct arc_sha1 *sha1;

			sha1 = (struct arc_sha1 *) cur->canon_hash;
			SHA1_Final(sha1->sha1_out, &sha1->sha1_ctx);

			if (sha1->sha1_tmpbio != NULL)
				(void) BIO_flush(sha1->sha1_tmpbio);

			break;
		  }

#ifdef HAVE_SHA256
		  case ARC_HASHTYPE_SHA256:
		  {
			struct arc_sha256 *sha256;

			sha256 = (struct arc_sha256 *) cur->canon_hash;
			SHA256_Final(sha256->sha256_out, &sha256->sha256_ctx);

			if (sha256->sha256_tmpbio != NULL)
				(void) BIO_flush(sha256->sha256_tmpbio);

			break;
		  }
#endif /* HAVE_SHA256 */

		  default:
			assert(0);
			/* NOTREACHED */
		}

		cur->canon_done = TRUE;
	}

	return ARC_STAT_OK;
}

/*
**  ARC_CANON_GETFINAL -- retrieve final digest
**
**  Parameters:
**  	canon -- ARC_CANON handle
**  	digest -- pointer to the digest (returned)
**  	dlen -- digest length (returned)
**
**  Return value:
**  	A ARC_STAT_* constant.
*/

ARC_STAT
arc_canon_getfinal(ARC_CANON *canon, u_char **digest, size_t *dlen)
{
	assert(canon != NULL);
	assert(digest != NULL);
	assert(dlen != NULL);

	if (!canon->canon_done)
		return ARC_STAT_INVALID;

	switch (canon->canon_hashtype)
	{
	  case ARC_HASHTYPE_SHA1:
	  {
		struct arc_sha1 *sha1;

		sha1 = (struct arc_sha1 *) canon->canon_hash;
		*digest = sha1->sha1_out;
		*dlen = sizeof sha1->sha1_out;

		return ARC_STAT_OK;
	  }

#ifdef HAVE_SHA256
	  case ARC_HASHTYPE_SHA256:
	  {
		struct arc_sha256 *sha256;

		sha256 = (struct arc_sha256 *) canon->canon_hash;
		*digest = sha256->sha256_out;
		*dlen = sizeof sha256->sha256_out;

		return ARC_STAT_OK;
	  }
#endif /* HAVE_SHA256 */

	  default:
		assert(0);
		/* NOTREACHED */
		return ARC_STAT_INTERNAL;
	}
}

/*
**  ARC_CANON_GETSEALHASHES -- retrieve a seal hash
**
**  Parameters:
**  	msg -- ARC message from which to get completed hashes
**  	setnum -- which seal's hash to get
**  	sh -- pointer to seal hash buffer (returned)
**  	shlen -- bytes used at sh (returned)
**
**  Return value:
**  	ARC_STAT_OK -- successful completion
**  	ARC_STAT_INVALID -- hashing hasn't been completed
*/

ARC_STAT
arc_canon_getsealhash(ARC_MESSAGE *msg, int setnum, void **sh, size_t *shlen)
{
	ARC_STAT status;
	struct arc_canon *sdc;
	u_char *sd;
	size_t sdlen;

	assert(msg != NULL);
	assert(setnum <= msg->arc_nsets);

	sdc = msg->arc_sealcanons[setnum - 1];

	status = arc_canon_getfinal(sdc, &sd, &sdlen);
	if (status != ARC_STAT_OK)
		return status;
	*sh = sd;
	*shlen = sdlen;

	return ARC_STAT_OK;
}

/*
**  ARC_CANON_GETHASHES -- retrieve hashes
**
**  Parameters:
**  	msg -- ARC message from which to get completed hashes
**  	hh -- pointer to header hash buffer (returned)
**  	hhlen -- bytes used at hh (returned)
**  	bh -- pointer to body hash buffer (returned)
**  	bhlen -- bytes used at bh (returned)
**
**  Return value:
**  	ARC_STAT_OK -- successful completion
**  	ARC_STAT_INVALID -- hashing hasn't been completed
*/

ARC_STAT
arc_canon_gethashes(ARC_MESSAGE *msg, void **hh, size_t *hhlen,
                    void **bh, size_t *bhlen)
{
	ARC_STAT status;
	struct arc_canon *hdc;
	struct arc_canon *bdc;
	u_char *hd;
	u_char *bd;
	size_t hdlen;
	size_t bdlen;

	hdc = msg->arc_valid_hdrcanon;
	bdc = msg->arc_valid_bodycanon;

	status = arc_canon_getfinal(hdc, &hd, &hdlen);
	if (status != ARC_STAT_OK)
		return status;
	*hh = hd;
	*hhlen = hdlen;

	status = arc_canon_getfinal(bdc, &bd, &bdlen);
	if (status != ARC_STAT_OK)
		return status;
	*bh = bd;
	*bhlen = bdlen;

	return ARC_STAT_OK;
}

/*
**  ARC_CANON_ADD_TO_SEAL -- canonicalize partial seal
**
**  Parameters:
**  	msg -- ARC message to update
**
**  Return value:
**  	ARC_STAT_OK -- successful completion
*/

ARC_STAT
arc_canon_add_to_seal(ARC_MESSAGE *msg)
{
	ARC_STAT status;
	struct arc_canon *sc;
	struct arc_hdrfield *hdr;

	sc = msg->arc_sealcanon;

	for (hdr = msg->arc_sealhead; hdr != NULL; hdr = hdr->hdr_next)
	{
		status = arc_canon_header(msg, msg->arc_sealcanon, hdr, TRUE);
		if (status != ARC_STAT_OK)
			return status;
	}

	return ARC_STAT_OK;
}

/*
**  ARC_PARSE_CANON_T -- parse a c= tag
**
**  Parameters:
**    tag        -- c=
**    hdr_canon  -- the header canon output
**    body_canon -- the body canon output
**
**  Return value:
**    ARC_STAT_OK -- successful completion
*/

ARC_STAT
arc_parse_canon_t(unsigned char *tag, arc_canon_t *hdr_canon, arc_canon_t *body_canon)
{
	char *token;
	int code;

	token = strtok(tag, "/");
	code = arc_name_to_code(canonicalizations, token);

	if (code == -1)
		return ARC_STAT_INVALID;

	*hdr_canon = (arc_canon_t) code;

	token = strtok(NULL, "/");
	code = arc_name_to_code(canonicalizations, token);

	if (code == -1)
		return ARC_STAT_INVALID;

	*body_canon = (arc_canon_t) code;

	return ARC_STAT_OK;
}
