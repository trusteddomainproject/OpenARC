/*
**  Copyright (c) 2016, The Trusted Domain Project.  All rights reserved.
*/

/* system includes */
#include <sys/types.h>
#include <assert.h>

/* libopendkim includes */
#include "base64.h"

/* base64 alphabet */
static unsigned char alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* base64 decode stuff */
static int decoder[256] =
{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,
	0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
	14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0,
	0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#ifndef NULL
# define NULL	0
#endif /* ! NULL */

/*
**  ARC_BASE64_DECODE -- decode a base64 blob
**
**  Parameters:
**  	str -- string to decide
**  	buf -- where to write it
**  	buflen -- bytes available at "buf"
**
**  Return value:
**  	>= 0 -- success; length of what was decoded is returned
**  	-1 -- corrupt
**  	-2 -- not enough space at "buf"
*/

int
arc_base64_decode(u_char *str, u_char *buf, size_t buflen)
{
	int n = 0;
	int bits = 0;
	int char_count = 0;
	u_char *c;

	assert(str != NULL);
	assert(buf != NULL);

	for (c = str; *c != '=' && *c != '\0'; c++)
	{
		/* end padding */
		if (*c == '=' || *c == '\0')
			break;

		/* skip stuff not part of the base64 alphabet (RFC2045) */
		if (!((*c >= 'A' && *c <= 'Z') ||
		      (*c >= 'a' && *c <= 'z') ||
		      (*c >= '0' && *c <= '9') ||
		      (*c == '+') ||
		      (*c == '/')))
			continue;

		/* everything else gets decoded */
		bits += decoder[(int) *c];
		char_count++;
		if (n + 3 > buflen)
			return -2;
		if (char_count == 4)
		{
			buf[n++] = (bits >> 16);
			buf[n++] = ((bits >> 8) & 0xff);
			buf[n++] = (bits & 0xff);
			bits = 0;
			char_count = 0;
		}
		else
		{
			bits <<= 6;
		}
	}

	/* XXX -- don't bother checking for proper termination (for now) */

	/* process trailing data, if any */
	switch (char_count)
	{
	  case 0:
		break;

	  case 1:
		/* base64 decoding incomplete; at least two bits missing */
		return -1;

	  case 2:
		if (n + 1 > buflen)
			return -2;
		buf[n++] = (bits >> 10);
		break;

	  case 3:
		if (n + 2 > buflen)
			return -2;
		buf[n++] = (bits >> 16);
		buf[n++] = ((bits >> 8) & 0xff);
		break;
	}

	return n;
}

/*
**  ARC_BASE64_ENCODE -- encode base64 data
**
**  Parameters:
**  	data -- data to encode
**  	datalen -- bytes at "data" to encode
**  	buf -- where to write the encoding
**  	buflen -- bytes available at "buf"
**
**  Return value:
**  	>= 0 -- success; number of bytes written to "buf" returned
**   	-1 -- failure (not enough space at "buf")
*/

int
arc_base64_encode(u_char *data, size_t datalen, u_char *buf, size_t buflen)
{
	int bits;
	int c;
	int char_count;
	size_t n;

	assert(data != NULL);
	assert(buf != NULL);

	bits = 0;
	char_count = 0;
	n = 0;

	for (c = 0; c < datalen; c++)
	{
		bits += data[c];
		char_count++;
		if (char_count == 3)
		{
			if (n + 4 > buflen)
				return -1;

			buf[n++] = alphabet[bits >> 18];
			buf[n++] = alphabet[(bits >> 12) & 0x3f];
			buf[n++] = alphabet[(bits >> 6) & 0x3f];
			buf[n++] = alphabet[bits & 0x3f];
			bits = 0;
			char_count = 0;
		}
		else
		{
			bits <<= 8;
		}
	}

	if (char_count != 0)
	{
		if (n + 4 > buflen)
			return -1;

		bits <<= 16 - (8 * char_count);
		buf[n++] = alphabet[bits >> 18];
		buf[n++] = alphabet[(bits >> 12) & 0x3f];
		if (char_count == 1)
		{
			buf[n++] = '=';
			buf[n++] = '=';
		}
		else
		{
			buf[n++] = alphabet[(bits >> 6) & 0x3f];
			buf[n++] = '=';
		}
	}

	return n;
}
