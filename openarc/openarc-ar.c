/*
**  Copyright (c) 2007-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2011-2014, 2016, The Trusted Domain Project.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <ctype.h>
#include <assert.h>
#include <string.h>
#ifdef ARTEST
# include <sysexits.h>
#endif /* ARTEST */

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* openarc includes */
#include "openarc-ar.h"

/* macros */
#define	ARES_ENDOF(x)		((x) + sizeof(x) - 1)
#define	ARES_STRORNULL(x)	((x) == NULL ? "(null)" : (x))
#define	ARES_TOKENS		";=."
#define	ARES_TOKENS2		"=."

#define	ARES_MAXTOKENS		512

/* tables */
struct lookup
{
	char *	str;
	int	code;
};

struct lookup methods[] =
{
	{ "arc",		ARES_METHOD_ARC },
	{ "auth",		ARES_METHOD_AUTH },
	{ "dkim",		ARES_METHOD_DKIM },
	{ "dkim-adsp",		ARES_METHOD_DKIMADSP },
	{ "dkim-atps",		ARES_METHOD_DKIMATPS },
	{ "dmarc",		ARES_METHOD_DMARC },
	{ "domainkeys",		ARES_METHOD_DOMAINKEYS },
	{ "iprev",		ARES_METHOD_IPREV },
	{ "rrvs",		ARES_METHOD_RRVS },
	{ "sender-id",		ARES_METHOD_SENDERID },
	{ "smime",		ARES_METHOD_SMIME },
	{ "spf",		ARES_METHOD_SPF },
	{ NULL,			ARES_METHOD_UNKNOWN }
};

struct lookup aresults[] =
{
	{ "none",		ARES_RESULT_NONE },
	{ "pass",		ARES_RESULT_PASS },
	{ "fail",		ARES_RESULT_FAIL },
	{ "policy",		ARES_RESULT_POLICY },
	{ "neutral",		ARES_RESULT_NEUTRAL },
	{ "temperror",		ARES_RESULT_TEMPERROR },
	{ "permerror",		ARES_RESULT_PERMERROR },
	{ "nxdomain",		ARES_RESULT_NXDOMAIN },
	{ "signed",		ARES_RESULT_SIGNED },
	{ "unknown",		ARES_RESULT_UNKNOWN },
	{ "discard",		ARES_RESULT_DISCARD },
	{ "softfail",		ARES_RESULT_SOFTFAIL },
	{ NULL,			ARES_RESULT_UNKNOWN }
};

struct lookup ptypes[] =
{
	{ "smtp",		ARES_PTYPE_SMTP },
	{ "header",		ARES_PTYPE_HEADER },
	{ "body",		ARES_PTYPE_BODY },
	{ "policy",		ARES_PTYPE_POLICY },
	{ NULL,			ARES_PTYPE_UNKNOWN }
};

/*
**  ARES_TOKENIZE -- tokenize a string
**
**  Parameters:
**  	input -- input string
**  	outbuf -- output buffer
**  	outbuflen -- number of bytes available at "outbuf"
**  	tokens -- array of token pointers
**  	ntokens -- number of token pointers available at "tokens"
**
**  Return value:
**  	-1 -- not enough space at "outbuf" for tokenizing
**  	other -- number of tokens identified; may be greater than
**  	"ntokens" if there were more tokens found than there were
**  	pointers available.
*/

static int
ares_tokenize(u_char *input, u_char *outbuf, size_t outbuflen,
              u_char **tokens, int ntokens)
{
	_Bool quoted = FALSE;
	_Bool escaped = FALSE;
	_Bool intok = FALSE;
	int n = 0;
	int parens = 0;
	u_char *p;
	u_char *q;
	u_char *end;

	assert(input != NULL);
	assert(outbuf != NULL);
	assert(outbuflen > 0);
	assert(tokens != NULL);
	assert(ntokens > 0);

	q = outbuf;
	end = outbuf + outbuflen - 1;

	for (p = input; *p != '\0' && q <= end; p++)
	{
		if (escaped)				/* escape */
		{
			if (!intok)
			{
				if (n < ntokens)
					tokens[n] = q;
				intok = TRUE;
			}

			*q = *p;
			q++;
			escaped = FALSE;
		}
		else if (*p == '\\')			/* escape */
		{
			escaped = TRUE;
		}
		else if (*p == '"' && parens == 0)	/* quoting */
		{
			quoted = !quoted;

			if (!intok)
			{
				if (n < ntokens)
					tokens[n] = q;
				intok = TRUE;
			}
		}
		else if (*p == '(' && !quoted)		/* "(" (comment) */
		{
			parens++;

			if (!intok)
			{
				if (n < ntokens)
					tokens[n] = q;
				intok = TRUE;
			}

			*q = *p;
			q++;

		}
		else if (*p == ')' && !quoted)		/* ")" (comment) */
		{
			if (parens > 0)
			{
				parens--;

				if (parens == 0)
				{
					intok = FALSE;
					n++;

					*q = ')';
					q++;
					if (q <= end)
					{
						*q = '\0';
						q++;
					}
				}
			}
		}
		else if (quoted)			/* quoted character */
		{
			*q = *p;
			q++;
		}
		else if (isascii(*p) && isspace(*p))	/* whitespace */
		{
			if (quoted || parens > 0)
			{
				if (intok)
				{
					*q = *p;
					q++;
				}
			}
			else if (intok)
			{
				intok = FALSE;
				*q = '\0';
				q++;
				n++;
			}
		}
		else if (strchr(ARES_TOKENS, *p) != NULL) /* delimiter */
		{
			if (parens > 0)
			{
				*q = *p;
				q++;
				continue;
			}

			if (intok)
			{
				intok = FALSE;
				*q = '\0';
				q++;
				n++;
			}

			if (q <= end)
			{
				*q = *p;
				if (n < ntokens)
				{
					tokens[n] = q;
					n++;
				}
				q++;
			}

			if (q <= end)
			{
				*q = '\0';
				q++;
			}
		}
		else					/* other */
		{
			if (!intok)
			{
				if (n < ntokens)
					tokens[n] = q;
				intok = TRUE;
			}

			*q = *p;
			q++;
		}
	}

	if (q >= end)
		return -1;

	if (intok)
	{
		*q = '\0';
		n++;
	}

	return n;
}

/*
**  ARES_CONVERT -- convert a string to its code
**
**  Parameters:
**  	table -- in which table to look up
**  	str -- string to find
**
**  Return value:
**  	A code translation of "str".
*/

static int
ares_convert(struct lookup *table, char *str)
{
	int c;

	assert(table != NULL);
	assert(str != NULL);

	for (c = 0; ; c++)
	{
		if (table[c].str == NULL ||
		    strcasecmp(table[c].str, str) == 0)
			return table[c].code;
	}

	/* NOTREACHED */
}

/*
**  ARES_XCONVERT -- convert a code to its string
**
**  Parameters:
**  	table -- in which table to look up
**  	code -- code to find
**
**  Return value:
**  	A string translation of "code".
*/

static char *
ares_xconvert(struct lookup *table, int code)
{
	int c;

	assert(table != NULL);

	for (c = 0; ; c++)
	{
		if (table[c].str == NULL || table[c].code == code)
			return table[c].str;
	}

	/* NOTREACHED */
}

/*
**  ARES_DEDUP -- if we've gotten multiple results of the same method,
**                discard the older one
**
**  Parameters:
**  	ar -- pointer to a (struct authres)
**  	n -- the last one that was loaded
**
**  Return value:
**  	TRUE iff a de-duplication happened, leaving the result referenced by
** 	"n" open.
*/

static _Bool
ares_dedup(struct authres *ar, int n)
{
	int c;

	for (c = 0; c < n; c++)
	{
		if (ar->ares_result[c].result_method == ar->ares_result[n].result_method &&
		    ar->ares_result[c].result_method != ARES_METHOD_DKIM)
		{
			memcpy(&ar->ares_result[c], &ar->ares_result[n],
			       sizeof(ar->ares_result[c]));
			return TRUE;
		}
	}

	return FALSE;
}

/*
**  ARES_PARSE -- parse an Authentication-Results: header, return a
**                structure containing a parsed result
**
**  Parameters:
**  	hdr -- NULL-terminated contents of an Authentication-Results:
**  	       header field
**  	ar -- a pointer to a (struct authres) loaded by values after parsing
**
**  Return value:
**  	0 on success, -1 on failure.
*/

int
ares_parse(u_char *hdr, struct authres *ar)
{
	int n;
	int ntoks;
	int c;
	int r = 0;
	int state;
	int prevstate;
	u_char tmp[ARC_MAXHEADER + 2];
	u_char *tokens[ARES_MAXTOKENS];

	assert(hdr != NULL);
	assert(ar != NULL);

	memset(ar, '\0', sizeof *ar);
	memset(tmp, '\0', sizeof tmp);

	ntoks = ares_tokenize(hdr, tmp, sizeof tmp, tokens, ARES_MAXTOKENS);
	if (ntoks == -1 || ntoks > ARES_MAXTOKENS)
		return -1;

	prevstate = -1;
	state = 0;
	n = 0;

	for (c = 0; c < ntoks; c++)
	{
		if (tokens[c][0] == '(')		/* comment */
		{
			strlcpy((char *) ar->ares_result[n - 1].result_comment,
			        (char *) tokens[c],
			        sizeof ar->ares_result[n - 1].result_comment);
			continue;
		}

		switch (state)
		{
		  case 0:				/* authserv-id */
			if (!isascii(tokens[c][0]) ||
			    !isalnum(tokens[c][0]))
				return -1;

			if (tokens[c][0] == ';')
			{
				prevstate = state;
				state = 3;
			}
			else
			{
				strlcat((char *) ar->ares_host,
				        (char *) tokens[c],
				        sizeof ar->ares_host);

				prevstate = state;
				state = 1;
			}

			break;

		  case 1:				/* [version] */
			if (tokens[c][0] == '.' &&
			    tokens[c][1] == '\0' && prevstate == 0)
			{
				strlcat((char *) ar->ares_host,
				        (char *) tokens[c],
				        sizeof ar->ares_host);

				prevstate = state;
				state = 0;

				break;
			}

			if (tokens[c][0] == ';')
			{
				prevstate = state;
				state = 3;
			}
			else if (isascii(tokens[c][0]) &&
			         isdigit(tokens[c][0]))
			{
				strlcpy((char *) ar->ares_version,
				        (char *) tokens[c],
				        sizeof ar->ares_version);

				prevstate = state;
				state = 2;
			}
			else
			{
				return -1;
			}

			break;

		  case 2:				/* ; */
			if (tokens[c][0] != ';' ||
			    tokens[c][1] != '\0')
				return -1;

			prevstate = state;
			state = 3;

			break;

		  case 3:				/* method */
			if (n == 0 || !ares_dedup(ar, n))
				n++;

			if (n >= MAXARESULTS)
				return 0;

			r = 0;

			ar->ares_result[n - 1].result_method = ares_convert(methods,
			                                                    (char *) tokens[c]);
			prevstate = state;
			state = 4;

			break;

		  case 4:				/* = */
			if (tokens[c][0] != '=' ||
			    tokens[c][1] != '\0')
				return -1;

			prevstate = state;
			state = 5;

			break;

		  case 5:				/* result */
			ar->ares_result[n - 1].result_result = ares_convert(aresults,
			                                                    (char *) tokens[c]);
			ar->ares_result[n - 1].result_comment[0] = '\0';
			prevstate = state;
			state = 6;

			break;

		  case 7:				/* = (reason) */
			if (tokens[c][0] != '=' ||
			    tokens[c][1] != '\0')
				return -1;

			prevstate = state;
			state = 8;

			break;

		  case 8:
			strlcpy((char *) ar->ares_result[n - 1].result_reason,
			        (char *) tokens[c],
			        sizeof ar->ares_result[n - 1].result_reason);

			prevstate = state;
			state = 9;

			break;

		  case 6:				/* reason/propspec */
			if (tokens[c][0] == ';' &&	/* neither */
			    tokens[c][1] == '\0')
			{
				prevstate = state;
				state = 3;

				continue;
			}

			if (strcasecmp((char *) tokens[c], "reason") == 0)
			{				/* reason */
				prevstate = state;
				state = 7;

				continue;
			}
			else
			{
				prevstate = state;
				state = 9;
			}

			/* FALLTHROUGH */

		  case 9:				/* ptype */
			if (prevstate == 13 &&
			    strchr(ARES_TOKENS2, tokens[c][0]) != NULL &&
			    tokens[c][1] == '\0')
			{
				r--;

				strlcat((char *) ar->ares_result[n - 1].result_value[r],
				        (char *) tokens[c],
				        sizeof ar->ares_result[n - 1].result_value[r]);

				prevstate = state;
				state = 13;

				continue;
			}

			if (tokens[c][0] == ';' &&
			    tokens[c][1] == '\0')
			{
				prevstate = state;
				state = 3;

				continue;
			}
			else
			{
				ares_ptype_t x;

				x = ares_convert(ptypes, (char *) tokens[c]);
				if (x == ARES_PTYPE_UNKNOWN)
					return -1;

				if (r < MAXPROPS)
					ar->ares_result[n - 1].result_ptype[r] = x;

				prevstate = state;
				state = 10;
			}

			break;

		  case 10:				/* . */
			if (tokens[c][0] != '.' ||
			    tokens[c][1] != '\0')
				return -1;

			prevstate = state;
			state = 11;

			break;

		  case 11:				/* property */
			if (r < MAXPROPS)
			{
				strlcpy((char *) ar->ares_result[n - 1].result_property[r],
				        (char *) tokens[c],
				        sizeof ar->ares_result[n - 1].result_property[r]);
			}

			prevstate = state;
			state = 12;

			break;

		  case 12:				/* = */
			if (tokens[c][0] != '=' ||
			    tokens[c][1] != '\0')
				return -1;

			prevstate = state;
			state = 13;

			break;

		  case 13:				/* value */
			if (r < MAXPROPS)
			{
				strlcat((char *) ar->ares_result[n - 1].result_value[r],
				        (char *) tokens[c],
				        sizeof ar->ares_result[n - 1].result_value[r]);
				r++;
				ar->ares_result[n - 1].result_props = r;
			}

			prevstate = state;
			state = 9;

			break;
		}
	}

	/* error out on non-terminal states */
	if (state == 4 || state == 7 || state == 10 ||
	    state == 11 || state == 12)
		return -1;

	if (n > 1)
	{
		if (ares_dedup(ar, n - 1))
			n--;
	}

	ar->ares_count = n;

	return 0;
}

/*
**  ARES_GETMETHOD -- translate a method code to its name
**
**  Parameters:
**  	method -- method to convert
**
**  Return value:
**  	String matching the provided method, or NULL.
*/

const char *
ares_getmethod(ares_method_t method)
{
	return (const char *) ares_xconvert(methods, method);
}

/*
**  ARES_GETRESULT -- translate a result code to its name
**
**  Parameters:
**  	result -- result to convert
**
**  Return value:
**  	String matching the provided result, or NULL.
*/

const char *
ares_getresult(ares_result_t result)
{
	return (const char *) ares_xconvert(aresults, result);
}

/*
**  ARES_GETPTYPE -- translate a ptype code to its name
**
**  Parameters:
**  	ptype -- ptype to convert
**
**  Return value:
**  	String matching the provided ptype, or NULL.
*/

const char *
ares_getptype(ares_ptype_t ptype)
{
	return (const char *) ares_xconvert(ptypes, ptype);
}

#ifdef ARTEST
/*
**  MAIN -- program mainline
**
**  Parameters:
**  	argc, argv -- the usual
**
**  Return value:
**  	EX_USAGE or EX_OK
*/

# define NTOKENS 256

int
main(int argc, char **argv)
{
	int c;
	int d;
	int status;
	char *p;
	char *progname;
	struct authres ar;
	u_char buf[1024];
	u_char *toks[NTOKENS];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	if (argc != 2)
	{
		printf("%s: usage: %s header-value\n", progname, progname);
		return EX_USAGE;
	}

	c = ares_tokenize(argv[1], buf, sizeof buf, toks, NTOKENS);
	for (d = 0; d < c; d++)
		printf("token %d = '%s'\n", d, toks[d]);

	printf("\n");

	status = ares_parse(argv[1], &ar);
	if (status == -1)
	{
		printf("%s: ares_parse() returned -1\n", progname);
		return EX_OK;
	}

	printf("%d result%s found\n", ar.ares_count,
	       ar.ares_count == 1 ? "" : "s");

	printf("authserv-id '%s'\n", ar.ares_host);
	printf("version '%s'\n", ar.ares_version);

	for (c = 0; c < ar.ares_count; c++)
	{
		printf("result #%d, %d propert%s\n", c,
		       ar.ares_result[c].result_props,
		       ar.ares_result[c].result_props == 1 ? "y" : "ies");

		printf("\tmethod \"%s\"\n",
		       ares_xconvert(methods,
		                     ar.ares_result[c].result_method));
		printf("\tresult \"%s\"\n",
		       ares_xconvert(aresults,
		                     ar.ares_result[c].result_result));
		printf("\treason \"%s\"\n", ar.ares_result[c].result_reason);

		for (d = 0; d < ar.ares_result[c].result_props; d++)
		{
			printf("\tproperty #%d\n", d);
			printf("\t\tptype \"%s\"\n",
			       ares_xconvert(ptypes,
			                     ar.ares_result[c].result_ptype[d]));
			printf("\t\tproperty \"%s\"\n",
			       ar.ares_result[c].result_property[d]);
			printf("\t\tvalue \"%s\"\n",
			       ar.ares_result[c].result_value[d]);
		}
	}
}
#endif /* ARTEST */
