/*
**  Copyright (c) 2010-2012, 2017, The Trusted Domain Project.
**    All rights reserved.
*/

/* for Solaris */
#ifndef _REENTRANT
# define _REENTRANT
#endif /* ! REENTRANT */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

/* libopenarc includes */
#include "arc.h"
#include "arc-internal.h"
#include "arc-dns.h"

/* OpenARC includes */
#include "build-config.h"

/* macros, limits, etc. */
#ifndef MAXPACKET
# define MAXPACKET      8192
#endif /* ! MAXPACKET */

/*
**  Standard UNIX resolver stub functions
*/

struct arc_res_qh
{
	int		rq_error;
	int		rq_dnssec;
	size_t		rq_buflen;
};

/*
**  ARC_RES_INIT -- initialize the resolver
**
**  Parameters:
**  	srv -- service handle (returned)
**
**  Return value
**  	0 on success, !0 on failure
*/

int
arc_res_init(void **srv)
{
#ifdef HAVE_RES_NINIT
	struct __res_state *res;

	res = ARC_MALLOC(sizeof(struct __res_state));
	if (res == NULL)
		return -1;

	memset(res, '\0', sizeof(struct __res_state));

	if (res_ninit(res) != 0)
	{
		ARC_FREE(res);
		return -1;
	}

	*srv = res;

	return 0;
#else /* HAVE_RES_NINIT */
	if (res_init() == 0)
	{
		*srv = (void *) 0x01;
		return 0;
	}
	else
	{
		return -1;
	}
#endif /* HAVE_RES_NINIT */
}

/*
**  ARC_RES_CLOSE -- shut down the resolver
**
**  Parameters:
**  	srv -- service handle
**
**  Return value:
**  	None.
*/

void
arc_res_close(void *srv)
{
#ifdef HAVE_RES_NINIT
	struct __res_state *res;

	res = srv;

	if (res != NULL)
	{
		res_nclose(res);
		ARC_FREE(res);
	}
#endif /* HAVE_RES_NINIT */
}

/*
**  ARC_RES_CANCEL -- cancel a pending resolver query
**
**  Parameters:
**  	srv -- query service handle (ignored)
**  	qh -- query handle (ignored)
**
**  Return value:
**  	0 on success, !0 on error
**
**  Notes:
**  	The standard UNIX resolver is synchronous, so in theory this can
**  	never get called.  We have not yet got any use cases for one thread
**  	canceling another thread's pending queries, so for now just return 0.
*/

int
arc_res_cancel(void *srv, void *qh)
{
	if (qh != NULL)
		ARC_FREE(qh);

	return 0;
}

/*
**  ARC_RES_QUERY -- initiate a DNS query
**
**  Parameters:
**  	srv -- service handle (ignored)
**  	type -- RR type to query
**  	query -- the question to ask
**  	buf -- where to write the answer
**  	buflen -- bytes at "buf"
** 	qh -- query handle, used with arc_res_waitreply
**
**  Return value:
**  	0 on success, -1 on error
**
**  Notes:
**  	This is a stub for the stock UNIX resolver (res_) functions, which
**  	are synchronous so no handle needs to be created, so "qh" is set to
**  	"buf".  "buf" is actually populated before this returns (unless
**  	there's an error).
*/

int
arc_res_query(void *srv, int type, unsigned char *query, unsigned char *buf,
               size_t buflen, void **qh)
{
	int n;
	int ret;
	struct arc_res_qh *rq;
	unsigned char qbuf[HFIXEDSZ + MAXPACKET];
#ifdef HAVE_RES_NINIT
	struct __res_state *statp;
#endif /* HAVE_RES_NINIT */

#ifdef HAVE_RES_NINIT
	statp = srv;
	n = res_nmkquery(statp, QUERY, (char *) query, C_IN, type, NULL, 0,
	                 NULL, qbuf, sizeof qbuf);
#else /* HAVE_RES_NINIT */
	n = res_mkquery(QUERY, (char *) query, C_IN, type, NULL, 0, NULL, qbuf,
	                sizeof qbuf);
#endif /* HAVE_RES_NINIT */
	if (n == (size_t) -1)
		return ARC_DNS_ERROR;

#ifdef HAVE_RES_NINIT
	ret = res_nsend(statp, qbuf, n, buf, buflen);
#else /* HAVE_RES_NINIT */
	ret = res_send(qbuf, n, buf, buflen);
#endif /* HAVE_RES_NINIT */
	if (ret == -1)
		return ARC_DNS_ERROR;

	rq = (struct arc_res_qh *) ARC_MALLOC(sizeof *rq);
	if (rq == NULL)
		return ARC_DNS_ERROR;

	rq->rq_dnssec = ARC_DNSSEC_UNKNOWN;
	if (ret == -1)
	{
		rq->rq_error = errno;
		rq->rq_buflen = 0;
	}
	else
	{
		rq->rq_error = 0;
		rq->rq_buflen = (size_t) ret;
	}

	*qh = (void *) rq;

	return ARC_DNS_SUCCESS;
}

/*
**  ARC_RES_WAITREPLY -- wait for a reply to a pending query
**
**  Parameters:
**  	srv -- service handle
**  	qh -- query handle
**  	to -- timeout
**  	bytes -- number of bytes in the reply (returned)
**  	error -- error code (returned)
**
**  Return value:
**  	A ARC_DNS_* code.
**
**  Notes:
**  	Since the stock UNIX resolver is synchronous, the reply was completed
** 	before arc_res_query() returned, and thus this is almost a no-op.
*/

int
arc_res_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
                   int *error, int *dnssec)
{
	struct arc_res_qh *rq;

	assert(qh != NULL);

	rq = qh;

	if (bytes != NULL)
		*bytes = rq->rq_buflen;
	if (error != NULL)
		*error = rq->rq_error;
	if (dnssec != NULL)
		*dnssec = rq->rq_dnssec;

	return ARC_DNS_SUCCESS;
}

/*
**  ARC_RES_SETNS -- set nameserver list
**
**  Parameters:
**  	srv -- service handle
**  	nslist -- nameserver list, as a string
**
**  Return value:
**  	ARC_DNS_SUCCESS -- success
**  	ARC_DNS_ERROR -- error
*/

int
arc_res_nslist(void *srv, const char *nslist)
{
#ifdef HAVE_RES_SETSERVERS
	int nscount = 0;
	char *tmp;
	char *ns;
	char *last = NULL;
	struct sockaddr_in in;
# ifdef AF_INET6
	struct sockaddr_in6 in6;
# endif /* AF_INET6 */
	struct state *res;
	res_sockaddr_union nses[MAXNS];

	assert(srv != NULL);
	assert(nslist != NULL);

	memset(nses, '\0', sizeof nses);

	tmp = ARC_STRDUP(nslist);
	if (tmp == NULL)
		return ARC_DNS_ERROR;

	for (ns = strtok_r(tmp, ",", &last);
	     ns != NULL && nscount < MAXNS;
	     ns = strtok_r(NULL, ",", &last)
	{
		memset(&in, '\0', sizeof in);
# ifdef AF_INET6
		memset(&in6, '\0', sizeof in6);
# endif /* AF_INET6 */

		if (inet_pton(AF_INET, ns, (struct in_addr *) &in.sin_addr,
		              sizeof in.sin_addr) == 1)
		{
			in.sin_family= AF_INET;
			in.sin_port = htons(DNSPORT);
			memcpy(&nses[nscount].sin, &in,
			       sizeof nses[nscount].sin);
			nscount++;
		}
# ifdef AF_INET6
		else if (inet_pton(AF_INET6, ns,
		                   (struct in6_addr *) &in6.sin6_addr,
		                   sizeof in6.sin6_addr) == 1)
		{
			in6.sin6_family= AF_INET6;
			in6.sin6_port = htons(DNSPORT);
			memcpy(&nses[nscount].sin6, &in6,
			       sizeof nses[nscount].sin6);
			nscount++;
		}
# endif /* AF_INET6 */
		else
		{
			ARC_FREE(tmp);
			return ARC_DNS_ERROR;
		}
	}

	res = srv;
	res_setservers(res, nses, nscount);

	ARC_FREE(tmp);
#endif /* HAVE_RES_SETSERVERS */

	return ARC_DNS_SUCCESS;
}
